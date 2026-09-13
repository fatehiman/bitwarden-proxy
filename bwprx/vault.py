"""The only thing in the system that talks to the Bitwarden CLI.

One process owns exactly one `bw` session key, held in memory. That is the
whole point of bwprx: `bw unlock` mints a new session key and invalidates the
previous one, so anything that unlocks a second time breaks whoever unlocked
first. Funnelling every read and write through this single owner removes that
class of bug, and means the master password is typed once per session instead
of once per operation.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import audit, config

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Bitwarden item types
TYPE_LOGIN = 1


class VaultError(RuntimeError):
    pass


class Locked(VaultError):
    pass


class NotFound(VaultError):
    pass


def find_bw() -> Optional[str]:
    found = shutil.which("bw")
    if found:
        return found
    # winget's package directory is not always on PATH for service-like starts.
    local = os.environ.get("LOCALAPPDATA")
    if local:
        guess = os.path.join(
            local, "Microsoft", "WinGet", "Packages",
            "Bitwarden.CLI_Microsoft.Winget.Source_8wekyb3d8bbwe", "bw.exe")
        if os.path.exists(guess):
            return guess
    return None


class Vault:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._session: Optional[str] = None
        self._last_used: float = 0.0
        self._bw = find_bw()
        self._email: Optional[str] = None

    # ---------------------------------------------------------------- basics

    @property
    def bw_path(self) -> Optional[str]:
        return self._bw

    def _run(self, args: List[str], *, stdin: Optional[bytes] = None,
             env_extra: Optional[Dict[str, str]] = None,
             use_session: bool = True) -> subprocess.CompletedProcess:
        if not self._bw:
            raise VaultError("Bitwarden CLI (bw) not found on PATH")
        env = dict(os.environ)
        # Never let an inherited BW_SESSION decide anything for us.
        env.pop("BW_SESSION", None)
        if env_extra:
            env.update(env_extra)
        cmd = [self._bw] + args
        if use_session and self._session:
            cmd += ["--session", self._session]
        return subprocess.run(
            cmd, input=stdin, capture_output=True, env=env,
            creationflags=_NO_WINDOW, timeout=120)

    def cli_status(self) -> Dict[str, Any]:
        """`bw status` without a session: says logged out / locked / unlocked."""
        try:
            proc = self._run(["status"], use_session=False)
            return json.loads(proc.stdout.decode("utf-8", "replace") or "{}")
        except (VaultError, ValueError, subprocess.SubprocessError):
            return {}

    # ---------------------------------------------------------------- session

    @property
    def is_unlocked(self) -> bool:
        with self._lock:
            return self._session is not None

    @property
    def email(self) -> Optional[str]:
        return self._email

    def seconds_left(self) -> Optional[int]:
        """Seconds until the idle timer locks us, or None when locked."""
        with self._lock:
            if self._session is None:
                return None
            timeout = int(config.get("idle_timeout_minutes")) * 60
            return max(0, int(self._last_used + timeout - time.time()))

    def touch(self) -> None:
        with self._lock:
            if self._session is not None:
                self._last_used = time.time()

    def unlock(self, master_password: str) -> None:
        """Exchange the master password for a session key.

        The password goes in through a one-shot randomly named environment
        variable, so it never appears in a command line where other local
        processes could read it.
        """
        status = self.cli_status()
        state = status.get("status")
        if state == "unauthenticated" or not state:
            raise VaultError(
                "Bitwarden CLI is not logged in. Run `bw login` in a terminal, "
                "then try again.")

        var = "BWPRX_" + uuid.uuid4().hex
        try:
            proc = self._run(
                ["unlock", "--passwordenv", var, "--raw"],
                env_extra={var: master_password},
                use_session=False)
        finally:
            master_password = ""

        key = proc.stdout.decode("utf-8", "replace").strip()
        if proc.returncode != 0 or not key:
            err = proc.stderr.decode("utf-8", "replace").strip() or "unlock failed"
            raise VaultError(err.splitlines()[0] if err else "unlock failed")

        with self._lock:
            self._session = key
            self._last_used = time.time()
            self._email = status.get("userEmail")

        audit.record("vault_unlocked", account=self._email)
        try:
            self._run(["sync"])
        except Exception:
            pass

    def lock(self, reason: str = "manual") -> None:
        with self._lock:
            had = self._session is not None
            self._session = None
            self._last_used = 0.0
        if had:
            audit.record("vault_locked", reason=reason)

    def _require_session(self) -> None:
        if not self.is_unlocked:
            raise Locked("Vault is locked. Unlock bwprx from the tray icon.")

    # ------------------------------------------------------------------ read

    def get_item(self, query: str) -> Dict[str, Any]:
        """Look up one item by name, URI or id. `bw get item` does the matching."""
        self._require_session()
        proc = self._run(["get", "item", query])
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            low = err.lower()
            if "not found" in low:
                raise NotFound(f"No vault item matches {query!r}")
            if "more than one" in low:
                raise VaultError(
                    f"{query!r} matches more than one item - ask for it by id")
            if "master password" in low or "locked" in low:
                # Our session key stopped working (e.g. something else ran
                # `bw unlock`). Drop it so the user is asked to unlock again
                # instead of every lookup silently failing.
                self.lock(reason="session key rejected")
                raise Locked("The vault session expired. Unlock bwprx again.")
            raise VaultError(err or "bw get item failed")
        try:
            return json.loads(out)
        except ValueError:
            raise VaultError("Could not parse the item returned by bw")

    @staticmethod
    def credential_fields(item: Dict[str, Any]) -> Dict[str, Optional[str]]:
        login = item.get("login") or {}
        uris = login.get("uris") or []
        uri = uris[0].get("uri") if uris else None
        return {
            "username": login.get("username"),
            "password": login.get("password"),
            "totp": login.get("totp"),
            "uri": uri,
            "notes": item.get("notes"),
            "name": item.get("name"),
            "credential_id": item.get("id"),
        }

    # Fields that may leave the vault in a listing. Everything else - password,
    # totp, notes, custom fields - is dropped before the data goes anywhere,
    # because a listing is for finding an item, not for reading it.
    LIST_SAFE_FIELDS = ("id", "name", "folderId", "type", "favorite", "revisionDate")

    def list_items(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Titles and locations only - never secrets."""
        self._require_session()
        args = ["list", "items"]
        if search:
            args += ["--search", search]
        proc = self._run(args)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            if "master password" in err.lower() or "locked" in err.lower():
                self.lock(reason="session key rejected")
                raise Locked("The vault session expired. Unlock bwprx again.")
            raise VaultError(err or "bw list items failed")
        try:
            raw = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
        except ValueError:
            raise VaultError("Could not parse the item list returned by bw")

        out: List[Dict[str, Any]] = []
        for item in raw:
            safe = {k: item.get(k) for k in self.LIST_SAFE_FIELDS}
            login = item.get("login") or {}
            safe["username"] = login.get("username")
            safe["uris"] = [u.get("uri") for u in (login.get("uris") or []) if u.get("uri")]
            safe["has_totp"] = bool(login.get("totp"))
            safe["has_notes"] = bool(item.get("notes"))
            out.append(safe)
        return out

    def list_folders(self) -> List[Dict[str, Any]]:
        self._require_session()
        proc = self._run(["list", "folders"])
        if proc.returncode != 0:
            raise VaultError(
                proc.stderr.decode("utf-8", "replace").strip() or "bw list folders failed")
        try:
            raw = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
        except ValueError:
            raise VaultError("Could not parse the folder list returned by bw")
        # The "no folder" pseudo-folder has a null id; it is not a real folder.
        return [{"id": f.get("id"), "name": f.get("name")}
                for f in raw if f.get("id")]

    # --------------------------------------------------------------- folders

    @staticmethod
    def normalise_folder(path: str) -> str:
        """`  projects // buloot / ` -> `projects/buloot`.

        Bitwarden folders are a FLAT list; nesting is purely a display effect of
        `/` inside the name. So a path is just a name, and getting the spacing
        and stray separators right is what stops `Projects/Buloot` and
        `Projects / Buloot` becoming two different folders.
        """
        parts = [p.strip() for p in str(path).replace("\\", "/").split("/")]
        return "/".join(p for p in parts if p)

    def find_folder(self, path: str) -> Optional[Dict[str, Any]]:
        """Match a folder by full path, case-insensitively."""
        wanted = self.normalise_folder(path).lower()
        if not wanted:
            return None
        for folder in self.list_folders():
            if self.normalise_folder(folder.get("name") or "").lower() == wanted:
                return folder
        return None

    def missing_folder_levels(self, path: str) -> List[str]:
        """Which levels of `a/b/c` do not exist yet, outermost first."""
        parts = self.normalise_folder(path).split("/")
        if not parts or parts == [""]:
            return []
        have = {self.normalise_folder(f.get("name") or "").lower()
                for f in self.list_folders()}
        missing = []
        for depth in range(1, len(parts) + 1):
            level = "/".join(parts[:depth])
            if level.lower() not in have:
                missing.append(level)
        return missing

    def create_folder(self, name: str) -> Dict[str, Any]:
        name = self.normalise_folder(name)
        if not name:
            raise VaultError("Folder name is empty")
        self._require_session()
        proc = self._run(["create", "folder"], stdin=self._encode({"name": name}))
        return self._parse_write(proc, "create folder")

    def ensure_folder(self, path: str) -> Dict[str, Any]:
        """Return the folder for `path`, creating it and any missing parents.

        Bitwarden does not require the parent to exist for `a/b` to *look*
        nested, but a real `a` keeps the tree tidy in the apps and lets items be
        filed at the parent level later.
        """
        path = self.normalise_folder(path)
        existing = self.find_folder(path)
        if existing:
            return existing
        created = None
        for level in self.missing_folder_levels(path):
            created = self.create_folder(level)
        if created is None:  # pragma: no cover - find_folder said it was absent
            raise VaultError(f"Could not create folder {path!r}")
        return {"id": created.get("id"), "name": created.get("name")}

    def move_item(self, item_id: str, folder_id: Optional[str]) -> Dict[str, Any]:
        """Put an item in a folder, or take it out of one with `None`."""
        self._require_session()
        item = self.get_item(item_id)
        item["folderId"] = folder_id
        proc = self._run(["edit", "item", item_id], stdin=self._encode(item))
        return self._parse_write(proc, "edit")

    def get_totp(self, query: str) -> Optional[str]:
        self._require_session()
        proc = self._run(["get", "totp", query])
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").strip() or None

    # ----------------------------------------------------------------- write

    def generate_password(self, length: Optional[int] = None) -> str:
        self._require_session()
        length = int(length or config.get("generate_length"))
        proc = self._run([
            "generate", "--uppercase", "--lowercase", "--number", "--special",
            "--length", str(length)])
        pw = proc.stdout.decode("utf-8", "replace").strip()
        if proc.returncode != 0 or not pw:
            raise VaultError("Password generation failed")
        return pw

    @staticmethod
    def _encode(payload: Dict[str, Any]) -> bytes:
        """Base64 the item ourselves rather than shelling out to `bw encode`."""
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw)

    def create_login(self, *, name: str, username: Optional[str] = None,
                     password: Optional[str] = None, uri: Optional[str] = None,
                     notes: Optional[str] = None, folder_id: Optional[str] = None,
                     totp: Optional[str] = None) -> Dict[str, Any]:
        self._require_session()
        # Written out by hand: `bw get template item` needs an unlocked session
        # and its shape has moved between CLI releases, while this schema has not.
        item: Dict[str, Any] = {
            "organizationId": None,
            "collectionIds": None,
            "folderId": folder_id,
            "type": TYPE_LOGIN,
            "name": name,
            "notes": notes,
            "favorite": False,
            "fields": [],
            "reprompt": 0,
            "login": {
                "uris": [{"match": None, "uri": uri}] if uri else [],
                "username": username,
                "password": password,
                "totp": totp,
            },
        }
        proc = self._run(["create", "item"], stdin=self._encode(item))
        return self._parse_write(proc, "create")

    def edit_login(self, item_id: str, *, name: Optional[str] = None,
                   username: Optional[str] = None, password: Optional[str] = None,
                   uri: Optional[str] = None, notes: Optional[str] = None,
                   totp: Optional[str] = None,
                   folder_id: Optional[str] = None) -> Dict[str, Any]:
        self._require_session()
        item = self.get_item(item_id)
        login = item.setdefault("login", {})
        if name is not None:
            item["name"] = name
        if folder_id is not None:
            item["folderId"] = folder_id or None
        if notes is not None:
            item["notes"] = notes
        if username is not None:
            login["username"] = username
        if password is not None:
            login["password"] = password
        if totp is not None:
            login["totp"] = totp
        if uri is not None:
            login["uris"] = [{"match": None, "uri": uri}]
        proc = self._run(["edit", "item", item_id], stdin=self._encode(item))
        return self._parse_write(proc, "edit")

    @staticmethod
    def _parse_write(proc: subprocess.CompletedProcess, what: str) -> Dict[str, Any]:
        out = proc.stdout.decode("utf-8", "replace").strip()
        if proc.returncode != 0 or not out:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise VaultError(err or f"bw {what} item failed")
        try:
            item = json.loads(out)
        except ValueError:
            raise VaultError(f"bw {what} item returned unparsable output")
        if not item.get("id"):
            raise VaultError(f"bw {what} item returned no id")
        return item

    def delete_item(self, item_id: str, permanent: bool = False) -> None:
        """Delete by id only.

        Never by name: a fuzzy match that picks the wrong item is recoverable
        for a read and not for a delete. Default is a soft delete, so the item
        lands in the Bitwarden trash and can be restored.
        """
        self._require_session()
        args = ["delete", "item", item_id]
        if permanent:
            args.append("--permanent")
        proc = self._run(args)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            if "not found" in err.lower():
                raise NotFound(f"No vault item with id {item_id}")
            raise VaultError(err or "bw delete item failed")

    def sync(self) -> None:
        self._require_session()
        self._run(["sync"])
