"""Decision layer: vault + approval cache + dialog + audit log.

The HTTP layer stays a thin shell over this, and the tray talks to the same
object, so there is exactly one place where "may this happen?" is answered.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Tuple

from . import audit, config
from .cache import ApprovalCache
from .clientinfo import ClientInfo
from .ui import ApprovalRequest, UiService, ask_approval, ask_master_password
from .vault import Locked, NotFound, Vault, VaultError

READ_FIELDS = ["username", "password", "totp", "uri", "notes", "domain", "credential_id"]

# How many matched items the approval dialog lists individually before
# collapsing the rest into "... (+N more)". No secrets appear in this list
# either way - just the same name/username/folder that `find` itself returns.
PREVIEW_ITEM_CAP = 15


class Denied(RuntimeError):
    """The user said no, or the dialog timed out."""


def _item_text(item: Dict[str, Any]) -> str:
    """Everything about an item that a plain-text search is allowed to match:
    name, username, URIs - never notes or any secret field."""
    parts = [item.get("name") or "", item.get("username") or ""]
    parts += item.get("uris") or []
    return " ".join(parts).lower()


def _search_stages(items: List[Dict[str, Any]], query: str):
    """Widen a search step by step until something matches.

    `bw list items --search` treats the whole query as one strict pattern, so
    a query like "pexel api key" - three words describing one item - often
    matches nothing even though the item is right there under a slightly
    different name. Real vault contents are metadata (titles, usernames,
    URIs), not secrets, so there is no privacy reason to be this strict about
    finding them; the approval dialog is what actually decides whether the
    result reaches the agent, not the matching pass.

    Stages, from strictest to loosest, stopping at the first with any match:

    1. the exact phrase, as typed.
    2. every word present (any order).
    3. all but one word present, then all but two, ... down to
    4. any single word present.

    Yields `(label, matched_items)` pairs lazily so the caller can stop at the
    first non-empty stage.
    """
    terms = [t for t in query.lower().split() if t]
    if not terms:
        yield "(everything)", items
        return

    texts = [(item, _item_text(item)) for item in items]

    phrase = " ".join(terms)
    if len(terms) > 1:
        yield f'exact phrase "{query.strip()}"', [i for i, t in texts if phrase in t]

    n = len(terms)
    for k in range(n, 0, -1):
        matched = [i for i, t in texts if sum(term in t for term in terms) >= k]
        if k == n:
            label = "exact word match" if n == 1 else "all words matched (any order)"
        elif k == 1:
            label = "loosened - any one word matched"
        else:
            label = f"loosened - at least {k} of {n} words matched"
        yield label, matched


def _preview_lines(items: List[Dict[str, Any]]) -> str:
    lines = []
    for item in items[:PREVIEW_ITEM_CAP]:
        name = item.get("name") or "(unnamed)"
        user = item.get("username") or "(no username)"
        where = item.get("folder") or "(no folder)"
        lines.append(f"{name}  -  {user}  -  {where}")
    if len(items) > PREVIEW_ITEM_CAP:
        lines.append(f"... (+{len(items) - PREVIEW_ITEM_CAP} more)")
    return "\n".join(lines) if lines else "(none)"


class Broker:
    def __init__(self, vault: Vault, ui: UiService) -> None:
        self.vault = vault
        self.ui = ui
        self.cache = ApprovalCache()
        self._unlock_lock = threading.Lock()
        # Serialised so two agents cannot stack two dialogs on top of each other.
        self._approval_lock = threading.Lock()
        self.on_activity = None  # set by the tray for balloon notifications

    # ------------------------------------------------------------------ unlock

    def ensure_unlocked(self, interactive: bool = True) -> None:
        if self.vault.is_unlocked:
            return
        if not interactive:
            raise Locked("Vault is locked")
        with self._unlock_lock:
            if self.vault.is_unlocked:
                return
            status = self.vault.cli_status()
            account = status.get("userEmail")
            error: Optional[str] = None
            for _ in range(3):
                pw = self.ui.call(lambda root: ask_master_password(root, account, error))
                if pw is None:
                    audit.record("unlock_cancelled")
                    raise Denied("Unlock cancelled")
                try:
                    self.vault.unlock(pw)
                    return
                except VaultError as exc:
                    error = str(exc)
                    audit.record("unlock_failed", reason=error)
            raise Denied("Unlock failed")

    # ---------------------------------------------------------------- approval

    def _approve(self, *, action: str, query: str, client: ClientInfo,
                 title: str, summary: str, details: List[Tuple[str, str]],
                 choices, default_seconds: int, danger: bool = False) -> None:
        """Raise Denied unless a live grant covers this, or the user approves."""
        grant = self.cache.check(action, query, client.key)
        if grant is not None:
            audit.record("auto_approved", action=action, item=query,
                         client=client.name or "unknown", use=grant.uses,
                         expires_in=f"{grant.seconds_left}s")
            self._notify(f"{action}: {query}",
                         f"Auto-approved ({grant.seconds_left}s left)")
            return

        with self._approval_lock:
            # Another thread may have been granted permission while we queued.
            grant = self.cache.check(action, query, client.key)
            if grant is not None:
                audit.record("auto_approved", action=action, item=query,
                             client=client.name or "unknown", use=grant.uses)
                return

            req = ApprovalRequest(
                action=action, title=title, summary=summary, details=details,
                client=client.describe(), remember_choices=choices,
                default_remember=default_seconds, danger=danger)
            approved, remember = self.ui.call(lambda root: ask_approval(root, req))

        if not approved:
            audit.record("denied", action=action, item=query,
                         client=client.name or "unknown")
            raise Denied(f"{action} denied by user")

        if remember > 0:
            self.cache.grant(action, query, client.key, remember)
        audit.record("approved", action=action, item=query,
                     client=client.name or "unknown",
                     remembered=f"{remember}s" if remember else "once")

    def _notify(self, title: str, message: str) -> None:
        if callable(self.on_activity):
            try:
                self.on_activity(title, message)
            except Exception:
                pass

    # -------------------------------------------------------------------- read

    def read_credential(self, query: str, client: ClientInfo,
                        fields: Optional[List[str]] = None) -> Dict[str, Any]:
        self.ensure_unlocked()
        # Resolve first, so the dialog can name the item rather than the raw query.
        item = self.vault.get_item(query)
        cred = self.vault.credential_fields(item)

        wanted = [f for f in (fields or READ_FIELDS) if f in READ_FIELDS]
        details = [
            ("Item", cred.get("name") or query),
            ("Username", cred.get("username") or "(none)"),
            ("URI", cred.get("uri") or "(none)"),
            ("Fields", ", ".join(wanted)),
        ]
        self._approve(
            action="read", query=query, client=client,
            title="bwprx - credential request",
            summary="An agent is asking for a credential from your vault.",
            details=details,
            choices=config.READ_REMEMBER_CHOICES,
            default_seconds=int(config.get("default_read_remember_seconds")))

        self.vault.touch()
        out: Dict[str, Any] = {}
        for f in wanted:
            if f == "domain":
                out["domain"] = _domain_from_uri(cred.get("uri"))
            elif f == "totp":
                out["totp"] = self.vault.get_totp(cred["credential_id"]) if cred.get("totp") else None
            else:
                out[f] = cred.get(f)
        out["name"] = cred.get("name")
        return out

    # -------------------------------------------------------------------- list

    def list_items(self, client: ClientInfo, search: Optional[str] = None,
                   include_folders: bool = True,
                   folder: Optional[str] = None) -> Dict[str, Any]:
        """Titles, ids, usernames and URIs - no secrets ever.

        An agent cannot ask for "the deb13 password" without first finding out
        that the item is called "deb13 root". Searching is therefore a normal
        part of the flow, not an escape hatch - but it still shows what accounts
        exist, so by default it is approved like anything else.

        The matching itself is done here, not by `bw`'s own `--search`, which
        treats a multi-word query as one strict pattern and often finds
        nothing for a guessed query like "pexel api key". Instead the full
        (metadata-only) list is fetched once and matched progressively - see
        `_search_stages` - stopping at the first stage that finds anything.
        Whatever that stage returns is exactly what the approval dialog shows
        and exactly what the agent gets if approved, so a looser match never
        means a surprise: the user sees the actual result list before saying
        yes.
        """
        self.ensure_unlocked()
        items = self.vault.list_items(None)
        # A folder filter needs the folder list whatever the caller asked for.
        folders = self.vault.list_folders() if (include_folders or folder) else []
        names = {f["id"]: f["name"] for f in folders}
        for item in items:
            item["folder"] = names.get(item.get("folderId"))

        if folder is not None:
            wanted = self.vault.normalise_folder(folder)
            ids = {f["id"] for f in folders
                   if self.vault.normalise_folder(f.get("name") or "").lower()
                   == wanted.lower()} if wanted else {None}
            if wanted and not ids:
                raise NotFound(f"No folder named {wanted!r}")
            items = [i for i in items if i.get("folderId") in ids]

        match_label = "(everything)"
        if search:
            for label, matched in _search_stages(items, search):
                if matched:
                    items, match_label = matched, label
                    break
            else:
                items, match_label = [], "no match, even loosened to a single word"

        if config.get("require_approval_for_list"):
            details = [
                ("Search", search or "(everything)"),
                ("Folder", self.vault.normalise_folder(folder) or "(no folder)"
                           if folder is not None else "(any)"),
                ("Match method", match_label),
                ("Matches", str(len(items))),
                ("Items that would be returned", _preview_lines(items)),
                ("Returns", "names, ids, usernames, URIs and folders - "
                            "no passwords, TOTP codes or notes"),
            ]
            self._approve(
                action="list", query=search or "*", client=client,
                title="bwprx - vault search",
                summary="An agent wants to search your vault for item names.",
                details=details,
                choices=config.READ_REMEMBER_CHOICES,
                default_seconds=int(config.get("default_read_remember_seconds")))

        self.vault.touch()
        return {"items": items, "folders": folders, "count": len(items),
                "match_method": match_label}

    # ------------------------------------------------------------------- write

    def _folder_plan(self, folder: Optional[str]) -> Tuple[Optional[str], str]:
        """Work out what `--folder` means before anything is approved.

        Returns `(normalised path or None, text for the dialog)`. Nothing is
        created here: the user has to see, and approve, the folders that a
        write would bring into existence.
        """
        if folder is None:
            return None, "(unchanged)"
        path = self.vault.normalise_folder(folder)
        if not path:
            return "", "(none - top level)"
        missing = self.vault.missing_folder_levels(path)
        if not missing:
            return path, path
        return path, f"{path}  (creates: {', '.join(missing)})"

    def _resolve_folder(self, path: Optional[str]) -> Optional[str]:
        """Path -> folder id, creating folders. Call only after approval."""
        if path is None:
            return None
        if path == "":
            return ""  # explicit "no folder"
        folder = self.vault.ensure_folder(path)
        audit.record("folder_used", folder=folder.get("name"), id=folder.get("id"))
        return folder.get("id")

    def create_login(self, client: ClientInfo, *, name: str,
                     username: Optional[str] = None, uri: Optional[str] = None,
                     password: Optional[str] = None, notes: Optional[str] = None,
                     folder: Optional[str] = None,
                     generate_length: Optional[int] = None) -> Dict[str, Any]:
        self.ensure_unlocked()
        generating = password is None
        folder_path, folder_text = self._folder_plan(folder)
        details = [
            ("Name", name),
            ("Folder", folder_text if folder is not None else "(none - top level)"),
            ("Username", username or "(none)"),
            ("URI", uri or "(none)"),
            ("Password", f"generate a new random one "
                         f"({generate_length or config.get('generate_length')} chars), "
                         f"never shown to the agent"
                         if generating else "set to a value the agent supplied"),
        ]
        if notes:
            details.append(("Notes", notes))
        self._approve(
            action="create", query=name, client=client,
            title="bwprx - create vault item",
            summary="An agent wants to CREATE a new login in your vault.",
            details=details,
            choices=config.WRITE_REMEMBER_CHOICES,
            default_seconds=int(config.get("default_write_remember_seconds")),
            danger=True)

        self.vault.touch()
        folder_id = self._resolve_folder(folder_path) or None
        if generating:
            password = self.vault.generate_password(generate_length)
        item = self.vault.create_login(name=name, username=username,
                                       password=password, uri=uri, notes=notes,
                                       folder_id=folder_id)
        audit.record("created", item=item.get("name"), id=item.get("id"),
                     folder=folder_path or "(none)")
        return _write_result(item, generated=generating, folder=folder_path)

    def edit_login(self, client: ClientInfo, item_id: str, *,
                   name: Optional[str] = None, username: Optional[str] = None,
                   uri: Optional[str] = None, password: Optional[str] = None,
                   notes: Optional[str] = None, rotate: bool = False,
                   folder: Optional[str] = None,
                   generate_length: Optional[int] = None) -> Dict[str, Any]:
        self.ensure_unlocked()
        existing = self.vault.get_item(item_id)
        folder_path, folder_text = self._folder_plan(folder)
        changes = []
        if name is not None:
            changes.append(f"name -> {name}")
        if folder is not None:
            changes.append(f"folder -> {folder_text}")
        if username is not None:
            changes.append(f"username -> {username}")
        if uri is not None:
            changes.append(f"uri -> {uri}")
        if notes is not None:
            changes.append("notes -> (replaced)")
        if rotate:
            changes.append(f"password -> new random "
                           f"({generate_length or config.get('generate_length')} chars)")
        elif password is not None:
            changes.append("password -> value supplied by the agent")
        if not changes:
            raise ValueError("Nothing to change")

        details = [
            ("Item", existing.get("name") or item_id),
            ("Item id", item_id),
            ("Changes", "\n".join(changes)),
        ]
        self._approve(
            action="edit", query=item_id, client=client,
            title="bwprx - edit vault item",
            summary="An agent wants to EDIT an existing login in your vault.",
            details=details,
            choices=config.WRITE_REMEMBER_CHOICES,
            default_seconds=int(config.get("default_write_remember_seconds")),
            danger=True)

        self.vault.touch()
        folder_id = self._resolve_folder(folder_path)
        if rotate:
            password = self.vault.generate_password(generate_length)
        item = self.vault.edit_login(item_id, name=name, username=username,
                                     password=password, uri=uri, notes=notes,
                                     folder_id=folder_id)
        audit.record("edited", item=item.get("name"), id=item.get("id"))
        return _write_result(item, generated=rotate, folder=folder_path)

    # ----------------------------------------------------------------- folders

    def list_folders(self, client: ClientInfo) -> Dict[str, Any]:
        """Folder names only. No items, so nothing here names an account."""
        self.ensure_unlocked()
        folders = self.vault.list_folders()
        self.vault.touch()
        return {"folders": sorted(folders, key=lambda f: (f.get("name") or "").lower()),
                "count": len(folders)}

    def create_folder(self, client: ClientInfo, path: str) -> Dict[str, Any]:
        """Create `a/b/c` and any missing level above it."""
        self.ensure_unlocked()
        path = self.vault.normalise_folder(path)
        if not path:
            raise ValueError("folder name is required")
        existing = self.vault.find_folder(path)
        if existing:
            return {"id": existing.get("id"), "name": existing.get("name"),
                    "created": False}

        missing = self.vault.missing_folder_levels(path)
        details = [
            ("Folder", path),
            ("Creates", "\n".join(missing)),
            ("Note", "Bitwarden folders are a flat list; the '/' is what makes "
                     "them show as nested."),
        ]
        self._approve(
            action="folder", query=path, client=client,
            title="bwprx - create vault folder",
            summary="An agent wants to CREATE a folder in your vault.",
            details=details,
            choices=config.WRITE_REMEMBER_CHOICES,
            default_seconds=int(config.get("default_write_remember_seconds")),
            danger=True)

        self.vault.touch()
        folder = self.vault.ensure_folder(path)
        audit.record("folder_created", folder=folder.get("name"), id=folder.get("id"))
        return {"id": folder.get("id"), "name": folder.get("name"), "created": True}

    def move_item(self, client: ClientInfo, item_id: str,
                  folder: Optional[str]) -> Dict[str, Any]:
        """Move one item into a folder, or out of every folder with `""`.

        Separate from `edit` so that filing things away never needs an approval
        that could also change a password.
        """
        self.ensure_unlocked()
        existing = self.vault.get_item(item_id)
        name = existing.get("name") or item_id
        folder_path, folder_text = self._folder_plan(folder if folder is not None else "")

        current = None
        if existing.get("folderId"):
            match = [f for f in self.vault.list_folders()
                     if f.get("id") == existing.get("folderId")]
            current = match[0].get("name") if match else None

        details = [
            ("Item", name),
            ("Item id", item_id),
            ("From", current or "(no folder)"),
            ("To", folder_text),
            ("Changes", "the folder only - no name, username or password is touched"),
        ]
        self._approve(
            action="move", query=item_id, client=client,
            title="bwprx - move vault item",
            summary="An agent wants to MOVE an item to another folder.",
            details=details,
            choices=config.WRITE_REMEMBER_CHOICES,
            default_seconds=int(config.get("default_write_remember_seconds")),
            danger=True)

        self.vault.touch()
        folder_id = self._resolve_folder(folder_path) or None
        item = self.vault.move_item(item_id, folder_id)
        audit.record("moved", item=item.get("name"), id=item_id,
                     folder=folder_path or "(none)")
        return {"id": item.get("id"), "name": item.get("name"),
                "folder": folder_path or None,
                "moved_from": current or None}

    def delete_item(self, client: ClientInfo, item_id: str,
                    permanent: bool = False) -> Dict[str, Any]:
        """Delete one item by id. Always asks - there is no remember option."""
        self.ensure_unlocked()
        existing = self.vault.get_item(item_id)
        name = existing.get("name") or item_id
        login = existing.get("login") or {}

        details = [
            ("Item", name),
            ("Item id", item_id),
            ("Username", login.get("username") or "(none)"),
            ("Delete type", "PERMANENT - cannot be undone" if permanent
                            else "move to Bitwarden trash (restorable)"),
        ]
        # Deletion is the one action with no safe failure mode, so the
        # "don't ask again" list is a single entry: this once, or not at all.
        self._approve(
            action="delete", query=item_id, client=client,
            title="bwprx - delete vault item",
            summary="An agent wants to DELETE an item from your vault.",
            details=details,
            choices=[("Just this once", 0)],
            default_seconds=0,
            danger=True)

        self.vault.touch()
        self.vault.delete_item(item_id, permanent=permanent)
        audit.record("deleted", item=name, id=item_id,
                     permanent=str(bool(permanent)))
        return {"id": item_id, "name": name,
                "deleted": "permanent" if permanent else "trash"}

    # ------------------------------------------------------------------ status

    def status(self) -> Dict[str, Any]:
        cli = self.vault.cli_status()
        return {
            "unlocked": self.vault.is_unlocked,
            "account": self.vault.email or cli.get("userEmail"),
            "cli_status": cli.get("status"),
            "bw_path": self.vault.bw_path,
            "seconds_left": self.vault.seconds_left(),
            "idle_timeout_minutes": int(config.get("idle_timeout_minutes")),
            "grants": [
                {"action": g.action, "item": g.query, "client": g.client,
                 "seconds_left": g.seconds_left, "uses": g.uses}
                for g in self.cache.active()
            ],
        }


def _write_result(item: Dict[str, Any], generated: bool,
                  folder: Optional[str] = None) -> Dict[str, Any]:
    login = item.get("login") or {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "username": login.get("username"),
        "folder": folder or None,
        "password": "<written to vault, not shown>" if generated else "<set>",
    }


def _domain_from_uri(uri: Optional[str]) -> Optional[str]:
    if not uri:
        return None
    rest = uri.split("://", 1)[-1]
    rest = rest.split("@", 1)[-1]
    host = rest.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host or None
