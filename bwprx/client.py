"""Agent-facing command line client.

Talks to the tray app over loopback. `run` is the preferred command: it puts
the secret into a child process's environment and never prints it, so the value
never lands in an AI agent's transcript.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .paths import runtime_path
from .protocol import API_VERSION, REQUIRED_HEADER

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 3
EXIT_NOT_FOUND = 4
EXIT_LOCKED = 5
EXIT_UNAVAILABLE = 6

FIELDS = ["username", "password", "totp", "uri", "notes", "domain", "credential_id"]

# `notes` is deliberately NOT in --env-all. Notes are free text and very often
# hold extra secrets - other passwords, key fingerprints, recovery codes - that
# the caller never asked for. A caller that genuinely wants them must say so
# with an explicit --env VAR=notes.
ENV_ALL_FIELDS = [f for f in FIELDS if f != "notes"]
# Generous: the user may take a while to answer the approval dialog.
TIMEOUT = 300


class ClientError(RuntimeError):
    def __init__(self, message: str, exit_code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _runtime() -> Dict[str, Any]:
    p = runtime_path()
    if not p.exists():
        raise ClientError(
            "bwprx is not running. Start the tray app (bwprx.exe) and try again.",
            EXIT_UNAVAILABLE)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ClientError(f"Cannot read {p}: {exc}", EXIT_UNAVAILABLE)


def _request(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rt = _runtime()
    url = f"{rt['url']}{path}"
    data = json.dumps(body or {}).encode("utf-8") if method == "POST" else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {rt['token']}")
    req.add_header(REQUIRED_HEADER, API_VERSION)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            message = payload.get("error", {}).get("message") or str(exc)
        except Exception:
            message = str(exc)
        code = {403: EXIT_DENIED, 404: EXIT_NOT_FOUND,
                423: EXIT_LOCKED}.get(exc.code, EXIT_ERROR)
        raise ClientError(message, code)
    except urllib.error.URLError as exc:
        raise ClientError(f"Cannot reach bwprx: {exc.reason}", EXIT_UNAVAILABLE)


# ------------------------------------------------------------------ commands

def cmd_status(args: argparse.Namespace) -> int:
    data = _request("GET", "/v1/status")
    if args.json:
        print(json.dumps(data, indent=2))
        return EXIT_OK
    print(f"vault    : {'unlocked' if data.get('unlocked') else 'locked'}")
    print(f"account  : {data.get('account') or '-'}")
    left = data.get("seconds_left")
    if left is not None:
        print(f"locks in : {left // 60}m idle")
    grants = data.get("grants") or []
    print(f"remembered approvals: {len(grants)}")
    for g in grants:
        print(f"  - {g['action']} {g['item']} ({g['seconds_left']}s left, "
              f"{g['uses']} uses)")
    return EXIT_OK


def cmd_find(args: argparse.Namespace) -> int:
    body = {"search": args.search, "include_folders": not args.no_folders}
    if args.folder is not None:
        body["folder"] = args.folder
    data = _request("POST", "/v1/list", body)
    items = data["items"]
    if args.json:
        print(json.dumps(data, indent=2))
        return EXIT_OK

    if not items:
        print(f"no items match {args.search!r}" if args.search else "vault is empty")
        return EXIT_NOT_FOUND

    width = min(44, max((len(i.get("name") or "") for i in items), default=10))
    print(f"{'NAME'.ljust(width)}  {'USERNAME'.ljust(28)}  FOLDER / ID")
    print("-" * (width + 60))
    for item in sorted(items, key=lambda i: (i.get("folder") or "", i.get("name") or "")):
        name = (item.get("name") or "(unnamed)")[:width].ljust(width)
        user = (item.get("username") or "-")[:28].ljust(28)
        where = item.get("folder") or "(no folder)"
        print(f"{name}  {user}  {where}")
        print(f"{' ' * width}  {' ' * 28}  id={item.get('id')}")
        for uri in (item.get("uris") or [])[:2]:
            print(f"{' ' * width}  {' ' * 28}  uri={uri}")
    print(f"\n{data['count']} item(s). No passwords, TOTP codes or notes are "
          f"returned by find - use `run` or `get` for those.")
    return EXIT_OK


def cmd_get(args: argparse.Namespace) -> int:
    fields = args.fields.split(",") if args.fields else None
    data = _request("POST", "/v1/credential",
                    {"query": args.query, "fields": fields})
    cred = data["credential"]
    if args.json:
        print(json.dumps({"success": True, "credential": cred}))
    else:
        for k, v in cred.items():
            if v is not None:
                print(f"{k}: {v}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        raise ClientError("no command given after --", EXIT_ERROR)
    if not args.env and not args.env_all:
        raise ClientError("use --env VAR=field and/or --env-all", EXIT_ERROR)

    mappings: List[tuple] = []
    for pair in args.env or []:
        if "=" not in pair:
            raise ClientError(f"bad --env value {pair!r}, expected VAR=field")
        var, field = pair.split("=", 1)
        if field not in FIELDS:
            raise ClientError(f"unknown field {field!r}; valid: {', '.join(FIELDS)}")
        mappings.append((var, field))

    wanted = sorted({f for _v, f in mappings}
                    | (set(ENV_ALL_FIELDS) if args.env_all else set()))
    data = _request("POST", "/v1/credential", {"query": args.query, "fields": wanted})
    cred = data["credential"]

    env = dict(os.environ)
    if args.env_all:
        for field in ENV_ALL_FIELDS:
            value = cred.get(field)
            if value is not None:
                env[f"AAC_{field.upper()}" if args.aac_prefix else f"BWPRX_{field.upper()}"] = str(value)
    for var, field in mappings:  # explicit mappings win
        value = cred.get(field)
        if value is not None:
            env[var] = str(value)

    try:
        proc = subprocess.run(args.command, env=env)
        return proc.returncode
    except FileNotFoundError:
        raise ClientError(f"command not found: {args.command[0]}", EXIT_ERROR)
    finally:
        cred.clear()


def cmd_create(args: argparse.Namespace) -> int:
    body: Dict[str, Any] = {"name": args.name}
    for key in ("username", "uri", "notes", "folder"):
        value = getattr(args, key)
        if value is not None:
            body[key] = value
    if args.password is not None:
        body["password"] = args.password
    if args.length:
        body["generate_length"] = args.length
    data = _request("POST", "/v1/item/create", body)
    print(json.dumps(data["item"], indent=2) if args.json
          else _fmt_item("CREATED", data["item"]))
    return EXIT_OK


def cmd_edit(args: argparse.Namespace) -> int:
    body: Dict[str, Any] = {"id": args.id}
    for key in ("name", "username", "uri", "notes", "folder"):
        value = getattr(args, key)
        if value is not None:
            body[key] = value
    if args.rotate:
        body["rotate"] = True
    elif args.password is not None:
        body["password"] = args.password
    if args.length:
        body["generate_length"] = args.length
    data = _request("POST", "/v1/item/edit", body)
    print(json.dumps(data["item"], indent=2) if args.json
          else _fmt_item("UPDATED", data["item"]))
    return EXIT_OK


def cmd_delete(args: argparse.Namespace) -> int:
    data = _request("POST", "/v1/item/delete",
                    {"id": args.id, "permanent": args.permanent})
    item = data["item"]
    if args.json:
        print(json.dumps(item, indent=2))
    else:
        where = ("deleted permanently" if item.get("deleted") == "permanent"
                 else "moved to the Bitwarden trash")
        print(f"RESULT: DELETED\nid: {item.get('id')}\n"
              f"name: {item.get('name')}\n{where}")
    return EXIT_OK


def cmd_folders(args: argparse.Namespace) -> int:
    if args.create:
        data = _request("POST", "/v1/folder/create", {"name": args.create})
        folder = data["folder"]
        if args.json:
            print(json.dumps(folder, indent=2))
        else:
            verb = "CREATED" if folder.get("created") else "ALREADY EXISTS"
            print(f"RESULT: {verb}\nname: {folder.get('name')}\n"
                  f"id: {folder.get('id')}")
        return EXIT_OK

    data = _request("POST", "/v1/folders")
    folders = data["folders"]
    if args.json:
        print(json.dumps(data, indent=2))
        return EXIT_OK
    if not folders:
        print("no folders")
        return EXIT_OK
    have = {(f.get("name") or "").lower() for f in folders}
    for f in folders:
        name = f.get("name") or ""
        parts = name.split("/")
        # Indent by depth so the flat list reads as the tree Bitwarden shows.
        # But if the parent level has no folder of its own, show the whole path:
        # two folders called "deb13" under different missing parents would
        # otherwise print as the same line.
        parent = "/".join(parts[:-1]).lower()
        label = parts[-1] if (not parent or parent in have) else name
        print(f"{'  ' * (len(parts) - 1)}{label}".ljust(40) + f"  id={f.get('id')}")
    print(f"\n{data['count']} folder(s). Nesting is the '/' in the name - "
          f"Bitwarden folders are one flat list.")
    return EXIT_OK


def cmd_move(args: argparse.Namespace) -> int:
    folder = "" if args.no_folder else args.folder
    if folder is None:
        raise ClientError("use --folder <path> or --no-folder", EXIT_ERROR)
    data = _request("POST", "/v1/item/move", {"id": args.id, "folder": folder})
    item = data["item"]
    if args.json:
        print(json.dumps(item, indent=2))
    else:
        print(f"RESULT: MOVED\nid: {item.get('id')}\n"
              f"name: {item.get('name')}\n"
              f"from: {item.get('moved_from') or '(no folder)'}\n"
              f"to: {item.get('folder') or '(no folder)'}")
    return EXIT_OK


def _fmt_item(verb: str, item: Dict[str, Any]) -> str:
    return (f"RESULT: {verb}\n"
            f"id: {item.get('id')}\n"
            f"name: {item.get('name')}\n"
            f"folder: {item.get('folder') or '(no folder)'}\n"
            f"username: {item.get('username')}\n"
            f"password: {item.get('password')}")


# -------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bwprx-client",
        description="Ask bwprx for a Bitwarden credential, or create/edit one. "
                    "Every request needs the user to approve it.",
        epilog="Prefer `run`: it injects the secret into a child process and "
               "never prints it.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="show vault state and remembered approvals")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser(
        "find", help="search vault item titles - no secrets are returned")
    s.add_argument("--search", help="substring to match; omit to list everything")
    s.add_argument("--no-folders", action="store_true",
                   help="skip the folder hierarchy")
    s.add_argument("--folder", metavar="PATH",
                   help="only items in this folder, e.g. \"Projects/Buloot\"; "
                        "pass \"\" for items in no folder at all")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_find)

    s = sub.add_parser("get", help="print a credential (the value enters your output)")
    s.add_argument("--query", required=True, help="item name, URI or id")
    s.add_argument("--fields", help=f"comma separated subset of: {','.join(FIELDS)}")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("run", help="run a command with the credential in its environment")
    s.add_argument("--query", required=True, help="item name, URI or id")
    s.add_argument("--env", action="append", metavar="VAR=field",
                   help="map one field to an environment variable")
    s.add_argument("--env-all", action="store_true",
                   help=f"inject {', '.join(ENV_ALL_FIELDS)} as BWPRX_<FIELD>. "
                        f"Excludes notes on purpose - notes often hold other "
                        f"secrets; ask for them with --env VAR=notes if needed")
    s.add_argument("--aac-prefix", action="store_true",
                   help="use AAC_<FIELD> names instead, for scripts written "
                        "against Bitwarden Agent Access")
    s.add_argument("command", nargs=argparse.REMAINDER,
                   help="-- followed by the command to run")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("create", help="create a new login item")
    s.add_argument("--name", required=True)
    s.add_argument("--folder", metavar="PATH",
                   help="file it here, e.g. \"Projects/Buloot\". Missing "
                        "levels are created after you approve them")
    s.add_argument("--username")
    s.add_argument("--uri")
    s.add_argument("--notes")
    s.add_argument("--password", help="omit to generate one the agent never sees")
    s.add_argument("--length", type=int, help="generated password length")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_create)

    s = sub.add_parser("edit", help="edit an existing login item")
    s.add_argument("--id", required=True, help="vault item id")
    s.add_argument("--name")
    s.add_argument("--folder", metavar="PATH",
                   help="move it to this folder as part of the edit")
    s.add_argument("--username")
    s.add_argument("--uri")
    s.add_argument("--notes")
    s.add_argument("--rotate", action="store_true",
                   help="replace the password with a new random one")
    s.add_argument("--password", help="set an explicit password")
    s.add_argument("--length", type=int, help="generated password length")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_edit)

    s = sub.add_parser("folders", help="list vault folders, or create one")
    s.add_argument("--create", metavar="PATH",
                   help="create \"Projects/Buloot\" and any missing level above it")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_folders)

    s = sub.add_parser("move", help="move an item into a folder (by id only)")
    s.add_argument("--id", required=True, help="vault item id")
    s.add_argument("--folder", metavar="PATH",
                   help="destination, e.g. \"Projects/Buloot\"")
    s.add_argument("--no-folder", action="store_true",
                   help="take it out of every folder instead")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_move)

    s = sub.add_parser("delete", help="delete a login item (by id only)")
    s.add_argument("--id", required=True, help="vault item id")
    s.add_argument("--permanent", action="store_true",
                   help="skip the trash and destroy it; cannot be undone")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_delete)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.func(args)
    except ClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
