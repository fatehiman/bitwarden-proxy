# How bwprx is put together

## The shape of it

```
  bwprx-client.exe                  bwprx.exe (tray)                 bw CLI
  ----------------                  ----------------                 ------
  find / run / get      HTTP        server.py                        local
  create / edit    ──127.0.0.1──►   broker.py  ──► ui.py (dialog)     vault
                                        │                              ▲
                                        ├──► cache.py  (grants)        │
                                        ├──► audit.py  (log)           │
                                        └──► vault.py  ────────────────┘
```

Only `vault.py` ever runs `bw`. Only `broker.py` decides whether something is
allowed. `server.py` is a thin shell over the broker, so the tray menu and the
API cannot drift apart in what they permit.

## Modules

| File | Job |
|---|---|
| `paths.py` | where config, the audit log and `runtime.json` live; ACLs the token file |
| `config.py` | defaults, JSON settings file, the two "remember for" lists |
| `audit.py` | append-only log, rotated at 2 MB; never records secrets |
| `vault.py` | the **only** caller of `bw`; owns the single session key |
| `cache.py` | remembered approvals, keyed `(action, item, calling program)` |
| `clientinfo.py` | resolves the caller's real PID from the OS connection table |
| `ui.py` | one Tk thread; the unlock dialog and the approval dialog |
| `broker.py` | vault + cache + dialog + audit — the one place that says yes or no |
| `server.py` | loopback HTTP, bearer token, browser-header rejection |
| `watchdog.py` | idle timer and Windows lock/sleep detection |
| `tray`/`app.py` | pystray icon, menu, and process lifecycle |
| `client.py` | the agent-facing CLI |
| `protocol.py` | constants shared by client and server, with no imports of its own |

## Two threading rules

1. **pystray owns the main thread** on Windows. `icon.run()` never returns until
   quit.
2. **Tk objects belong to the thread that made them.** So `ui.py` runs a private
   `Tk()` root on its own thread and other threads submit callables to it and
   block for the answer. HTTP handler threads call `ui.call(...)` and wait.

Approvals are serialised behind one lock, so two agents cannot stack two
dialogs on top of each other and have the user approve the wrong one.

## Why one process owns the session

`bw unlock` derives a **new** session key and invalidates the previous one.
Anything that unlocks a second time silently breaks whoever unlocked first —
lookups then fail as "not found" rather than "locked", which looks like a denial
and is very hard to diagnose.

So: one owner, one key, held in memory only, never written to disk, never handed
to a caller. `vault.py` also watches for `bw` replying with a master-password
prompt, which means the key was invalidated behind its back; it then drops the
key and reports `locked` so you get an honest unlock prompt instead of silent
failures.

## The approval cache

Key: `(action, query, calling program)` — all lower-cased.

- `read "deb13 root"` and `read "1080ad6b-…"` are **different keys**, because
  they are different queries, even though they resolve to the same item. That
  errs toward asking too often rather than too rarely.
- A grant never widens: approving one item grants nothing about any other.
- Reads offer up to 6 hours, writes up to 5 minutes.
- Every use of a grant is logged, and raises a tray balloon, so silent access is
  still visible.
- Locking the vault clears every grant.

## HTTP API

`http://127.0.0.1:<port>`, port and token in
`%LOCALAPPDATA%\bwprx\runtime.json`.

Every request needs:

```
Authorization: Bearer <token>
X-Bwprx-Client: 1
```

and is refused if it carries `Origin` or `Referer` — a web page cannot set the
custom header cross-origin without a preflight, and preflights are never
answered.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/v1/status` | — | vault state, idle countdown, live grants |
| POST | `/v1/list` | `{search, include_folders, folder}` | titles, ids, usernames, URIs, folders |
| POST | `/v1/credential` | `{query, fields}` | the requested fields |
| POST | `/v1/item/create` | `{name, username, uri, password?, notes, folder, generate_length}` | `{id, name, username, folder}` |
| POST | `/v1/item/edit` | `{id, name?, username?, uri?, password?, rotate?, notes?, folder?}` | `{id, name, username, folder}` |
| POST | `/v1/item/delete` | `{id, permanent}` | `{id, name, deleted}` |
| POST | `/v1/item/move` | `{id, folder}` | `{id, name, folder, moved_from}` |
| POST | `/v1/folders` | — | every folder, id and name |
| POST | `/v1/folder/create` | `{name}` | `{id, name, created}` |

Status codes: `403` denied, `404` not found, `423` locked, `400` bad request,
`500` vault error. The client maps these to exit codes 3 / 4 / 5 / 1 / 1.

`/v1/list` never returns `password`, `totp`, `notes` or custom fields — they are
stripped in `vault.list_items()` before the data leaves that function.

## Folders

Bitwarden folders are a **flat list of names**; the tree in the apps is a
display effect of `/` inside a name. So bwprx has no tree either — it treats a
folder name as a path and does three things with it:

- `normalise_folder` collapses whitespace and stray separators, so
  `Projects / Buloot ` and `Projects/Buloot` cannot become two folders.
- `missing_folder_levels` reports which levels of `a/b/c` do not exist yet. The
  approval dialog shows that list, so no folder is ever created without the user
  seeing its name first.
- `ensure_folder` creates those levels, outermost first, and returns the leaf.

Creating a parent is not strictly required — Bitwarden renders `a/b` as nested
even with no `a` — but a real parent keeps the tree tidy and lets items be filed
at the parent level later.

`move` is its own action rather than a flag on `edit`, so that an approval to
file something away can never also carry a password change.

## Building

`build.py` drives PyInstaller twice:

- **`bwprx.exe`** — `--windowed`, with `pystray._win32` and
  `PIL._tkinter_finder` as hidden imports.
- **`bwprx-client.exe`** — `--console`, and explicitly **excludes** `tkinter`
  and `pystray`. That is why the constants it shares with the server live in
  `protocol.py`: importing them from `server.py` would drag the whole UI stack
  into the client binary.
