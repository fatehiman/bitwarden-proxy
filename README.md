# bwprx — a consent layer between AI agents and your Bitwarden vault

`bwprx` is a small Windows tray app. It holds **one** unlocked Bitwarden session
and hands out **one credential at a time**, each time asking you first.

An AI agent never gets your vault, never gets a session key, and never gets your
master password. It gets exactly the one secret you approved, and — if you use
`run` — it does not even get to see that.

```
   Claude Code / any agent            bwprx tray app            Bitwarden
   ------------------------           --------------            ---------
   bwprx-client run ...   ──HTTP──►   approval dialog   ──bw──►  local vault
                                      (you click Yes)            + bitwarden.com
                          ◄─────────  one credential
```

Nothing leaves the machine except the Bitwarden CLI's normal traffic to
Bitwarden's own servers. There is no relay and no third-party service.

---

## Why this exists

The obvious options both fail in the same way:

| | Problem |
|---|---|
| **Bitwarden MCP server** | Takes a `BW_SESSION` token, then exposes `list` and `get` over the **whole vault**. One approval, unlimited access, forever. |
| **Bitwarden Agent Access** (`aac`) | Right idea — per-credential approval — but read-only, routes through a public cloud relay, has no way to hold a session, and its console UI must stay open. |

Both also trip over the same Bitwarden CLI behaviour: **`bw unlock` mints a new
session key and invalidates the old one.** So any second unlock silently breaks
whatever unlocked first. `aac` plus a write helper meant reads started failing
with "credential not found" every time you wrote to the vault.

`bwprx` fixes that by construction: one process owns the one session, and every
read and write goes through it.

---

## What you get

- **Tray app.** No console window to keep open. Right-click for state, lock, and
  the remembered-approval list.
- **Unlock once.** Master password typed one time. The session is held in memory
  and locks after **6 hours idle** (configurable), when Windows locks or sleeps,
  or when you quit.
- **Approve each request.** A dialog names the item, the fields, and the real
  program asking (resolved from the OS connection table, so it cannot be faked).
- **"Don't ask again for…"** — `1m / 5m / 10m / 30m / 1h / 2h / 3h / 6h` for
  reads, and `1m / 5m` for writes. An agent uploading twenty files asks once, not
  twenty times.
- **Read, search, create and edit.** Agent Access could only read.
- **Folders.** List them, create them (including missing parent levels), file
  items into them, and search one folder at a time.
- **Secrets can stay out of the agent's context** via `run`, which injects the
  credential into a child process's environment and never prints it.
- **Audit log** of every request and decision, with no secrets in it.

---

## Install

Needs the Bitwarden CLI, logged in:

```powershell
winget install Bitwarden.CLI
bw login
```

Then either run from source:

```powershell
pip install -r requirements.txt
pythonw bwprx_app.py
```

or build the two executables:

```powershell
python build.py
```

| Output | What it is |
|---|---|
| `dist\bwprx.exe` | the tray app — start this and leave it running |
| `dist\bwprx-client.exe` | what agents and scripts call |

To start it with Windows, put a shortcut to `bwprx.exe` in
`shell:startup`.

### How it is installed on this workstation

Set up 2026-09-13. The skill and the settings hook are machine-local files, so
this does **not** follow the Claude Code account to another machine.

| Path | What |
|---|---|
| `E:\www\bitwarden-proxy\` | this project |
| `E:\www\bitwarden-proxy\dist\bwprx.exe` | tray app — must be running |
| `E:\www\bitwarden-proxy\dist\bwprx-client.exe` | what agents call |
| `E:\www\bitwarden-proxy\tools\bw-guard.ps1` | PreToolUse hook blocking direct vault access |
| `E:\appServices\cmnBatchFiles\start-bwprx.cmd` | start it |
| `E:\appServices\cmnBatchFiles\stop-bwprx.cmd` | stop it (locks the vault) |
| `%USERPROFILE%\.claude\skills\bitwarden-prx\SKILL.md` | the skill Claude Code follows |
| `%USERPROFILE%\.claude\settings.json` → `hooks.PreToolUse` | registers the guard |
| `%LOCALAPPDATA%\bwprx\` | `config.json`, `audit.log`, `runtime.json` |

Bitwarden CLI `bw` 2026.5.0 (winget `Bitwarden.CLI`), logged in, is the only
prerequisite. The `dist\` binaries are not in git — rebuild with
`python build.py`.

The skill and the hook registration live in `~/.claude/` rather than in any
repo's `.claude/`, because a repo's `.claude/` is committed and would reach every
clone. The guard *script* is in this repo, because it is code and holds no
secrets.

---

## Using it

### Find the item first

Titles are rarely exactly what you guessed, so start here. Returns names, ids,
usernames, URIs and folders — **never** passwords, TOTP codes or notes.

```powershell
bwprx-client find --search deb13
bwprx-client find                 # everything
bwprx-client find --search aws --json
```

### Use a credential without seeing it — preferred

```powershell
bwprx-client run --query "deb13 root" --env PGPASSWORD=password -- psql
bwprx-client run --query "deb13 root" --env-all -- deploy.cmd
```

`--env-all` injects `BWPRX_USERNAME`, `BWPRX_PASSWORD`, `BWPRX_TOTP`,
`BWPRX_URI`, `BWPRX_DOMAIN`, `BWPRX_CREDENTIAL_ID`.

**`notes` is deliberately excluded from `--env-all`**, because notes routinely
hold other secrets nobody asked for. Ask for them explicitly if you really need
them: `--env NOTES=notes`.

Add `--aac-prefix` to get `AAC_*` names instead, for scripts written against
Bitwarden Agent Access.

### Print a credential — only when the value itself is needed

```powershell
bwprx-client get --query "deb13 root" --fields username,password --json
```

This puts the secret in the caller's output, where an AI agent will keep it in
its transcript. Prefer `run`.

### Create and edit

```powershell
# create with a generated password that nothing outside the vault ever sees
bwprx-client create --name "Example Corp" --folder "Projects/Example"   --uri https://example.com --username me@example.com

# rotate a password in place
bwprx-client edit --id <vault-item-id> --rotate --length 32
```

Omit `--password` and bwprx generates one itself, writes it to the vault, and
reports only the item id and name.

### Folders

Bitwarden folders are **one flat list**. What looks like a tree in the apps is
just a `/` inside the folder's name, so `Projects/Buloot` is a single folder
whose name contains a slash. bwprx treats that as a path anyway: it normalises
spacing, matches case-insensitively, and creates any missing level for you —
after showing you, in the approval dialog, exactly which folders it would
create.

```powershell
bwprx-client folders                                # the tree
bwprx-client folders --create "Projects/Buloot"     # creates Projects too, if absent
bwprx-client find --folder "Projects/Buloot"        # one folder only
bwprx-client find --folder ""                       # items filed nowhere

bwprx-client move --id <id> --folder "Projects/Buloot"
bwprx-client move --id <id> --no-folder             # out of every folder
```

`move` is deliberately separate from `edit`: filing something away should never
need an approval that could also change a password. It touches `folderId` and
nothing else.

Pass `--folder` to `create` so a new item lands in the right place in one
approval, rather than a create followed by a move.

### Delete

```powershell
bwprx-client delete --id <vault-item-id>              # to the Bitwarden trash
bwprx-client delete --id <vault-item-id> --permanent  # cannot be undone
```

Takes an **id only**, never a name, and always asks - there is no "don't ask
again" for deletion.

### Check state

```powershell
bwprx-client status
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error |
| 3 | **you denied it**, or the dialog timed out |
| 4 | no matching item |
| 5 | vault locked — unlock from the tray |
| 6 | bwprx is not running |

---

## Settings

`%LOCALAPPDATA%\bwprx\config.json` (tray → *Open settings file*):

| Key | Default | What it does |
|---|---|---|
| `idle_timeout_minutes` | `360` | lock after this much idle time |
| `lock_on_workstation_lock` | `true` | lock when Windows locks or sleeps |
| `port` | `7395` | loopback port for the API |
| `approval_timeout_seconds` | `120` | no answer counts as **deny** |
| `require_approval_for_list` | `true` | ask before `find` too |
| `notify_on_auto_approve` | `true` | tray balloon when a remembered grant is used |
| `generate_length` | `24` | default generated password length |

Restart the tray app after editing.

Files live in `%LOCALAPPDATA%\bwprx\`: `config.json`, `audit.log`, and
`runtime.json` (the loopback port and API token — ACL'd to your account only).

---

## The Bitwarden CLI behaviour this was built around

**Unlocking the CLI mints a new session key and invalidates the previous one.**

That single behaviour broke the earlier `aac` setup: every write (which had to
unlock separately) silently killed the listener's session. Reads then failed
with *"No credential found"* — and **no approval prompt at all** — which looks
exactly like a denial and is very hard to diagnose.

bwprx removes the whole class of bug: one process owns the one session, and
every read and write goes through it. It also detects the case where `bw` starts
asking for a master password (meaning something else invalidated the key), drops
the key, and reports `locked`, so you get an honest unlock prompt.

**Do not unlock the CLI by hand while bwprx is running.** It breaks bwprx's
session. The guard blocks it.

---

## The guard

This workstation runs Claude Code in bypass-permissions mode, where the normal
permission prompt never appears. So the rule is enforced by a **PreToolUse
hook**, which runs whatever the permission mode is. `tools/bw-guard.ps1` inspects
every `Bash` and `PowerShell` command and **exits 2 (block)** on:

- reading the vault directly (`get`, `list`, `export`)
- `send` and `serve`
- unlocking the CLI by hand
- the session-key and app-data environment variables
- `@bitwarden/mcp-server`
- `aac connect|listen|run|connections`

Still allowed: `bw status`, `bw login`, `bw lock`, `bw logout`, `bw sync`,
`bw generate`, `bw --version`, and everything `bwprx-client`.

Verified: listing vault items is refused even under bypass permissions.
`tools/test-bw-guard.ps1` runs the cases.

---

## Gotchas

1. **Do not unlock the CLI by hand while bwprx runs** — see the section above.

2. **`bw` can report `unauthenticated` even though the account data is present.**
   Seen on 2026-09-13: `global_account_activeAccountId` in
   `%APPDATA%\Bitwarden CLI\data.json` went empty while tokens and ciphers were
   still there, so **every** unlock failed regardless of the password. Fix:
   `bw login` again. Check with `bw status` — it must say `locked`, not
   `unauthenticated`.

3. **Notes fields hold secrets.** `--env-all` and `find` both exclude `notes` on
   purpose. On 2026-09-13 a test with the old `--env-all` (which included notes)
   printed a server root password into a Claude transcript, because that item
   keeps console passwords in its notes. The password had to be rotated. Ask for
   notes only with an explicit `--env NOTES=notes`.

4. **Each call costs 3-4 s.** Most of that is Bitwarden CLI start-up, which is a
   Node process. A remembered grant removes the dialog but not this cost.

5. **`find` prompts too, by default.** It returns no secrets, but the list of
   accounts you hold is worth protecting. Set `require_approval_for_list: false`
   in `%LOCALAPPDATA%\bwprx\config.json` if that is not worth the prompts.

6. **Quitting bwprx locks the vault and drops all grants.** So does Windows
   locking or sleeping, and 6 hours idle.

7. **Do not let PowerShell write `~/.claude/settings.json`.** Windows
   PowerShell 5.1 writes a UTF-8 **BOM** by default (`Out-File`, `Set-Content`,
   `>`). Claude Code rejects the file with *"Settings file is not a valid JSON
   object"* even though the JSON itself is fine — the three bytes `EF BB BF` at
   the start are the whole problem. Hit on 2026-09-13 when the guard hook was
   registered. Write it with Python, or with
   `[IO.File]::WriteAllText($p, $json, [Text.UTF8Encoding]::new($false))`.

8. **Delete always asks, and takes an id only.** No remember option, and no
   deleting by name. The default moves the item to the Bitwarden trash;
   `--permanent` destroys it.

9. **There is no folder delete.** Folders can be created and filled, but
   removing one is a rare, destructive act with no undo in the CLI — do it in
   the Bitwarden app.

---

## Alternatives that were evaluated and rejected

`aac` was installed, paired and tested on 2026-09-13, then retired the same day.
Its files are parked in `E:\appServices\_retired\aac-2026-09-13\`.

- <https://github.com/bitwarden/agent-access> (`aac`) — right idea, wrong fit:
  **read-only** (the provider trait has only `name/status/unlock/lookup`, and the
  wire protocol has one request type, `credential_request`), routes through a
  **public cloud relay** (`wss://ap.lesspassword.dev`) that is pointless for a
  same-machine agent, cannot hold a session, and its console UI must stay open.
  Still early preview, with a draft protocol that has open gaps (no payload
  padding; rendezvous MITM hardening unimplemented).
- <https://github.com/bitwarden/mcp-server> — takes a session token and exposes
  `list`/`get` over the **whole vault**. One setup, unlimited access, no
  per-request consent.

---

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit, and the API
- [SECURITY.md](SECURITY.md) — the threat model, honestly, including what this
  does **not** protect against
