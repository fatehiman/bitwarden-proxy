# Security notes

Written plainly, including the parts that are not reassuring.

## What bwprx is for

Stopping an AI agent — which is fallible, and whose transcript is stored
somewhere — from holding open-ended access to a password vault. It narrows that
to: one credential, one approval, one moment.

## What it actually protects

**Blast radius.** An agent gets the item you approved. Not the vault. A
compromised or confused agent cannot enumerate and drain everything, because
each new item raises a new dialog.

**The master password.** Typed into a Tk dialog owned by bwprx, passed to `bw`
through a one-shot randomly named environment variable, and dropped immediately.
It never appears in a command line, never in the API, never in a log, and never
reaches a caller.

**The session key.** Held in one process's memory. Never written to disk, never
returned by any endpoint. Callers cannot use it to go around bwprx.

**Secrets in the agent's transcript.** `run` injects the credential into a child
process's environment and prints nothing. This is the single most useful habit:
the value never enters the model's context, so it cannot be logged, summarised,
or sent anywhere.

**Notes.** Excluded from `--env-all` and from `find` on purpose. Notes fields
routinely contain other passwords, recovery codes and key material that nobody
asked for. They must be requested explicitly.

**Who is asking.** The dialog names the real calling process, resolved by
matching the connection's source port against the OS connection table — not from
anything the caller said about itself.

**Silent access is visible.** Every use of a remembered grant is logged and
raises a tray balloon.

**Other local accounts.** The API listens on loopback only. The token sits in
`%LOCALAPPDATA%\bwprx\runtime.json`, ACL'd to your account with inheritance
removed.

**Web pages.** Requests carrying `Origin` or `Referer` are refused, and a custom
header is required, so a page that guesses the port still cannot drive the API.

**Walking away.** Idle timeout (6 h default), plus locking when Windows locks or
sleeps, plus Lock now in the tray. Locking clears all remembered grants.

## What it does NOT protect against

Be clear-eyed about these.

**Anything running as you, on this machine.** This is the big one. The token
file is readable by your own account, so any program you run can call the API.
It will still raise an approval dialog — so it cannot be silent — but bwprx is a
**consent layer, not a sandbox**. It does not defend against malware already
running as you; such malware could read the token, or simply read your vault
files directly.

**A remembered grant.** While a grant is live, that exact item goes to that
exact program with no prompt. That is the point, and it is a real reduction in
security. Prefer short windows. Every use is still logged.

**Approval fatigue.** If you click Approve without reading, the dialog achieves
nothing. The button is disabled for the first 500 ms to stop a stray click or
keystroke landing on it, `Escape` denies, closing the window denies, and no
answer within 120 s denies — but it cannot make you read.

**What the agent does afterwards.** Once a credential is in a child process, it
is out of bwprx's hands. `run` keeps it out of the model's context; it does not
stop the command itself from printing it. Do not point `run` at a command that
echoes its environment.

**Memory.** Python strings are immutable and cannot be reliably wiped. The
session key and credentials in flight exist in the process heap until garbage
collected. A memory-dumping attacker with your privileges wins.

**Your Bitwarden account.** bwprx is a gate in front of the local CLI. It does
nothing about a compromised Bitwarden account, a stolen master password, or your
other Bitwarden clients.

**The `bw` CLI.** bwprx trusts it completely.

## Deliberate design choices

**Approval required for `find`.** It returns no secrets, but the list of
accounts you hold is itself worth protecting. Turn it off with
`require_approval_for_list: false` if the prompts are not worth it to you.

**Writes remember for at most 5 minutes.** Writes are rare and not reversible.
A 6-hour standing permission to modify vault items is not a trade worth making.

**Timeout means deny.** An unanswered dialog is denied, never approved.

**Delete asks every time.** Deletion is the one action with no safe failure
mode, so its "don't ask again" list has exactly one entry: this once. It also
takes an item **id only**, never a name - a fuzzy match that picks the wrong
item is recoverable for a read and not for a delete. The default is a soft
delete into the Bitwarden trash; `--permanent` is available and says plainly in
the dialog that it cannot be undone.

## Reporting

This is a personal tool in a personal repository. If something here is wrong,
open an issue on the repo.
