<#
  Claude Code PreToolUse guard: keep AI agents away from the vault directly.

  Credentials on this machine go through bwprx, which asks the user to approve
  each single request. This hook blocks the ways around that. It runs even in
  bypass-permissions mode, where the normal permission prompt never appears.

  Registered in ~/.claude/settings.json:

    "hooks": { "PreToolUse": [ {
        "matcher": "Bash|PowerShell",
        "hooks": [ { "type": "command",
          "command": "powershell -NoProfile -ExecutionPolicy Bypass -File \"E:/appServices/aac/bw-guard.ps1\"" } ] } ] }

  Reads the hook JSON on stdin. Exit 2 = block. Exit 0 = allow.
#>

$ErrorActionPreference = 'Stop'

try { $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }

$cmd = $payload.tool_input.command
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

# Match `bw` only where a shell would actually run it: at the start, or after a
# separator, an opening bracket, a backtick or a quote. Prose that merely
# mentions the command mid-sentence is not executable and must not be blocked -
# otherwise writing documentation about this guard trips the guard.
$cmdPos = '(?:^|[\n;&|(){}`"''])\s*'

# Each entry: regex -> why it is blocked.
# The lookbehind stops "bwprx" and paths like "./bw" from matching "bw".
$blocked = @(
    @{ re = "$cmdPos" + 'bw(\.exe)?\s+(get|list|export)\b'
       why = 'reads the vault directly, with no approval prompt' },
    @{ re = "$cmdPos" + 'bw(\.exe)?\s+(send|serve)\b'
       why = 'exposes vault contents' },
    @{ re = "$cmdPos" + 'bw(\.exe)?\s+unlock\b'
       why = 'would hand you a session key with full vault access' },
    @{ re = 'BW_SESSION'
       why = 'a session key grants full vault access' },
    @{ re = 'BITWARDENCLI_APPDATA_DIR'
       why = 'points the CLI at the vault state directly' },
    @{ re = '@bitwarden/mcp-server'
       why = 'the Bitwarden MCP server exposes the whole vault at once' },
    @{ re = "$cmdPos" + 'aac(\.exe)?\s+(connect|listen|run|connections)\b'
       why = 'Bitwarden Agent Access is retired here; it routed through a public relay' }
)

foreach ($rule in $blocked) {
    if ($cmd -imatch $rule.re) {
        $msg = @"
BLOCKED by bw-guard: this command $($rule.why).

This machine uses bwprx, so the user approves each single credential by hand.
Use the 'bitwarden-prx' skill instead:

  find   : bwprx-client find --search <text>
  read   : bwprx-client run --query <name-or-id> --env VAR=password -- <command>
           bwprx-client get --query <name-or-id> --json   (only if the value itself is needed)
  write  : bwprx-client create --name <name> --username <user> --uri <uri>
           bwprx-client edit --id <id> --rotate

Client: E:\www\bitwarden-proxy\dist\bwprx-client.exe
Allowed bw commands: status, login, lock, logout, sync, generate, --version.
"@
        [Console]::Error.WriteLine($msg)
        exit 2
    }
}

exit 0
