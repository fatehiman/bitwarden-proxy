$guard = "E:\www\bitwarden-proxy\tools\bw-guard.ps1"

# name, command, expected exit (2 = blocked, 0 = allowed)
$cases = @(
    @{ n = 'plain vault read';        c = 'bw get item github';                       want = 2 },
    @{ n = 'list items';              c = 'bw list items';                            want = 2 },
    @{ n = 'after &&';                c = 'echo hi && bw list items';                 want = 2 },
    @{ n = 'after semicolon';         c = 'cd /tmp; bw export';                       want = 2 },
    @{ n = 'inside double quotes';    c = 'powershell -c "bw get item x"';            want = 2 },
    @{ n = 'bash command sub';        c = 'X=`bw get item x`';                        want = 2 },
    @{ n = 'unlock';                  c = 'bw unlock --raw';                          want = 2 },
    @{ n = 'BW_SESSION';              c = '$env:BW_SESSION = "abc"';                  want = 2 },
    @{ n = 'mcp server';              c = 'npx -y @bitwarden/mcp-server';             want = 2 },
    @{ n = 'aac connect';             c = 'aac connect --domain github.com';          want = 2 },
    @{ n = 'prose mid-sentence';      c = 'blocks direct bw get and bw list calls';   want = 0 },
    @{ n = 'bwprx client find';       c = 'bwprx-client find --search deb13';         want = 0 },
    @{ n = 'bwprx run';               c = 'bwprx-client run --query x --env-all -- y'; want = 0 },
    @{ n = 'bw status allowed';       c = 'bw status';                                want = 0 },
    @{ n = 'bw login allowed';        c = 'bw login';                                 want = 0 },
    @{ n = 'bw generate allowed';     c = 'bw generate --length 24';                  want = 0 }
)

$fail = 0
foreach ($case in $cases) {
    $json = @{ tool_input = @{ command = $case.c } } | ConvertTo-Json -Compress
    $json | powershell -NoProfile -ExecutionPolicy Bypass -File $guard 2>$null | Out-Null
    $got = $LASTEXITCODE
    $ok = ($got -eq $case.want)
    if (-not $ok) { $fail++ }
    "{0}  {1,-24} want={2} got={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $case.n, $case.want, $got
}
""
if ($fail -eq 0) { "ALL $($cases.Count) CASES PASSED" } else { "$fail FAILURE(S)" }
