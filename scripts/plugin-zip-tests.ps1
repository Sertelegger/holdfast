# The Windows half of the plugin bootstrap's safe-extraction rules, asserted
# against the zip corpus scripts/plugin-archive-corpus.py generates.
# Driven by scripts/plugin-archive-tests.sh --zip; runnable on its own.
param(
    [Parameter(Mandatory = $true)][string]$Lib,
    [Parameter(Mandatory = $true)][string]$Corpus
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. $Lib

$manifest = Join-Path $Corpus 'MANIFEST'
if (-not (Test-Path -LiteralPath $manifest)) { throw "no MANIFEST at $manifest" }

$cases = @(Get-Content -LiteralPath $manifest | ForEach-Object {
    $p = $_ -split '\s+', 4
    if ($p.Count -ge 3 -and $p[0] -ceq 'zip') { , @($p[1], $p[2]) }
})
# Anti-vacuity: a MANIFEST whose zip rows stopped being generated would make
# this loop run zero times and exit 0 -- a green tick for an untested
# extractor. Same guard the tar harness carries.
if ($cases.Count -lt 8) { throw "MANIFEST holds only $($cases.Count) zip case(s); expected at least 8" }

$sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("hf-zip-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $sandbox | Out-Null
$pass = 0
$fail = 0
try {
    foreach ($c in $cases) {
        $name = $c[0]
        $verdict = $c[1]
        $dest = Join-Path $sandbox ([System.IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        $err = ''
        $rc = 0
        try {
            $null = Expand-HoldfastArchive -Archive (Join-Path $Corpus (Join-Path 'zip' $name)) -DestDir $dest -Want 'holdfast.exe'
        } catch {
            $rc = 1
            $err = $_.Exception.Message
        }
        # Nothing may ever land outside the destination, whatever was
        # returned: an extractor that threw after writing is not a rejection.
        $stray = @(Get-ChildItem -Path $sandbox -Recurse -Force -Filter 'HF_PWN_*' -ErrorAction SilentlyContinue)
        $wanted = if ($verdict -ceq 'ACCEPT') { 0 } else { 1 }
        if ($rc -eq $wanted -and $stray.Count -eq 0) {
            $pass++
        } else {
            $fail++
            Write-Host ("    BAD  {0,-24} want={1,-6} rc={2} stray={3} {4}" -f $name, $verdict, $rc, $stray.Count, $err)
        }
        Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ("    zip: pass={0} fail={1} of {2} case(s)" -f $pass, $fail, $cases.Count)
if ($fail -ne 0) { exit 1 }
exit 0
