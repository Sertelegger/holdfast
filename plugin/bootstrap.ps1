# Holdfast plugin bootstrap -- the Windows launcher spec section 13.3 describes.
# PowerShell 5.1+ (built into Windows 10/11). Reached through bootstrap.cmd,
# which is what `${CLAUDE_PLUGIN_ROOT}/bootstrap` resolves to on Windows IF
# the spawn path does PATHEXT resolution -- see the header of `bootstrap`.
#
# **UNVERIFIED AND LOAD-BEARING:** whether a native child's stdout survives
# PowerShell's pipeline intact is not settled here, and MCP is a byte stream
# of JSON-RPC over stdio. If PowerShell re-encodes it, the server will appear
# to connect and then talk nonsense. There was no Windows host available when
# this landed; `plugin/README.md` names the CI step that settles it.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$UrlReleases = 'https://github.com/Sertelegger/holdfast/releases'
$UrlSource = 'https://github.com/Sertelegger/holdfast#build-and-try-it'
$UrlOwnBin = 'https://github.com/Sertelegger/holdfast/tree/main/plugin#using-a-binary-you-built-yourself'
$RepoGit = 'https://github.com/Sertelegger/holdfast'

# One plain line on stderr, the same shape `bootstrap` writes. Not
# Write-Error: under `$ErrorActionPreference = 'Stop'` that throws a
# formatted error record instead, which pwsh 7 wraps at the console width and
# decorates with ANSI colour, so the MCP log holds a word-wrapped box rather
# than the sentence, and the `exit 1` after it never runs.
function Die([string]$msg) { [Console]::Error.WriteLine("holdfast bootstrap: $msg"); exit 1 }

# --- 0. an explicitly named binary ----------------------------------------
# HOLDFAST_BOOTSTRAP_BIN, exactly as the Unix `bootstrap` treats it: exec that
# file, no download, no version comparison, and a refusal rather than a
# fallback when it is not usable. Above everything it makes irrelevant.
# "Absolute" means drive-qualified or UNC on Windows -- `\foo` and `C:foo`
# are rooted there but resolve against the current drive or directory, which
# is whichever project Claude Code was started in. The `/` arm is pwsh on a
# Unix host, which is where scripts/plugin-bootstrap-tests.sh runs this.
if ($env:HOLDFAST_BOOTSTRAP_BIN) {
    $Bin = $env:HOLDFAST_BOOTSTRAP_BIN
    if ([System.IO.Path]::DirectorySeparatorChar -eq '/') {
        $IsAbs = $Bin.StartsWith('/')
    } else {
        $IsAbs = $Bin -match '^([A-Za-z]:[\\/]|\\\\)'
    }
    if (-not $IsAbs) {
        Die "HOLDFAST_BOOTSTRAP_BIN must be an absolute path, and '$Bin' is not -- this runs in whichever project Claude Code was started in, so a relative path names a different file in each one"
    }
    if (-not (Test-Path -LiteralPath $Bin -PathType Leaf)) {
        Die "HOLDFAST_BOOTSTRAP_BIN is $Bin, which is not a file -- nothing was downloaded in its place, because the variable asks for exactly that binary"
    }
    & $Bin @args
    exit $LASTEXITCODE
}

# $PSScriptRoot first, for the same reason `bootstrap` prefers $0: the cwd is
# the user's, never the plugin root.
$Root = $PSScriptRoot
if (-not $Root -and $env:CLAUDE_PLUGIN_ROOT) { $Root = $env:CLAUDE_PLUGIN_ROOT }
if (-not $Root) { Die "cannot locate my own directory; reinstall the plugin" }

. (Join-Path $Root 'lib-safe-extract.ps1')

$VersionFile = Join-Path $Root 'version.txt'
if (-not (Test-Path -LiteralPath $VersionFile)) { Die "version.txt is missing from $Root; reinstall the plugin" }
$Version = (Get-Content -LiteralPath $VersionFile -Raw).Trim()
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+') { Die "version.txt does not hold a version: '$Version'" }

$Arch = $env:PROCESSOR_ARCHITECTURE
switch ($Arch) {
    'AMD64' { $Target = 'windows-x86_64' }
    'ARM64' { Die "no prebuilt binary for windows-aarch64 -- build holdfast from source ($UrlSource) and set HOLDFAST_BOOTSTRAP_BIN to its absolute path ($UrlOwnBin)" }
    default { Die "no prebuilt binary for '$Arch' -- build holdfast from source ($UrlSource) and set HOLDFAST_BOOTSTRAP_BIN to its absolute path ($UrlOwnBin)" }
}
$Exe = 'holdfast.exe'
$ArchiveName = "holdfast-$Target.zip"
# Kept under the 500 characters `claude mcp list` shows; see `bootstrap`.
$BuildIt = "build it -- cargo install --locked --git $RepoGit --tag v$Version holdfast -- and set HOLDFAST_BOOTSTRAP_BIN to its absolute path in the `"env`" block of Claude Code's settings.json, then restart. See $UrlOwnBin"

# ${CLAUDE_PLUGIN_DATA} for the same reasons the Unix half prefers it:
# uninstall-scoped, and not a well-known path a hostile local process can
# pre-create. LOCALAPPDATA is the Windows-shaped fallback for a hand run.
if ($env:CLAUDE_PLUGIN_DATA) {
    $CacheRoot = $env:CLAUDE_PLUGIN_DATA
} elseif ($env:LOCALAPPDATA) {
    $CacheRoot = Join-Path $env:LOCALAPPDATA 'holdfast'
} else {
    Die "neither CLAUDE_PLUGIN_DATA nor LOCALAPPDATA is set, so there is nowhere to cache the binary -- build holdfast from source and set HOLDFAST_BOOTSTRAP_BIN to its absolute path ($UrlOwnBin)"
}
$CacheDir = Join-Path $CacheRoot 'bin'
$Cached = Join-Path $CacheDir "holdfast-v$Version-$Target.exe"
$SumsCached = Join-Path $CacheDir "SHA256SUMS-v$Version.txt"

$BaseUrl = if ($env:HOLDFAST_BOOTSTRAP_BASE_URL) { $env:HOLDFAST_BOOTSTRAP_BASE_URL } else { 'https://github.com/Sertelegger/holdfast/releases/download' }

# --- 1. cache hit ---------------------------------------------------------
# `&` rather than Start-Process: the child must inherit this process's stdio
# handles, because on Windows those handles ARE the MCP transport.
if ((Test-Path -LiteralPath $Cached) -and (Test-Path -LiteralPath $SumsCached)) {
    & $Cached @args
    exit $LASTEXITCODE
}

# --- 2. download ----------------------------------------------------------
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
# Inside the cache directory, not $env:TEMP: a cross-volume Move-Item is a
# copy-then-delete, and a concurrent bootstrap can then see a half-written
# binary. Same rule as the Unix half.
$Tmp = Join-Path $CacheDir (".dl." + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
try {
    if ($BaseUrl -notmatch '^https://' -and -not $env:HOLDFAST_BOOTSTRAP_INSECURE) {
        Die "refusing a non-TLS URL ($BaseUrl) -- TLS to GitHub is the whole of the v0.1.0 trust root (spec A-4)"
    }
    # TLS 1.2 is not the default on Windows PowerShell 5.1 and github.com
    # refuses anything older, so this line is what makes the fetch work at all.
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $SumsTmp = Join-Path $Tmp 'SHA256SUMS.txt'
    # Not published and not reachable need opposite advice; see the same
    # block in `bootstrap`. A WebException (5.1) or HttpResponseException (7)
    # carries the status when a server answered, and nothing when none did.
    $SumsUrl = "$BaseUrl/v$Version/SHA256SUMS.txt"
    try {
        Invoke-WebRequest -Uri $SumsUrl -OutFile $SumsTmp -UseBasicParsing
    } catch {
        $Status = $null
        try { $Status = [int]$_.Exception.Response.StatusCode } catch { }
        if ($Status -eq 404) {
            Die "no holdfast v$Version binary to download: the v$Version release answered 404 -- unpublished, a draft, or without binaries. To run Holdfast now, $BuildIt"
        } elseif ($Status) {
            Die "$SumsUrl answered HTTP $Status -- retry later, or $BuildIt"
        }
        Die "cannot reach $SumsUrl -- is this host online? On an air-gapped or firewalled host, fetch $ArchiveName and SHA256SUMS.txt from $UrlReleases/tag/v$Version on a connected machine, verify the checksum yourself, and place the extracted binary at $Cached with SHA256SUMS.txt beside it as $SumsCached -- both files, or it is a cache miss. Or $BuildIt"
    }

    # Whole-field equality against exactly one line, never a substring match:
    # a release that adds holdfast-windows-x86_64-msvc.zip must not be able to
    # satisfy the lookup for holdfast-windows-x86_64.zip.
    $matched = @(Get-Content -LiteralPath $SumsTmp | ForEach-Object {
        $parts = $_ -split '\s+', 2
        if ($parts.Count -eq 2) {
            $name = $parts[1].Trim().TrimStart('*')
            if ($name -ceq $ArchiveName) { $parts[0].Trim().ToLowerInvariant() }
        }
    })
    if ($matched.Count -ne 1 -or $matched[0] -notmatch '^[0-9a-f]{64}$') {
        Die "the v$Version release manifest has no single well-formed entry for $ArchiveName -- this platform may not be built for that release"
    }
    $Want = $matched[0]

    $ArcTmp = Join-Path $Tmp $ArchiveName
    try {
        Invoke-WebRequest -Uri "$BaseUrl/v$Version/$ArchiveName" -OutFile $ArcTmp -UseBasicParsing
    } catch {
        Die "cannot download $ArchiveName from $BaseUrl/v$Version/ although the manifest lists it -- retry, or $BuildIt"
    }
    $Got = (Get-FileHash -LiteralPath $ArcTmp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Got -cne $Want) {
        Die "checksum mismatch for $ArchiveName (manifest says $Want, download hashed $Got) -- nothing was installed"
    }

    $XDir = Join-Path $Tmp 'x'
    New-Item -ItemType Directory -Force -Path $XDir | Out-Null
    $null = Expand-HoldfastArchive -Archive $ArcTmp -DestDir $XDir -Want $Exe

    # Manifest first, binary second, so a later run never sees a binary
    # without the manifest that vouched for it.
    Move-Item -LiteralPath $SumsTmp -Destination $SumsCached -Force
    Move-Item -LiteralPath (Join-Path $XDir $Exe) -Destination $Cached -Force
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

& $Cached @args
exit $LASTEXITCODE
