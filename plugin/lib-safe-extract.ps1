# Safe single-member zip extraction for the Holdfast bootstrap (Windows half
# of spec section 13.3 step 5). Dot-sourced by bootstrap.ps1 and by
# scripts/plugin-archive-tests.sh's zip cell.
#
# **Expand-Archive is forbidden here and section 13.3 should say so by name.**
# Windows PowerShell 5.1 -- the version section 13.3 targets -- ships
# Microsoft.PowerShell.Archive 1.0.1.0, which predates the traversal check
# that PS 7's 1.2.5 has. And 1.2.5 is not sufficient either: measured, it
# accepts a two-entry archive, accepts a nested-directory archive, and writes
# a Unix symlink entry out as a regular file whose *content* is the link
# target. The rule the tar side enforces -- exactly one entry, named exactly
# what we expect -- is not expressible through that cmdlet at all.
#
# No archive-supplied string is ever joined onto a filesystem path below. The
# destination is built from $DestDir and $Want, both of which are ours.

function Expand-HoldfastArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$DestDir,
        [Parameter(Mandatory = $true)][string]$Want,
        [long]$MaxBytes = 134217728
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        # --- the whitelist, same shape as the tar side -----------------------
        $entries = @($zip.Entries)
        if ($entries.Count -ne 1) {
            throw "archive does not contain exactly one entry (got $($entries.Count)) -- refusing it"
        }
        $e = $entries[0]
        # -cne: case-SENSITIVE. A case-insensitive compare would accept
        # HOLDFAST.EXE, and on a case-sensitive host that is a different file.
        if ($e.FullName -cne $Want) {
            throw "archive member is '$($e.FullName)', expected exactly '$Want'"
        }
        # FullName carries the directory part and Name does not, so requiring
        # them equal is how "no path component, no drive letter, no ..\" is
        # enforced without ever parsing the string.
        if ($e.Name -cne $Want) {
            throw "archive member '$($e.FullName)' has a path component"
        }
        if ($e.Length -le 0 -or $e.Length -gt $MaxBytes) {
            throw "archive member size $($e.Length) is out of bounds (0 < n <= $MaxBytes)"
        }

        # --- Unix mode bits, when the writer set any -------------------------
        # The high 16 bits of ExternalAttributes carry st_mode for a zip made
        # on a Unix host. **Requiring S_IFREG unconditionally rejects
        # legitimate archives** -- Python's zipfile writes 0o600<<16 with no
        # type bits at all, and a Windows-made zip leaves the high word zero.
        # That bug was written here first and rejected the GOOD fixture; it is
        # exactly the check that would then have been "fixed" by deleting it.
        # So: enforce the type only when a type is declared, and the setuid
        # bits always.
        $mode = ($e.ExternalAttributes -shr 16) -band 0xFFFF
        if (($mode -band 0xF000) -ne 0 -and ($mode -band 0xF000) -ne 0x8000) {
            throw ("archive member is not a regular file (mode 0x{0:X})" -f $mode)
        }
        if (($mode -band 0xC00) -ne 0) {
            throw ("archive member carries a setuid/setgid bit (mode 0x{0:X})" -f $mode)
        }

        # --- extract to a path WE construct ---------------------------------
        $dest = [System.IO.Path]::Combine($DestDir, $Want)
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)

        # --- validate what landed -------------------------------------------
        $fi = Get-Item -LiteralPath $dest -Force
        if ($fi.Length -ne $e.Length) { throw "extracted size does not match the declared size" }
        if ($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "'$Want' landed as a reparse point"
        }
        if ($fi.Attributes -band [System.IO.FileAttributes]::Directory) {
            throw "'$Want' landed as a directory"
        }
        return $dest
    } finally {
        $zip.Dispose()
    }
}
