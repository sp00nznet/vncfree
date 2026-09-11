# Decrypts the saved password for one Mac and starts vncfree - see add-mac.ps1
# in this same folder, which is what actually sets this up for you.
#
# The password lives at ~/.vncfree/<MacHost>.pw.txt as a DPAPI-protected secure
# string - readable only by this Windows account on this machine, and nowhere
# else, since DPAPI keys do not survive a reinstall or move to another PC. It
# is decrypted into the environment for this one process only, never written
# back to disk in plain text.
param(
    [Parameter(Mandatory)] [string]$MacHost,   # e.g. okzulu2.local
    [Parameter(Mandatory)] [string]$User,
    [int]$Port = 5900
)

$credPath = "$env:USERPROFILE\.vncfree\$MacHost.pw.txt"
if (-not (Test-Path $credPath)) {
    Write-Error "No saved credential for $MacHost at $credPath - run add-mac.ps1 first."
    exit 1
}

# vncfree.exe next to this script, or built from this repo checkout, or on PATH.
$exe = @(
    (Join-Path $PSScriptRoot "vncfree.exe"),
    (Join-Path $PSScriptRoot "..\target\release\vncfree.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { $exe = "vncfree.exe" }

$secure = Get-Content $credPath | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:VNC_USERNAME = $User
    $env:VNC_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    & $exe "${MacHost}:${Port}"
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Item Env:\VNC_PASSWORD -ErrorAction SilentlyContinue
}
