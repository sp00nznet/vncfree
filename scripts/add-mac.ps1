# One-click VNC access to a Mac: saves its password (prompted, DPAPI-encrypted
# to this Windows account), installs the generic connect script alongside it,
# writes a no-argument wrapper, and creates Desktop and Start Menu shortcuts
# that point at it.
#
#   powershell -ExecutionPolicy Bypass -File add-mac.ps1 -MacHost okzulu2.local -User tariq
#
# Re-run it for every Mac you want a shortcut for, and again after a Windows
# reinstall - the saved passwords do not survive that, since they are
# encrypted with a key tied to this specific Windows installation.
param(
    [Parameter(Mandatory)] [string]$MacHost,
    [Parameter(Mandatory)] [string]$User,
    [int]$Port = 5900,
    [string]$BinDir = "$env:USERPROFILE\bin"
)

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

foreach ($f in "vnc-connect.ps1", "vnc-save-credential.ps1") {
    Copy-Item (Join-Path $PSScriptRoot $f) (Join-Path $BinDir $f) -Force
}

$credPath = "$env:USERPROFILE\.vncfree\$MacHost.pw.txt"
if (-not (Test-Path $credPath)) {
    & (Join-Path $BinDir "vnc-save-credential.ps1") -MacHost $MacHost
}

# A wrapper with no parameters, because that is what a shortcut can point at
# without a properties dialog full of arguments to get right once and forget.
$safeName = $MacHost -replace '[^a-zA-Z0-9]', '-'
$wrapperPath = Join-Path $BinDir "vnc-$safeName.ps1"
@"
# Shortcut target: connect to $MacHost with no arguments to type.
& "`$PSScriptRoot\vnc-connect.ps1" -MacHost "$MacHost" -User "$User" -Port $Port
"@ | Set-Content -Path $wrapperPath -Encoding utf8

$iconExe = @(
    (Join-Path $PSScriptRoot "..\target\release\vncfree.exe"),
    (Join-Path $BinDir "vncfree.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$sh = New-Object -ComObject WScript.Shell
$shortcuts = @(
    "$env:USERPROFILE\Desktop\VNC - $MacHost.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\VNC - $MacHost.lnk"
)
foreach ($path in $shortcuts) {
    $lnk = $sh.CreateShortcut($path)
    $lnk.TargetPath = "powershell.exe"
    $lnk.Arguments = "-ExecutionPolicy Bypass -File `"$wrapperPath`""
    $lnk.WorkingDirectory = $BinDir
    if ($iconExe) { $lnk.IconLocation = "$iconExe,0" }
    $lnk.Description = "Connect to $MacHost over VNC"
    $lnk.Save()
    Write-Output "shortcut: $path"
}

Write-Output "wrapper: $wrapperPath"
Write-Output ""
Write-Output "Taskbar pin has to be done by hand: right-click either shortcut and choose"
Write-Output "Pin to taskbar - Microsoft removed the scriptable way to do this."
