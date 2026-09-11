# Saves (or updates) the encrypted password for one Mac, prompted interactively
# so it never has to pass through a chat log, a script argument, or shell
# history - all of which persist somewhere you would not want a password.
#
#   powershell -ExecutionPolicy Bypass -File vnc-save-credential.ps1 -MacHost okzulu2.local
param(
    [Parameter(Mandatory)] [string]$MacHost
)

$credDir = "$env:USERPROFILE\.vncfree"
New-Item -ItemType Directory -Force -Path $credDir | Out-Null

$secure = Read-Host -Prompt "Password for $MacHost" -AsSecureString
$secure | ConvertFrom-SecureString | Set-Content -Path "$credDir\$MacHost.pw.txt" -Encoding utf8
Write-Output "saved encrypted credential for $MacHost"
