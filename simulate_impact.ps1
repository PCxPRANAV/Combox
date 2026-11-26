# =====================================================================
# Forensic Lab Impact Simulator (safe stand-in)
# ---------------------------------------------------------------------
# Purpose: produces the file-system telemetry a real impact-stage
# attack would leave (file renames in a watched folder, a note file
# created) WITHOUT performing any encryption, encoding, or destructive
# transformation of file contents, and without deleting original data.
#
# What it actually does:
#   1. Ensures C:\CanaryData exists with 5 dummy .txt files.
#   2. Renames each .txt to .txt.locked (contents untouched).
#   3. Writes a plain-text advisory note to the Desktop.
#
# What it deliberately does NOT do:
#   - No reading/transforming of file bytes (no XOR, no Base64, no AES)
#   - No deletion of original data
#   - No network callback of its own (the lure already made one request)
# =====================================================================

$CanaryPath = "C:\CanaryData"

if (!(Test-Path -Path $CanaryPath)) {
    New-Item -ItemType Directory -Path $CanaryPath -Force | Out-Null
    1..5 | ForEach-Object {
        "CONFIDENTIAL FINANCIAL RECORD #$_ (lab canary file, not real data)" |
            Out-File -FilePath "$CanaryPath\document$_.txt" -Encoding utf8
    }
}

Start-Sleep -Seconds 2

Get-ChildItem -Path $CanaryPath -Filter *.txt | ForEach-Object {
    Rename-Item -Path $_.FullName -NewName ($_.Name + ".locked")
}

$Note = @"
=== FORENSIC LAB ADVISORY (SIMULATION ONLY) ===
This is a controlled classroom exercise. No files were encrypted.
Canary files in $CanaryPath were renamed with a .locked extension
to generate Sysmon Event ID 11 (file rename) telemetry for analysis.
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

Set-Content -Path "$HOME\Desktop\README_RECOVER.txt" -Value $Note

Write-Host "[+] Impact simulation complete. Files renamed to .locked (contents unchanged)."
