# Builds a Windows EXE wrapper for ULS_Setup.ps1 using ps2exe.
# Run this script on Windows PowerShell as Administrator.

[CmdletBinding()]
param(
    [string]$InputScript = "",
    [string]$OutputExe = "",
    [switch]$InstallPs2Exe
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($InputScript)) {
    $InputScript = Join-Path -Path $scriptRoot -ChildPath "ULS_Setup.ps1"
}
if ([string]::IsNullOrWhiteSpace($OutputExe)) {
    $OutputExe = Join-Path -Path $scriptRoot -ChildPath "dist\ULS_Setup.exe"
}

if (-not (Test-Path -Path $InputScript)) {
    throw "Input setup script not found: $InputScript"
}

if (-not (Get-Command -Name Invoke-ps2exe -ErrorAction SilentlyContinue)) {
    if (-not $InstallPs2Exe) {
        throw "Invoke-ps2exe not found. Re-run with -InstallPs2Exe to install the module."
    }

    Write-Host "Installing ps2exe module..."
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}

Import-Module ps2exe -ErrorAction Stop

$outDir = Split-Path -Path $OutputExe -Parent
if (-not (Test-Path -Path $outDir)) {
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
}

Write-Host "Building EXE..."
Invoke-ps2exe -inputFile $InputScript -outputFile $OutputExe -requireAdmin

Write-Host "Build complete: $OutputExe"
Write-Host "Place Sysmon.exe, both Sysmon XML configs, and ULS_Agent.ps1 next to the EXE when distributing."
