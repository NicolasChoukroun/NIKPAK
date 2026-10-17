<#
  build.ps1 - build nikpak.exe on Windows with PowerShell.

  Usage (from the nikpak folder, in PowerShell):
      .\build.ps1                 # release build -> dist\nikpak.exe
      .\build.ps1 -Test           # run the unit tests first
  If PowerShell refuses to run scripts:
      powershell -ExecutionPolicy Bypass -File .\build.ps1
#>
param([switch]$Test)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

# --- 1. Is Rust (cargo) installed? ------------------------------------------
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
    }
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host 'Rust (cargo) was not found.' -ForegroundColor Yellow
    Write-Host 'Install it first, then open a NEW PowerShell window and run this script again:'
    Write-Host '    winget install Rustlang.Rustup'
    Write-Host '    winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
    Write-Host 'or download the installer from https://rustup.rs'
    exit 1
}

Write-Host "Using $(cargo --version)"

# --- 2. Test (optional) -------------------------------------------------------
if ($Test) {
    cargo test --release
    if ($LASTEXITCODE -ne 0) { Write-Host 'Tests failed.' -ForegroundColor Red; exit $LASTEXITCODE }
}

# --- 3. Build -------------------------------------------------------------------
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'Build failed. Most common cause: the Visual Studio C++ Build Tools are missing.' -ForegroundColor Red
    Write-Host 'Install them with:'
    Write-Host '    winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
    exit $LASTEXITCODE
}

# --- 4. Copy the result -----------------------------------------------------------
New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item -Force 'target\release\nikpak.exe' 'dist\nikpak.exe'
$size = [math]::Round((Get-Item 'dist\nikpak.exe').Length / 1MB, 2)
Write-Host ''
Write-Host "OK -> $PSScriptRoot\dist\nikpak.exe  ($size MB)" -ForegroundColor Green
Write-Host 'Try:  .\dist\nikpak.exe -help'
