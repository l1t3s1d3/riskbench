<#
.SYNOPSIS
    Sets up and starts RiskDesk on Windows.

.DESCRIPTION
    Creates a virtual environment, installs dependencies, writes .env from the
    template on first run, creates the database, then serves the application.
    Safe to re-run: existing environments and .env files are left alone.

.PARAMETER Port
    Port to listen on. Defaults to 8080.

.PARAMETER BindHost
    Address to bind. Defaults to 127.0.0.1 (this machine only). Only change this
    if you have put authentication in front of the app -- it ships with none.

.PARAMETER Demo
    Load synthetic data after setup, so the interface has something in it.

.PARAMETER SkipInstall
    Skip the dependency install step on a known-good environment.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run.ps1 -Demo
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string]$BindHost = "127.0.0.1",
    [switch]$Demo,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Message) Write-Host "  $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host "  $Message" -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host "  $Message" -ForegroundColor Red }

# --- work out where the project actually is -----------------------------------
#
# Two traps here, both of which surface as "could not open requirements file":
#
#   1. $PSScriptRoot is empty when a script is dot-sourced or piped as text
#      rather than run with -File, so it needs fallbacks.
#   2. Set-Location changes PowerShell's own location but does NOT update
#      [Environment]::CurrentDirectory, which is what native executables such as
#      python.exe inherit. Without setting both, python launches in whatever
#      directory the shell started in and cannot see requirements.txt or the
#      app package. The absolute paths below are belt and braces on top.

$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
$root = (Resolve-Path -LiteralPath $root).Path

Set-Location -LiteralPath $root
[Environment]::CurrentDirectory = $root

$requirements = Join-Path $root "requirements.txt"
$envExample   = Join-Path $root ".env.example"
$envFile      = Join-Path $root ".env"
$venvDir      = Join-Path $root ".venv"
$venvPython   = Join-Path $venvDir "Scripts\python.exe"

# --- pre-flight ---------------------------------------------------------------

Write-Step "Project folder: $root"

$missing = @()
foreach ($required in @($requirements, $envExample, (Join-Path $root "app\cli.py"))) {
    if (-not (Test-Path -LiteralPath $required)) { $missing += $required }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Fail "This does not look like the RiskDesk project folder."
    Write-Fail "Missing:"
    foreach ($m in $missing) { Write-Fail "    $m" }
    Write-Host ""
    Write-Warn "Run run.ps1 from inside the extracted folder -- the one containing"
    Write-Warn "requirements.txt and the app\ directory. If you extracted the zip by"
    Write-Warn "dragging it, check you are not one level too high: Windows sometimes"
    Write-Warn "creates riskdesk\riskdesk\. Copying run.ps1 out on its own does this too."
    Write-Host ""
    exit 1
}

# --- locate a suitable Python -------------------------------------------------
# The app uses PEP 604 unions (int | None) in FastAPI route signatures, which
# FastAPI resolves at runtime, so 3.10 is a hard floor rather than a suggestion.

$python = $null
foreach ($candidate in @(
    @{ Exe = "py";      Args = @("-3") },
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
)) {
    $cmd = Get-Command $candidate.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
        $probeArgs = @($candidate.Args) + @("-c", "import sys; print('%d.%d' % sys.version_info[:2])")
        $version = & $candidate.Exe $probeArgs 2>$null
    } catch { continue }
    if (-not $version) { continue }
    $parts = "$version".Trim().Split(".")
    if ($parts.Count -ge 2 -and [int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10) {
        $python = $candidate
        Write-Step "Using Python $("$version".Trim()) via '$($candidate.Exe)'"
        break
    }
}

if (-not $python) {
    Write-Host ""
    Write-Fail "RiskDesk needs Python 3.10 or newer, and could not find it."
    Write-Fail "Install it from https://www.python.org/downloads/windows/ and tick"
    Write-Fail "'Add python.exe to PATH' during setup, then run this script again."
    Write-Host ""
    Write-Warn "If Windows opened the Microsoft Store instead of running Python, turn off"
    Write-Warn "the aliases under Settings > Apps > Advanced app settings > App execution"
    Write-Warn "aliases."
    Write-Host ""
    exit 1
}

# --- virtual environment ------------------------------------------------------

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Step "Creating virtual environment in $venvDir"
    $venvArgs = @($python.Args) + @("-m", "venv", $venvDir)
    & $python.Exe $venvArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        Write-Fail "Could not create the virtual environment at $venvDir"
        exit 1
    }
}

# Calling the venv interpreter by absolute path avoids Activate.ps1 entirely, so
# this never depends on the machine's PowerShell execution policy.

if (-not $SkipInstall) {
    Write-Step "Installing dependencies"
    & $venvPython -m pip install --quiet --upgrade pip
    & $venvPython -m pip install --quiet -r $requirements
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Dependency install failed. Check your network or proxy settings."
        Write-Warn "Behind a proxy, set HTTPS_PROXY first, or install manually:"
        Write-Warn "    `"$venvPython`" -m pip install -r `"$requirements`""
        exit 1
    }
}

# --- configuration ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $envFile)) {
    Copy-Item -LiteralPath $envExample -Destination $envFile
    Write-Warn "Created .env from the template. Add source credentials when you have them."
}

Write-Step "Preparing the database"
& $venvPython -m app.cli init
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Database setup failed. See the error above."
    exit 1
}

if ($Demo) {
    Write-Step "Loading demo data"
    & $venvPython -m app.cli demo
}

# --- serve --------------------------------------------------------------------

$url = "http://{0}:{1}" -f $BindHost, $Port
Write-Host ""
Write-Host "  RiskDesk is starting on $url" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

if ($BindHost -ne "127.0.0.1" -and $BindHost -ne "localhost") {
    Write-Warn "You are binding to $BindHost, which exposes this app beyond your machine."
    Write-Warn "RiskDesk ships with no authentication. Put it behind your IdP first."
    Write-Host ""
}

& $venvPython -m app.cli serve --host $BindHost --port $Port
