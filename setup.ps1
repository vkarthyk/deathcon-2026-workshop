<#
.SYNOPSIS
Install and launch the workshop in native Windows PowerShell, including a Windows VM.
.EXAMPLE
.\setup.ps1
.EXAMPLE
.\setup.ps1 -Port 8889
.EXAMPLE
.\setup.ps1 -Python 'C:\Python311\python.exe' -PrepareOnly
#>
[CmdletBinding()]
param(
    [string]$Python,
    [ValidateRange(1, 65535)]
    [int]$Port = 8888,
    [switch]$PrepareOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE): $Executable $($Arguments -join ' '). Check the error above."
    }
}

Push-Location $PSScriptRoot
try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Use bash setup.sh on macOS/Linux or inside WSL. This launcher targets native Windows.'
    }
    # Use an explicit executable or discover Python; never require venv activation.
    $candidates = @()
    if ($Python) {
        $candidates += @{ Executable = $Python; Prefix = @() }
    } else {
        $candidates += @{ Executable = 'py'; Prefix = @('-3') }
        $candidates += @{ Executable = 'python'; Prefix = @() }
        $candidates += @{ Executable = 'python3'; Prefix = @() }
    }
    $selected = $null
    $versionCheck = "import sys, struct; sys.exit(0 if sys.version_info >= (3,10) and struct.calcsize('P') == 8 else 1)"
    foreach ($candidate in $candidates) {
        $command = Get-Command $candidate.Executable -CommandType Application -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        $prefix = @($candidate.Prefix)
        try {
            & $command.Source @prefix -c $versionCheck 2>$null
            $candidateExit = $LASTEXITCODE
        } catch {
            continue
        }
        if ($candidateExit -eq 0) {
            $selected = @{ Executable = $command.Source; Prefix = $prefix }
            break
        }
    }
    if (-not $selected) {
        throw 'Install 64-bit Python 3.10+ (3.11 recommended) from python.org, include the Python launcher, reopen PowerShell, and retry. You can also pass -Python C:\path\to\python.exe.'
    }
    $environmentPython = Join-Path $PSScriptRoot '.workshop-venv\Scripts\python.exe'
    if (-not (Test-Path $environmentPython)) {
        if (Test-Path (Join-Path $PSScriptRoot '.workshop-venv\bin\python')) {
            throw 'This folder contains a Linux/macOS virtual environment. Extract a fresh workshop copy for Windows; virtual environments cannot be shared across platforms.'
        }
        Write-Host 'Creating the Windows workshop Python environment...'
        Invoke-Checked -Executable $selected.Executable -Arguments (@($selected.Prefix) + @('-m', 'venv', '.workshop-venv'))
    }
    Invoke-Checked -Executable $environmentPython -Arguments @('-c', $versionCheck)
    Write-Host 'Checking/installing workshop dependencies (initial setup requires internet)...'
    Invoke-Checked -Executable $environmentPython -Arguments @(
        '-m', 'pip', 'install', '--disable-pip-version-check', '--retries', '1', '--timeout', '30',
        '-r', (Join-Path $PSScriptRoot 'requirements-notebooks.txt')
    )
    Invoke-Checked -Executable $environmentPython -Arguments @(
        '-m', 'ipykernel', 'install', '--sys-prefix', '--name', 'python3', '--display-name', 'Python 3 (workshop)'
    )
    if ($PrepareOnly) {
        Write-Host 'Ready. Run .\setup.ps1 to open JupyterLab, or use .workshop-venv\Scripts\python.exe for the CTFs.'
    } else {
        Write-Host 'Opening notebook 00. Keep this PowerShell window open and use the printed token URL.'
        Invoke-Checked -Executable $environmentPython -Arguments @(
            '-m', 'jupyterlab', "--notebook-dir=$PSScriptRoot", '--ip=127.0.0.1', "--port=$Port",
            '--ServerApp.default_url=/lab/tree/notebooks/00_Start_here.ipynb'
        )
    }
} finally {
    Pop-Location
}
