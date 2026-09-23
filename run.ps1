# SecureMailScope launcher (Windows PowerShell).
#
#   .\run.ps1                 # bootstrap venv + run the zero-credential demo
#   .\run.ps1 dashboard       # forward any subcommand to the CLI
#   .\run.ps1 analyze x.pcap --out-dir out
#
# Set $env:SMS_NO_VENV = "1" to use the current environment instead of .venv.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

if ($env:SMS_NO_VENV -ne "1") {
    if (-not (Test-Path ".venv")) {
        Write-Host "[run] creating virtualenv in .venv ..."
        & $py -m venv .venv
    }
    & ".venv\Scripts\Activate.ps1"
    $py = "python"
}

# Install the package (with all extras) once; a core install still runs the
# demo even if the optional extras cannot be fetched offline.
& $py -c "import securemailscope" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[run] installing SecureMailScope ..."
    & $py -m pip install --upgrade pip | Out-Null
    & $py -m pip install -e ".[all]"
    if ($LASTEXITCODE -ne 0) { & $py -m pip install -e . }
}

$cmd = if ($args.Count -eq 0) { @("demo") } else { $args }
Write-Host "[run] securemailscope $($cmd -join ' ')"
& $py -m securemailscope @cmd
exit $LASTEXITCODE
