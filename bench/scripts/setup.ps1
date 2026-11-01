# Reproducible setup of the otabench MVP on Windows (Python 3.13, Go >= 1.25,
# Node ^22.22.2 or ^24.15.0 (required by tuf-js 6.0.1), uv).
# Run from the bench directory:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
$bench = Split-Path -Parent $PSScriptRoot
$third = Join-Path (Split-Path -Parent $bench) "third_party"
$conf = Join-Path $third "tuf-conformance"
$confCommit = "3d3fbb8164a7b0d404cff08b13594104ec3fef4f"   # pinned: tuf-conformance v2.5.0+ (2026-10-26)

if (-not (Test-Path $conf)) {
    git clone https://github.com/theupdateframework/tuf-conformance $conf
}
git -C $conf fetch --depth 1 origin $confCommit
git -C $conf checkout $confCommit

Set-Location $bench
uv venv --python 3.13 .venv
uv pip install --python .venv\Scripts\python.exe "tuf==7.0.1" "securesystemslib[crypto]==1.6.0" "pyyaml==6.0.3" $conf

New-Item -ItemType Directory -Force clients\bin | Out-Null
go build -C (Join-Path $conf "clients\go-tuf") -o (Join-Path $bench "clients\bin\go-tuf.exe") .

Push-Location clients\tuf-js
npm install --no-audit --no-fund
Pop-Location

Copy-Item (Join-Path $conf "clients\python-tuf\python_tuf.py") clients\python-tuf\python_tuf.py -Force
Write-Host "done. try:  .venv\Scripts\python.exe -m otabench run --quick"
