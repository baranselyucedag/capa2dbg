# Smoke checks for capa2dbg (no malware execution)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dp32 = Join-Path $root "bin\Release\capa2dbg.dp32"
$jsonCfg = Join-Path $root "bin\Release\capa2dbg.json"
$sample = $env:CAPA2DBG_SAMPLE_JSON

Write-Host "== artifact check =="
if (-not (Test-Path $dp32)) { throw "Missing dp32 - build Release Win32 first" }
if (-not (Test-Path $jsonCfg)) { throw "Missing capa2dbg.json next to dp32" }
$len = (Get-Item $dp32).Length
Write-Host "OK: capa2dbg.dp32 ($len bytes)"

Write-Host "== export check =="
$dumpbin = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x86\dumpbin.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($dumpbin) {
    $exports = & $dumpbin.FullName /EXPORTS $dp32 | Out-String
    foreach ($sym in @("pluginit", "plugsetup", "plugstop")) {
        if ($exports -notmatch $sym) { throw "Missing export: $sym" }
    }
    Write-Host "OK: pluginit/plugsetup/plugstop exported"

    $deps = & $dumpbin.FullName /DEPENDENTS $dp32 | Out-String
    if ($deps -notmatch "bcrypt.dll") { throw "Missing import: bcrypt.dll (SHA256 cache)" }
    Write-Host "OK: bcrypt.dll imported"
} else {
    Write-Host "SKIP: dumpbin not found"
}

Write-Host "== offline capa JSON logic =="
if ($sample -and (Test-Path $sample)) {
    python (Join-Path $root "tools\validate_capa_json.py") $sample
} else {
    Write-Host "SKIP: set CAPA2DBG_SAMPLE_JSON to a capa -vv -j output to validate parsing"
}

Write-Host "== offline cache logic =="
python (Join-Path $root "tools\cache_sim.py")

Write-Host "== interactive reminder =="
Write-Host "Copy capa2dbg.dp32 and capa2dbg.json into the x32dbg plugins folder."
Write-Host "Load a PE, then: capa_load <report.json>  or  capa_run"
Write-Host "ALL SMOKE CHECKS PASSED"
