# Fallback: wrk на хосте, если контейнер loadgen не нужен.
# Для нагрузки — сервис loadgen в compose (сеть haproxy:8080).
#
#     cd deploy
#     .\loadgen\run-host.ps1
#
# Нужны node и wrk в PATH. Скрипт гасит контейнер loadgen и направляет
# контроллер на http://host.docker.internal:8090.

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$deploy = Split-Path $here -Parent
$root = Split-Path $deploy -Parent

function Find-Cmd([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$node = Find-Cmd "node"
$wrk = Find-Cmd "wrk"
if (-not $node) {
    Write-Error "node не найден в PATH"
}
if (-not $wrk) {
    Write-Error "wrk не найден в PATH. Для нагрузки поднимите сервис loadgen в compose."
}
$env:Path = "$(Split-Path $wrk -Parent);$env:Path"

Write-Host "node  $node"
Write-Host "wrk   $wrk"

Push-Location $deploy
try {
    docker compose stop loadgen 2>$null | Out-Null
    $env:CONTROLLER_LOADGEN_URL = "http://host.docker.internal:8090"
    docker compose up -d --no-deps controller
} finally {
    Pop-Location
}

$env:TARGET = "http://127.0.0.1:8081"
$env:NATS_MONITOR = "http://127.0.0.1:8222"
$env:PORT = "8090"
$env:LOADGEN_RUNNER = "host"
$env:LOADGEN_CASES = Join-Path $root "tests\load\cases.mjs"

Write-Host "loadgen host  :8090  target=$($env:TARGET)  cases=$($env:LOADGEN_CASES)"
Write-Host "UX /traffic ходит сюда через контроллер."
Set-Location $here
& $node "$here\server.mjs"
