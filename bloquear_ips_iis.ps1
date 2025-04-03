# Solicitar credenciales de MikroTik
$mikrotikIP = "<IP-mikrotik>"
$usuario = "<USUARIO-mikrotik>"
$securePassword = Read-Host "Ingrese la contraseña de MikroTik" -AsSecureString
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))

# Obtener la fecha actual en formato de los logs de IIS
$fechaActual = Get-Date -Format "yyMMdd"
$logFile = "C:\inetpub\logs\LogFiles\W3SVC1\u_ex$fechaActual.log"

# Verificar si el archivo de log existe
if (-Not (Test-Path $logFile)) {
    Write-Host "El archivo de log $logFile no existe. Saliendo..." -ForegroundColor Red
    exit
}

Write-Host "Procesando archivo de log: $logFile"

# Obtener la lista de IPs ya bloqueadas en MikroTik
$bloqueadas = & .\plink.exe -ssh -batch -pw $password $usuario@$mikrotikIP "ip firewall address-list print where list=blacklist" 2>$null | `
    Select-String -Pattern "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)" | `
    ForEach-Object { $_.Matches.Groups[1].Value }

if ($bloqueadas -eq $null) {
    Write-Host "No se pudo obtener la lista de IPs bloqueadas o la lista está vacía." -ForegroundColor Yellow
    $bloqueadas = @()
}

# Leer las IPs atacantes del log de IIS
$ipsDetectadas = Select-String -Path $logFile -Pattern "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \d+\.\d+\.\d+\.\d+ .*? (\d+\.\d+\.\d+\.\d+) .*? (401|403|404)" | `
    ForEach-Object { $_.Matches.Groups[1].Value } | `
    Sort-Object -Unique | `
    Where-Object { $_ -notin $bloqueadas }

# Si no hay IPs nuevas para bloquear, salir
if ($ipsDetectadas.Count -eq 0) {
    Write-Host "No hay IPs nuevas para bloquear." -ForegroundColor Green
    exit
}

Write-Host "IPs detectadas para bloquear: $($ipsDetectadas -join ', ')" -ForegroundColor Cyan

# Bloquear solo las IPs nuevas en MikroTik
foreach ($ip in $ipsDetectadas) {
    Write-Host "Bloqueando IP: $ip en MikroTik..."
    & .\plink.exe -ssh -batch -pw $password $usuario@$mikrotikIP "ip firewall address-list add list=blacklist address=$ip timeout=1d"
}

Write-Host "Proceso completado." -ForegroundColor Green
