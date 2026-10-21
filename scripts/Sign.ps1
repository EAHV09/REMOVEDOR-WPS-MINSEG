param(
 [Parameter(Mandatory=$true)][string]$Executable,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
 [Parameter(Mandatory=$true)][string]$SignToolPath,
 [Parameter(Mandatory=$true)][uri]$TimestampUrl
)
$ErrorActionPreference='Stop'
if($TimestampUrl.Scheme -notin @('http','https')){throw 'Se requiere un servidor de sellado de tiempo HTTP(S) autorizado.'}
if(-not (Test-Path -LiteralPath $Executable -PathType Leaf)){throw 'No existe el EXE.'}
if(-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)){throw 'No existe SignTool de Windows SDK.'}
$certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$CertificateThumbprint)
if(-not $certificate.HasPrivateKey){throw 'El certificado no tiene una clave privada disponible.'}
& $SignToolPath sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $Executable
if($LASTEXITCODE -ne 0){throw 'Falló la firma. No distribuir como firmado.'}
& $SignToolPath verify /pa /v $Executable
if($LASTEXITCODE -ne 0){throw 'La firma no pudo verificarse.'}
Get-FileHash -LiteralPath $Executable -Algorithm SHA256
