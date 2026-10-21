# Verifica sin ejecutar el archivo ni instalar certificados.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedThumbprint
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$file = Get-Item -LiteralPath $Path
if ($file.PSIsContainer) { throw 'Se esperaba un archivo.' }
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
    throw "Firma no válida: $($signature.Status). No publicar."
}
if ($signature.SignerCertificate.Thumbprint -ine $ExpectedThumbprint) {
    throw 'El certificado no coincide con el autorizado para este proyecto. No publicar.'
}
if ($null -eq $signature.TimeStamperCertificate) {
    throw 'Falta el sello de tiempo. No publicar.'
}
[pscustomobject]@{
    File = $file.Name
    Status = [string]$signature.Status
    Signer = $signature.SignerCertificate.Subject
    Thumbprint = $signature.SignerCertificate.Thumbprint
    TimestampSigner = $signature.TimeStamperCertificate.Subject
    SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
}
