[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$RequireSignedHelpers,
    [string]$ExpectedThumbprint
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot 'dist/signpath-candidate' }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
# No borra ni reutiliza salidas anteriores: evita mezclar una firma vieja con un build nuevo.
if (Test-Path -LiteralPath $destination) { throw 'Usa una carpeta de salida nueva para este candidato.' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$helpers = @('AppLockerHost.ps1', 'BuildPolicy.ps1')
if ($RequireSignedHelpers) {
    foreach ($name in $helpers) {
        & "$PSScriptRoot/Test-SignedFile.ps1" -Path (Join-Path $projectRoot "src/Minseg.Core/$name") -ExpectedThumbprint $ExpectedThumbprint | Out-Null
    }
}
Push-Location $projectRoot
try {
    $sdk = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $sdk -ne '10.0.401') { throw 'Se requiere .NET SDK 10.0.401.' }
    # Origen NuGet único, dependencias bloqueadas y consulta de vulnerabilidades obligatoria.
    foreach ($project in @('tests/Minseg.Tests/Minseg.Tests.csproj', 'src/Minseg.App/Minseg.App.csproj', 'tests/Minseg.Smoke/Minseg.Smoke.csproj')) {
        & dotnet restore $project --locked-mode --configfile NuGet.Config --nologo -p:NuGetAudit=true -p:NuGetAuditMode=all '-warnaserror:NU1900,NU1903,NU1904,NU1905'
        if ($LASTEXITCODE -ne 0) { throw "Falló la restauración bloqueada de $project." }
    }
    & dotnet test tests/Minseg.Tests/Minseg.Tests.csproj -c Release --no-restore --nologo -m:1 -p:UseSharedCompilation=false
    if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas. No se prepara el candidato.' }
    & "$projectRoot/tests/Test-AppLockerState.ps1" -Scratch (Join-Path $projectRoot 'dist/state-tests')
    & dotnet build tests/Minseg.Smoke/Minseg.Smoke.csproj -c Release --no-restore --nologo -m:1 -p:UseSharedCompilation=false
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo compilar la prueba visual.' }
    $screenshots = "$destination-ui"
    & dotnet tests/Minseg.Smoke/bin/Release/net10.0-windows/win-x64/Minseg.Smoke.dll $screenshots
    if ($LASTEXITCODE -ne 0) { throw 'Fallaron las pruebas de interfaz.' }
    & dotnet publish src/Minseg.App/Minseg.App.csproj -c Release -r win-x64 --self-contained true --no-restore --nologo -o $destination -m:1 -p:UseSharedCompilation=false
    if ($LASTEXITCODE -ne 0) { throw 'Falló la compilación del candidato.' }
    $exe = Join-Path $destination 'MINSEG-Control.exe'
    $files = @(Get-ChildItem -LiteralPath $destination -Force)
    if ($files.Count -ne 1 -or $files[0].Name -ne 'MINSEG-Control.exe') { throw 'La salida no contiene exactamente el EXE previsto.' }
    $metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    [xml]$props = Get-Content -LiteralPath 'Directory.Build.props' -Raw
    $version = [string]$props.Project.PropertyGroup.Version
    if ($version -notmatch '^\d+\.\d+\.\d+$' -or $metadata.ProductName -cne 'REMOVEDOR DEL WPS MINSEG' -or $metadata.ProductVersion -cne $version) {
        throw 'Los metadatos del EXE no coinciden con el producto y la versión del proyecto.'
    }
    # Las pruebas usan datos ficticios; no se ejecutan desinstaladores ni cambios de políticas.
    $evidence = "$destination-evidence"
    if (Test-Path -LiteralPath $evidence) { throw 'La carpeta de evidencia ya existe.' }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    $helperHashes = foreach ($name in $helpers) {
        @{ File=$name; SHA256=(Get-FileHash -LiteralPath "src/Minseg.Core/$name" -Algorithm SHA256).Hash }
    }
    [ordered]@{
        Product='REMOVEDOR DEL WPS MINSEG'; Version=$version; SDK=$sdk; Runtime='10.0.12'; Architecture='win-x64'
        Commit=$env:GITHUB_SHA; Repository=$env:GITHUB_REPOSITORY; RunId=$env:GITHUB_RUN_ID
        HelpersRequiredSigned=[bool]$RequireSignedHelpers; Helpers=$helperHashes
        UnsignedExeSHA256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        Status='Candidato; falta la firma del EXE y el piloto en Windows/Bitdefender'
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$evidence/build.json" -Encoding utf8
    & dotnet list tests/Minseg.Tests/Minseg.Tests.csproj package --include-transitive --format json --no-restore | Set-Content -LiteralPath "$evidence/test-dependencies.json" -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo generar el inventario de dependencias de prueba.' }
    Copy-Item -LiteralPath $screenshots -Destination (Join-Path $evidence 'ui') -Recurse
    Copy-Item -LiteralPath "$projectRoot/docs/signpath/COMPONENTES.md" -Destination $evidence
    if ($env:GITHUB_OUTPUT) { Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "version=$version" }
    Get-FileHash -LiteralPath $exe -Algorithm SHA256
}
finally { Pop-Location }
