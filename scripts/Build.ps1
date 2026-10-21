param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if(-not $OutputDirectory){$OutputDirectory=Join-Path $projectRoot 'dist'}
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
& dotnet test (Join-Path $projectRoot 'tests\Minseg.Tests\Minseg.Tests.csproj') -c Release -m:1
if($LASTEXITCODE -ne 0){throw 'Las pruebas fallaron. No se publica el EXE.'}
& dotnet publish (Join-Path $projectRoot 'src\Minseg.App\Minseg.App.csproj') -c Release -r win-x64 --self-contained true -o $OutputDirectory -m:1
if($LASTEXITCODE -ne 0){throw 'No se pudo publicar el EXE.'}
Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'MINSEG-Control.exe') -Algorithm SHA256
