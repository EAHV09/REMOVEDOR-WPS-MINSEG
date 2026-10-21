param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$ExtractionDirectory
)
$ErrorActionPreference='Stop'
$program=(Resolve-Path -LiteralPath $Executable).Path
$cache=[IO.Path]::GetFullPath($ExtractionDirectory)
[IO.Directory]::CreateDirectory($cache) | Out-Null
# These read-only/invalid modes never prepare Office, uninstall software or change Windows policies.
foreach($item in @(@('--check-package',0),@('--prepare-office-invalid',64),@('--remove-machine anydesk',64),@('--remove-machine both',64),@('--unknown',64))) {
    $start=[Diagnostics.ProcessStartInfo]::new($program)
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.Arguments=[string]$item[0]
    $start.EnvironmentVariables['DOTNET_BUNDLE_EXTRACT_BASE_DIR']=$cache
    $process=[Diagnostics.Process]::Start($start)
    try {
        if(-not $process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            throw ('Package check timed out: '+$item[0])
        }
        if($process.ExitCode -ne $item[1]) {throw ('Unexpected exit '+$process.ExitCode+' for '+$item[0])}
        [pscustomobject]@{Check=$item[0];Exit=$process.ExitCode}
    } finally { $process.Dispose() }
}
