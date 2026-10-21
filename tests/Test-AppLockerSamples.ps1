param([Parameter(Mandatory=$true)][string]$Policy,[Parameter(Mandatory=$true)][string]$Samples)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Run this read-only check in Windows PowerShell 5.1, not PowerShell 7.'}
Import-Module AppLocker
# Supplied signed samples only. This test never downloads or runs an installer, nor applies a policy.
$names=@('AnyDesk.exe','WPSOffice.exe','wps_office_inst.exe','renamed-office-setup.exe','renamed-remote-tool.exe')
$paths=@($names|ForEach-Object {Join-Path $Samples $_})
foreach($path in $paths){if((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw ('Sample signature not valid: '+$path)}}
$system=[Environment]::SystemDirectory
$allowed=@((Join-Path ([Environment]::GetFolderPath('Windows')) 'explorer.exe'),(Join-Path $system 'cmd.exe'),(Join-Path $system 'msiexec.exe'),(Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'))
$results=@(Test-AppLockerPolicy -XmlPolicy $Policy -Path ($paths+$allowed) -User S-1-1-0)
if($results.Count -ne 9){throw 'Missing policy decisions'}
foreach($result in $results) {
    $expected=if($paths -contains $result.FilePath){'Denied'}else{'Allowed'}
    if($result.PolicyDecision.ToString() -ne $expected){throw ('Unexpected decision for '+$result.FilePath)}
    [pscustomobject]@{File=[IO.Path]::GetFileName($result.FilePath);Decision=$result.PolicyDecision.ToString();Sha256=(Get-FileHash -LiteralPath $result.FilePath -Algorithm SHA256).Hash}
}
