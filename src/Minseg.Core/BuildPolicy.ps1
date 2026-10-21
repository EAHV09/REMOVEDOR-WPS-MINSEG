param([Parameter(Mandatory=$true)][string]$InputXml,[Parameter(Mandatory=$true)][string]$OutputCip,[Parameter(Mandatory=$true)][string]$SamplesJson)
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules\ConfigCI\ConfigCI.psd1')) -ErrorAction Stop
$samples = @(Get-Content -LiteralPath $SamplesJson -Raw | ConvertFrom-Json)
$rules = @()
foreach ($sample in $samples) {
    if ((Get-FileHash -LiteralPath $sample.Path -Algorithm SHA256).Hash -ne $sample.Sha256) { throw 'La muestra cambió.' }
    # Hash uses Windows Authenticode image hashing, not a raw file digest.
    $rules += New-CIPolicyRule -DriverFilePath $sample.Path -Level FilePublisher -Fallback Hash -Deny
}
if ($rules.Count -gt 0) {
    $samplePolicy = Join-Path (Split-Path -Parent $InputXml) 'muestras.xml'
    $merged = Join-Path (Split-Path -Parent $InputXml) 'combinada.xml'
    New-CIPolicy -FilePath $samplePolicy -Rules $rules -UserPEs -MultiplePolicyFormat | Out-Null
    Merge-CIPolicy -PolicyPaths @($InputXml,$samplePolicy) -OutputFilePath $merged | Out-Null
    # Keep this tool's stable policy identity and requested audit/enforcement mode.
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $original = New-Object System.Xml.XmlDocument
    $reader = [System.Xml.XmlReader]::Create($InputXml,$settings)
    try { $original.Load($reader) } finally { $reader.Dispose() }
    $document = New-Object System.Xml.XmlDocument
    $reader = [System.Xml.XmlReader]::Create($merged,$settings)
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $document.SiPolicy.PolicyID = $original.SiPolicy.PolicyID
    $document.SiPolicy.BasePolicyID = $original.SiPolicy.BasePolicyID
    $document.SiPolicy.VersionEx = $original.SiPolicy.VersionEx
    $document.SiPolicy.ReplaceChild($document.ImportNode($original.SiPolicy.Rules,$true),$document.SiPolicy.Rules) | Out-Null
    $document.Save($InputXml)
}
ConvertFrom-CIPolicy -XmlFilePath $InputXml -BinaryFilePath $OutputCip | Out-Null
Write-Output 'Política compilada. Todavía no aplicada.'
