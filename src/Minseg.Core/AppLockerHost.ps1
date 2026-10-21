param(
    [Parameter(Mandatory=$true)][ValidateSet('Read','Audit','Enforce','Remove')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$StoreRoot,
    [Parameter(Mandatory=$true)][string]$AuditXml,
    [Parameter(Mandatory=$true)][string]$EnforceXml
)
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
foreach($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.Diagnostics','AppLocker')) {
    Import-Module -Name ([IO.Path]::Combine($PSHOME,"Modules\$module\$module.psd1")) -ErrorAction Stop
}
$expectedRoot=[IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'),'MINSEG-Control')
if(-not [IO.Path]::GetFullPath($StoreRoot).Equals($expectedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Carpeta de politica no permitida.'}
$marker=Join-Path $StoreRoot 'applocker-state.json'
$logName='Microsoft-Windows-AppLocker/EXE and DLL'

function Assert-PrivatePath([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor.Length -gt 3) {
        if([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if(([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Se encontro un enlace en una ruta de politica.'}
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    if([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) {
        $acl=Get-Acl -LiteralPath $Path
        $allowed=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        if($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value){throw 'Propietario de politica no permitido.'}
        $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and ($rule.FileSystemRights -band $write) -ne 0 -and $allowed -notcontains $rule.IdentityReference.Value){throw 'Permisos de politica inseguros.'}
        }
    }
}
function Read-Xml([string]$Text) {
    if($Text.Length -gt 4000000){throw 'Politica demasiado grande.'}
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create((New-Object IO.StringReader($Text)),$settings)
    $doc=New-Object Xml.XmlDocument
    try{$doc.Load($reader)}finally{$reader.Dispose()}
    if($doc.DocumentElement.Name -ne 'AppLockerPolicy'){throw 'Formato de politica no valido.'}
    return ,$doc
}
function Read-SafeXml([string]$Path) {
    Assert-PrivatePath $Path
    if((Get-Item -LiteralPath $Path).Length -gt 4000000){throw 'Politica demasiado grande.'}
    return ,(Read-Xml ([IO.File]::ReadAllText($Path)))
}
function Node-Key([Xml.XmlElement]$Node) {
    $attributes=@($Node.Attributes | Sort-Object Name | ForEach-Object { $_.Name+'='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Value)) })
    $children=@($Node.ChildNodes | Where-Object {$_ -is [Xml.XmlElement]} | ForEach-Object {Node-Key $_} | Sort-Object)
    return $Node.Name+'['+($attributes -join ';')+']{'+($children -join ';')+'}'
}
function Policy-Key([Xml.XmlDocument]$Document) {
    $copy=$Document.CloneNode($true)
    # Windows may add empty NotConfigured collections when exporting a policy.
    foreach($node in @($copy.SelectNodes('/AppLockerPolicy/RuleCollection'))) {
        if($node.ChildNodes.Count -eq 0 -and $node.GetAttribute('EnforcementMode') -eq 'NotConfigured'){$null=$node.ParentNode.RemoveChild($node)}
    }
    return Node-Key $copy.DocumentElement
}
function Local-Policy { return ,(Read-Xml ([string](Get-AppLockerPolicy -Local -Xml))) }
function Effective-Policy { return ,(Read-Xml ([string](Get-AppLockerPolicy -Effective -Xml))) }
function Assert-Unmanaged {
    # AppLocker cmdlets do not include CSP policy. Refuse local replacement on enrolled PCs.
    foreach($path in @('SOFTWARE\Microsoft\Provisioning\OMADM\Accounts','SOFTWARE\Microsoft\Enrollments')) {
        $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path)
        if($null -eq $key){continue}
        try {
            if($path.EndsWith('Accounts') -and $key.SubKeyCount -gt 0){throw 'Este equipo esta administrado por MDM. TI debe integrar estas reglas en su politica; no se reemplazo ninguna.'}
            foreach($name in $key.GetSubKeyNames()) {
                $entry=$key.OpenSubKey($name)
                if($null -eq $entry){continue}
                try {if($entry.GetValue('EnrollmentState',0) -eq 1){throw 'Este equipo esta inscrito en MDM. TI debe integrar estas reglas; no se reemplazo ninguna politica.'}}
                finally{$entry.Dispose()}
            }
        } finally {$key.Dispose()}
    }
}
function Hash-File([string]$Path) {Assert-PrivatePath $Path; return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Write-Atomic([string]$Path,[string]$Text) {
    Assert-PrivatePath $Path
    $temp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    $stream=New-Object IO.FileStream($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.Encoding]::UTF8.GetBytes($Text);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    if([IO.File]::Exists($Path)){[IO.File]::Replace($temp,$Path,$null)}else{[IO.File]::Move($temp,$Path)}
}
function Read-Record {
    Assert-PrivatePath $marker
    if((Get-Item -LiteralPath $marker).Length -gt 16384){throw 'Registro de politica invalido.'}
    $record=[IO.File]::ReadAllText($marker)|ConvertFrom-Json
    if($record.Audit -isnot [bool] -or $record.Removed -isnot [bool] -or [long]$record.BeforeEvent -lt 0){throw 'Registro de politica invalido.'}
    $null=[DateTimeOffset]::Parse($record.RequestedAt)
    foreach($hash in @($record.CurrentHash,$record.BaselineHash,$record.PreviousHash)) {
        $path=Snapshot-Path $hash
        if((Hash-File $path) -ne $hash){throw 'Los archivos de politica cambiaron. Se conservaron sin modificar.'}
    }
    return $record
}
function Snapshot-Path([string]$Hash) {
    if($Hash -cnotmatch '^[A-F0-9]{64}$'){throw 'Huella de politica invalida.'}
    return Join-Path $StoreRoot ('applocker-'+$Hash+'.xml')
}
function Save-Snapshot([Xml.XmlDocument]$Document) {
    $bytes=[Text.Encoding]::UTF8.GetBytes($Document.OuterXml)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}
    $path=Snapshot-Path $hash
    if([IO.File]::Exists($path)) {
        if((Hash-File $path) -ne $hash){throw 'Un respaldo cambio. No se reemplazo.'}
    }else{Write-Atomic $path $Document.OuterXml}
    return $hash
}
function Latest-Event {
    try {return Get-WinEvent -FilterHashtable @{LogName=$logName;Id=8001} -MaxEvents 1 -ErrorAction Stop}
    catch {return $null}
}
function Policy-Matches($Expected) {
    return (Policy-Key (Local-Policy)) -ceq (Policy-Key $Expected) -and (Policy-Key (Effective-Policy)) -ceq (Policy-Key $Expected)
}
function Transition-Policy($Record) {
    $desired=Read-SafeXml (Snapshot-Path $Record.CurrentHash)
    if(Policy-Matches $desired){return ,$desired}
    # Interrupted requests remain recoverable only while both local and effective policy match the saved predecessor.
    $previous=Read-SafeXml (Snapshot-Path $Record.PreviousHash)
    if(Policy-Matches $previous){return ,$previous}
    throw 'Hay reglas distintas o una politica de la institucion. No se sobreescribio nada. TI debe integrar el bloqueo.'
}
function State([string]$Status,[string]$Detail,$Audit=$null) {return @{Status=$Status;Detail=$Detail;Audit=$Audit}}
function Read-State($Record) {
    $expected=Read-SafeXml (Snapshot-Path $Record.CurrentHash)
    if(-not (Policy-Matches $expected)){
        if(Policy-Matches (Read-SafeXml (Snapshot-Path $Record.PreviousHash))){return State 'Cambio pendiente' 'Windows conserva el estado anterior. Puedes reintentar la auditoria o desactivar las reglas MINSEG.' $Record.Audit}
        return State 'No comprobado' 'La politica local o de la institucion cambio. No se declara activo el bloqueo.' $Record.Audit
    }
    $service=Get-Service -Name AppIDSvc
    if($service.Status -ne 'Running' -or $service.StartType -ne 'Automatic'){return State 'Por comprobar' 'AppIDSvc no esta iniciado en automatico; no se confirma la carga o desactivacion del bloqueo.' $Record.Audit}
    $event=Latest-Event
    if($null -eq $event -or [long]$event.RecordId -le [long]$Record.BeforeEvent -or $event.TimeCreated.ToUniversalTime() -lt [DateTimeOffset]::Parse($Record.RequestedAt).UtcDateTime){return State 'Por comprobar' 'Las reglas estan guardadas, pero Windows aun no confirma su carga. Espera y pulsa Comprobar estado.' $Record.Audit}
    if($Record.Removed){return State 'No activo' 'Se desactivaron las reglas MINSEG. El servicio de Windows AppIDSvc permanece disponible.'}
    if($Record.Audit){return State 'En auditoría' 'AppLocker esta en prueba. Registra WPS y AnyDesk sin bloquear. Comprueba tus programas antes de activar.' $true}
    return State 'Bloqueo activo' 'AppLocker bloquea EXE/MSI firmados con los nombres de producto WPS Office, Kingsoft Office o AnyDesk. Incluye procesos de servicios y sigue activo al cerrar. Otras variantes requieren reglas nuevas.' $false
}
function Assert-Current($Expected) {
    if((Policy-Key (Local-Policy)) -cne (Policy-Key $Expected) -or (Policy-Key (Effective-Policy)) -cne (Policy-Key $Expected)){
        throw 'Hay reglas distintas o una politica de la institucion. No se sobreescribio nada. TI debe integrar el bloqueo.'
    }
}
function Check-UnrelatedApps {
    $paths=@([IO.Path]::Combine([Environment]::GetFolderPath('Windows'),'explorer.exe'),[IO.Path]::Combine([Environment]::SystemDirectory,'cmd.exe'),[IO.Path]::Combine([Environment]::SystemDirectory,'msiexec.exe'),[IO.Path]::Combine($PSHOME,'powershell.exe'))
    $decisions=@(Test-AppLockerPolicy -XmlPolicy $EnforceXml -Path $paths -User ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
    if($decisions.Count -ne $paths.Count -or @($decisions | Where-Object {$_.PolicyDecision.ToString() -notin @('Allowed','AllowedByDefault')}).Count -gt 0){throw 'La politica no supero la comprobacion de aplicaciones de Windows. No se aplico.'}
}

Assert-PrivatePath $StoreRoot
Assert-PrivatePath $AuditXml;Assert-PrivatePath $EnforceXml
$auditDoc=Read-SafeXml $AuditXml;$enforceDoc=Read-SafeXml $EnforceXml
$lockPath=Join-Path $StoreRoot 'applocker-operation.lock';Assert-PrivatePath $lockPath
# ASVS 15.4.1: this lock lives in the protected directory and stays held by the child if the UI times out.
$operationLock=New-Object IO.FileStream($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    Assert-Unmanaged
    $record=if([IO.File]::Exists($marker)){Read-Record}else{$null}
    if($null -ne $record) {
        $current=Read-SafeXml (Snapshot-Path $record.CurrentHash)
        $empty=Read-Xml '<AppLockerPolicy Version="1" />'
        $expected=if($record.Removed){$empty}elseif($record.Audit){$auditDoc}else{$enforceDoc}
        if((Policy-Key $current) -cne (Policy-Key $expected)){throw 'La politica guardada no corresponde a las reglas de esta version.'}
        $prior=Read-SafeXml (Snapshot-Path $record.PreviousHash)
        if(@((Policy-Key $empty),(Policy-Key $auditDoc),(Policy-Key $enforceDoc)) -cnotcontains (Policy-Key $prior)){throw 'El respaldo anterior no corresponde a MINSEG.'}
    }
    if($Mode -eq 'Read') {
        $result=if($null -eq $record){State 'Sin aplicar' 'No hay un bloqueo AppLocker creado por MINSEG.'}else{Read-State $record}
        $result | ConvertTo-Json -Compress;exit 0
    }
    if(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Se necesitan permisos de administrador.'}
    $empty=Read-Xml '<AppLockerPolicy Version="1" />'
    if($null -eq $record) {
        if($Mode -ne 'Audit'){throw 'Primero aplica la prueba en auditoria.'}
        Assert-Current $empty
        $baseline=Local-Policy
        $previous=$baseline
    } else {
        $baseline=Read-SafeXml (Snapshot-Path $record.BaselineHash)
        if((Policy-Key $baseline) -cne (Policy-Key $empty)){throw 'El respaldo inicial no esta vacio. No se reemplazara una politica ajena.'}
        $previous=Transition-Policy $record
        if($Mode -eq 'Enforce' -and ($record.Removed -or -not $record.Audit -or (Read-State $record).Status -ne 'En auditoría')){throw 'Primero debe estar cargada la auditoria y comprobada la compatibilidad.'}
    }
    $desired=if($Mode -eq 'Remove'){$baseline}elseif($Mode -eq 'Audit'){$auditDoc}else{$enforceDoc}
    Check-UnrelatedApps
    if($Mode -ne 'Remove') {
        & ([IO.Path]::Combine([Environment]::SystemDirectory,'sc.exe')) config AppIDSvc start= auto | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Windows no permitio preparar AppIDSvc. No se aplico la politica.'}
        Start-Service -Name AppIDSvc
        if((Get-Service AppIDSvc).Status -ne 'Running'){throw 'AppIDSvc no se inicio. No se aplico la politica.'}
    }
    # Recheck immediately before replacing only our own local policy. Never merge an allow-all into foreign rules.
    Assert-Current $previous
    $event=Latest-Event;$before=if($null -eq $event){0}else{[long]$event.RecordId}
    # Immutable, content-addressed snapshots are committed before the single atomic manifest update.
    # A crash cannot leave a manifest referring to an overwritten previous policy.
    $newRecord=@{Audit=($Mode -eq 'Audit');Removed=($Mode -eq 'Remove');CurrentHash=(Save-Snapshot $desired);BaselineHash=(Save-Snapshot $baseline);PreviousHash=(Save-Snapshot $previous);BeforeEvent=$before;RequestedAt=[DateTimeOffset]::UtcNow.ToString('O')}
    Write-Atomic $marker ($newRecord|ConvertTo-Json -Compress)
    $applyPath=Snapshot-Path $newRecord.CurrentHash
    Set-AppLockerPolicy -XmlPolicy $applyPath
    $result=Read-State $newRecord
    $result | ConvertTo-Json -Compress
} finally {$operationLock.Dispose()}
