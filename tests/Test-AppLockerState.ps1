param([Parameter(Mandatory=$true)][string]$Scratch)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$scriptPath=Join-Path $PSScriptRoot '..\src\Minseg.Core\AppLockerHost.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw ($errors | Out-String)}
# Only load function definitions. Never invoke the helper's top-level policy/service operations.
foreach($node in $ast.EndBlock.Statements){if($node -is [Management.Automation.Language.FunctionDefinitionAst]){. ([scriptblock]::Create($node.Extent.Text))}}
function Set-AppLockerPolicy {throw 'Forbidden during tests'}
function Start-Service {throw 'Forbidden during tests'}
function Assert-PrivatePath([string]$Path) {if(-not [IO.Path]::GetFullPath($Path).StartsWith($script:StoreRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Test path escaped scratch'}}
function Local-Policy {return ,$script:local}
function Effective-Policy {return ,$script:effective}
function Get-Service {return @{Status='Running';StartType='Automatic'}}
function Latest-Event {return $script:event}
function Check([bool]$Ok,[string]$Name) {if(-not $Ok){throw $Name};$script:passed++;Write-Output ('PASS '+$Name)}
function Must-Throw([scriptblock]$Action,[string]$Name) {$threw=$false;try{& $Action|Out-Null}catch{$threw=$true};Check $threw $Name}
$script:passed=0
$script:StoreRoot=Join-Path ([IO.Path]::GetFullPath($Scratch)) ([Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($StoreRoot)
$marker=Join-Path $StoreRoot 'applocker-state.json'
$empty=Read-Xml '<AppLockerPolicy Version="1" />'
$audit=Read-Xml '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly" /></AppLockerPolicy>'
$enforce=Read-Xml '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled" /></AppLockerPolicy>'
$emptyHash=Save-Snapshot $empty;$auditHash=Save-Snapshot $audit;$enforceHash=Save-Snapshot $enforce
$script:local=$audit;$script:effective=$audit
$record=@{Audit=$false;Removed=$false;CurrentHash=$enforceHash;PreviousHash=$auditHash;BaselineHash=$emptyHash;BeforeEvent=100;RequestedAt=[DateTimeOffset]::UtcNow.ToString('O')}
$script:event=@{RecordId=101;TimeCreated=[DateTime]::UtcNow.AddSeconds(1)}
Check ((Read-State $record).Status -eq 'Cambio pendiente') 'Interrupted promotion never claims active'
Check ((Policy-Key (Transition-Policy $record)) -eq (Policy-Key $audit)) 'Interrupted promotion recovers verified predecessor'
$script:local=$enforce;$script:effective=$enforce
Check ((Read-State $record).Status -eq 'Bloqueo activo') 'Current policy and new event confirm active'
$script:event=@{RecordId=101;TimeCreated=[DateTime]::UtcNow.AddHours(-1)}
Check ((Read-State $record).Status -eq 'Por comprobar') 'Stale event cannot confirm a new request'
$script:event=$null
Check ((Read-State $record).Status -eq 'Por comprobar') 'Unavailable event log cannot confirm enforcement'
$removal=@{Audit=$false;Removed=$true;CurrentHash=$emptyHash;PreviousHash=$enforceHash;BaselineHash=$emptyHash;BeforeEvent=100;RequestedAt=[DateTimeOffset]::UtcNow.ToString('O')}
$script:local=$empty;$script:effective=$empty
Check ((Read-State $removal).Status -eq 'Por comprobar') 'Removal also requires load confirmation'
$script:event=@{RecordId=101;TimeCreated=[DateTime]::UtcNow.AddSeconds(1)}
Check ((Read-State $removal).Status -eq 'No activo') 'Removal confirmed after matching reload'
$script:local=$enforce;$script:effective=$enforce
$script:effective=Read-Xml '<AppLockerPolicy Version="1"><RuleCollection Type="Msi" EnforcementMode="Enabled" /></AppLockerPolicy>'
Check ((Read-State $record).Status -eq 'No comprobado') 'Foreign effective policy never claims active'
Must-Throw {Transition-Policy $record} 'Recovery refuses a foreign policy'
Check ((Policy-Key (Read-SafeXml (Snapshot-Path $auditHash))) -eq (Policy-Key $audit)) 'New snapshot never overwrites previous snapshot'
Write-Atomic $marker ($record|ConvertTo-Json -Compress)
Check ((Read-Record).CurrentHash -eq $enforceHash) 'Atomic manifest references readable snapshots'
[IO.File]::AppendAllText((Snapshot-Path $enforceHash),' ')
Must-Throw {Read-Record} 'Tampered snapshot rejects operation'
Must-Throw {Snapshot-Path '..\outside'} 'Snapshot cannot escape storage'
Must-Throw {Read-Xml '<!DOCTYPE AppLockerPolicy [<!ENTITY e SYSTEM "file:///C:/Windows/win.ini">]><AppLockerPolicy Version="1">&e;</AppLockerPolicy>'} 'External XML entities rejected'
Write-Output ('Total: '+$passed+' passed; no host policy or service changes')
