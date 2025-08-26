[CmdletBinding()]
param(
  [string]$Target,
  [string]$LogPath = "$env:TEMP\TerminateApp-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [string]$Arg1
)

if ($Arg1 -and -not $Target) { $Target = $Arg1 }

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + $tz
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try{Move-Item -Path $tmp -Destination $Path -Force}catch{Move-Item -Path $tmp -Destination ($Path + '.new') -Force}
}

function Get-FileHashSafe {
  param([string]$Path)
  try {
    if($Path -and (Test-Path $Path -PathType Leaf)){
      return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpper()
    }
  } catch { }
  return $null
}

function Get-ProcMeta {
  param([int]$ProcessId)
  $wmi = $null
  try { $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop } catch {}
  $name = $null; $exe = $null; $sid = $null; $ppid = $null
  if($wmi){
    $name = $wmi.Name
    $exe  = $wmi.ExecutablePath
    $ppid = $wmi.ParentProcessId
    $sid  = $wmi.SessionId
  } else {
    try { $p = Get-Process -Id $ProcessId -ErrorAction Stop; $name=$p.ProcessName; $sid=$p.SessionId } catch {}
    try { $exe = (Get-Process -Id $ProcessId -ErrorAction Stop).Path } catch {}
  }
  $user = $null
  if($wmi){
    try { $owner = $wmi | Invoke-CimMethod -MethodName GetOwner; if($owner.User){ $user = $owner.User } } catch {}
  }
  [pscustomobject]@{
    name        = $name
    process_id  = $ProcessId
    exe_path    = $exe
    username    = $user
    parent_pid  = $ppid
    session_id  = $sid
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : Terminate Application ==="

try{
  if (-not $Target) { throw "Target is required (process name or numeric PID)" }

  $mode = if ($Target -match '^\d+$') { 'pid' } else { 'name' }
  Write-Log "Mode: $mode" 'INFO'
  Write-Log "Target: $Target" 'INFO'

  $killed = New-Object System.Collections.Generic.List[object]
  $notFound = $false

  if ($mode -eq 'pid') {
    $targetPid = [int]$Target
    $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    if ($proc) {
      $meta = Get-ProcMeta -ProcessId $proc.Id
      $sw=[System.Diagnostics.Stopwatch]::StartNew()
      try {
        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        $sw.Stop()
        $hash = Get-FileHashSafe -Path $meta.exe_path
        Write-Log "Terminated PID $($proc.Id) [$($meta.name)]" 'INFO'
        $killed.Add([pscustomobject]@{
          name=$meta.name; pid=$meta.process_id; exe_path=$meta.exe_path; username=$meta.username;
          parent_pid=$meta.parent_pid; session_id=$meta.session_id; terminate_ms=[int]$sw.Elapsed.TotalMilliseconds;
          signature_sha256=$hash
        })
      } catch {
        Write-Log "Failed to terminate PID $($proc.Id): $($_.Exception.Message)" 'ERROR'
        $notFound = $true
      }
    } else {
      Write-Log "No process found with PID $Target" 'WARN'
      $notFound = $true
    }
  } else {
    $procs = Get-Process -Name $Target -ErrorAction SilentlyContinue
    if ($procs) {
      foreach ($p in $procs) {
        $meta = Get-ProcMeta -ProcessId $p.Id
        $sw=[System.Diagnostics.Stopwatch]::StartNew()
        try {
          Stop-Process -Id $p.Id -Force -ErrorAction Stop
          $sw.Stop()
          $hash = Get-FileHashSafe -Path $meta.exe_path
          Write-Log "Terminated [$($p.Id)] $($meta.name)" 'INFO'
          $killed.Add([pscustomobject]@{
            name=$meta.name; pid=$meta.process_id; exe_path=$meta.exe_path; username=$meta.username;
            parent_pid=$meta.parent_pid; session_id=$meta.session_id; terminate_ms=[int]$sw.Elapsed.TotalMilliseconds;
            signature_sha256=$hash
          })
        } catch {
          Write-Log "Failed to terminate [$($p.Id)] $($meta.name): $($_.Exception.Message)" 'ERROR'
        }
      }
      if ($killed.Count -eq 0) { $notFound = $true }
    } else {
      Write-Log "No process found matching name '$Target'" 'WARN'
      $notFound = $true
    }
  }

  $ts = Now-Timestamp
  $lines = @()

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'Terminate-App'
    copilot_action = $true
    type           = 'summary'
    mode           = $mode
    target         = $Target
    killed_count   = $killed.Count
    status         = if ($notFound -and $killed.Count -eq 0) { 'not_found' } else { 'terminated' }
  } | ConvertTo-Json -Compress -Depth 6)

  foreach ($k in $killed) {
    $lines += ([pscustomobject]@{
      timestamp        = $ts
      host             = $HostName
      action           = 'Terminate-App'
      copilot_action   = $true
      type             = 'terminated'
      name             = $k.name
      pid              = $k.pid
      exe_path         = $k.exe_path
      username         = $k.username
      parent_pid       = $k.parent_pid
      session_id       = $k.session_id
      terminate_ms     = $k.terminate_ms
      signature_sha256 = $k.signature_sha256
    } | ConvertTo-Json -Compress -Depth 6)
  }

  if ($notFound -and $killed.Count -eq 0) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'Terminate-App'
      copilot_action = $true
      type           = 'not_found'
      target         = $Target
    } | ConvertTo-Json -Compress -Depth 4)
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count,$ARLog) 'INFO'
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = Now-Timestamp
    host           = $HostName
    action         = 'Terminate-App'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
