[CmdletBinding()]
param(
  [string]$Target,  
  [string]$LogPath = "$env:TEMP\TerminateApp-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
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
  Add-Content -Path $LogPath -Value $line
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

Rotate-Log
Write-Log "=== SCRIPT START : Terminate Application ==="

try{
  if (-not $Target) { throw "Target is required (name or PID; no interactive input allowed)" }

  $mode = if ($Target -match '^\d+$') { 'pid' } else { 'name' }
  Write-Log "Mode: $mode" 'INFO'
  Write-Log "Target: $Target" 'INFO'

  $killed = @()
  $notFound = $false

  if ($mode -eq 'pid') {
    $proc = Get-Process -Id [int]$Target -ErrorAction SilentlyContinue
    if ($proc) {
      try {
        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        Write-Log "Terminated PID $($proc.Id) [$($proc.ProcessName)]" 'INFO'
        $killed += [pscustomobject]@{ name = $proc.ProcessName; pid = $proc.Id }
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
        try {
          Stop-Process -Id $p.Id -Force -ErrorAction Stop
          Write-Log "Terminated [$($p.Id)] $($p.ProcessName)" 'INFO'
          $killed += [pscustomobject]@{ name = $p.ProcessName; pid = $p.Id }
        } catch {
          Write-Log "Failed to terminate [$($p.Id)] $($p.ProcessName): $($_.Exception.Message)" 'ERROR'
        }
      }
      if ($killed.Count -eq 0) { $notFound = $true }
    } else {
      Write-Log "No process found matching name '$Target'" 'WARN'
      $notFound = $true
    }
  }
  $ts = (Get-Date).ToString('o')
  $lines = @()

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'terminate_app_summary'
    mode           = $mode
    target         = $Target
    killed_count   = $killed.Count
    status         = if ($notFound -and $killed.Count -eq 0) { 'not_found' } else { 'terminated' }
    copilot_action = $true
  } | ConvertTo-Json -Compress -Depth 3)

  foreach ($k in $killed) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'terminate_app'
      name           = $k.name
      pid            = $k.pid
      status         = 'terminated'
      copilot_action = $true
    } | ConvertTo-Json -Compress -Depth 3)
  }

  if ($notFound -and $killed.Count -eq 0) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'terminate_app'
      target         = $Target
      status         = 'not_found'
      copilot_action = $true
    } | ConvertTo-Json -Compress -Depth 3)
  }

  $ndjson   = [string]::Join("`n", $lines)
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

  $recordCount = $lines.Count
  try{
    # Atomic overwrite; .new fallback if locked
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Wrote $recordCount NDJSON record(s) to $ARLog" 'INFO'
  }catch{
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote to $($ARLog).new" 'WARN'
  }
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = (Get-Date).ToString('o')
    host           = $HostName
    action         = 'terminate_app'
    status         = 'error'
    error          = $_.Exception.Message
    copilot_action = $true
  }
  $ndjson = ($err | ConvertTo-Json -Compress -Depth 3)
  $tempFile="$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force
  try{
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Error JSON written to $ARLog" 'INFO'
  }catch{
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote error to $($ARLog).new" 'WARN'
  }
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
