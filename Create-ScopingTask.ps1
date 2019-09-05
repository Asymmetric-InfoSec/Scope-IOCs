<#
.SYNOPSIS
  Name: Create-ScopingTask.ps1
  
.DESCRIPTION
  This script allows for incident responders to scope specific indicators of compromise
  based on user input. The indicators of comrpomise that can be searched are:  


.NOTES
  Release Date: 9/4/2019
  Updated: 
   
  Author: Drew Schmitt

.EXAMPLE
 

#>

param (

  [Parameter(ParameterSetName = "Setup", Position = 0, Mandatory = $true)][String]$Argument,
  [Parameter(ParameterSetName = "Setup", Position = 1, Mandatory = $false)][PSCredential]$Credential,
  [Parameter(ParameterSetName = "Setup", Position = 2, Mandatory = $false)][DateTime]$Date = (Get-Date).AddMinutes(5),
  [Parameter(ParameterSetName = "Setup", Position = 3, Mandatory = $false)][Int32]$Interval = 30,
  [Parameter(ParameterSetName = "Setup", Position = 4, Mandatory = $false)][Int32]$Duration = 30,
  [Parameter(ParameterSetName = "Removal", Position = 0, Mandatory = $true)][Switch]$Remove

)

process {

  $Exists = Get-ScheduledTask -TaskName 'Scope-IOCs' -ErrorAction SilentlyContinue

  if (!$Exists -and !$Remove){

    if (!$Credential){

      $Credential = (Get-Credential -Message 'Provide your domain credentials (Domain\Username) and password')
    }

    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $Argument -WorkingDirectory $PSScriptRoot

    $IntervalTime = (New-Timespan -Minutes $Interval)
    $TaskDuration = (New-Timespan -Days $Duration)
    $Trigger = New-ScheduledTaskTrigger -Once -At $Date -RepetitionInterval $IntervalTime -RepetitionDuration $TaskDuration

    $Principal = New-ScheduledTaskPrincipal -UserId ($Credential.UserName) -LogonType Password -RunLevel Highest

    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

    $Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings

    Register-ScheduledTask -TaskName 'Scope-IOCs' -InputObject $Task -User ($Credential.UserName) -Password ($Credential.GetNetworkCredential().Password)

  }

  if ($Exists -and !$Remove){

    Write-Warning 'Scope-IOCs scheduled task detected. Remove existing scheduled task using Remove parameter before running again.'
    Exit

  }

  if ($Remove){

    if (!$Exists){

      Write-Warning 'Scope-IOCs task does not exist. Quitting'
      Exit
    }

    if ($Exists){

      #Stop scheduled task if running
      Stop-ScheduledTask -TaskName 'Scope-IOCs'

      #Unregister and remove scheduled task, do not prompt for confirmation
      Unregister-ScheduledTask -TaskName 'Scope-IOCs' -Confirm:$false

    }
  }
}
