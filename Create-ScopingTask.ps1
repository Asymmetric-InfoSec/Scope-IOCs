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

#Requires -RunAsAdministrator

param (

  [Parameter(Mandatory=$true)][String]$Argument,
  [DateTime]$Date = (Get-Date).AddMinutes(5),
  [Int32]$Interval = 30,
  [Parameter(Mandatory=$true)][String]$UserAccount

)

process {

  $Exists = Get-ScheduledTask -TaskName 'Scope-IOCs'

  if (!$Exists){

    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argumment $Argument -WorkingDirectory $PSScriptRoot

    $IntervalTime = (New-Timespan -Minutes $Interval)
    $Duration = ([timeSpan]::maxvalue)
    $Trigger = New-ScheduledTaskTrigger -Once -At $Date -RepetitionInterval $IntervalTime -RepetitionDuration $Duration

    $Principal = New-ScheduledTaskPrincipal -UserId $UserAccount -LogonType Password -RunLevel Limited 

    $Settings = New-ScheduledTaskSettingsSet

    $Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings

    Register-ScheduledTask 'Scope-IOCs' -InputObject $Task

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
