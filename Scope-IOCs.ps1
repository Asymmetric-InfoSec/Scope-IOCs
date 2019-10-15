<#
.SYNOPSIS
  Name: Scope-IOCs.ps1
  
.DESCRIPTION
  This script allows for incident responders to scope specific indicators of compromise
  based on user input. The indicators of comrpomise that can be searched are:

  File:                     Determine if a file name with an unknown path exists
  Path:                     Determine if a full directory or file path exists
  IP Address:               Determine if a network connection is currently established with a specific IP address
  Process:                  Determine if a specific process is running
  Service:                  Determine if a specific service exists
  Local User Account:       Determine if a specific local user account exists
  Registry Key:             Deteremine if a specific regisry key (designated by full path) exists
  
PARAMETERS

Scoping Files

  -File
    Used to specify the file name that will be searched for when running the script using the Scope-File parameter set

  -FileStartPath
    Used to specify the starting directory that the script will use to begin searching for a file when using the Scope-File parameter set

      

Scoping Directory and File Paths

  -Path
    Specifies the full path that will be tested when running the script using the Scope-Path parameter set
      

Scoping IP Addresses

  -IPAddress
    Used to specify the IP address that will be searched for when running the script using the Scope-IPAddress parameter set


Scoping Processes

  -Process
    Used to specify the process name that will be searched for when running the script using the Scope-Process parameter set      

Scoping Services

  -Service
    Used to specify the service name that will be searched for when running the script using the Scope-Service parameter set
      
Scoping Local User Accounts
  -User
    Used to specify the local user name that will be searched for when running the script using the Scope-LocalUsers parameter set      

Scoping Registry Keys

  -RegKey
    Used to specify the full path to the registry key that will be searched for when running the script using the Scope-RegKey parameter set

Host Import Parameters

  -TargetFile
    Specifies the text or csv file containing hostnames that will be imported and used as the base to scope against
    Note: for csv's, the column header must be ComputerName
  
  -Target
    Specified by the user and will be used as the host base to scope against

  -ADTarget
    Specifies the base DN that will be used to collect hosts from in AD

    -ServersOnly
      Used when scoping against servers only
    
    -WorkstationsOnly
      Used when scoping against workstations only

    -BothTargetTypes
      Used when scoping against both servers and workstations

Output Parameters

  -OutputDir
    Specifies the location of the output directory that will be created for output

PowerShell Remoting Specific Parameters

  -ThrottleLimit
    Used to specify the value for ThrottleLimit to use with Invoke-Command. Default is set to use the PS Remoting default of 32

.NOTES
    Release Date: 2/14/2019
    Updated: 9/3/2019
   
    Author: Drew Schmitt

.EXAMPLE

Scope a file with an unknown path against a user specified host

Scope-IOCs.ps1 -File testfile.txt -FileStartPath C:\ -Target test-PC -OutputDir C:\Tools\Scoping  

.EXAMPLE 

Scope a specific path against a host base specified by a CSV file

Scope-IOCs.ps1 -Path C:\Tools\testfile.txt -TargetFile C:\test\hosts.csv -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope an IP address against a host base specified by a TXT file

Scope-IOCs.ps1 -IPAddress '172.217.4.46' -TargetFile C:\test\hosts.txt -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific process against a host base consisting of only workstations and specified by ADTarget

Scope-IOCs.ps1 -Process 'evil.exe' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -WorkstationsOnly -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific service against a host base consisting of only servers and specified by ADTarget

Scope-IOCs.ps1 -Service 'evilservice' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -ServersOnly -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific local user account against a host base consisting of both servers and workstations and specified by ADTarget

Scope-IOCs.ps1 -User 'eviluseraccount' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -BothTargetTypes -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific registry key against a host base consisting of user specified hosts

Scope-IOCs.ps1 -RegKey HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilKey -Target "PC1,PC2,PC3,PC4,PC5" -OutputDir C:\Tools\Scoping

#>

param (

# Parameter set for Scope-File
[Parameter(ParameterSetName = "Scope-File", Position = 0, Mandatory = $true)]
[String]$File,

[Parameter(ParameterSetName = "Scope-File", Position = 1, Mandatory = $true)]
[String]$FileStartPath,

# Parameter set for Scope-Path
[Parameter(ParameterSetName = "Scope-Path", Position = 0, Mandatory = $true)]
[String]$Path,

# Parameter set for Scope-IPAddress
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 0, Mandatory = $true)]
[String]$IPAddress,

# Parameter set for Scope-Process
[Parameter(ParameterSetName = "Scope-Process", Position = 0, Mandatory = $true)]
[String]$Process,

# Parameter set for Scope-Service
[Parameter(ParameterSetName = "Scope-Service", Position = 0, Mandatory = $true)]
[String]$Service,

#Parameter set for Scope-LocalUsers
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 0, Mandatory = $true)]
[String]$User,

# Parameter set for Scope-RegKey
[Parameter(ParameterSetName = "Scope-RegKey", Position = 0, Mandatory = $true)]
[String]$RegKey,

# Common Parameters
[Parameter(ParameterSetName = "Scope-File", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 1, Mandatory = $false)]
[string] $TargetFile,

[Parameter(ParameterSetName = "Scope-File", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 1, Mandatory = $false)]
[string[]] $Target,

[Parameter(ParameterSetName = "Scope-File", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 1, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 1, Mandatory = $false)]
[string] $ADTarget,

[Parameter(ParameterSetName = "Scope-File", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Path", Position = 2, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 2, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Process", Position = 2, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Service", Position = 2, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 2, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 2, Mandatory = $true)]
[string] $OutputDir,

[Parameter(ParameterSetName = "Scope-File", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 3, Mandatory = $false)]
[switch] $ServersOnly,

[Parameter(ParameterSetName = "Scope-File", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 3, Mandatory = $false)]
[switch] $WorkstationsOnly,

[Parameter(ParameterSetName = "Scope-File", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 3, Mandatory = $false)]
[switch] $BothTargetTypes,

[Parameter(ParameterSetName = "Scope-File", Position = 5, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 4, Mandatory = $false)]
[Int32] $PSThrottleLimit = 0

)

process {

# Functions  

# Files based on file name only (not full path)

function Scope-File {

  param ([string]$File, [string]$FileStartPath )

  # Determine if file is found on system
  $FileEvalPath = Get-ChildItem -Path $FileStartPath -Recurse -Name -Include $File

  # Append eval results to CSV
  if ($FileEvalPath){

    $FilePathArray = ($FileEvalPath -Join "`n")

    # return PSCustomObject for recording in CSV - includes path of discovered child object
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"; Path = $FilePathArray}
    return [PSCustomObject]$OutHash
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"; Path = $null}
    return [PSCustomObject]$OutHash
  }
}

# File or directory based on full path
function Scope-Path {

  param ([string]$Path)

  # Determine if path is found on system
  $PathEval = Test-Path -Path $Path

  # Append eval results to CSV
  # return PSCustomObject for recording in CSV
  $OutHash =@{ Host = $env:COMPUTERNAME; Detected = [Boolean]$PathEval}
  return [PSCustomObject]$OutHash    
}

# IP ADDRESSES
function Scope-IPAddress {

  param ([string]$IPAddress)

  # Determine if the IP address is found on system
  $IPAddressEval = netstat -naob | Select-String -pattern ".*$IPAddress.*" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value

  # Determine if IP address is found on system
  # return PSCustomObject for recording in CSV
  $OutHash =@{ Host = $env:COMPUTERNAME; Detected = [Boolean]$IPAddressEval; Details = ($IPAddressEval -Join "`n")}
  return [PSCustomObject]$OutHash
    
}

# PROCESSES
function Scope-Process {

  param ([string]$Process)

  # Determine if the process is found on system
  $ProcessEval = Get-CimInstance -ClassName win32_process -Filter "name LIKE '$Process%'"

  # Determine if process is found on system
  $NameArray = ($ProcessEval.Name -Join "`n")
  $EPArray = ($ProcessEval.ExecutablePath -Join "`n")
  $CMDLineArray = ($ProcessEval.Commandline -Join "`n")
  $PIDArray = ($ProcessEval.ProcessID -Join "`n")
  $PPIDArray = ($ProcessEval.ParentProcessID -Join "`n")

  # return PSCustomObject for recording in CSV
  $OutHash =@{ Host = $env:COMPUTERNAME; Detected = [Boolean]$ProcessEval; Name = $NameArray; ExecutablePath = $EPArray; Commandline = $CMDLineArray; PID = $PIDArray; ParentPID = $PPIDArray }
  return [PSCustomObject]$OutHash

}

# SERVICES
function Scope-Service {

  param ([string]$Service)

  # Determine if the IP address is found on system
  $ServiceEval = Get-CimInstance -ClassName win32_service -Filter "name LIKE '$Service%'"

  # Determine if service is found on system

  $NameArray = ($ServiceEval.Name -Join "`n")
  $DNArray = ($ServiceEval.DisplayName -Join "`n")
  $PIDArray = ($ServiceEval.ProcessID -Join "`n")
  $PathArray = ($ServiceEval.PathName -Join "`n")
  $STArray = ($ServiceEval.ServiceType -Join "`n")
  $SMArray = ($ServiceEval.StartMode -Join "`n")
  $StatusArray = ($ServiceEval.Status -Join "`n")

  # return PSCustomObject for recording in CSV
  $OutHash =@{ Host = $env:COMPUTERNAME; Detected = [Boolean]$ServiceEval; Name = $NameArray; DisplayName = $DNArray; PID = $PIDArray; Path = $PathArray; ServiceType = $STArray; StartMode = $SMArray; Status = $StatusArray }
  return [PSCustomObject]$OutHash
    
  }

# USER ACCOUNTS
function Scope-LocalUsers {

  param ([string]$User)

  # Determine if the IP address is found on system
  $UserEval = Get-LocalUser -Name $User -ErrorAction SilentlyContinue

  # Determine if service is found on system
  $NameArray = ($UserEval.Name -Join "`n")
  $EnabledArray = ($UserEval.Enabled -Join "`n")
        
  # return PSCustomObject for recording in CSV
  $OutHash =@{ Host = $env:COMPUTERNAME; Detected = [Boolean]$UserEval; Name = $NameArray; Enabled = $EnabledArray }
  return [PSCustomObject]$OutHash
    
}

# REGISTRY KEYS - Specific Registry key at a specific path
function Scope-RegKey {

  param ([string]$RegKey)

  #Mount PS Drive for processes
  $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS

  # Determine if path is found on system
  $FullKeyEval = ((Get-Item -Path $RegKey).Name -Join "`n")

  # Append eval results to CSV
  # return PSCustomObject for recording in CSV

  $OutHash =@{Host = $env:COMPUTERNAME; Detected = [Boolean]$FullKeyEval; Keys = $FullKeyEval}
  return [PSCustomObject]$OutHash

  $null = Remove-PSDrive -Name HKU -Force 
    
}

# Write-Log Function
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [String]$Message
    )

    process {
        # Get UTC $Date
        $Date = (Get-Date).ToUniversalTime()

        # Build the $LogPath
        $LogPath = ('{0}\{1:yyyy-MM-dd}_Log.csv' -f $OutputDir, $Date)

        # Build $LogLine
        $LogLine = [PSCustomObject]@{
            Date = ('{0:u}' -f $Date)
            UserName = $ENV:UserName
            Message = $Message
        }

        $LogLine | Export-Csv -NoTypeInformation -Append -Path $LogPath
    }
}

# Validate that Active Directory module is loaded and ready for use
if (!(Get-Command 'Get-ADComputer')){

  try {

    Import-Module 'ActiveDirectory' -ErrorAction Stop

  } catch {

    $ADModule = $False
    Write-Warning "An error occured while importing the Active Directory module. Continuing, however, AD capabilities will be degraded."

  }

} 

# Validate that only one host ingestion parameter was used

if (([bool]$TargetFile + [bool]$Target + [bool]$ADTarget) -ne 1){

  Throw "Only one host ingestion parameter can be used. Quitting."

}

# Output Directory
# Verify if output directory exists, if not create it
  $OutputTest = Test-Path $OutputDir

  If (-not $OutputTest) {

    New-Item -Type Directory -Path $OutputDir -Force | Out-Null

  }

  # Build hosts list for use during invocation of IOC Scoping
  if ($TargetFile) {

    try {

      $Hosts = Import-CSV $TargetFile | Select -ExpandProperty ComputerName -ErrorAction Stop

    } catch {

      try {

        $Hosts = Get-Content $TargetFile -ErrorAction Stop

      } catch {

        throw "An error occured while Importing Hosts using the TargetFile parameter. Quitting."

      }
    }
  } 

  if ($Target){

    try {

      $Hosts = $Target

    } catch {

      throw "Error occurred while importing hosts with Target parameter. Quitting."

    }

  }

  if ($ADTarget){

    if ($ADModule){

      if ($WorkstationsOnly){

        try {

          $Hosts = Get-ADComputer -Filter { OperatingSystem -eq 'Windows 7 Enterprise' -or OperatingSystem -eq 'Windows 10 Enterprise' } -SearchBase $ADTarget | Select-Object -ExpandProperty Name -ErrorAction Stop

        } catch {

          Throw "Could not expand ADTarget to obtain hosts. Quitting."

        }

      } elseif ($ServersOnly){

          $Confirm = Read-Host "You are about to run scoping against all servers in the specific AD Target. Are you sure you want to continue? [Y/N]"

          if ($confirm.ToLower() -ne 'y'){

            Exit
          }

         try {

          $Hosts = Get-ADComputer -Filter { OperatingSystem -like 'Windows Server*' } -SearchBase $ADTarget | Select-Object -ExpandProperty Name -ErrorAction Stop

        } catch {

          Throw "Could not expand ADTarget to obtain hosts. Quitting."

        }

      } elseif ($BothTargetTypes){

          $Confirm = Read-Host "You are about to run scoping against all workstations and servers in the specific AD Target. Are you sure you want to continue? [Y/N]"

          if ($confirm.ToLower() -ne 'y'){

            Exit
          }

         try {

          $Hosts = Get-ADComputer -SearchBase $ADTarget | Select-Object -ExpandProperty Name -ErrorAction Stop

        } catch {

          Throw "Could not expand ADTarget to obtain hosts. Quitting."

        }

      } else {

        Throw "No scope flags provided for AD Scoping. Quitting."

      }
    }

    if (!$ADModule){

      throw "AD import selected, but AD Module not available or could not be imported. Quitting."
    }
  }

#Let the scoping begin
$Message = "Scoping began at $(Get-Date)"
Write-Log -Message $Message

#Scope IOCs
#Execute based on selected parameter set
switch ($PSCmdlet.ParameterSetName) {
  "Scope-File" { $Arguments = @($File,$FileStartPath); $ScriptBlock = ${Function:Scope-File} }
  "Scope-Path" { $Arguments = @($Path); $ScriptBlock = ${Function:Scope-Path} }
  "Scope-IPAddress" { $Arguments = @($IPAddress); $ScriptBlock = ${Function:Scope-IPAddress} }
  "Scope-Process" { $Arguments = @($Process); $ScriptBlock =  ${Function:Scope-Process} }
  "Scope-Service" { $Arguments = @($Service); $ScriptBlock =  ${Function:Scope-Service} }
  "Scope-LocalUsers" { $Arguments = @($UserName); $ScriptBlock = ${Function:Scope-LocalUsers} }
  "Scope-RegKey" { $Arguments = @($RegKey); $ScriptBlock = ${Function:Scope-RegKey} }
}

# PowerShell Remoting for the win
try {

  Invoke-Command -ComputerName $Hosts -ScriptBlock $ScriptBlock -ArgumentList $Arguments -ThrottleLimit $PSThrottleLimit | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_{2}.csv" -f $OutputDir, $(Get-Date), $PSCmdlet.ParameterSetName) -Append -ErrorAction Stop

} catch {
    
  $Message = "There was a problem running ScopeIOCs.ps1 using the {0} parameter" -f ($PSCmdlet.ParameterSetName -Replace '^Scope-')
  Write-Log -Message $Message
  Write-Warning $Message
}

#End Scoping
$Message = "Scoping ended at $(Get-Date)"
Write-Log -Message $Message 

}