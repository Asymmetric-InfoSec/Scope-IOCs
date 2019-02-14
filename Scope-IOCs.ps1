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
    Used when specifying that a File scoping will occur when running the script

    -FileStartPath
      Used to specify the starting directory that the script will use to begin searching for a file when using the File parameter

    -FileName
      Used to specify the file name that will be searched for when running the script using the File parameter

Scoping Directory and File Paths

  -Path
    Used when specifying that a Path scoping will occur when running the script (should be a directory or file path)

    -PathName
      Specifies the full path that will be tested when running the script using the Path parameter

Scoping IP Addresses

  -IPAddress
    Used when specifying that an IP address scoping will occur when running the script

    -Address
      Used to specify the IP address that will be searched for when running the script using the IPAddress parameter

Scoping Processes

  -Process
    Used when specifying that a Process scoping will occur when running the script

    -ProcessName
      Used to specify the process name that will be searched for when running the script using the Process parameter

Scoping Services

  -Service
    Used when specifying that a Service scoping will occur when running the script

    -ServiceName
      Used to specify the service name that will be searched for when running the script using the Service parameter

Scoping Local User Accounts
  -User
    Used to specify that a Local User scoping will occur when running the script

    -UserName
      Used to specify the local user name that will be searched for when running the script using the User parameter

Scoping Registry Keys

  -RegKey
    Used to specify that a Registry Key scoping will occur when running the script

    -FullKeyPath
      Used to specify the full path to the registry key that will be searched for when running the script using the RegKey parameter

Host Import Parameters

  -TargetTXTFile
    Specifies a TXT file containing hostnames that will be imported and used as the base to scope against

  -TargetCSVFile
    Specifies a CSV file containing hostnames that will be imported and used as the host base to scope against
    Note: the column header must be ComputerName

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

.NOTES
    Updated: 2/14/2019        
    Release Date: 2/14/2019
   
    Author: Drew Schmitt

.EXAMPLE

Scope a file with an unknown path against a user specified host

Scope-IOCs.ps1 -File -FileStartPath C:\ -FileName testfile.txt -Target test-PC -OutputDir C:\Tools\Scoping  

.EXAMPLE 

Scope a specific path against a host base specified by a CSV file

Scope-IOCs.ps1 -Path -PathName C:\Tools\testfile.txt -TargetCSVFile C:\test\hosts.csv -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope an IP address against a host base specified by a TXT file

Scope-IOCs.ps1 -IPAddress -Address '172.217.4.46' -TargetTXTFile C:\test\hosts.txt -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific process against a host base consisting of only workstations and specified by ADTarget

Scope-IOCs.ps1 -Process -ProcessName 'evil.exe' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -WorkstationsOnly -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific service against a host base consisting of only servers and specified by ADTarget

Scope-IOCs.ps1 -Service -ServiceNAme 'evilservice' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -ServersOnly -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific local user account against a host base consisting of both servers and workstations and specified by ADTarget

Scope-IOCs.ps1 -User -UserName 'eviluseraccount' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -BothTargetTypes -OutputDir C:\Tools\Scoping

.EXAMPLE

Scope a specific registry key against a host base consisting of user specified hosts

Scope-IOCs.ps1 -RegKey -FullKeyPath HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilKey -Target "PC1,PC2,PC3,PC4,PC5" -OutputDir C:\Tools\Scoping

#>

param (

# Parameter set for Scope-File
[Parameter(ParameterSetName = "Scope-File", Position = 0)]
[Switch]$File,

[Parameter(ParameterSetName = "Scope-File", Position = 1)]
[String]$FileStartPath,

[Parameter(ParameterSetName = "Scope-File", Position = 2)]
[String]$FileName,

# Parameter set for Scope-Path
[Parameter(ParameterSetName = "Scope-Path", Position = 0)]
[Switch]$Path,

[Parameter(ParameterSetName = "Scope-Path", Position = 1)]
[String]$PathName,

# Parameter set for Scope-IPAddress
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 0)]
[Switch]$IPAddress,

[Parameter(ParameterSetName = "Scope-IPAddress", Position = 1)]
[String]$Address,

# Parameter set for Scope-Process
[Parameter(ParameterSetName = "Scope-Process", Position = 0)]
[Switch]$Process,

[Parameter(ParameterSetName = "Scope-Process", Position = 1)]
[String]$ProcessName,

# Parameter set for Scope-Service
[Parameter(ParameterSetName = "Scope-Service", Position = 0)]
[Switch]$Service,

[Parameter(ParameterSetName = "Scope-Service", Position = 1)]
[String]$ServiceName,

#Parameter set for Scope-LocalUsers
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 0)]
[Switch]$User,

[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 1)]
[String]$UserName,

# Parameter set for Scope-RegKey
[Parameter(ParameterSetName = "Scope-RegKey", Position = 0)]
[Switch]$RegKey,

[Parameter(ParameterSetName = "Scope-RegKey", Position = 1)]
[String]$FullKeyPath,

# Common Parameters
[Parameter(ParameterSetName = "Scope-File", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 2, Mandatory = $false)]
[string] $TargetTXTFile,

[Parameter(ParameterSetName = "Scope-File", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 2, Mandatory = $false)]
[string] $TargetCSVFile,

[Parameter(ParameterSetName = "Scope-File", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 2, Mandatory = $false)]
[string[]] $Target,

[Parameter(ParameterSetName = "Scope-File", Position = 3, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 2, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 2, Mandatory = $false)]
[string] $ADTarget,

[Parameter(ParameterSetName = "Scope-File", Position = 4, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Path", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Process", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-Service", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 3, Mandatory = $true)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 3, Mandatory = $true)]
[string] $OutputDir,

[Parameter(ParameterSetName = "Scope-File", Position = 5, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 4, Mandatory = $false)]
[switch] $ServersOnly,

[Parameter(ParameterSetName = "Scope-File", Position = 5, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 4, Mandatory = $false)]
[switch] $WorkstationsOnly,

[Parameter(ParameterSetName = "Scope-File", Position = 5, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Path", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-IPAddress", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Process", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-Service", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-LocalUsers", Position = 4, Mandatory = $false)]
[Parameter(ParameterSetName = "Scope-RegKey", Position = 4, Mandatory = $false)]
[switch] $BothTargetTypes


)


process {

# Functions  

# Files based on file name only (not full path)

function Scope-File {

  param ([string]$FileStartPath, [string]$FileName)

  # Determine if file is found on system
  $FileEvalPath = Get-ChildItem -Path $FileStartPath -Recurse -Name -Include $FileName

  # Append eval results to CSV
  if ($FileEvalPath){

    #Create a nicer formatted array for use in the CSV output
    foreach ($FilePath in $FileEvalPath){

        $FilePathArray += "$Path`n"

    }

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

  param ([string]$PathName)

  # Determine if path is found on system
  $PathEval = Test-Path $PathName

  # Append eval results to CSV
  if ($PathEval){

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"}
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"}
    return [PSCustomObject]$OutHash
  }
}

# IP ADDRESSES
function Scope-IPAddress {

  param ([string]$Address)

  # Determine if the IP address is found on system
  $IPAddressEval = netstat | select-string -pattern $Address

  # Determine if path is found on system
  if ($IPAddressEval){

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"; Details = $IPAddressEval}
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"; Details = $null}
    return [PSCustomObject]$OutHash
  }
}

# PROCESSES
function Scope-Process {

  param ([string]$ProcessName)

  # Determine if the IP address is found on system
  $ProcessEval = Get-CimInstance -ClassName win32_process -Filter "name LIKE '$ProcessName%'"

  # Determine if process is found on system
  if ($ProcessEval){

    $ProcessDetails = $ProcessEval | Select Name, ExecutablePath, Commandline, ProcessID, ParentProcessID

    #Create nicer formatted arrays for use in the CSV output
    foreach ($Object in $ProcessDetails){
        
        $NameArray += ("{0}`n" -f $Object.Name)
        $EPArray += ("{0}`n" -f $Object.ExecutablePath)
        $CMDLineArray += ("{0}`n" -f $Object.Commandline)
        $PIDArray += ("{0}`n" -f $Object.ProcessID)
        $PPIDArray += ("{0}`n" -f $Object.ParentProcessID)

    }

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"; Name = $NameArray; ExecutablePath = $EPArray; Commandline = $CMDLineArray; PID = $PIDArray; ParentPID = $PPIDArray }
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"; Name = $null; ExecutablePath = $null; Commandline = $null; PID = $null; ParentPID = $null}
    return [PSCustomObject]$OutHash
  }
}

# SERVICES
function Scope-Service {

  param ([string]$ServiceName)

  # Determine if the IP address is found on system
  $ServiceEval = Get-CimInstance -ClassName win32_service -Filter "name LIKE '$ServiceName%'"

  # Determine if service is found on system
  if ($ServiceEval){

    $ServiceDetails = $ServiceEval | Select ProcessID, Name, DisplayName, PathName, ServiceType, StartMode, Status

    #Create nicer formatted arrays for use in the CSV output
    foreach ($Object in $ServiceDetails){

        $NameArray += ("{0}`n" -f $Object.Name)
        $DNArray += ("{0}`n" -f $Object.DisplayName)
        $PIDArray += ("{0}`n" -f $Object.ProcessID)
        $PathArray += ("{0}`n" -f $Object.PathName)
        $STArray += ("{0}`n" -f $Object.ServiceType)
        $SMArray += ("{0}`n" -f $Object.StartMode)
        $StatusArray += ("{0}`n" -f $Object.Status)

    }

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"; Name = $NameArray; DisplayName = $DNArray; PID = $PIDArray; Path = $PathArray; ServiceType = $STArray; StartMode = $SMArray; Status = $StatusArray }
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"; Name = $null; DisplayName = $null; PID = $null; Path = $null; ServiceType = $null; StartMode = $null; Status = $null }
    return [PSCustomObject]$OutHash
  }
}

# USER ACCOUNTS
function Scope-LocalUsers {

  param ([string]$UserName)

  # Determine if the IP address is found on system
  $UserEval = Get-LocalUser -Name $Username

  # Determine if service is found on system
  if ($UserEval){

    $UserDetails = $UserEval | Select Name, Enabled

    #Create nicer formatted arrays for use in the CSV output
    foreach ($Object in $UserDetails){
    
        $NameArray += ("{0}`n" -f $Object.Name)
        $EnabledArray += ("{0}`n" -f $Object.Enabled)
        
    }

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"; Name = $NameArray; Enabled = $EnabledArray }
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"; Name = $null; Enabled = $null }
    return [PSCustomObject]$OutHash
  }
}

# REGISTRY KEYS - Specific Registry key at a specific path
function Scope-RegKey {

  param ([string]$FullKeyPath)

  # Determine if path is found on system
  $FullKeyEval = Test-Path $FullKeyPath

  # Append eval results to CSV
  if ($FullKeyEval){

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "True"}
    return [PSCustomObject]$OutHash
    
  } else {

    # return PSCustomObject for recording in CSV
    $OutHash =@{ Host = $env:COMPUTERNAME; Detected = "False"}
    return [PSCustomObject]$OutHash
  }
}

# Validate that only one host ingestion parameter was used

if (([bool]$TargetTXTFile + [bool]$TargetCSVFile + [bool]$Target + [bool]$ADTarget) -ne 1){

  Throw "Only one host ingestion parameter can be used. Quitting."

}

# Output Directory

# Verify if output directory exists, if not create it
  $OutputTest = Test-Path $OutputDir

  If (-not $OutputTest) {

    New-Item -Type Directory -Path $OutputDir -Force | Out-Null

  }

  #Initiate Log File

  $Log = ("{0}\{1:yyyy-MM-dd}.log" -f $OutputDir, $(Get-Date))

  # Build hosts list for use during invocation of IOC Scoping

  if ($TargetTXTFile) {

    try {

      $Hosts = Get-Content $TargetTXTFile

    } catch {

      throw "Error occurred while importing hosts with TargetTXTFile parameter. Quitting."

    }


  } 

  if ($TargetCSVFile) {

    try {

      $HostsImport = Import-Csv $TargetCSVFile
      $Hosts = $HostsImport.ComputerName

    } catch {

      throw "Error occurred while importing hosts with TargetCSVFile parameter. Quitting."

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

    if ($WorkstationsOnly){

      try {

        $Hosts = Get-ADComputer -Filter { OperatingSystem -eq 'Windows 7 Enterprise' -or OperatingSystem -eq 'Windows 10 Enterprise' } -SearchBase $ADTarget | Select-Object -ExpandProperty Name

      } catch {

        Throw "Could not expand ADTarget to obtain hosts. Quitting."

      }
    } elseif ($ServersOnly){

        $Confirm = Read-Host "You are about to run scoping against all servers in the specific AD Target. Are you sure you want to continue? [Y/N]"

        if ($confirm.ToLower() -ne 'y'){

          Exit
        }

       try {

        $Hosts = Get-ADComputer -Filter { OperatingSystem -like 'Windows Server*' } -SearchBase $ADTarget | Select-Object -ExpandProperty Name

      } catch {

        Throw "Could not expand ADTarget to obtain hosts. Quitting."

      }

    } elseif ($BothTargetTypes){

        $Confirm = Read-Host "You are about to run scoping against all servers in the specific AD Target. Are you sure you want to continue? [Y/N]"

        if ($confirm.ToLower() -ne 'y'){

          Exit
        }

       try {

        $Hosts = Get-ADComputer -SearchBase $ADTarget | Select-Object -ExpandProperty Name

      } catch {

        Throw "Could not expand ADTarget to obtain hosts. Quitting."

      }

    } else {

      Throw "No scope flags provided for AD Scoping. Quitting."

    }

  }

  #Let the scoping begin

  Write-Host "Scoping began at $(Get-Date)"

  #Scope IOCs

  if ($File){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-File} -ArgumentList $StartPath, $FileName | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-File.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the file parameter."

    }


  }

  if ($Path){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-Path} -ArgumentList $PathName | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-Path.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the path parameter."

    }


  }

  if ($IPAddress){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-IPAddress} -ArgumentList $Address | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-IPAddress.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the IPAddress parameter."

    }


  }

  if ($Process){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-Process} -ArgumentList $ProcessName | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-Process.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the process parameter."

    }


  }

  if ($Service){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-Service} -ArgumentList $ServiceName | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-Service.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the service parameter."

    }


  }

  if ($User){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-LocalUsers} -ArgumentList $UserName | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-LocalUsers.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the User parameter."

    }


  }

  if ($RegKey){

    try {

      Invoke-Command -ComputerName $Hosts -Scriptblock ${Function:Scope-RegKey} -ArgumentList $FullKeyPAth | Export-Csv ("{0}\{1:yyyy-MM-dd_HH-mm}_Scope-RegKey.csv" -f $OutputDir, $(Get-Date)) -Append

    } catch {

      Add-Content $Log -Value "There was a problem running ScopeIOCs.ps1 using the RegKey parameter."

    }


  }

#End Scoping

Write-Host "Scoping ended at $(Get-Date)"
  
}