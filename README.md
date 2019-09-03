# Scope-IOCs

This script allows for incident responders to scope specific indicators of compromise
  based on user input. The indicators of comrpomise that can be scoped are:

  `File`:                     Determine if a file name with an unknown path exists
  
  `Path`:                     Determine if a full directory or file path exists
  
  `IP Address`:               Determine if a network connection is currently established with a specific IP address
  
  `Process`:                  Determine if a specific process is running
 
  `Service`:                  Determine if a specific service exists
  
  `Local User Account`:       Determine if a specific local user account exists
  
  `Registry Key`:             Deteremine if a specific regisry key (designated by full path) exists
  
## PARAMETERS

### Scoping Files

  `-File`
  
    Used to specify the file name that will be searched for when running the script using the Scope-File parameter set

  `FileStartPath`
  
    Used to specify the starting directory that the script will use to begin searching for a file when using the Scope-File parameter
    set     

### Scoping Directory and File Paths

 `-Path`
 
    Specifies the full path that will be tested when running the script using the Scope-Path parameter set
      

### Scoping IP Addresses

  `-IPAddress`
  
    Used to specify the IP address that will be searched for when running the script using the Scope-IPAddress parameter set


### Scoping Processes

  `-Process`
  
    Used to specify the process name that will be searched for when running the script using the Scope-Process parameter set      

### Scoping Services

  `-Service`
  
    Used to specify the service name that will be searched for when running the script using the Scope-Service parameter set
      
### Scoping Local User Accounts
  `-User`
  
    Used to specify the local user name that will be searched for when running the script using the Scope-LocalUsers parameter set      

### Scoping Registry Keys

  `-RegKey`
  
    Used to specify the full path to the registry key that will be searched for when running the script using the Scope-RegKey parameter
    set

### Host Import Parameters

  `-TargetFile`
  
    Specifies the text or csv file containing hostnames that will be imported and used as the base to scope against
    Note: for csv's, the column header must be ComputerName
  
  `-Target`
  
    Specified by the user and will be used as the host base to scope against

  `-ADTarget`
  
    Specifies the base DN that will be used to collect hosts from in AD

    `-ServersOnly`
    
      Used when scoping against servers only
    
    `-WorkstationsOnly`
    
      Used when scoping against workstations only

    `-BothTargetTypes`
    
      Used when scoping against both servers and workstations

### Output Parameters

  `-OutputDir`
  
    Specifies the location of the output directory that will be created for output

### PowerShell Remoting Specific Parameters

  `-ThrottleLimit`
  
    Used to specify the value for ThrottleLimit to use with Invoke-Command. Default is set to use the PS Remoting default of 32

## Examples

### Scope a file with an unknown path against a user specified host

`Scope-IOCs.ps1 -File testfile.txt -FileStartPath C:\ -Target test-PC -OutputDir C:\Tools\Scoping`

### Scope a specific path against a host base specified by a CSV file

`Scope-IOCs.ps1 -Path C:\Tools\testfile.txt -TargetFile C:\test\hosts.csv -OutputDir C:\Tools\Scoping`

### Scope an IP address against a host base specified by a TXT file

`Scope-IOCs.ps1 -IPAddress '172.217.4.46' -TargetFile C:\test\hosts.txt -OutputDir C:\Tools\Scoping`

### Scope a specific process against a host base consisting of only workstations and specified by ADTarget

`Scope-IOCs.ps1 -Process 'evil.exe' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -WorkstationsOnly -OutputDir C:\Tools\Scoping`

### Scope a specific service against a host base consisting of only servers and specified by ADTarget

`Scope-IOCs.ps1 -Service 'evilservice' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -ServersOnly -OutputDir C:\Tools\Scoping`

### Scope a specific local user account against a host base consisting of both servers and workstations and specified by ADTarget

`Scope-IOCs.ps1 -User 'eviluseraccount' -ADTarget OU=Location,OU=State,DC=Company,DC=Com -BothTargetTypes -OutputDir C:\Tools\Scoping`

### Scope a specific registry key against a host base consisting of user specified hosts

`Scope-IOCs.ps1 -RegKey HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilKey -Target "PC1,PC2,PC3,PC4,PC5" -OutputDir C:\Tools\Scoping`
