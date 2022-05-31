<#
.SYNOPSIS
    Retrieves Servers from Active Directory that have not been seen for a period of time.
.DESCRIPTION
    Use this to locate servers in Active Directory that appear to be missing. Missing servers are determined using the last logon date stored in AD. A default date
    of one year ago is used in the abscense of a specified date.
.NOTES
    This function is not supported in Linux.
    This function only uses an negative integer number to specify the "LastSeen" days; ie:"-25","-90","-365" etc.
#.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    Get-ADMissingServers.ps1
    Retrieves all AD servers that are enabled but have not been seen by AD since the default past date (one year ago today)
.EXAMPLE
    Get-ADMissingServers.ps1 -LastSeen -180
    Retrieves all AD servers that are enabled but have not been seen by AD for at least 180 days.
#>
function Verb-Noun {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            Mandatory = $false
            )]
            [int]
            $LastSeen = -180
    )
    
    begin {
        
    }
    
    process {
        $ServerResults = @()
        $MissingServers = @()

        Write-Verbose "Retrieving all Servers from Active Directory."
        $Servers = Get-ADComputer -Filter 'OperatingSystem -Like "*Server*"' -Properties DNSHostName,Enabled,LastLogonTimeStamp,operatingsystem,DistinguishedName
        Write-Verbose "Processing each AD Server object."
        $Servers | ForEach-Object -Process {
            $ServerData = [PSCustomObject]@{
                DNSHostName = 'UNKNOWN' 
                Enabled = 'UNKNOWN' 
                LastLogonDate = 'UNKNOWN'  
                OperatingSystem = 'UNKNOWN' 
                OU = 'UNKNOWN'  
            }

            $ServerData.DNSHostName = $_.DNSHostName
            $ServerData.Enabled = $_.enabled
            $ServerData.LastLogonDate = $([datetime]::FromFileTime($_.LastLogonTimeStamp))
            $ServerData.OperatingSystem = $_.OperatingSystem
            $ServerData.OU = $_.DistinguishedName
            $ServerResults += $ServerData
            Write-Verbose "Processed $_.DNSHostName."
        }
        Write-Verbose "Comparing each AD Server object's last login time stamp with today $LastSeen."
        $ServerResults | ForEach-Object -Process {
            if ($_.LastLogonDate -le (Get-Date).AddDays($LastSeen)){
                #Do something
                if ($_.OU.EndsWith("OU=Disabled_Servers,OU=ComputerAccounts,DC=canfor,DC=ca")) {
                    #do nothing
                    Write-Verbose "$_.DNSHostName does not fall within the criteria."
                }
                else {
                    $MissingServers += $_
                    Write-Verbose "$_.DNSHostName hasn't been seen since $_.LastLogonDate."
                }
            }
        }
        Write-Verbose "Outputing the final results."
        Return Write-Output $MissingServers
    }
    end {
        
    }
}