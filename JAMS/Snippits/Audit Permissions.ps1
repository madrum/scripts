Clear-Host
<#
Objective: produce report with individuals who have various types of access, on servers with matching naming convention in CSI and EBZE domain
* members with access to file shares and their access level
* members of local admins, remote desktop users, and power users groups, and their access level
* alert on instances where 'EVERYONE' user has access to anything

* AD Security Group audits (have owner for each AD group that is notifed monthly of the people in the group)
* AD Messaging Group audits (have owner for each AD group that is notifed monthly of the people in the group)

* SQL permissions
#>


$checkCsiDomain=$true
$checkEbzeDomain=$false
$checkLocalGroupAndShareAccess=$true
$checkADSecurityGroups=$true
$checkSqlPermissions=$true
$dateTimeFormat = "yyyy-MM-dd HH:mm:ss.fff zzz"
$fileNameDate = "_$(Get-Date -Format yyyy-MM-dd-HHmmss).txt"
$reportFolder = "C:\Temp\Server-SQL_SecurityAudit\"

#region Variables
$csiSQLServers = @{
    billing = "padatt04"
    listProdDefault = "padatt03"
    listProdOxinator = "padatt03\oxinator"
    listProdDaderbase = "padatt03\daderbase"
    tfs = "padatt05"
    #listToolDevDefault = "azuseg02, 10001"
    #listToolDevOxinator = "azuseg02\oxinator"
    #listToolDevDaderbase = "azuseg02\daderbase"
    #dev = "azuseg07"
    #listToolQADefault = "azuseg09, 10001"
    #listToolQAOxinator = "azuseg09\oxinator"
    #listToolQADaderbase = "azuseg09\daderbase"
    #integ = "azuseg14"
}

$ebzeSQLServers = @{
    prod = "rcgsqlprod, 10000"
    prodList = "prod list instance"
    prodLegacy = "prod legacy instance"
    knight = "padatte79"
    airWolf = "padatte80"
    rider = "valatte79"
    blueThunder = "valatte80"
    #azureWebSvc = "azusql02"
    staging = "padate78" #Staging
    stagingStage = "padate78\stage"
    stagingTest = "padate78\test"
    test = "valatte48"
    demo = "valatte48\demo"
}

#ref: https://dataedo.com/kb/query/sql-server/list-logins-on-server
$querySQLServer = @"
select
 sp.name
,sp.type_desc
,sp.is_disabled
,sl.sysadmin
,MAX(es.login_time) [recent_login]
,sp.create_date
,sp.modify_date
from
sys.server_principals sp
join sys.SYSLOGINS sl on sp.name = sl.loginname
left join sys.dm_exec_sessions es on sp.name = es.login_name
where sp.type not in ('G', 'R')
and sp.name not like '%#%'
and sp.name not like '%nt service%'
and sp.name not like '%nt authority%'
group by
sp.name
,sp.type_desc
,sp.is_disabled
,sl.sysadmin
,sp.create_date
,sp.modify_date
order by
sp.name
"@

$queryDatabases = "SELECT name FROM sys.databases order by name" #, database_id, create_date 

#ref: https://www.mssqltips.com/sqlservertip/5999/sql-server-database-users-to-roles-mapping-report/
$queryEachDatabase = @"
SELECT 
 ul.[name] [login_name]
,rolp.[name] [role]
FROM
sys.database_role_members mmbr, -- The Role OR members associations table
sys.database_principals rolp,     -- The DB Roles names table
sys.database_principals mmbrp,    -- The Role members table (database users)
sys.server_principals ul          -- The Login accounts table
WHERE Upper (mmbrp.[type]) IN ( 'S', 'U', 'G' ) -- No need for these system account types
AND Upper (mmbrp.[name]) NOT IN ('SYS','INFORMATION_SCHEMA')
AND rolp.[principal_id] = mmbr.[role_principal_id]
AND mmbrp.[principal_id] = mmbr.[member_principal_id]
AND ul.[sid] = mmbrp.[sid]
"@

$csiADSecurityGroups = @(
"CSI\ATTUS_Server_Admins",
"CSI\ATTUS_Server_Users",
"CSI\ComplianceEngineering",
"CSI\DevOps",
"CSI\Engineering",
"CSI\ListQAEngineers",
"CSI\RCG List Data Services",
"CSI\RCGListDataServicesDMF",
"CSI\QA",
"CSI\Local Server Admins - RCG Azure SEG",
"CSI\Remote Desktop - RCG Azure SEG")

$ebzeADSecurityGroups = @(
"EBZE\Attus_server_admins",
"EBZE\RCG_Integrations_Team")

#endregion #Variables

<#
.Description
Get-ADGroupMembersRecursive returns an array with recursive members of an AD group
#>
function Get-ADGroupMembersRecursive ([string]$ADGroupName) {
    [CmdletBinding()]
    
    $membersArray = @()
    Get-ADGroupMember -identity $ADGroupName.ToUpper().Replace("CSI\","").Replace("EBZE\","").Replace("AZURE\","") -Recursive | Sort-Object | ForEach-Object {
        if ($_.objectClass -eq 'user')
        {
            $membersArray += $_.SamAccountName.ToLower()
        }
    }

    return $membersArray
}

<#
.Description
Get-LocalGroupMembers returns an object array with local group access
#>
function Get-LocalGroupMembers ([string]$server) {
    [CmdletBinding()]

    $groupsArray = @() #store 1 or more groups
    $groupList = @("Remote Desktop Users", "Power Users","Administrators")
    $groupList | ForEach-Object {
        $groupName = $_
        $groupObj = [PSCustomObject]@{
            groupName = "$groupName"
        }
        
        $membersArray = @() #store 1 or more members
        $command = { Param ($argGroupName) net localgroup "$argGroupName" | Where-Object { $_ -AND $_ -notmatch "command completed successfully" } | Select-Object -skip 4 | Sort-Object } #skip 4 to ignore header info
        Invoke-Command -ComputerName $Server -ScriptBlock $command -ArgumentList $groupName -Verbose | ForEach-Object {
            $member = $_
            $memberObj = [PSCustomObject]@{
                memberName = "$($member)"
            }
            $membersArray += $memberObj
        }
        $groupObj | Add-Member -NotePropertyName "members" -NotePropertyValue $($membersArray | Sort-Object)
        $groupsArray += $groupObj
    }

    return $groupsArray
}

<#
.Description
Get-SharesAccess returns an object array with folder share access
#>
function Get-SharesAccess ([string]$server) {
    [CmdletBinding()]

    $cim = New-CimSession -ComputerName $server 
    $shares = Get-SmbShare -CimSession $cim | Where-Object { $_.Name -notlike '*$'}
    
    $sharesArray = @() #store 1 or more shares
    $shares | ForEach-Object {
        $share = $_
        $shareObj = [PSCustomObject]@{
            shareName = "$($share.Name)"
            sharePath = "$($share.Path)"
        }
        
        $accessArray = @() #store 1 or more access items
        $access = Get-SmbShareAccess -CimSession $cim -Name $share.Name
        $access | ForEach-Object {
            $accessInfo = $_
            $accessObj = [PSCustomObject]@{
                accountName = "$($accessInfo.AccountName)"
                accessRight = "$($accessInfo.AccessRight)"
            }
            $accessArray += $accessObj
        }
        $shareObj | Add-Member -NotePropertyName shareAccess -NotePropertyValue $($accessArray | Sort-Object accountName)
        $sharesArray += $shareObj
    }

    return $sharesArray
}

<#
.Description
Get-LocalGroupAndShareAccess returns an object with local group and folder share access
#>
function Get-LocalGroupAndShareAccess ([string]$server) {
    [CmdletBinding()]

    $groupAndShareObj = [PSCustomObject]@{
        description = "Local Group and File Share Access"
        server = "$server"
        dateTime = "$(Get-Date -Format $dateTimeFormat)"
    }
    $localGroups = Get-LocalGroupMembers $server
    $groupAndShareObj | Add-Member -NotePropertyName "localGroups" -NotePropertyValue $($localGroups | Sort-Object groupName)
    
    $sharedFolders = Get-SharesAccess $server
    $groupAndShareObj | Add-Member -NotePropertyName "sharedFolders" -NotePropertyValue $($sharedFolders | Sort-Object Name) 

    return $groupAndShareObj
}

<#
.Description
Get-ADSecurityGroupMembers returns an object with a full list of individual members of an AD Group and sub-groups
#>
function Get-ADSecurityGroupMembers ([string]$GroupName) { 
    [CmdletBinding()]
    
    $groupObj = [PSCustomObject]@{
        description = "AD Group Members"
        groupName = "$GroupName"
        dateTime = "$(Get-Date -Format $dateTimeFormat)"
    }
    $membersArray = Get-ADGroupMembersRecursive $group
    $groupObj | Add-Member -NotePropertyName "members" -NotePropertyValue $($membersArray | Sort-Object)

    return $groupObj
}

<#
.Description
Get-SqlAccess returns an object with SQL Server Instance permissions, as well as permissions per database
#>
function Get-SqlAccess ([string]$Environment, [string]$ServerInstance) {
    [CmdletBinding()]


    $sqlObj = [PSCustomObject]@{
        description = "SQL Server Access"
        environment = "$Environment"
        sqlServerInstance = "$ServerInstance"
        dateTime = "$(Get-Date -Format $dateTimeFormat)"
    }
    
    $sqlServerUserArray = @()
    $sqlServerUsers = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database master -Query $querySQLServer
    $sqlServerUsers | ForEach-Object {
        $user = $_
        $sqlUserObj = [PSCustomObject]@{
            name = "$($user.name)"
            loginType = "$($user.type_desc)"                
            enabled = "$(if ($user.is_disabled -eq 0) { $true } else { $false })"
            sysAdmin = "$(if ($user.sysadmin -eq 0) { $false } else { $true })"
            recentLogin = "$($user.recent_login)"
            dateCreated = "$($user.create_date)"
            dateModified = "$($user.modify_date)"
        }
        $sqlServerUserArray += $sqlUserObj
    }
    $sqlObj | Add-Member -NotePropertyName sqlServerUsers -NotePropertyValue $($sqlServerUserArray | Sort-Object name)


    $databaseArray = @()
    $databases = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database master -Query $queryDatabases
    $databases | ForEach-Object {
        $db = $_
        $dbObj = [PSCustomObject]@{
            name = $db.name
        }
        
        $dbUserArray = @()
        $dbs = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $db.name -Query $queryEachDatabase
        $dbs | ForEach-Object {
            $dbUser = $_
            $sqlDbUserObj = [PSCustomObject]@{
                name = $dbUser.login_name
                role = $dbUser.Role
            }
            $dbUserArray += $sqlDbUserObj
        }
        $dbObj | Add-Member -NotePropertyName users -NotePropertyValue $($dbUserArray | Sort-Object name)
        $databaseArray += $dbObj
    }
    $sqlObj | Add-Member -NotePropertyName databases -NotePropertyValue $($databaseArray | Sort-Object name)
    
    return $sqlObj
}


if ($checkCsiDomain) {
    $servers = Get-ADComputer -Filter "Name -like 'Padatt*'"
    $servers | ForEach-Object {
        $server = $_.DNSHostName.ToLower()
        
        if ($checkLocalGroupAndShareAccess) {
            "$(Get-Date) - $($server) Local Group and Folder Shares Access"
            Get-LocalGroupAndShareAccess $server | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$server.ToLower()+"-LocalGroupAndShareAccess"+$fileNameDate)"
        } else { "Skip CSI Local Group and Folder Shares Access" }

    }
    
    if ($checkADSecurityGroups) {
        $csiADSecurityGroups | ForEach-Object {
            $group = $_
            "$(Get-Date) - $($group) AD Security Group"
            Get-ADSecurityGroupMembers $group | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$group.Replace("\","-").ToLower()+"-AdSecurityGroup"+$fileNameDate)"
        }        
    } else { "Skip CSI AD Security Groups" }

    if ($checkSqlPermissions) {
        $csiSQLServers.GetEnumerator() | Sort-Object Name | ForEach-Object {
            $server = $_.Value
            $environment = $_.Name
            "$(Get-Date) - $($environment+" > "+$server) AD Security Group"
            Get-SqlAccess -Environment $environment -ServerInstance $server | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$environment+"-SqlAccess"+$fileNameDate)"
        }
    } else { "Skip CSI SQL Access" }
} else { "Skip CSI Domain Access Checks" }


if ($checkEbzeDomain){
    #look for padatte and valatte servers using "*atte*" filter
    $servers = Get-ADComputer -Filter "Name -like '*atte*'"
    $servers | ForEach-Object {
        $server = $_.DNSHostName.ToLower()
       
        if ($checkLocalGroupAndShareAccess) {
            "$(Get-Date) - $($server) Local Group and Folder Shares Access"
            Get-LocalGroupAndShareAccess $server | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$server.ToLower()+"-LocalGroupAndShareAccess"+$fileNameDate)"
        } else { "Skip EBZE Local Group and Folder Shares Access" }
    }

    if ($checkADSecurityGroups) {
        $ebzeADSecurityGroups | ForEach-Object {
            $group = $_
            "$(Get-Date) - $($group) AD Security Group"
            Get-ADSecurityGroupMembers $group | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$group.Replace("\","-").ToLower()+"-AdSecurityGroup"+$fileNameDate)"
        }
    } else { "Skip EBZE AD Security Groups" }

    if ($checkSqlPermissions) {
        $ebzeSQLServers.GetEnumerator() | Sort-Object Name | ForEach-Object {
            $server = $_.Value
            $environment = $_.Name
            "$(Get-Date) - $($environment+" > "+$server) AD Security Group"
            Get-SqlAccess -Environment $environment -ServerInstance $server | ConvertTo-Json -Depth 20 | Out-File "$($reportFolder+$environment+"-SqlAccess"+$fileNameDate)"
        }
    } else { "Skip EBZE SQL Access" }
} else { "Skip EBZE Domain Access Checks" }








