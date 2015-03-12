
$HostName = "msmdm.localhost"
$WebProjectPath = "MSMDM"

$SolutionPath = (Get-Location).Path

Import-Module -Name .\SetupTools -Force
Import-Module -Name WebAdministration

Write-Output "Solution Directory: $SolutionPath" 

## Add Hosts File Entry
New-HostFileEntry -IPAddress "127.0.0.1" -HostName $HostName

## Configure IIS
if (!(Test-Path "IIS:\AppPools\$HostName")) 
{
    Write-Output "Application Pool ($HostName) does not exist, creating"
    New-WebAppPool -Name "$HostName"
}

if (!(Test-Path "IIS:\Sites\$HostName")) 
{
    Write-Output "Website ($HostName) does not exist, creating"
    New-Website -Name "$HostName" -ApplicationPool "$HostName" -HostHeader "$HostName" -PhysicalPath "$SolutionPath\$WebProjectPath"
}
