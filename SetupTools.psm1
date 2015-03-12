function New-HostFileEntry
{
	<#
		.DESCRIPTION
			This function checks to see if an entry exists in the hosts file.
			If it does not, it attempts to add it and verifies the entry.

		.EXAMPLE
			Networkign.AddTo-Hosts -IPAddress 192.168.0.1 -HostName MyMachine

		.EXTERNALHELP
			None.

		.FORWARDHELPTARGETNAME
			None.

		.INPUTS
			System.String.

		.LINK
			None.

		.NOTES
			None.

		.OUTPUTS
			System.String.

		.PARAMETER IPAddress
			A string representing an IP address.

		.PARAMETER HostName
			A string representing a host name.

		.SYNOPSIS
			Add entries to the hosts file.
	#>

  param(
    [parameter(Mandatory=$true,position=0)]
	[string]
	$IPAddress,
	[parameter(Mandatory=$true,position=1)]
	[string]
	$HostName
  )

	$HostsLocation = "$env:windir\System32\drivers\etc\hosts";
	$NewHostEntry = "$IPAddress`t$HostName";

	if((gc $HostsLocation) -contains $NewHostEntry)
	{
	  Write-Output "The hosts file already contains the entry: $HostName.  File not updated.";
	}
	else
	{
		Write-Output "The hosts file does not contain the entry: $HostName.  Attempting to update.";
		Add-Content -Path $HostsLocation -Value $NewHostEntry;

		if((gc $HostsLocation) -contains $NewHostEntry)
		{
			Write-Output "New entry, $HostName, added to $HostsLocation.";
		}
		else
		{
			Write-Output "The new entry, $HostName, was not added to $HostsLocation.";
		}
	}
}

Export-Modulemember -Function New-HostFileEntry