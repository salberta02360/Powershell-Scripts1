<#
    .SYNOPSIS 
    Creates a new Windows Virtual Machine
    .EXAMPLE 
    Add-ComputertoAd.ps1 -hostname testhost -Path "OU=2012,OU=Production,OU=Windows,OU=THPSERVERS,DC=thp,DC=tahphq,DC=tahp"
    .PARAMETER Hostname
    Short name of host you wish to add to Active Directory
    .PARAMETER Path
    Specifies the X.500 path of the Organizational Unit (OU) or container where the new object is created.
#>

Param (	[Parameter(Mandatory=$TRUE)][String]$hostname,
        [Parameter(Mandatory=$TRUE)][String]$path
       
)

Import-Module ActiveDirectory
New-ADComputer -Name $hostname -SamAccountName $hostname -Path $path
