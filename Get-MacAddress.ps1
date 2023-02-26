# Get Mac Address based on IP Address.
# Catch cases where the IP is on an onboard NIC.

function Get-MacAddress {
    [CmdletBinding()]
    Param (
[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[string]$IPAddress)
    

try{
    Get-NetNeighbor -IPAddress "$IPAddress" -ErrorAction Stop
    return $result.LinkLayerAddress
}

catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]{
    Get-NetIPAddress | % {
        if ($_.IPAddress -eq $IPAddress){
           #Get InterfaceIndex of the NIC owning the mac address
           $IfIndex = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex | Select-Object InterfaceIndex | sort -Unique
            #Mac Addresses on local NIC
            $LocalMacAddress = Get-NetAdapter | ? { $_.ifIndex -eq $IfIndex.InterfaceIndex}
           return $LocalMacAddress.MacAddress
        }
    }
    
}
    
}


