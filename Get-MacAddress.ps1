# Get Mac Address based on IP Address.
# Catch cases where the IP is on an onboard NIC.

function Get-MacAddress {
    [CmdletBinding()]
    Param (
[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[string]$IPAddress)
    
s
try{
    $result = Get-NetNeighbor -IPAddress $IPAddress
    return $result.LinkLayerAddress
}

catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]{
    Get-NetIPAddress | % {
        if ($_.IPAddress -eq $IPAddress){
            
            
            #IP Addresses on local Nic
             % {Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex | select IPv4Address}
            
            #Mac Addresses on local NIC
            $LocalMacAddresses = Get-NetAdapter | Select MacAddress, IfIndex
            $LocalIPAddresses = $LocalMacAddresses | % { Get-NetIPAddress -InterfaceIndex $_.IfIndex | select IPv4Address | Sort-Object -Unique}
            
            

            return $
        }
    }
    
}
    
}


