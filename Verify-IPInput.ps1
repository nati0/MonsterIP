function Get-SubnetIPs {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Network
    )
    
    begin {
        # Define a regular expression to validate the input format
        $regex = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    }
    
    process {
        if ($Network -match $regex) {
            # Split the network into an IP address and subnet mask length
            $ip, $mask = $Network -split '/'
            
            # Calculate the number of host bits in the subnet mask
            $bits = 32 - $mask
            
            # Calculate the number of possible IP addresses in the subnet
            $count = [math]::Pow(2, $bits) - 2
            
            # Convert the IP address to a byte array
            $bytes = $ip.split('.').ForEach({[byte]$_})
            
            # Calculate the network portion of the IP address
            $ips = @()
            for ($i = 1; $i -le $count; $i++) {
                $bytes[-1]++
                for ($j = $bytes.Length - 1; $j -gt 0; $j--) {
                    if ($bytes[$j] -eq 256) {
                        $bytes[$j - 1]++
                        $bytes[$j] = 0
                    }
                    else {
                        break
                    }
                }
                $ips += [System.Net.IPAddress]$bytes -join '.'
            }
            $ips
        }
        else {
            throw "Invalid network format: $Network"
        }
    }
}