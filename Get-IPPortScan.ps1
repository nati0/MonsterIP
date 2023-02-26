function Get-IPPortScan {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript({Test-Connection -ComputerName $_ -Quiet -Count 1})]
        [string[]]$IPAddress,

        [Parameter(Mandatory = $true)]
        [string]$PortList,

        [Parameter()]
        [int]$Threads = 10,

        [Parameter()]
        [string]$MACLookupAPI = "https://api.macvendors.com/"
    )

    # Convert the port list to an array of integers
    $Ports = @()
    foreach ($Port in ($PortList -split ",")) {
        if ($Port -match "^\d+$") {
            $Ports += [int]$Port
        } else {
            # Get the port number for the service name
            $PortNumber = (Get-ServiceNameToPortNumber -ServiceName $Port)
            if ($PortNumber) {
                $Ports += $PortNumber
            }
        }
    }

    # If no ports are provided, use the top 50 most common
    if ($Ports.Count -eq 0) {
        $Ports = (Get-Top50Ports).Number
    }

    # Use a progress bar to show the progress of the IP address scanning
    $Progress = [System.Collections.ArrayList]::new()
    foreach ($IP in $IPAddress) {
        $Progress.Add($null) | Out-Null
    }
    $ProgressIndex = 0

    # Use a multi-threaded approach to scan the IP addresses and ports
    $JobParams = @{
        ScriptBlock = {
            Param($IPAddress, $Ports, $MACLookupAPI)

            # Get the MAC address for the IP address
            $MACAddress = ""
            try {
                $MACAddress = (Invoke-WebRequest -Uri "$MACLookupAPI?ip=$IPAddress" -UseBasicParsing).Content.Trim()
            } catch {}

            # Scan the ports for the IP address
            $Result = @{
                IPAddress = $IPAddress
                MACAddress = $MACAddress
                Vendor = ""
                Ports = @()
            }
            foreach ($Port in $Ports) {
                $TCPClient = New-Object System.Net.Sockets.TcpClient
                $AsyncConnect = $TCPClient.BeginConnect($IPAddress, $Port, $null, $null)
                if (!$AsyncConnect.AsyncWaitHandle.WaitOne(500)) {
                    # Timeout occurred
                    $TCPClient.Close()
                } else {
                    # Connection established
                    $Result.Ports += @{
                        Port = $Port
                        ServiceName = (Get-PortNumberToServiceName -PortNumber $Port)
                        WebInterface = (Get-WebInterfaceStatus -TCPClient $TCPClient)
                    }
                    $TCPClient.Close()
                }
            }

            # Get the vendor information for the MAC address
            if ($MACAddress) {
                try {
                    $VendorInfo = (Invoke-WebRequest -Uri "https://api.macvendors.com/$MACAddress" -UseBasicParsing).Content.Trim()
                    $Result.Vendor = $VendorInfo
                } catch {}
            }

            return $Result
        }
        ArgumentList = @($null, $Ports, $MACLookupAPI)
    }
    $Jobs = @()
    foreach ($IP in $IPAddress) {
        $JobParams.ArgumentList[0] = $IP
        $Jobs += Start-Job @JobParams
    }

    
}
    # Wait for all the jobs to finish and retrieve the results
 #   $