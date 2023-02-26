





[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$IPAddressRange,
    [Parameter(Mandatory=$false)]
    [string[]]$PortList = @("21","22","23","25","53","80","110","111","135","139","143","161","389","443","445","993","995","3389"),
    [Parameter(Mandatory=$false)]
    [string[]]$ServiceList = @("ftp","ssh","telnet","smtp","dns","http","pop3","rpc","netbios-ssn","imap","snmp","ldap","https","microsoft-ds","imaps","pop3s"),
    [Parameter(Mandatory=$false)]
    [int]$Threads = 10
)

# Validate IP Address range parameter
$ValidIPAddressRange = $false
try {
    $IPNetwork = [System.Net.IPAddress]::Parse($IPAddressRange)
    $ValidIPAddressRange = $true
}
catch {
    $IPNetwork = [System.Net.IPAddress]::None
    Write-Error "Invalid IP address range: $IPAddressRange"
}

# Validate port list parameter
$ValidPortList = $false
foreach ($Port in $PortList) {
    if ([int]::TryParse($Port, [ref]$null) -eq $false) {
        Write-Error "Invalid port number: $Port"
        $ValidPortList = $false
        break
    }
    else {
        $ValidPortList = $true
    }
}

# Validate service list parameter
$ValidServiceList = $false
foreach ($Service in $ServiceList) {
    $ServicePort = @{
        "ftp" = "21"
        "ssh" = "22"
        "telnet" = "23"
        "smtp" = "25"
        "dns" = "53"
        "http" = "80"
        "pop3" = "110"
        "rpc" = "111"
        "netbios-ssn" = "139"
        "imap" = "143"
        "snmp" = "161"
        "ldap" = "389"
        "https" = "443"
        "microsoft-ds" = "445"
        "imaps" = "993"
        "pop3s" = "995"
    }
    if ($ServicePort.ContainsKey($Service)) {
        $ValidServiceList = $true
    }
    else {
        Write-Error "Invalid service name: $Service"
        $ValidServiceList = $false
        break
    }
}

# If all parameters are valid, start scanning
if ($ValidIPAddressRange -and ($ValidPortList -or $ValidServiceList)) {
    $IPAddressRangeSplit = $IPAddressRange.Split("/")
    $IPRange = [System.Net.IPAddress]::Parse($IPAddressRangeSplit[0])
    $SubnetMask = [System.Net.IPAddress]::Parse($IPAddressRangeSplit[1])
    $IPNetwork = New-Object System.Net.IPAddress[] @([System.Net.IPAddress]::None)
    $IPNetwork[0] = $IPRange
    $IPNetwork[1] = $SubnetMask
    $IPAddresses = [System.Net.IPAddress]::GetNetworkAddress($IPRange, $SubnetMask),[System.Net.IPAddress]::GetBroadcastAddress($IPRange, $SubnetMask)

    $ScanResults = @()
    $Progress = 0
    $TotalProgress = $()

}

################ Problem her





function Get-PortScannerResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [IPAddress[]]$IPRange,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('FTP','SSH','SMTP','HTTP','HTTPS','DNS','POP3','IMAP','SNMP','LDAP','KERBEROS','SMTPS','HTTPS-ALT','MSSQL','MYSQL','ORACLE','RDP','VNC','TELNET','SSH-ALT','PING')]
        [string[]]$PortNames = @('HTTP','HTTPS','RDP','SSH','FTP','SMTP','DNS','POP3','IMAP','SNMP','LDAP','TELNET'),
        
        [Parameter(Mandatory = $false)]
        [int[]]$PortNumbers = @(80,443,3389,22,21,25,53,110,143,161,389,23),
        
        [Parameter(Mandatory = $false)]
        [int[]]$TopPorts = @(80,443,3389,22,21,25,53,110,143,161,389,23,445,139,53,135,137,138,1433,3306,1521,1434,1723,3389,5900,8080,10000,20000,49152..65535),
        
        [Parameter(Mandatory = $false)]
        [int]$ThreadCount = 10
    )

    # Array to store the results
    $Results = @()

    # If no ports are provided, use the default top ports
    if (!$PortNames -and !$PortNumbers) {
        $PortNumbers = $TopPorts
    }

    # Convert port names to numbers
    if ($PortNames) {
        $PortNumbers += $PortNames | ForEach-Object {
            [int]($PortMappings[$_])
        }
    }

    # Remove duplicates and sort
    $PortNumbers = $PortNumbers | Sort-Object | Get-Unique

    # Get IP range from CIDR notation
    $IPRange = Get-IPRange -CIDR $IPRange

    # Calculate total number of IPs to scan
    $TotalIPs = $IPRange.Count * $PortNumbers.Count

    # Initialize progress bar
    $Progress = 0
    $ProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar
    $ProgressBar.Minimum = 0
    $ProgressBar.Maximum = $TotalIPs
    $ProgressBar.Step = 1
    $ProgressBar.Show()

    # Initialize thread pool
    $JobPool = [System.Collections.ArrayList]::new()
    $JobResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
    $Semaphore = New-Object -TypeName System.Threading.SemaphoreSlim -ArgumentList 1, $ThreadCount

    # Scan each IP and port in parallel
    $PortNumbers | ForEach-Object {
        $Port = $_
        $IPRange | ForEach-Object {
            $IP = $_
            $Job = Start-Job -ScriptBlock {
                # Wait for semaphore
                $Semaphore.Wait()

                try {
                    # Scan IP and port
                    $ScanResult = Scan-IPPort -IPAddress $IP -Port $Port

                    # Perform MAC lookup
                    $MacAddress = Get-MacAddress -IPAddress $IP

                    # Create custom object with results
                    [PSCustomObject]@{
                        IPAddress = $ScanResult.IPAddress
                        Port = $ScanResult.Port


################ Muulig fejl her


# Define the cmdlet
function Invoke-IPScanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [IPAddress[]]$IPAddressRange,

        [Parameter(Mandatory = $false)]
        [string[]]$Ports = (1..50 | ForEach-Object { $_.ToString() }),

        [Parameter(Mandatory = $false)]
        [string[]]$Services,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1024)]
        [int]$MaxParallelThreads = 100
    )

    # Validate and sanitize user input
    $Ports = $Ports | ForEach-Object {
        if ($_ -as [int] -gt 0) {
            $_
        }
        else {
            try {
                [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetAllTcpConnections().Where({$_.ToString().Contains($_)}) | Select-Object -ExpandProperty RemoteEndPoint | Select-Object -ExpandProperty Port
            }
            catch {
                Write-Error "Could not convert $_ to a valid port number."
            }
        }
    }

    # Define progress bars
    $TotalIPs = $IPAddressRange.Count
    $TotalPorts = $Ports.Count
    $IPProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar
    $PortProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar

    # Set progress bar properties
    $IPProgressBar.Minimum = 0
    $IPProgressBar.Maximum = $TotalIPs
    $IPProgressBar.Step = 1
    $IPProgressBar.Style = "Continuous"

    $PortProgressBar.Minimum = 0
    $PortProgressBar.Maximum = $TotalPorts
    $PortProgressBar.Step = 1
    $PortProgressBar.Style = "Continuous"

    # Create runspace pool and add scripts to the pipeline
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelThreads)
    $RunspacePool.Open()

    # Create session state and populate it with variables
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList "Ports", $Ports, "List of ports to scan"))

    # Create pipeline and add the script
    $Pipeline = [System.Management.Automation.PowerShell]::Create($SessionState)
    $Pipeline.RunspacePool = $RunspacePool

    $ScriptBlock = {
        # Define scriptblock to run in each thread
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [ValidateNotNullOrEmpty()]
            [IPAddress]$IPAddress,

            [Parameter(Mandatory = $true)]
            [string[]]$Ports
        )

        # Create an object to hold scan results
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress.IPAddressToString
        $Result | Add-Member -MemberType NoteProperty -Name MACAddress -Value ""

        # Define an array to hold the port scan results
        $ScanResults = @()

        # Loop through the list of ports and perform a port scan
        foreach ($Port in $Ports) {
            # Update the port progress bar
            $PortProgressBar.Value = $PortProgressBar.Value + 1
            Write-Progress -Activity "Scanning port $Port on $($IPAddress.IPAddressToString)"

### Mulig fejl her

# Define the cmdlet
function Invoke-IPScanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [IPAddress[]]$IPAddressRange,

        [Parameter(Mandatory = $false)]
        [string[]]$Ports = (1..50 | ForEach-Object { $_.ToString() }),

        [Parameter(Mandatory = $false)]
        [string[]]$Services,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1024)]
        [int]$MaxParallelThreads = 100
    )

    # Validate and sanitize user input
    $Ports = $Ports | ForEach-Object {
        if ($_ -as [int] -gt 0) {
            $_
        }
        else {
            try {
                [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetAllTcpConnections().Where({$_.ToString().Contains($_)}) | Select-Object -ExpandProperty RemoteEndPoint | Select-Object -ExpandProperty Port
            }
            catch {
                Write-Error "Could not convert $_ to a valid port number."
            }
        }
    }

    # Define progress bars
    $TotalIPs = $IPAddressRange.Count
    $TotalPorts = $Ports.Count
    $IPProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar
    $PortProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar

    # Set progress bar properties
    $IPProgressBar.Minimum = 0
    $IPProgressBar.Maximum = $TotalIPs
    $IPProgressBar.Step = 1
    $IPProgressBar.Style = "Continuous"

    $PortProgressBar.Minimum = 0
    $PortProgressBar.Maximum = $TotalPorts
    $PortProgressBar.Step = 1
    $PortProgressBar.Style = "Continuous"

    # Create runspace pool and add scripts to the pipeline
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelThreads)
    $RunspacePool.Open()

    # Create session state and populate it with variables
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList "Ports", $Ports, "List of ports to scan"))

    # Create pipeline and add the script
    $Pipeline = [System.Management.Automation.PowerShell]::Create($SessionState)
    $Pipeline.RunspacePool = $RunspacePool

    $ScriptBlock = {
        # Define scriptblock to run in each thread
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [ValidateNotNullOrEmpty()]
            [IPAddress]$IPAddress,

            [Parameter(Mandatory = $true)]
            [string[]]$Ports
        )

        # Create an object to hold scan results
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress.IPAddressToString
        $Result | Add-Member -MemberType NoteProperty -Name MACAddress -Value ""

        # Define an array to hold the port scan results
        $ScanResults = @()

        # Loop through the list of ports and perform a port scan
        foreach ($Port in $Ports) {
            # Update the port progress bar
            $PortProgressBar.Value = $PortProgressBar.Value + 1
            Write-Progress -Activity "Scanning port $Port on $($IPAddress.IPAddressToString)"
####### MUlig fejl her



# Define the function that will be exported as a cmdlet
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

    # Wait for all the jobs to finish and retrieve the results
    $
#### FEJL HER


# Import MacAddressLookup module
Import-Module MacAddressLookup

# Function to lookup MAC address
function Lookup-MacAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    # Get MAC address from MacVendors.com's API
    $macAddress = Get-MacAddress -IpAddress $IPAddress -Verbose

    # Return MAC address if found
    if ($macAddress) {
        return $macAddress
    }

    # Return null if MAC address not found
    return $null
}

# Function to scan ports for a single IP address
function Scan-Ports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        [Parameter(Mandatory = $true)]
        [int[]]$PortList
    )

    # Create hashtable to store results
    $results = @{
        "IPAddress" = $IPAddress
        "MACAddress" = ""
        "VendorInfo" = ""
        "OpenPorts" = @()
        "WebInterfaces" = @()
    }

    # Lookup MAC address
    $macAddress = Lookup-MacAddress -IPAddress $IPAddress

    # If MAC address found, add to results
    if ($macAddress) {
        $results["MACAddress"] = $macAddress.MacAddress
        $results["VendorInfo"] = $macAddress.Vendor
    }

    # Loop through list of ports to scan
    foreach ($port in $PortList) {
        # Test port for connectivity
        $socket = New-Object Net.Sockets.TcpClient
        $async = $socket.BeginConnect($IPAddress, $port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(100, $false)
        if (!$socket.Connected) {
            $socket.Close()
            continue
        }
        $socket.EndConnect($async)
        $socket.Close()

        # If port is open, add to results
        $results["OpenPorts"] += $port
        if ($port -eq 80 -or $port -eq 443) {
            # Test for web interface
            $uri = "http://$IPAddress`:$port/"
            if (Test-WebInterface -Uri $uri) {
                $results["WebInterfaces"] += $uri
            }
            $uri = "https://$IPAddress`:$port/"
            if (Test-WebInterface -Uri $uri) {
                $results["WebInterfaces"] += $uri
            }
        }
    }

    # Output results
    $results
}

# Function to test for web interface
function Test-WebInterface {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    # Test for response
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method HEAD -TimeoutSec 5
        return $true
    }
    catch {
        return $false
    }
}

# Function to scan IP addresses in parallel
function Scan-IPAddresses {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$IPAddressList,
        [Parameter(Mandatory = $true)]
        [int[]]$PortList
    )

    # Initialize progress bar
    $totalIPs = $IPAddressList.Count
    $ipProgress = 0
    $progress = $null
    if ($PSCmdlet.ShouldProcess("$totalIPs IP addresses", "Scanning")) {
        $progress = $PSCmdlet.WriteProgress -Activity "Scanning IP addresses" -Status "0% complete" -Percent


### Fejl her


# Output the results in a table format with columns for IP address, MAC address, and vendor information.
# As well as open ports, and if there is a web interface of any of the open ports.
$report = $results | Select-Object IPAddress, MACAddress, Vendor, @{n='OpenPorts';e={$_.Ports -join ','}}, @{n='HasWebInterface';e={($_.Ports -contains 80) -or ($_.Ports -contains 443)}} | Sort-Object IPAddress
$report | Format-Table -AutoSize

# End of script



