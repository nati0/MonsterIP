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

#### FEJL HER



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



