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