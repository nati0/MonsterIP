#Convert-PortNameToNumber
#Get-IPRange



function Convert-PortNameToNumber {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('HTTP','HTTPS','SSH','FTP','SMTP','DNS','POP3','IMAP','SNMP','LDAP','TELNET',
        'NETBIOS-NS','NETBIOS-DGM','NETBIOS-SSN','KERBEROS','LDAP-SSL','LDAPS',
        'MYSQL','ORACLE','RDP','VNC','SNMPTRAP','SSH-ALT','HTTPS-ALT','SMTPS',
        'MSSQL','RADIUS','PPTP','MS-SQL-M','MONGO','REDIS','POSTGRESQL','ZABBIX-AGENT',
        'ZABBIX-TRAPPER','IKE','SYSLOG','IPSEC-NAT-T','BGP','LDAP2','LDAP2-SSL',
        'SMTP-MSA','IMAPS','POP3S','NNTPS','NTP','KRB5-TLS','KRB5-DES','KRB5-DES-CBC3',
        'SSH2-MAC','IPMI','ACCTVISO','TCPMUX','SQLNET','XE','SMTP-AUTH','ASTERISK',
        'KAMAILIO','WEBMIN','VPN-SERVICE','SMB','SMB-IPC','SMB-DIRECT','SMBADMIN',
        'SMB2','SMB2-DIRECT','MICROSOFT-DS','MSSQL-DS','DNS-IXFR','TACACS','TACACS+',
        'KERBEROS-AD-LOGIN','NAGIOS','NFS','NFSACL','KERBEROS-ADMIN','WEBDAV','WEBDAV-SSL',
        'WEBLOGIC','WEBLOGIC-SSL','REDIS-CLI','REDIS-SERVER','REDIS-SENTINEL','REDIS-SERVER-SSL',
        'GIT','HTTPS-CONNECT','MICROSOFT-LDAP','SILVERPEAK','SILVERPEAK-XML-API','IPV6-IPSEC',
        'VXWORKS-RTPS','VXWORKS-RTPS-SSL','VXWORKS-NAME','VXWORKS-NAME-SSL','VXWORKS-WDB',
        'RMI-IIOP','RMI-IIOP-SSL','WIN-RM','IMAPS4','LDAP3','LDAP3-SSL','FTP-DATA',
        'BITTORRENT-TRACKER','NETFLOW','NETFLOW-SCRUTINIZER','IAX2','IRC','IRC-S','ELASTICSEARCH',
        'ELASTICSEARCH-SSL','ACTIVEMQ','AMQP','CISCO-TCP-FIN','CISCO-TCP-SYN','CISCO-TCP-ACK',
        'CISCO-TCP-RST','CISCO-TCP-URG','CISCO-TCP-PSH','CISCO-TCP-ECE','CISCO-TCP-CWR',
        'GLASSFISH','GLASSFISH-SSL','BACULA-DIR','BACULA-FD','BACULA-SD','BACULA-BMON',
        'CUCUMBER-WIRE','IBM-DOMINO-SSL','IBM-DOMINO-ADMIN','HTTP-ALT','HTTP-PROXY','PROXY-HTTPS',
        'PCANYWHERE','CQL','CQL-SSL','ICECAST','ORACLE-EM','ORACLE-EM-SSL','POSTFIX')]
        [string]$PortName
    )

    try {
        $portMap = @{
            $portMap = @{
                'ftp'       = 21
                'ssh'       = 22
                'telnet'    = 23
                'smtp'      = 25
                'dns'       = 53
                'http'      = 80
                'pop3'      = 110
                'ntp'       = 123
                'netbios'   = 137
                'snmp'      = 161
                'ldap'      = 389
                'https'     = 443
                'smtps'     = 465
                'ldaps'     = 636
                'mssql'     = 1433
                'oracle'    = 1521
                'rdp'       = 3389
                'vnc'       = 5900
                'http-alt'  = 8080
                'smb'       = 445
                'imap'      = 993
                'imaps'     = 993
                'pop3s'     = 995
                'ssh-alt'   = 2222
                'http-alt2' = 8000
                'smtp-alt'  = 587
                'mysql'     = 3306
                'http-proxy'= 808
                'sip'       = 5060
                'sip-tls'   = 5061
                'microsoft-ds' = 445
                'submission' = 587
                'wsus'      = 8530, 8531
                'postgresql'= 5432
                'redis'     = 6379
                'docker'    = 2375, 2376
                'ftp-data'  = 20
                'sshalt'    = 2222
                'telnetalt' = 992
                'ping'      = 7
                'tftp'      = 69
                'bgp'       = 179
                'irc'       = 194
                'dhcp'      = 546, 547
                'tacacs'    = 49
                'ntp-alt'   = 103
                'imap3'     = 220
                'rsync'     = 873
                'ntp-pout'  = 1234
                'snmp-trap' = 162
                'ntp-dpts'  = 10000..10010
                'http-alt3' = 8069
                'cvs'       = 2401
                'mongodb'   = 27017
                'ldap-alt'  = 3268, 3269
                'rsync-alt' = 8730
                'biff'      = 512
                'who'       = 513
                'login'     = 514
                'shell'     = 515
                'printer'   = 515
                'talk'      = 517
                'ntalk'     = 518
                'route'     = 520
                'rip'       = 520
                'netstat'   = 15
                'finger'    = 79
                'http-prox' = 3128
                'socks'     = 1080
                'rsh'       = 514
                'rlogin'    =
            
        }

        if ($portMap.ContainsKey($PortName)) {
            return $portMap[$PortName]
        } else {
            throw "Invalid port name: $PortName"
        }
    } catch {
        throw "Failed to convert port name to number: $_"
    }
}


function Get-IPRange {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$StartIP,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$EndIP
    )

    try {
        $StartIPAddress = [System.Net.IPAddress]::Parse($StartIP)
        $EndIPAddress = [System.Net.IPAddress]::Parse($EndIP)
    } catch {
        Write-Error "Invalid IP address format. Please provide valid IP addresses."
        return
    }

    if ($StartIPAddress.AddressFamily -ne $EndIPAddress.AddressFamily) {
        Write-Error "Start and end IP addresses have different address families. Please provide IP addresses of the same family."
        return
    }

    if ($StartIPAddress.Address -gt $EndIPAddress.Address) {
        Write-Error "Start IP address is greater than end IP address. Please provide IP addresses in the correct order."
        return
    }

    $IPRange = [System.Net.IPAddress]::Parse("0.0.0.0").GetAddressBytes()
    $StartIPBytes = $StartIPAddress.GetAddressBytes()
    $EndIPBytes = $EndIPAddress.GetAddressBytes()

    for ($i = 0; $i -lt $IPRange.Length; $i++) {
        $IPRange[$i] = ($StartIPBytes[$i] -band $EndIPBytes[$i]) + (-bnot $EndIPBytes[$i])
    }

    return [System.Net.IPAddress]$IPRange
}

