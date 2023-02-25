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
            'FTP'        = 21
            'SSH'        = 22
            'SMTP'       = 25
            'HTTP'       = 80
            'HTTPS'      = 443
            'DNS'        = 53
            'POP3'       = 110
            'IMAP'       = 143
            'SNMP'       = 161
            'LDAP'       = 389
            'KERBEROS'   = 750
            'SMTPS'      = 465
            'HTTPS-ALT'  = 8443
            'MSSQL'      = 1433
            'MYSQL'      = 3306
            'ORACLE'     = 1521
            'RDP'        = 3389
            'VNC'        = 5900
            'TELNET'     = 23
            'SSH-ALT'    = 21098
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

