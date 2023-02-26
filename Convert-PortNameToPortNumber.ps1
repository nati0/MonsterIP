function Convert-PortNameToNumber {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateSet(
            'FTP','SSH','Telnet','SMTP','DNS','HTTP',
            'POP3','SFTP','SQL Services','NNTP','NTP',
            'IMAP4','SQL Services','SNMP','IRC','LDAP',
            'HTTPS','SMTPS','DHCP Client','DHCP Server',
            'SMTP','IPP','LDAPS','rsync','FTPS','IMAPS',
            'POP3S','Microsoft RPC','Microsoft SQL Server',
            'Microsoft SQL Monitor','Microsoft PPTP VPN',
            'UPnP','CVS','MySQL','Microsoft Remote Desktop',
            'iTunes','PostgreSQL','VNC HTTP','VNC','X11',
            'IRC','HTTPS Alt','HTTP Alt'
        )]
        [string]$Name
    )

$portMap = @{
    "FTP"                         = "21"
    "SSH"                         = "22"
    "Telnet"                      = "23"
    "SMTP1"                       = "25"
    "SMTP2"                       = "587"
    "DNS"                         = "53"
    "HTTP"                        = "80"
    "POP3"                        = "110"
    "SFTP"                        = "115"
    "SQL Services1"               = "118"
    "SQL Services2"               = "156"
    "NNTP"                        = "119"
    "NTP"                         = "123"
    "IMAP4"                       = "143"
    "SNMP"                        = "161"
    "IRC1"                        = "194"
    "IRC2"                        = "6667"
    "LDAP"                        = "389"
    "HTTPS"                       = "443"
    "SMTPS"                       = "465"
    "DHCP Client"                 = "546"
    "DHCP Server"                 = "547"
    "IPP"                         = "631"
    "LDAPS"                       = "636"
    "rsync"                       = "873"
    "FTPS"                        = "990"
    "IMAPS"                       = "993"
    "POP3S"                       = "995"
    "Microsoft RPC1"              = "1025"
    "Microsoft RPC2"              = "1026"
    "Microsoft RPC3"              = "1027"
    "Microsoft RPC4"              = "1028"
    "Microsoft RPC5"              = "1029"
    "Microsoft SQL Server"        = "1433"
    "Microsoft SQL Monitor"       = "1434"
    "Microsoft PPTP VPN"          = "1723"
    "UPnP"                        = "1900"
    "CVS"                         = "2401"
    "MySQL"                       = "3306"
    "Microsoft Remote Desktop"    = "3389"
    "iTunes"                      = "3689"
    "PostgreSQL"                  = "5432"
    "VNC HTTP"                    = "5800"
    "VNC"                         = "5900"
    "X11"                         = "6000"
    "HTTP Alt1"                   = "8000"
    "HTTP Alt2"                   = "8080"
    "HTTPS Alt"                   = "8443"
    "HTTP Alt3"                   = "8888"
}



    if ($portMap.ContainsKey($Name)) {
        return $portMap[$Name]
    } 
    else {
        throw "Invalid port name. Please specify a valid port name from the list of available options."
    }
}