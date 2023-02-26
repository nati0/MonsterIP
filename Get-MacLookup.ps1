

function Get-MacLookup {
    [CmdletBinding()]
    Param (
[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
[string]$MacAddress
    )

    $ApiUrl = 'https://api.macvendors.com/'
    $Result = Invoke-WebRequest -Uri $($ApiUrl+$MacAddress) -UseBasicParsing
    return $result.Content
}