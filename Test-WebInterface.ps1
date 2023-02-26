
function Test-WebInterface {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    # Test for response
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method GET -TimeoutSec 5 -UseBasicParsing
        return $true
    }
    catch {
        return $false
    }
}
