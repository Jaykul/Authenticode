function ConvertToStringData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )
    switch ($InputObject.GetType().FullName) {
        'System.Collections.Hashtable' {
            ($InputObject.Keys | % { "$_=$($InputObject.$_)" }) -join "`n"
        }
    }
}