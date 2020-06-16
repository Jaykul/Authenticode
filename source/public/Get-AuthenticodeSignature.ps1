function Get-AuthenticodeSignature {
    <#
        .SYNOPSIS
            Gets information about the Authenticode signature in a file.
        .DESCRIPTION
            The Get-AuthenticodeSignature function gets information about the Authenticode signature in a file.
            If the file is not signed, the information object is returned, but the fields are blank.
        .NOTES
            For information about Authenticode signatures in Windows PowerShell, type "get-help About_Signing".

            When specifying multiple values for a parameter, use commas to separate the values. For example, "-<parameter-name> <value1>, <value2>".
        .EXAMPLE
            Get-AuthenticodeSignature script.ps1

            To get the signature information about the script.ps1 script file.
        .EXAMPLE
            ls *.ps1,*.psm1,*.psd1 | Get-AuthenticodeSignature

            Get the signature information for all the script and data files
        .EXAMPLE
            Get-ChildItem *.ps1, *.psm1, *.psd1 | Get-AuthenticodeSignature |
                Where-Object {!(Test-AuthenticodeSignature $_ -Valid)} |
                Get-ChildItem | Set-AuthenticodeSignature

            This command gets information about the Authenticode signature in all of the script and module files in the current directory, and tests the signatures, then signs all of the ones that are not valid. Note that this is roughly equivalent to:

            Select-AuthenticodeSigned *.ps1, *.psm1, *.psd1 -InvalidOnly | Set-AuthenticodeSignature
    #>
    [OutputType([System.Management.Automation.Signature])]
    [Alias("gas")]
    [CmdletBinding()]
    param (
        # The path to the file(s) being examined. Wildcards are permitted, but they must lead to file(s).
        # Aliases                      Path, FullName
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("FullName", "Path")]
        [ValidateScript( {
                if ((resolve-path $_).Provider.Name -ne "FileSystem") {
                    throw "Specified Path is not in the FileSystem: '$_'"
                }
                if (!(Test-Path -PathType Leaf $_)) {
                    throw "Specified Path is not a File: '$_'"
                }
                return $true
            })]
        [string[]]
        $FilePath
    )

    process {
        Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $FilePath
    }
}