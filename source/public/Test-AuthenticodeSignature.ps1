
function Test-AuthenticodeSignature {
    <#
        .SYNOPSIS
            Tests a script signature to see if it is valid, or at least unaltered.
        .DESCRIPTION
            The Test-AuthenticodeSignature function processes the output of Get-AuthenticodeSignature to determine if it
            is Valid, OR **unaltered** and signed by the user's certificate
        .EXAMPLE
            ls *.ps1 | Get-AuthenticodeSignature | Where {Test-AuthenticodeSignature $_}
            To get the signature reports for all the scripts that we consider safely signed.
        .EXAMPLE
            ls *.ps1,*.psm1,*.psd1 | Get-AuthenticodeSignature | Where {!(Test-AuthenticodeSignature $_ -Valid)} | gci | Set-AuthenticodeSignature

            This command gets information about the Authenticode signature in all of the script and module files, and tests the signatures, then re-signs all of the files that are not valid.
        .EXAMPLE
            ls | ? { gas $_ | Test-AuthenticodeSignature }
            List all the valid signed scripts (or scripts signed by our cert)
        .NOTES
            Test-AuthenticodeSignature returns TRUE even if the root CA certificate can't be verified, as long as the signing certificate's thumbnail matches the one specified by Get-UserCertificate.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        # Specifies the signature object to test. This should be the output of Get-AuthenticodeSignature.
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        $Signature,

        # Force the signature to be valid.
        # Otherwise, we will accept the signature if it matches the "user" certificate (see Get-UserCertificate).
        [Alias("Valid")]
        [Switch]$ForceValid
    )

    return ( $Signature.Status -eq "Valid" -or
        ( !$ForceValid -and
            ($Signature.Status -eq "UnknownError") -and
            ($_.SignerCertificate.Thumbprint -eq $(Get-UserCertificate).Thumbprint)
        ) )
}