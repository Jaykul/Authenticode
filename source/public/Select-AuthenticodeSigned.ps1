function Select-AuthenticodeSigned {
    <#
      .SYNOPSIS
         Select files based on the status of their Authenticode Signature.
      .DESCRIPTION
         The Select-AuthenticodeSigned function filters files on the pipeline based on the state of their authenticode signature.
      .EXAMPLE
         ls | Select-AuthenticodeSigned -Mine -Broken | Set-AuthenticodeSignature

         Re-sign anything you signed before that has changed
      .EXAMPLE
         ls *.ps1,*.ps[dm]1 | Select-AuthenticodeSigned

         To get the signature information about the script.ps1 script file.
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthenticodeSignature

         Get the signature information for all the script and data files
      .NOTES
         For information about Authenticode signatures in Windows PowerShell, type "get-help About_Signing".

         When specifying multiple values for a parameter, use commas to separate the values. For example, "-<parameter-name> <value1>, <value2>".
    #>
    [Alias("slas")]
    [CmdletBinding()]
    [OutputType("System.Management.Automation.Signature")]
    param (
        # The path to the file(s) being examined. Wildcards are permitted, but they must lead to a single file.
        # Aliases                      Path, FullName
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("FullName", "Path")]
        [ValidateScript( {
                if ((resolve-path $_).Provider.Name -ne "FileSystem") {
                    throw "Specified Path is not in the FileSystem: '$_'"
                }
                return $true
            })]
        [string[]]
        $FilePath,

        # Return only files that are signed with the users' certificate (as returned by Get-UserCertificate).
        [Parameter()]
        [switch]$MineOnly,

        # Return only files that are NOT signed with the users' certificate (as returned by Get-UserCertificate).
        [Parameter()]
        [switch]$NotMineOnly,

        # Return only files with signatures that are broken (where the file has been edited, and the hash doesn't match).
        [Parameter()]
        [Alias("HashMismatch")]
        [switch]$BrokenOnly,

        # Returns the files that are Valid OR signed with the users' certificate (as returned by Get-UserCertificate).
        #
        # That is, TrustedOnly returns files returned by -ValidOnly OR -MineOnly (if you specify both parameters, you get only files that are BOTH -ValidOnly AND -MineOnly)
        [Parameter()]
        [switch]$TrustedOnly,

        # Return only files that are "Valid": This means signed with any cert where the certificate chain is verifiable to a trusted root certificate.  This may or may not include files signed with the user's certificate.
        [Parameter()]
        [switch]$ValidOnly,

        # Return only files that doesn't have a "Valid" signature, which includes files that aren't signed, or that have a hash mismatch, or are signed by untrusted certs (possibly including the user's certificate).
        [Parameter()]
        [switch]$InvalidOnly,

        # Return only signable files that aren't signed at all. That is, only files that support Subject Interface Package (SIP) but aren't signed.
        [Parameter()]
        [switch]$UnsignedOnly
    )
    process {
        if (!(Test-Path -PathType Leaf $FilePath)) {
            # if($ErrorAction -ne "SilentlyContinue") {
            #    Write-Error "Specified Path is not a File: '$FilePath'"
            # }
        } else {

            foreach ($sig in Get-AuthenticodeSignature -FilePath $FilePath) {

                # Broken only returns ONLY things which are HashMismatch
                if ($BrokenOnly -and $sig.Status -ne "HashMismatch") {
                    Write-Debug "$($sig.Status) - Not Broken: $FilePath"
                    return
                }

                # Trusted only returns ONLY things which are Valid
                if ($ValidOnly -and $sig.Status -ne "Valid") {
                    Write-Debug "$($sig.Status) - Not Trusted: $FilePath"
                    return
                }

                # AllValid returns only things that are SIGNED and not HashMismatch
                if ($TrustedOnly -and (($sig.Status -ne "HashMismatch") -or !$sig.SignerCertificate) ) {
                    Write-Debug "$($sig.Status) - Not Valid: $FilePath"
                    return
                }

                # InvalidOnly returns things that are Either NotSigned OR HashMismatch ...
                if ($InvalidOnly -and ($sig.Status -eq "Valid")) {
                    Write-Debug "$($sig.Status) - Valid: $FilePath"
                    return
                }

                # Unsigned returns only things that aren't signed
                # NOTE: we don't test using NotSigned, because that's only set for .ps1 or .exe files??
                if ($UnsignedOnly -and $sig.SignerCertificate ) {
                    Write-Debug "$($sig.Status) - Signed: $FilePath"
                    return
                }

                # Mine returns only things that were signed by MY CertificateThumbprint
                if ($MineOnly -and (!($sig.SignerCertificate) -or ($sig.SignerCertificate.Thumbprint -ne $((Get-UserCertificate).Thumbprint)))) {
                    Write-Debug "Originally signed by someone else, thumbprint: $($sig.SignerCertificate.Thumbprint)"
                    Write-Debug "Does not match your default certificate print: $((Get-UserCertificate).Thumbprint)"
                    Write-Debug "     $FilePath"
                    return
                }

                # NotMine returns only things that were NOT signed by MY CertificateThumbprint
                if ($NotMineOnly -and (!($sig.SignerCertificate) -or ($sig.SignerCertificate.Thumbprint -eq $((Get-UserCertificate).Thumbprint)))) {
                    if ($sig.SignerCertificate) {
                        Write-Debug "Originally signed by you, thumbprint: $($sig.SignerCertificate.Thumbprint)"
                        Write-Debug "Matches your default certificate print: $((Get-UserCertificate).Thumbprint)"
                        Write-Debug "     $FilePath"
                    }
                    return
                }

                if (!$BrokenOnly -and !$TrustedOnly -and !$ValidOnly -and !$InvalidOnly -and !$UnsignedOnly -and !($sig.SignerCertificate) ) {
                    Write-Debug "$($sig.Status) - Not Signed: $FilePath"
                    return
                }

                get-childItem $sig.Path
            }
        }
    }
}