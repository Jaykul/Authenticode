function Get-AuthenticodeCertificate {
    <#
        .SYNOPSIS
            Gets a code signing certificate
    #>
    [CmdletBinding()]
    param(
        # The name or path of the certificate: supports wildcards. Can be the thumbprint name of the certificate in the CERT: drive, or a path to a pfx file, etc.
        # It can be an actual X509Certificate2 object.
        $Name = $(Get-UserCertificate)
    )

    end {
        $Certificate = $Name
        # Until they get a cert, or hit ENTER without any input
        while ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            trap {
                Write-Warning "The authenticode module requires a code-signing certificate, and can't find yours!"
                Write-Host
                Write-Host "If this is the first time you've seen this error, please run Get-AuthenticodeCertificate by hand and specify the full path to your PFX file, or the Thumbprint of a cert in your OS Cert store -- and then answer YES to save that cert in the 'PrivateData' of the Authenticode Module metadata."
                Write-Host
                Write-Host "If you have seen this error multiple times, you may need to manually create a module manifest for this module with the path to your cert, and/or specify the certificate name each time you use it."
                Write-Error $_
                continue
            }
            ## If they haven't specified the name, prompt them:
            if (!$Name) {
                Push-Location Cert:\
                $certs = @(Get-ChildItem -Recurse -CodeSigningCert | Sort-Object NotAfter)
                Pop-Location
                if ($certs.Count) {
                    Write-Host "You have $($certs.Count) code signing certificates in your local certificate storage which you can specify by partial Thumbprint, or you may specify the path to a .pfx file:" -fore cyan
                    $certs | Out-Host
                }
                $Name = $(Read-Host "Please specify a user certificate (wildcards allowed)")
                if (!$Name) {
                    return
                }
            }

            Write-Verbose "Certificate Path: $Name"
            ## Check "CurrentUsers\My" first, because it's MOST LIKELY there, and it will be MUCH faster in some cases.
            $ResolvedPath = Get-ChildItem Cert:\CurrentUser\My -Recurse -CodeSigningCert | Where-Object { $_.ThumbPrint -like $Name } | Select-Object -Expand PSPath
            if (!$ResolvedPath) {
                ## We have to at least check the other folders too, if we didn't find it.
                $ResolvedPath = Get-ChildItem Cert:\ -Recurse -CodeSigningCert | Where-Object { $_.ThumbPrint -like $Name } | Select-Object -Expand PSPath
            }

            if (!$ResolvedPath) {
                Write-Verbose "Not a Certificate path: $Path"
                $ResolvedPath = Resolve-Path $Name -ErrorAction "SilentlyContinue" | Where-Object { Test-Path $_ -PathType Leaf -ErrorAction "SilentlyContinue" }
            }

            if (!$ResolvedPath) {
                Write-Verbose "Not a full or legit relative path Path: $ResolvedPath"
                $ResolvedPath = Resolve-Path (Join-Path $PsScriptRoot $Name -ErrorAction "SilentlyContinue") -ErrorAction "SilentlyContinue" | Where-Object { Test-Path $_ -PathType Leaf -ErrorAction "SilentlyContinue" }
                Write-Verbose "Resolved File Path: $ResolvedPath"
            }

            if (@($ResolvedPath).Count -gt 1) {
                throw "You need to specify enough of the name to narrow it to a single certificate. '$Name' returned $(@($ResolvedPath).Count):`n$($ResolvedPath|Out-String)"
            }

            $Certificate = get-item $ResolvedPath -ErrorAction "SilentlyContinue"
            if ($Certificate -is [System.IO.FileInfo]) {
                $Certificate = Get-PfxCertificate $Certificate -ErrorAction "SilentlyContinue"
            }
            $Name = $Null # Blank it out so we re-prompt them
        }
        Write-Verbose "Certificate: $($Certificate | Out-String)"
        return $Certificate
    }
}