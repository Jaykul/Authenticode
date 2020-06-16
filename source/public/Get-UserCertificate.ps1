function Get-UserCertificate {
    <#
        .SYNOPSIS
            Gets the user's default signing certificate so we don't have to ask them over and over...
        .DESCRIPTION
            The Get-UserCertificate function retrieves and returns a certificate from the user. It also stores the certificate so it can be reused without re-querying for the location and/or password ...
    #>
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    [CmdletBinding()]
    param(
        # The name is the thumbprint or Cert: path or file system path to the certificate
        $Name
    )
    begin {
        if ($Name) {
            $Script:UserCertificate = Get-AuthenticodeCertificate $Name
        }
    }
    end {

        $ModuleManifest = Join-Path $PSScriptRoot Authenticode.psd1
        if (Test-Path $ModuleManifest) {
            try {
                $OldCertificateString = (((Get-Content $ModuleManifest) -join "`n") -replace '(?s).*Certificates\s+=\s+ConvertFrom-StringData\s+"(.*)".*', '$1')
                $Certificates = ConvertFrom-StringData $OldCertificateString
            } catch {
                $OldCertificateString = $null
                $Certificates = @{ }
            }
        } else {
            $OldCertificateString = ""
            $Certificates = @{ }
        }

        ## If they don't have a cert, or they haven't stored it...
        if (!(Test-Path Variable:Script:UserCertificate) -or
            ($Script:UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) -or
            ($Script:UserCertificate.Thumbprint -ne $Certificates.${Env:ComputerName})
        ) {
            ## Verbose output
            if ($VerbosePreference -gt "SilentlyContinue") {
                if (!(Test-Path Variable:Script:UserCertificate)) {
                    Write-Verbose "Loading User Certificate from Module Config: $($Certificates.${Env:ComputerName} )"
                } else {
                    Write-Verbose "Saving User Certificate to Module Config: ($($Script:UserCertificate.Thumbprint) -ne $($Certificates.${Env:ComputerName}))"
                }
            }

            Write-Debug "PrivateData: $($ExecutionContext.SessionState.Module | fl * | Out-String)"
            ## If they don't have a cert
            if (!(Test-Path Variable:Script:UserCertificate) -or $Script:UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $Script:UserCertificate = Get-AuthenticodeCertificate $Certificates.${Env:ComputerName}
            }
            Write-Verbose "Confirming Certificate: $($Script:UserCertificate.Thumbprint)"

            ## If their cert isn't stored at least temporarily...
            if ($Script:UserCertificate -and (!$Certificates.${Env:ComputerName} -or
                    ($Certificates.${Env:ComputerName} -ne $Script:UserCertificate.Thumbprint))) {
                ## Store it temporarily ...
                $Certificates.${Env:ComputerName} = $Script:UserCertificate.Thumbprint

                ## And ask them if they want to store it permanently
                Write-Verbose "Updating Module Metadata"
                if ($Host.UI -and $Host.UI.PromptForChoice -and (0 -eq
                        $Host.UI.PromptForChoice("Keep this certificate for future sessions?", $Script:UserCertificate,
                            [Management.Automation.Host.ChoiceDescription[]]@("&Yes", "&No"), 0))
                ) {
                    Write-Warning $Certificates
                    $NewCertificateString = ConvertToStringData $Certificates
                    if (!(Test-Path $ModuleManifest) -or $OldCertificateString -eq $Null) {
                        Set-Content $ModuleManifest ((
                                '@{',
                                '   ModuleToProcess = "Authenticode.psm1"',
                                '   ModuleVersion = "2.7"',
                                '   FileList = "Authenticode.psm1", "Authenticode.psd1"',
                                '   Author = "Joel Bennett"',
                                '   CompanyName = "HuddledMasses.org"',
                                '   Copyright = "Copyright (c) 2008-2015, Joel Bennett"',
                                '   PowerShellVersion = "2.0"',
                                '   Description = "Function wrappers for Authenticode Signing cmdlets"',
                                '   PrivateData = @{',
                                '       Certificates = ConvertFrom-StringData "',
                                $NewCertificateString,
                                '       "',
                                '       PSData = @{',
                                '           # Tags applied to this module. These help with module discovery in online galleries.',
                                '           Tags = @("Authenticode","CodeSigning","Certificates")',
                                '           # A URL to the license for this module.',
                                '           LicenseUri = "http://opensource.org/licenses/ms-pl"',
                                '           # A URL to the main website for this project.',
                                '           ProjectUri = "https://github.com/Jaykul/Authenticode"',
                                '       }',
                                '   }',
                                '   GUID = "4a14168f-41b8-4bc4-9ebf-83d5e6b84476"',
                                '   FunctionsToExport = @("Set-AuthenticodeSignature","Get-AuthenticodeSignature","Test-AuthenticodeSignature",',
                                '                       "Select-AuthenticodeSigned","Start-AutoSign",',
                                '                       "Get-AuthenticodeCertificate","Get-UserCertificate")',
                                '   AliasesToExport = "gas","sas","slas","sign"',
                                '}' ) -join "`n")
                    } else {
                        Set-Content $ModuleManifest (((Get-Content $ModuleManifest) -join "`n") -replace '(?s)Certificates\s+=\s+ConvertFrom-StringData\s+"[\s\r\n]*(.*)[\s\r\n]*"',
                            "Certificates = ConvertFrom-StringData `"`n`t$(${NewCertificateString} -replace "`n", "`n`t")`n`t`"")
                    }
                }
            }
        }
        return $Script:UserCertificate
    }
}