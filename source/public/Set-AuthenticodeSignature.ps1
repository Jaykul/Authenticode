function Set-AuthenticodeSignature {
    <#
        .SYNOPSIS
            Adds an Authenticode signature to a Windows PowerShell script or other file.
        .DESCRIPTION
            The Set-AuthenticodeSignature function adds an Authenticode signature to any file that supports Subject Interface Package (SIP).

            In a Windows PowerShell script file, the signature takes the form of a block of text that indicates the end of the instructions that are executed in the script. If there is a signature  in the file when this cmdlet runs, that signature is removed.
        .NOTES
            After the certificate has been validated, but before a signature is added to the file, the function checks the value of the $SigningApproved preference variable. If this variable is not set, or has a value other than TRUE, you are prompted to confirm the signing of the script.

            When specifying multiple values for a parameter, use commas to separate the values. For example, "<parameter-name> <value1>, <value2>".
        .EXAMPLE
            ls *.ps1 | Set-AuthenticodeSignature -Certificate $Certificate

            To sign all of the files with the specified certificate
        .EXAMPLE
            ls *.ps1,*.psm1,*.psd1 | Get-AuthenticodeSignature | Where {!(Test-AuthenticodeSignature $_ -Valid)} | gci | Set-AuthenticodeSignature

            List all the script files, and get and test their signatures, and then sign all of the ones that are not valid, using the user's default certificate.
        .EXAMPLE
            Set-AuthenticodeSignature -Module PSCX

            Signs the whole PSCX module at once (all the ps1, psm1, psd1, dll, exe, and ps1xml files, etc.).
    #>
    [OutputType([System.Management.Automation.Signature])]
    [Alias("sas", "sign")]
    [CmdletBinding(DefaultParameterSetName = "File")]
    param (
        # Specifies the path to a file that is being signed.
        # Aliases                      Path, FullName
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "File")]
        [Alias("FullName")]
        [ValidateScript( {
                if ((resolve-path $_).Provider.Name -ne "FileSystem") {
                    throw "Specified Path is not in the FileSystem: '$_'"
                }
                return $true
            })]
        [string[]]$FilePath,

        # Specifies a module name (or path) to sign.
        # When you specify a module name, all of the files in that folder and it's subfolders are signed (if they are signable).
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Module")]
        [Alias("ModuleName")]
        [string[]]$ModuleBase,

        # Specifies the certificate that will be used to sign the script or file.
        # Enter a certificate thumbprint (supports wildcards), or variable that stores the certificate or an expression that gets the certificate.
        # If the certificate is not valid or does not have code-signing authority, the command fails.
        #
        # To find a certificate, use Get-AuthenticodeCertificate
        # To set (or see) the default certificate, use Get-UserCertificate.
        [Parameter(Position = 2, Mandatory = $false)]
        $Certificate,

        # Allows the cmdlet to append a signature to a read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.
        [Switch]$Force,

        # Specifies the hashing algorithm that Windows uses to compute the digital signature for the file. The default is SHA1, which is the Windows default hashing algorithm.

        # Files that are signed with a different hashing algorithm might not be recognized on other systems.
        [ValidateSet("SHA", "MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [String]$HashAlgorithm, #="SHA1"

        # Determines which certificates in the certificate trust chain are included in the digital signature. "NotRoot" is the default.
        # Valid values are:
        # -- Signer: Includes only the signer's certificate.
        # -- NotRoot: Includes all of the certificates in the certificate chain, except for the root authority.
        # -- All: Includes all the certificates in the certificate chain.
        [ValidateSet("Signer", "NotRoot", "All")]
        [String]$IncludeChain, #="NotRoot"

        # Uses the specified time stamp server to add a time stamp to the signature. Type the URL of the time stamp server as a string.
        # Defaults to Verisign's server: http://timestamp.verisign.com/scripts/timstamp.dll

        # The time stamp represents the exact time that the certificate was added to the file. A time stamp prevents the script from failing if the certificate expires because users and programs can verify that the certificate was valid atthe time of signing.
        [String]$TimestampServer = "http://timestamp.verisign.com/scripts/timstamp.dll"
    )
    begin {
        Write-Verbose $("ParameterSetName Begin: " + $PSCmdlet.ParameterSetName)
        ## Can't specify this as a default value if we're in the pipeline, it doesn't get bound in time?
        if (!$Certificate) {
            $Certificate = Get-UserCertificate
        }
        if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $Certificate = Get-AuthenticodeCertificate $Certificate
        }
        $PSBoundParameters["Certificate"] = $Certificate
        $PSBoundParameters["TimestampServer"] = $TimestampServer
    }
    process {
        Write-Verbose $("ParameterSetName Process: " + $PSCmdlet.ParameterSetName)

        if ($PSCmdlet.ParameterSetName -eq "Module") {
            $ModuleBase = $ModuleBase | Split-Path -Leaf
            Write-Verbose "Signing Modules: $($ModuleBase -join ', ')"
            $FilePath = Get-Module -List $ModuleBase | Split-Path |
            Get-ChildItem -Recurse |
            Where-Object { !$_.PsIsContainer -and (".ps1", ".psm1", ".psd1", ".ps1xml", ".dll", ".exe" -contains $_.Extension) } |
            Select-Object -Expand FullName

            $null = $PSBoundParameters.Remove("ModuleBase")
            Write-Verbose "Signing Files: $($FilePath | Out-String)"
        }

        Write-Verbose $("ParameterSetName 4: " + $PSCmdlet.ParameterSetName)
        foreach ($file in @($FilePath)) {
            trap {
                Write-Warning "Could not sign file '$File' `n`n because $_"; continue
            }
            $PSBoundParameters.FilePath = $file
            if (Test-Path $file -Type Leaf) {
                Write-Verbose "Set Authenticode Signature on $FilePath with $($Certificate | Out-String)"
                $null = $PSBoundParameters.Remove("ModuleBase")
                Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
            } else {
                $PSBoundParameters.FilePath = Get-ChildItem $file -Recurse |
                Where-Object { !$_.PsIsContainer -and (".ps1", ".psm1", ".psd1", ".ps1xml", ".dll", ".exe" -contains $_.Extension) } |
                Select-Object -Expand FullName
                Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
            }
        }
        return
    }
}