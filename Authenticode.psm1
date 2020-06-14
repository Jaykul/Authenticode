#Requires -version 2.0

function ConvertTo-StringData { 
   [CmdletBinding()]
   param(
      [Parameter(ValueFromPipeline = $true)]
      $InputObject
   )
   switch ($InputObject.GetType().FullName) {
      'System.Collections.Hashtable' { ($InputObject.Keys | ForEach-Object { "$_=$($InputObject.$_)" }) -join "`n" }
   }  
}

function Get-UserCertificate {
   <#
      .SYNOPSIS
       Gets the user's default signing certificate so we don't have to ask them over and over...
      .DESCRIPTION
       The Get-UserCertificate function retrieves and returns a certificate from the user. It also stores the certificate so it can be reused without re-querying for the location and/or password ... 
      .RETURNVALUE
       An X509Certificate2 suitable for code-signing
   #>
   [CmdletBinding()]
   param ( $Name )
   begin {
      if ($Name) { 
         $Script:UserCertificate = Get-AuthCodeCertificate $Name
      }
   }
   end {

      $ModuleManifest = Join-Path $PSScriptRoot Authenticode.psd1
      if (Test-Path $ModuleManifest) {
         try {         
            $OldCertificateString = (((Get-Content $ModuleManifest) -join "`n") -replace '(?s).*Certificates\s+=\s+ConvertFrom-StringData\s+"(.*)".*', '$1')
            $Certificates = ConvertFrom-StringData $OldCertificateString
         }
         catch {
            $OldCertificateString = $null
            $Certificates = @{}
         }
      }
      else {
         $OldCertificateString = ""
         $Certificates = @{}
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
            }
            else {
               Write-Verbose "Saving User Certificate to Module Config: ($($Script:UserCertificate.Thumbprint) -ne $($Certificates.${Env:ComputerName}))"
            }
         }
         
         Write-Debug "PrivateData: $($ExecutionContext.SessionState.Module | format-list * | Out-String)"
         ## If they don't have a cert
         if (!(Test-Path Variable:Script:UserCertificate) -or $Script:UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $Script:UserCertificate = Get-AuthCodeCertificate $Certificates.${Env:ComputerName}
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
               $NewCertificateString = ConvertTo-StringData $Certificates
               if (!(Test-Path $ModuleManifest) -or $Null -eq $OldCertificateString ) {
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
                        '   FunctionsToExport = @("Set-AuthCodeSignature","Get-AuthCodeSignature","Test-AuthCodeSignature",',
                        '                       "Select-AuthCodeSigned","Start-AutoSign",',
                        '                       "Get-AuthCodeCertificate","Get-UserCertificate")',
                        '   AliasesToExport = "gas","sas","slas","sign"',
                        '}' ) -join "`n")                 
               }
               else {
                  Set-Content $ModuleManifest (((Get-Content $ModuleManifest) -join "`n") -replace '(?s)Certificates\s+=\s+ConvertFrom-StringData\s+"[\s\r\n]*(.*)[\s\r\n]*"',
                     "Certificates = ConvertFrom-StringData `"`n`t$(${NewCertificateString} -replace "`n", "`n`t")`n`t`"")
               }
            }
         }
      }
      return $Script:UserCertificate
   }
}

function Get-AuthCodeCertificate {
   [CmdletBinding()]
   param (
      $Name = $(Get-UserCertificate)
   )

   end {
      $Certificate = $Name
      # Until they get a cert, or hit ENTER without any input
      while ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
         trap {
            Write-Host "The authenticode module requires a code-signing certificate, and can't find yours!"
            Write-Host
            Write-Host "If this is the first time you've seen this error, please run Get-AuthCodeCertificate by hand and specify the full path to your PFX file, or the Thumbprint of a cert in your OS Cert store -- and then answer YES to save that cert in the 'PrivateData' of the Authenticode Module metadata."
            Write-Host
            Write-Host "If you have seen this error multiple times, you may need to manually create a module manifest for this module with the path to your cert, and/or specify the certificate name each time you use it."
            Write-Error $_
            continue      
         }
         ## If they haven't specified the name, prompt them:
         if (!$Name) {
            push-Location Cert:\
            $certs = @(Get-ChildItem -Recurse -CodeSigningCert | Sort-Object NotAfter)
            pop-Location
            if ($certs.Count) {
               Write-Host "You have $($certs.Count) code signing certificates in your local certificate storage which you can specify by partial Thumbprint, or you may specify the path to a .pfx file:" -fore cyan
               $certs | Out-Host
            }
            $Name = $(Read-Host "Please specify a user certificate (wildcards allowed)")
            if (!$Name) { return }
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

function Test-AuthCodeSignature {
   <#
      .SYNOPSIS
         Tests a script signature to see if it is valid, or at least unaltered.
      .DESCRIPTION
         The Test-AuthCodeSignature function processes the output of Get-AuthCodeSignature to determine if it 
         is Valid, OR **unaltered** and signed by the user's certificate
      .EXAMPLE
         ls *.ps1 | Get-AuthCodeSignature | Where {Test-AuthCodeSignature $_}
         To get the signature reports for all the scripts that we consider safely signed.
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthCodeSignature | Where {!(Test-AuthCodeSignature $_ -Valid)} | gci | Set-AuthCodeSignature

         This command gets information about the Authenticode signature in all of the script and module files, and tests the signatures, then re-signs all of the files that are not valid.
      .EXAMPLE
         ls | ? { gas $_ | Test-AuthCodeSignature }
         List all the valid signed scripts (or scripts signed by our cert)
      .NOTES
         Test-AuthCodeSignature returns TRUE even if the root CA certificate can't be verified, as long as the signing certificate's thumbnail matches the one specified by Get-UserCertificate.
      .INPUTTYPE
         System.Management.Automation.Signature
      .RETURNVALUE
         Boolean value representing whether the script's signature is valid, or YOUR certificate
   #>
   [CmdletBinding()]
   param (
      # Specifies the signature object to test. This should be the output of Get-AuthCodeSignature.
      [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
      $Signature,

      # Switch parameter, forces the signature to be valid -- otherwise, even if the certificate chain can't be verified, we will accept the cert which matches the "user" certificate (see Get-UserCertificate).
      # Aliases                      Valid
      [Alias("Valid")]
      [Switch]$ForceValid
   )

   return ( $Signature.Status -eq "Valid" -or 
      ( !$ForceValid -and 
         ($Signature.Status -eq "UnknownError") -and 
         ($_.SignerCertificate.Thumbprint -eq $(Get-UserCertificate).Thumbprint) 
      ) )
}

function Set-AuthCodeSignature {
   <#
      .SYNOPSIS
         Adds an Authenticode signature to a Windows PowerShell script or other file.
      .DESCRIPTION
         The Set-AuthCodeSignature function adds an Authenticode signature to any file that supports Subject Interface Package (SIP).
       
         In a Windows PowerShell script file, the signature takes the form of a block of text that indicates the end of the instructions that are executed in the script. If there is a signature  in the file when this cmdlet runs, that signature is removed.
      .NOTES
         After the certificate has been validated, but before a signature is added to the file, the function checks the value of the $SigningApproved preference variable. If this variable is not set, or has a value other than TRUE, you are prompted to confirm the signing of the script.
       
         When specifying multiple values for a parameter, use commas to separate the values. For example, "<parameter-name> <value1>, <value2>".
      .EXAMPLE
         ls *.ps1 | Set-AuthCodeSignature -Certificate $Certificate
         
         To sign all of the files with the specified certificate
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthCodeSignature | Where {!(Test-AuthCodeSignature $_ -Valid)} | gci | Set-AuthCodeSignature

         List all the script files, and get and test their signatures, and then sign all of the ones that are not valid, using the user's default certificate.
      .EXAMPLE
         Set-AuthCodeSignature -Module PSCX
         
         Signs the whole PSCX module at once (all the ps1, psm1, psd1, dll, exe, and ps1xml files, etc.).
      .INPUTTYPE
         String. You can pipe a file path to Set-AuthCodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
   #>
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
      # To find a certificate, use Get-AuthCodeCertificate
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
         $Certificate = Get-AuthCodeCertificate $Certificate
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
         trap { Write-Warning "Could not sign file '$File' `n`n because $_"; continue }
         $PSBoundParameters.FilePath = $file
         if (Test-Path $file -Type Leaf) {
            Write-Verbose "Set Authenticode Signature on $FilePath with $($Certificate | Out-String)"
            $null = $PSBoundParameters.Remove("ModuleBase")
            Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
         }
         else {
            $PSBoundParameters.FilePath = Get-ChildItem $file -Recurse |
            Where-Object { !$_.PsIsContainer -and (".ps1", ".psm1", ".psd1", ".ps1xml", ".dll", ".exe" -contains $_.Extension) } | 
            Select-Object -Expand FullName
            Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
         }
      }
      return
   }
}

function Get-AuthCodeSignature {
   <#
      .SYNOPSIS

         Gets information about the Authenticode signature in a file.
      .DESCRIPTION
         The Get-AuthCodeSignature function gets information about the Authenticode signature in a file. If the file is not signed, the information is retrieved, but the fields are blank.
      .NOTES
         For information about Authenticode signatures in Windows PowerShell, type "get-help About_Signing".

         When specifying multiple values for a parameter, use commas to separate the values. For example, "-<parameter-name> <value1>, <value2>".
      .EXAMPLE
         Get-AuthCodeSignature script.ps1
         
         To get the signature information about the script.ps1 script file.
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthCodeSignature
         
         Get the signature information for all the script and data files
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthCodeSignature | Where {!(Test-AuthCodeSignature $_ -Valid)} | gci | Set-AuthCodeSignature

         This command gets information about the Authenticode signature in all of the script and module files, and tests the signatures, then signs all of the ones that are not valid.
      .INPUTTYPE
         String. You can pipe the path to a file to Get-AuthCodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
      ###################################################################################################>
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

function Select-AuthCodeSigned {
   <#
      .SYNOPSIS
         Select files based on the status of their Authenticode Signature.
      .DESCRIPTION
         The Select-AuthCodeSigned function filters files on the pipeline based on the state of their authenticode signature.
      .EXAMPLE
         ls | Select-AuthCodeSigned -Mine -Broken | Set-AuthCodeSignature
         
         Re-sign anything you signed before that has changed
      .EXAMPLE
         ls *.ps1,*.ps[dm]1 | Select-AuthCodeSigned
         
         To get the signature information about the script.ps1 script file.
      .EXAMPLE
         ls *.ps1,*.psm1,*.psd1 | Get-AuthCodeSignature
         
         Get the signature information for all the script and data files
      .NOTES
         For information about Authenticode signatures in Windows PowerShell, type "get-help About_Signing".

         When specifying multiple values for a parameter, use commas to separate the values. For example, "-<parameter-name> <value1>, <value2>".
      .INPUTTYPE
         String. You can pipe the path to a file to Get-AuthCodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
      ###################################################################################################>
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
      }
      else {

         foreach ($sig in Get-AuthCodeSignature -FilePath $FilePath) {
         
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

function Start-AutoSign {
   # .Synopsis
   #     Start a FileSystemWatcher to automatically sign scripts when you save them
   # .Description
   #     Create a FileSystemWatcher with a scriptblock that uses the Authenticode script Module to sign anything that changes
   # .Parameter Path
   #     The path to the folder you want to monitor
   # .Parameter Filter
   #     A filter to select only certain files: by default, *.ps*  (because we can only sign .ps1, .psm1, .psd1, and .ps1xml 
   # .Parameter Recurse
   #     Whether we should also watch autosign files in subdirectories
   # .Parameter CertPath
   #     The path or name of a certain certificate, to override the defaults from the Authenticode Module
   # .Parameter NoNotify
   #     Whether wo should avoid using Growl to notify the user each time we sign something.
   # .Notes 
   #     Don't run this on a location where you're going to be generating hundreds of files ;)
   param($Path = ".", $Filter = "*.ps*", [Switch]$Recurse, $CertPath, [Switch]$NoNotify)

   if (!$NoNotify -and (Get-Module Growl -ListAvailable -ErrorAction 0)) {
      Import-Module Growl
      Register-GrowlType AutoSign "Signing File" -ErrorAction 0
   }
   else { $NoNotify = $false }

   $realItem = Get-Item $Path -ErrorAction Stop
   if (-not $realItem) { return } 

   $Action = {
      ## Files that can't be signed show up as "UnknownError" with this message:
      $InvalidForm = "The form specified for the subject is not one supported or known by the specified trust provider"
      ## Files that are signed with a cert we don't trust also show up as UnknownError, but with different messages:
      # $UntrustedCert  = "A certificate chain could not be built to a trusted root authority"
      # $InvalidCert = "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"
      # $ExpiredCert = "A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file"
      
      ForEach ($file in Get-ChildItem $eventArgs.FullPath | Get-AuthCodeSignature | 
         Where-Object { $_.Status -ne "Valid" -and $_.StatusMessage -ne $invalidForm } | 
         Select-Object -ExpandProperty Path ) {
         if (!$NoNotify) {
            Send-Growl AutoSign "Signing File" "File $($eventArgs.ChangeType), signing:" "$file"
         }
         if ($CertPath) {
            Set-AuthCodeSignature -FilePath $file -Certificate $CertPath
         }
         else {
            Set-AuthCodeSignature -FilePath $file
         }
      }
   }
   $watcher = New-Object IO.FileSystemWatcher $realItem.Fullname, $filter -Property @{ IncludeSubdirectories = $Recurse }
   Register-ObjectEvent $watcher "Created" "AutoSignCreated$($realItem.Fullname)" -Action $Action > $null
   Register-ObjectEvent $watcher "Changed" "AutoSignChanged$($realItem.Fullname)" -Action $Action > $null
   Register-ObjectEvent $watcher "Renamed" "AutoSignChanged$($realItem.Fullname)" -Action $Action > $null
}

Set-Alias gas          Get-AuthCodeSignature -Description "Authenticode Module Alias"
Set-Alias sas          Set-AuthCodeSignature -Description "Authenticode Module Alias"
Set-Alias slas         Select-AuthCodeSigned -Description "Authenticode Module Alias"
Set-Alias sign         Set-AuthCodeSignature -Description "Authenticode Module Alias"

Export-ModuleMember -Alias gas, sas, slas, sign -Function Set-AuthCodeSignature, Get-AuthCodeSignature, Test-AuthCodeSignature, Select-AuthCodeSigned, Get-UserCertificate, Get-AuthCodeCertificate, Start-AutoSign

# SIG # Begin signature block
# MIIX8wYJKoZIhvcNAQcCoIIX5DCCF+ACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWuKPE/VSpyqigo/DUiNwWiSt
# kFGgghMmMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUwMIIEGKADAgECAhAECRgbX9W7ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9v
# dCBDQTAeFw0xMzEwMjIxMjAwMDBaFw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNp
# Z25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4R
# r2d3B9MLMUkZz9D7RZmxOttE9X/lqJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrw
# nIal2CWsDnkoOn7p0WfTxvspJ8fTeyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnC
# wlLyFGeKiUXULaGj6YgsIJWuHEqHCN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8
# y5Kh5TsxHM/q8grkV7tKtel05iv+bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM
# 0SAlI+sIZD5SlsHyDxL0xY4PwaLoLFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6f
# pjOp/RnfJZPRAgMBAAGjggHNMIIByTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGsw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcw
# AoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBP
# BgNVHSAESDBGMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93
# d3cuZGlnaWNlcnQuY29tL0NQUzAKBghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoK
# o6XqcQPAYPkt9mV1DlgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DQYJKoZIhvcNAQELBQADggEBAD7sDVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+
# C2D9wz0PxK+L/e8q3yBVN7Dh9tGSdQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119E
# efM2FAaK95xGTlz/kLEbBw6RFfu6r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR
# 4pwUR6F6aGivm6dcIFzZcbEMj7uo+MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4v
# cn4c10lFluhZHen6dGRrsutmQ9qzsIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwH
# gfqL2vmCSfdibqFT+hKUGIUukpHqaGxEMrJmoecYpJpkUe8wggVVMIIEPaADAgEC
# AhAM7NF1d7OBuRMX7VCjxmCvMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25p
# bmcgQ0EwHhcNMjAwNjE0MDAwMDAwWhcNMjMwNjE5MTIwMDAwWjCBkTELMAkGA1UE
# BhMCQVUxGDAWBgNVBAgTD05ldyBTb3V0aCBXYWxlczEUMBIGA1UEBxMLQ2hlcnJ5
# YnJvb2sxGjAYBgNVBAoTEURhcnJlbiBKIFJvYmluc29uMRowGAYDVQQLExFEYXJy
# ZW4gSiBSb2JpbnNvbjEaMBgGA1UEAxMRRGFycmVuIEogUm9iaW5zb24wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCPs8uaOSScUDQwhtE/BxPUnBT/FRn
# pQUzLoBTKW0YSKAxUbEURehXJuNBfAj2GGnMOHaB3EvdbxXl1NfLOo3wtRdro04O
# MjOH56Al/9+Rc6DNY48Pl9Ogvuabglah+5oDC/YOYjZS2C9AbBGGRTFjeGHT4w0N
# LLPbxyoTF/wfqZNNy5p+C7823gDR12OvWFgEdTiDnVkn3phxGy8xlK7yrJwFQ0Sn
# z8RknEFSaoKnuYqLvaOiOSG77q6M4+LbGAbwhYToaqWa4xWFFJS8XsX0+t6LA+0a
# Kb3ZEb1GyfySDW2TFf/V1RhuM4iBc6YTUUCj9BTqcpWKgkw2k2xUQHP9AgMBAAGj
# ggHFMIIBwTAfBgNVHSMEGDAWgBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4E
# FgQU6HpAuSSJdceLWep4ajN6JIQcAOgwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBD
# MDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
# dC5jb20vQ1BTMAgGBmeBDAEEATCBhAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2ln
# bmluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA1agcO
# M3seD1Cs5pnHRXwwrhzieRgF4UMJgDI/9KrBh4C0o8DsXvaa+YlXoTdhmeKW/xv5
# i9mkVNmvD3wa3AKe5CNwiPc5kx96lC7BXWfdLoY7ejfTGkoa7qHR3gusmQhuZW+L
# dFmvtTyu4eqcjhOBthoJYp3B8tv8JR99pSxFfsE6C4VGdhKHAmZkDMiaAHHava9Z
# xl4+Uof+TuS6lQBZJjw8Xw76W93DNU9JUNb4+hOp8jir1q7/RTvtQ3QWr+iEzJD8
# JRfvfXF4LpFvlOOWYOF22EU/ciGjUVfQYi7nk/LnHzipb46747K1BwAVnHbYMDx0
# BRtLc/s4g9qZxTrxMYIENzCCBDMCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQ
# DOzRdXezgbkTF+1Qo8ZgrzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAig
# AoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgEL
# MQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUfLFlaXHidqXY2E9LoHPc
# 4CkgVZUwDQYJKoZIhvcNAQEBBQAEggEAn021h+qPs40ZYEdLgQzq8yrZ4zscJ5Px
# oO/8Yn2v6TYjsa1pARrS5nMk3q64Iaw01WQm1+kmLx/jrUTXLASU91O4FbdzkWLS
# +GOUHDKuy8D5xh6kUsbmp1fGfMfd408GYgkuaC/ShKkQlfmqdFWjTHzt8tBjdVIl
# OftujXqhnkx++0o3mFJe51U6Jd+1uZur6uA86JmNtp7EMa17ZS5iQyxBBqCh9gmS
# W74x+NjxTVkb6LAe+vbVoEI+7xD9SYTm/8xplaBugPBxjQ9aULOxGm0gyTmvDorq
# j9Cz3X6J0QReZ1dwTgjZz3uoqNTEJkzAj+dTdGtCXeMy06q4N15R2qGCAgswggIH
# BgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQK
# ExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBT
# dGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkGBSsO
# AwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yMDA2MTQyMzI3NTdaMCMGCSqGSIb3DQEJBDEWBBQqrJ5mbNYoOsWdhTcJOaj5
# kG0xqjANBgkqhkiG9w0BAQEFAASCAQBSm2qOguPMlLGhaPZLKIC8m1BCGK9JKbPY
# cR217V8sgoodPkJ6lPJOSzGwgq1w3Cin2aUOvNQ7fO0PGd03aF38uK/1JAkCupfO
# xyWc7465J9VtFrctq5pHgO+fTyQqVmWExdNa8FtLWQbH4+x6HPZONPZKAiJkOv7D
# cmhevhYargFdBPB8tuy9fi93tvHBlrYTmQutxDJqEyWUe/c0SQQ8jboSiYtBj8VD
# FVIudnNVHG4/vumrDBsWTN0OfGOmON2zDG3xKCRh8DH47tvxvq3AAPB97P2vkGjg
# lW8meqx+XdRe+PViDrjghjbLHm25+l8ZFV0sRDpdTh3S4UQ/BdS9
# SIG # End signature block
