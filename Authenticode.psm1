#Requires -version 2.0

function ConvertTo-StringData { 
   [CmdletBinding()]
   param(
      [Parameter(ValueFromPipeline=$true)]
      $InputObject
   )
   switch($InputObject.GetType().FullName) {
      'System.Collections.Hashtable' { ($InputObject.Keys | % { "$_=$($InputObject.$_)" }) -join "`n" }
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
      if($Name) { 
         $Script:UserCertificate = Get-AuthenticodeCertificate $Name
      }
   }
   end {

      $ModuleManifest = Join-Path $PSScriptRoot Authenticode.psd1
      if(Test-Path $ModuleManifest) {
         try {         
            $OldCertificateString = (((Get-Content $ModuleManifest) -join "`n") -replace '(?s).*Certificates\s+=\s+ConvertFrom-StringData\s+"(.*)".*','$1')
            $Certificates = ConvertFrom-StringData $OldCertificateString
         } catch {
            $OldCertificateString = $null
            $Certificates = @{}
         }
      } else {
         $OldCertificateString = ""
         $Certificates = @{}
      }
      
      ## If they don't have a cert, or they haven't stored it...
      if(!(Test-Path Variable:Script:UserCertificate) -or 
         ($Script:UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) -or
         ($Script:UserCertificate.Thumbprint -ne $Certificates.${Env:ComputerName})
      ) {
         ## Verbose output
         if($VerbosePreference -gt "SilentlyContinue") {
            if(!(Test-Path Variable:Script:UserCertificate)) {
               Write-Verbose "Loading User Certificate from Module Config: $($Certificates.${Env:ComputerName} )"
            } else {
               Write-Verbose "Saving User Certificate to Module Config: ($($Script:UserCertificate.Thumbprint) -ne $($Certificates.${Env:ComputerName}))"
            }
         }
         
         Write-Debug "PrivateData: $($ExecutionContext.SessionState.Module | fl * | Out-String)"
         ## If they don't have a cert
         if(!(Test-Path Variable:Script:UserCertificate) -or $Script:UserCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $Script:UserCertificate = Get-AuthenticodeCertificate $Certificates.${Env:ComputerName}
         }
         Write-Verbose "Confirming Certificate: $($Script:UserCertificate.Thumbprint)"
         
         ## If their cert isn't stored at least temporarily...
         if($Script:UserCertificate -and (!$Certificates.${Env:ComputerName} -or
                                         ($Certificates.${Env:ComputerName} -ne $Script:UserCertificate.Thumbprint)))
         {
            ## Store it temporarily ...
            $Certificates.${Env:ComputerName} = $Script:UserCertificate.Thumbprint
            
            ## And ask them if they want to store it permanently
            Write-Verbose "Updating Module Metadata"
            if($Host.UI -and $Host.UI.PromptForChoice -and (0 -eq
               $Host.UI.PromptForChoice("Keep this certificate for future sessions?", $Script:UserCertificate,
               [Management.Automation.Host.ChoiceDescription[]]@("&Yes","&No"), 0))
            ) {
               Write-Warning $Certificates
               $NewCertificateString = ConvertTo-StringData $Certificates
               if(!(Test-Path $ModuleManifest) -or $OldCertificateString -eq $Null) {
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

function Get-AuthenticodeCertificate {
   [CmdletBinding()]
   param (
      $Name = $(Get-UserCertificate)
   )

   end {
      $Certificate = $Name
      # Until they get a cert, or hit ENTER without any input
      while($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
         trap {
            Write-Host "The authenticode module requires a code-signing certificate, and can't find yours!"
            Write-Host
            Write-Host "If this is the first time you've seen this error, please run Get-AuthenticodeCertificate by hand and specify the full path to your PFX file, or the Thumbprint of a cert in your OS Cert store -- and then answer YES to save that cert in the 'PrivateData' of the Authenticode Module metadata."
            Write-Host
            Write-Host "If you have seen this error multiple times, you may need to manually create a module manifest for this module with the path to your cert, and/or specify the certificate name each time you use it."
            Write-Error $_
            continue      
         }
         ## If they haven't specified the name, prompt them:
         if(!$Name) {
            push-Location Cert:\
            $certs = @(Get-ChildItem -Recurse -CodeSigningCert | Sort NotAfter)
            pop-Location
            if($certs.Count) {
               Write-Host "You have $($certs.Count) code signing certificates in your local certificate storage which you can specify by partial Thumbprint, or you may specify the path to a .pfx file:" -fore cyan
               $certs | Out-Host
            }
            $Name = $(Read-Host "Please specify a user certificate (wildcards allowed)")
            if(!$Name) { return }
         }
         
         Write-Verbose "Certificate Path: $Name"
         ## Check "CurrentUsers\My" first, because it's MOST LIKELY there, and it will be MUCH faster in some cases.
         $ResolvedPath = Get-ChildItem Cert:\CurrentUser\My -Recurse -CodeSigningCert | Where {$_.ThumbPrint -like $Name } | Select -Expand PSPath
         if(!$ResolvedPath) {
            ## We have to at least check the other folders too, if we didn't find it.
            $ResolvedPath = Get-ChildItem Cert:\ -Recurse -CodeSigningCert | Where {$_.ThumbPrint -like $Name } | Select -Expand PSPath
         }
         
         if(!$ResolvedPath) {
            Write-Verbose "Not a Certificate path: $Path"
            $ResolvedPath = Resolve-Path $Name -ErrorAction "SilentlyContinue" | Where { Test-Path $_ -PathType Leaf -ErrorAction "SilentlyContinue" }
         }
         
         if(!$ResolvedPath) {
            Write-Verbose "Not a full or legit relative path Path: $ResolvedPath"
            $ResolvedPath = Resolve-Path (Join-Path $PsScriptRoot $Name -ErrorAction "SilentlyContinue") -ErrorAction "SilentlyContinue" | Where { Test-Path $_ -PathType Leaf -ErrorAction "SilentlyContinue" }
            Write-Verbose "Resolved File Path: $ResolvedPath"
         }
         
         if(@($ResolvedPath).Count -gt 1) {
            throw "You need to specify enough of the name to narrow it to a single certificate. '$Name' returned $(@($ResolvedPath).Count):`n$($ResolvedPath|Out-String)"
         }

         $Certificate = get-item $ResolvedPath -ErrorAction "SilentlyContinue"
         if($Certificate -is [System.IO.FileInfo]) {
            $Certificate = Get-PfxCertificate $Certificate -ErrorAction "SilentlyContinue"
         }
         $Name = $Null # Blank it out so we re-prompt them
      }
      Write-Verbose "Certificate: $($Certificate | Out-String)"
      return $Certificate
   }
}

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
      .INPUTTYPE
         System.Management.Automation.Signature
      .RETURNVALUE
         Boolean value representing whether the script's signature is valid, or YOUR certificate
   #>
   [CmdletBinding()]
   param (
      # Specifies the signature object to test. This should be the output of Get-AuthenticodeSignature.
      [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
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
      .INPUTTYPE
         String. You can pipe a file path to Set-AuthenticodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
   #>
   [CmdletBinding(DefaultParameterSetName="File")]
   param (
      # Specifies the path to a file that is being signed.
      # Aliases                      Path, FullName      
      [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="File")]
      [Alias("FullName")]
      [ValidateScript({ 
         if((resolve-path $_).Provider.Name -ne "FileSystem") {
            throw "Specified Path is not in the FileSystem: '$_'" 
         }
         return $true
      })]
      [string[]]$FilePath,

      # Specifies a module name (or path) to sign. 
      # When you specify a module name, all of the files in that folder and it's subfolders are signed (if they are signable).
      [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="Module")]
      [Alias("ModuleName")]
      [string[]]$ModuleBase,

      # Specifies the certificate that will be used to sign the script or file.
      # Enter a certificate thumbprint (supports wildcards), or variable that stores the certificate or an expression that gets the certificate.
      # If the certificate is not valid or does not have code-signing authority, the command fails.
      #
      # To find a certificate, use Get-AuthenticodeCertificate
      # To set (or see) the default certificate, use Get-UserCertificate.
      [Parameter(Position=2, Mandatory=$false)]
      $Certificate,

      # Allows the cmdlet to append a signature to a read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.
      [Switch]$Force,

      # Specifies the hashing algorithm that Windows uses to compute the digital signature for the file. The default is SHA1, which is the Windows default hashing algorithm.

      # Files that are signed with a different hashing algorithm might not be recognized on other systems.
      [ValidateSet("SHA","MD5","SHA1","SHA256","SHA384","SHA512")]
      [String]$HashAlgorithm, #="SHA1"

      # Determines which certificates in the certificate trust chain are included in the digital signature. "NotRoot" is the default.
      # Valid values are:
      # -- Signer: Includes only the signer's certificate.
      # -- NotRoot: Includes all of the certificates in the certificate chain, except for the root authority.
      # -- All: Includes all the certificates in the certificate chain.
      [ValidateSet("Signer","NotRoot","All")]
      [String]$IncludeChain, #="NotRoot"

      # Uses the specified time stamp server to add a time stamp to the signature. Type the URL of the time stamp server as a string.
      # Defaults to Verisign's server: http://timestamp.verisign.com/scripts/timstamp.dll

      # The time stamp represents the exact time that the certificate was added to the file. A time stamp prevents the script from failing if the certificate expires because users and programs can verify that the certificate was valid atthe time of signing.
      [String]$TimestampServer = "http://timestamp.verisign.com/scripts/timstamp.dll"
   )
   begin {
      Write-Verbose $("ParameterSetName Begin: " + $PSCmdlet.ParameterSetName)
      ## Can't specify this as a default value if we're in the pipeline, it doesn't get bound in time?
      if(!$Certificate) {
         $Certificate = Get-UserCertificate
      }
      if($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
         $Certificate = Get-AuthenticodeCertificate $Certificate
      }
      $PSBoundParameters["Certificate"] = $Certificate
      $PSBoundParameters["TimestampServer"] = $TimestampServer
   }
   process {
      Write-Verbose $("ParameterSetName Process: " + $PSCmdlet.ParameterSetName)

      if($PSCmdlet.ParameterSetName -eq "Module"){
         $ModuleBase = $ModuleBase | Split-Path -Leaf
         Write-Verbose "Signing Modules: $($ModuleBase -join ', ')"
         $FilePath = Get-Module -List $ModuleBase | Split-Path |
                        Get-ChildItem -Recurse |
                        Where-Object { !$_.PsIsContainer -and  (".ps1",".psm1",".psd1",".ps1xml",".dll",".exe" -contains $_.Extension) } | 
                        Select-Object -Expand FullName

         $null = $PSBoundParameters.Remove("ModuleBase")
         Write-Verbose "Signing Files: $($FilePath | Out-String)"
      }
      
      Write-Verbose $("ParameterSetName 4: " + $PSCmdlet.ParameterSetName)
      foreach($file in @($FilePath)) {
         trap { Write-Warning "Could not sign file '$File' `n`n because $_"; continue }
         $PSBoundParameters.FilePath = $file
         if(Test-Path $file -Type Leaf) {
            Write-Verbose "Set Authenticode Signature on $FilePath with $($Certificate | Out-String)"
            $null = $PSBoundParameters.Remove("ModuleBase")
            Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
         } else {
            $PSBoundParameters.FilePath = Get-ChildItem $file -Recurse |
               Where-Object { !$_.PsIsContainer -and  (".ps1",".psm1",".psd1",".ps1xml",".dll",".exe" -contains $_.Extension) } | 
               Select-Object -Expand FullName
            Microsoft.PowerShell.Security\Set-AuthenticodeSignature @PSBoundParameters
         }
      }
      return
   }
}

function Get-AuthenticodeSignature {
   <#
      .SYNOPSIS

         Gets information about the Authenticode signature in a file.
      .DESCRIPTION
         The Get-AuthenticodeSignature function gets information about the Authenticode signature in a file. If the file is not signed, the information is retrieved, but the fields are blank.
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
         ls *.ps1,*.psm1,*.psd1 | Get-AuthenticodeSignature | Where {!(Test-AuthenticodeSignature $_ -Valid)} | gci | Set-AuthenticodeSignature

         This command gets information about the Authenticode signature in all of the script and module files, and tests the signatures, then signs all of the ones that are not valid.
      .INPUTTYPE
         String. You can pipe the path to a file to Get-AuthenticodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
      ###################################################################################################>
   [CmdletBinding()]
   param (
      # The path to the file(s) being examined. Wildcards are permitted, but they must lead to file(s).
      # Aliases                      Path, FullName
      [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
      [Alias("FullName","Path")]
      [ValidateScript({ 
         if((resolve-path $_).Provider.Name -ne "FileSystem") {
            throw "Specified Path is not in the FileSystem: '$_'" 
         }
         if(!(Test-Path -PathType Leaf $_)) { 
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
      .INPUTTYPE
         String. You can pipe the path to a file to Get-AuthenticodeSignature.
      .RETURNVALUE
         System.Management.Automation.Signature
      ###################################################################################################>
   [CmdletBinding()]
   [OutputType("System.Management.Automation.Signature")]
   param ( 
      # The path to the file(s) being examined. Wildcards are permitted, but they must lead to a single file.
      # Aliases                      Path, FullName
      [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
      [Alias("FullName","Path")]
      [ValidateScript({ 
         if((resolve-path $_).Provider.Name -ne "FileSystem") {
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
      if(!(Test-Path -PathType Leaf $FilePath)) { 
         # if($ErrorAction -ne "SilentlyContinue") {
         #    Write-Error "Specified Path is not a File: '$FilePath'"
         # }
      } else {

         foreach($sig in Get-AuthenticodeSignature -FilePath $FilePath) {
         
         # Broken only returns ONLY things which are HashMismatch
         if($BrokenOnly   -and $sig.Status -ne "HashMismatch") 
         { 
            Write-Debug "$($sig.Status) - Not Broken: $FilePath"
            return 
         }
         
         # Trusted only returns ONLY things which are Valid
         if($ValidOnly    -and $sig.Status -ne "Valid") 
         { 
            Write-Debug "$($sig.Status) - Not Trusted: $FilePath"
            return 
         }
         
         # AllValid returns only things that are SIGNED and not HashMismatch
         if($TrustedOnly  -and (($sig.Status -ne "HashMismatch") -or !$sig.SignerCertificate) ) 
         { 
            Write-Debug "$($sig.Status) - Not Valid: $FilePath"
            return 
         }
         
         # InvalidOnly returns things that are Either NotSigned OR HashMismatch ...
         if($InvalidOnly  -and ($sig.Status -eq "Valid")) 
         { 
            Write-Debug "$($sig.Status) - Valid: $FilePath"
            return 
         }
         
         # Unsigned returns only things that aren't signed
         # NOTE: we don't test using NotSigned, because that's only set for .ps1 or .exe files??
         if($UnsignedOnly -and $sig.SignerCertificate ) 
         { 
            Write-Debug "$($sig.Status) - Signed: $FilePath"
            return 
         }
         
         # Mine returns only things that were signed by MY CertificateThumbprint
         if($MineOnly     -and (!($sig.SignerCertificate) -or ($sig.SignerCertificate.Thumbprint -ne $((Get-UserCertificate).Thumbprint))))
         {
            Write-Debug "Originally signed by someone else, thumbprint: $($sig.SignerCertificate.Thumbprint)"
            Write-Debug "Does not match your default certificate print: $((Get-UserCertificate).Thumbprint)"
            Write-Debug "     $FilePath"
            return 
         }

         # NotMine returns only things that were NOT signed by MY CertificateThumbprint
         if($NotMineOnly  -and (!($sig.SignerCertificate) -or ($sig.SignerCertificate.Thumbprint -eq $((Get-UserCertificate).Thumbprint))))
         {
            if($sig.SignerCertificate) {
               Write-Debug "Originally signed by you, thumbprint: $($sig.SignerCertificate.Thumbprint)"
               Write-Debug "Matches your default certificate print: $((Get-UserCertificate).Thumbprint)"
               Write-Debug "     $FilePath"
            }
            return 
         }
         
         if(!$BrokenOnly  -and !$TrustedOnly -and !$ValidOnly -and !$InvalidOnly -and !$UnsignedOnly -and !($sig.SignerCertificate) ) 
         { 
            Write-Debug "$($sig.Status) - Not Signed: $FilePath"
            return 
         }
         
         get-childItem $sig.Path
      }}
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
   param($Path=".", $Filter= "*.ps*", [Switch]$Recurse, $CertPath, [Switch]$NoNotify)

   if(!$NoNotify -and (Get-Module Growl -ListAvailable -ErrorAction 0)) {
      Import-Module Growl
      Register-GrowlType AutoSign "Signing File" -ErrorAction 0
   } else { $NoNotify = $false }

   $realItem = Get-Item $Path -ErrorAction Stop
   if (-not $realItem) { return } 

   $Action = {
      ## Files that can't be signed show up as "UnknownError" with this message:
      $InvalidForm = "The form specified for the subject is not one supported or known by the specified trust provider"
      ## Files that are signed with a cert we don't trust also show up as UnknownError, but with different messages:
      # $UntrustedCert  = "A certificate chain could not be built to a trusted root authority"
      # $InvalidCert = "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"
      # $ExpiredCert = "A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file"
      
      ForEach($file in Get-ChildItem $eventArgs.FullPath | Get-AuthenticodeSignature | 
         Where-Object { $_.Status -ne "Valid" -and $_.StatusMessage -ne $invalidForm } | 
         Select-Object -ExpandProperty Path ) 
      {
         if(!$NoNotify) {
            Send-Growl AutoSign "Signing File" "File $($eventArgs.ChangeType), signing:" "$file"
         }
         if($CertPath) {
            Set-AuthenticodeSignature -FilePath $file -Certificate $CertPath
         } else {
            Set-AuthenticodeSignature -FilePath $file
         }
      }
   }
   $watcher = New-Object IO.FileSystemWatcher $realItem.Fullname, $filter -Property @{ IncludeSubdirectories = $Recurse }
   Register-ObjectEvent $watcher "Created" "AutoSignCreated$($realItem.Fullname)" -Action $Action > $null
   Register-ObjectEvent $watcher "Changed" "AutoSignChanged$($realItem.Fullname)" -Action $Action > $null
   Register-ObjectEvent $watcher "Renamed" "AutoSignChanged$($realItem.Fullname)" -Action $Action > $null
}

Set-Alias gas          Get-AuthenticodeSignature -Description "Authenticode Module Alias"
Set-Alias sas          Set-AuthenticodeSignature -Description "Authenticode Module Alias"
Set-Alias slas         Select-AuthenticodeSigned -Description "Authenticode Module Alias"
Set-Alias sign         Set-AuthenticodeSignature -Description "Authenticode Module Alias"

Export-ModuleMember -Alias gas,sas,slas,sign -Function Set-AuthenticodeSignature, Get-AuthenticodeSignature, Test-AuthenticodeSignature, Select-AuthenticodeSigned, Get-UserCertificate, Get-AuthenticodeCertificate, Start-AutoSign


# SIG # Begin signature block
# MIIXxAYJKoZIhvcNAQcCoIIXtTCCF7ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUu+Va8Cy2oCdXSwpacscHgmoL
# 6sygghL3MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# ggUmMIIEDqADAgECAhACXbrxBhFj1/jVxh2rtd9BMA0GCSqGSIb3DQEBCwUAMHIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJ
# RCBDb2RlIFNpZ25pbmcgQ0EwHhcNMTUwNTA0MDAwMDAwWhcNMTYwNTExMTIwMDAw
# WjBtMQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxFzAVBgNVBAcTDldl
# c3QgSGVucmlldHRhMRgwFgYDVQQKEw9Kb2VsIEguIEJlbm5ldHQxGDAWBgNVBAMT
# D0pvZWwgSC4gQmVubmV0dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AJfRKhfiDjMovUELYgagznWf+HFcDENk118Y/K6UkQDwKmVyVOvDyaVefjSmZZcV
# NZqqYpm9d/Iajf2dauyC3pg3oay8KfXAADLHgbmbvYDc5zGuUNsTzMUOKlp9h13c
# qsg898JwpRpI659xCQgJjZ6V83QJh+wnHvjA9ojjA4xkbwhGp4Eit6B/uGthEA11
# IHcFcXeNI3fIkbwWiAw7ZoFtSLm688NFhxwm+JH3Xwj0HxuezsmU0Yc/po31CoST
# nGPVN8wppHYZ0GfPwuNK4TwaI0FEXxwdwB+mEduxa5e4zB8DyUZByFW338XkGfc1
# qcJJ+WTyNKFN7saevhwp02cCAwEAAaOCAbswggG3MB8GA1UdIwQYMBaAFFrEuXsq
# CqOl6nEDwGD5LfZldQ5YMB0GA1UdDgQWBBQV0aryV1RTeVOG+wlr2Z2bOVFAbTAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1
# oDOgMYYvaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1n
# MS5jcmwwNaAzoDGGL2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3Vy
# ZWQtY3MtZzEuY3JsMEIGA1UdIAQ7MDkwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUH
# AgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgYQGCCsGAQUFBwEBBHgw
# djAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUF
# BzAChkJodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNz
# dXJlZElEQ29kZVNpZ25pbmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0B
# AQsFAAOCAQEAIi5p+6eRu6bMOSwJt9HSBkGbaPZlqKkMd4e6AyKIqCRabyjLISwd
# i32p8AT7r2oOubFy+R1LmbBMaPXORLLO9N88qxmJfwFSd+ZzfALevANdbGNp9+6A
# khe3PiR0+eL8ZM5gPJv26OvpYaRebJTfU++T1sS5dYaPAztMNsDzY3krc92O27AS
# WjTjWeILSryqRHXyj8KQbYyWpnG2gWRibjXi5ofL+BHyJQRET5pZbERvl2l9Bo4Z
# st8CM9EQDrdG2vhELNiA6jwenxNPOa6tPkgf8cH8qpGRBVr9yuTMSHS1p9Rc+ybx
# FSKiZkOw8iCR6ZQIeKkSVdwFf8V+HHPrETCCBTAwggQYoAMCAQICEAQJGBtf1btm
# dVNDtW+VUAgwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UE
# AxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoX
# DTI4MTAyMjEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNl
# cnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAPjTsxx/DhGvZ3cH0wsxSRnP0PtFmbE620T1f+Wo
# ndsy13Hqdp0FLreP+pJDwKX5idQ3Gde2qvCchqXYJawOeSg6funRZ9PG+yknx9N7
# I5TkkSOWkHeC+aGEI2YSVDNQdLEoJrskacLCUvIUZ4qJRdQtoaPpiCwgla4cSocI
# 3wz14k1gGL6qxLKucDFmM3E+rHCiq85/6XzLkqHlOzEcz+ryCuRXu0q16XTmK/5s
# y350OTYNkO/ktU6kqepqCquE86xnTrXE94zRICUj6whkPlKWwfIPEvTFjg/Bougs
# UfdzvL2FsWKDc0GCB+Q4i2pzINAPZHM8np+mM6n9Gd8lk9ECAwEAAaOCAc0wggHJ
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4
# MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3JsME8GA1UdIARIMEYwOAYKYIZIAYb9bAAC
# BDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAoG
# CGCGSAGG/WwDMB0GA1UdDgQWBBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAfBgNVHSME
# GDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQsFAAOCAQEAPuwN
# WiSz8yLRFcgsfCUpdqgdXRwtOhrE7zBh134LYP3DPQ/Er4v97yrfIFU3sOH20ZJ1
# D1G0bqWOWuJeJIFOEKTuP3GOYw4TS63XX0R58zYUBor3nEZOXP+QsRsHDpEV+7qv
# tVHCjSSuJMbHJyqhKSgaOnEoAjwukaPAJRHinBRHoXpoaK+bp1wgXNlxsQyPu6j4
# xRJon89Ay0BEpRPw5mQMJQhCMrI2iiQC/i9yfhzXSUWW6Fkd6fp0ZGuy62ZD2rOw
# jNXpDd32ASDOmTFjPQgaGLOBm0/GkxAG/AeB+ova+YJJ92JuoVP6EpQYhS6Skepo
# bEQysmah5xikmmRR7zGCBDcwggQzAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAv
# BgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EC
# EAJduvEGEWPX+NXGHau130EwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKoflTJ0GlyOX2eKxcHX
# 8LYk4p+pMA0GCSqGSIb3DQEBAQUABIIBADnDmr5+cRNaH0B+OW8IDqZptMjoX48s
# uyfG6uH1PtpU12uSOhEsh7WyCrHL83LlXqCt1cSFqMH1etQ+QH+aZkDIFb5RcY4D
# 9WXQRSoliH7lsp3oDkPCKnJYZh/jpCkbHBHzMBnsteOBKlvUw1qqQ0FIkwCd2uz3
# qnZN0hGuLGwahVQ2DCmXWfbL5f14Cu4PgJIvtI8fK0FOaw2VAc8eAbxW5OlE4yLR
# 5eZyZyU6x7rTep5f0Hbg6YOmxBLIylBWPBPK/1Fc8WrWdLSc8bbAAxORmfNfC5Ep
# GlApcSbT/pGYvOS94HlkB5215e8mBNoJmzIGj0YdyKslmAjorQTpyNWhggILMIIC
# BwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUg
# U3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUr
# DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx
# DxcNMTUwNTA1MDUyOTU1WjAjBgkqhkiG9w0BCQQxFgQUKS7O0z1LgYirWVfxnRH6
# CT/6OIUwDQYJKoZIhvcNAQEBBQAEggEACURNO3bv5G+Uz/5liNvkOgPlwM/2CdEb
# OqlMMVNbGNkG5X/tD+w7iJD44msdsX7AGKUhhy8Nyw/CFVrV1eH7y06d546zB1E9
# VqtqcD6HpCsxDQRdgTLqf/kzEP6F/LSC2k0EWfzfQjcg+7M/2suo1BlxOqWTQ1ej
# 9QG0Qg/5UTKAzeU50rxAlwpWTnIb3UkYmEWu5G4sBCvij/6EPzH9/J0MgnZglNPO
# vgDTy01fYyIPdr1IGqnIbOg00BfUbetVM0GXR5m7gHwYxSztMkGtAykdXmI22KD3
# 6Q/jrbqbdt/2S7eR6o3uLByK4iZM1IHXNp6jayKhJHms2T5XdzNLvg==
# SIG # End signature block
