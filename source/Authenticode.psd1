@{

# Script module or binary module file associated with this manifest.
RootModule = 'Authenticode.psm1'

# Version number of this module.
ModuleVersion = '2.6.1'

# ID used to uniquely identify this module
GUID = '4a14168f-41b8-4bc4-9ebf-83d5e6b84476'

# Author of this module
Author = 'Joel Bennett'

# Company or vendor of this module
CompanyName = 'HuddledMasses.org'

# Copyright statement for this module
Copyright = 'Copyright (c) 2008-2015, Joel Bennett'

# Description of the functionality provided by this module
Description = 'Function wrappers for Authenticode Signing cmdlets'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @('Set-AuthenticodeSignature','Get-AuthenticodeSignature','Test-AuthenticodeSignature',
                    'Select-AuthenticodeSigned','Start-AutoSign',
                    'Get-AuthenticodeCertificate','Get-UserCertificate')

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = 'gas','sas','slas','sign'

# List of all files packaged with this module
FileList = 'Authenticode.psm1', 'Authenticode.psd1'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{
    Certificates = ConvertFrom-StringData "
	XPS=881B870CE094C28F04EBAA1954BDDC49AC9181F7
	DUO=881B870CE094C28F04EBAA1954BDDC49AC9181F7
	"
    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Authenticode','CodeSigning','Certificates')

        # A URL to the license for this module.
        LicenseUri = 'http://opensource.org/licenses/ms-pl'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/Jaykul/Authenticode'

    } # End of PSData hashtable
} # End of PrivateData hashtable

}
