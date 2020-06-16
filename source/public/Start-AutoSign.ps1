
function Start-AutoSign {
    <#
        .SYNOPSIS
            Start a FileSystemWatcher to automatically sign scripts when you save them
        .DESCRIPTION
            Create a FileSystemWatcher with a scriptblock that uses the Authenticode script Module to sign anything that changes
        .NOTES
            Don't run this on a location where you're going to be generating hundreds of files ;)
    #>
    [CmdletBinding()]
    param(
        # The path to the folder you want to monitor.
        # Defaults to the current working directory from the FileSystem provider.
        [Parameter()]
        $Path = $(Get-Location -Provider FileSystem),

        # A filter to select only certain files.
        # Defaults to *.ps* to sign for instance .ps1, .psm1, .psd1, and .ps1xml
        $Filter = "*.ps*",

        # Whether we should also watch and autosign files in subdirectories
        # Defaults to false
        [Switch]$Recurse,

        # The path or name of a certain certificate, to override the defaults from the Authenticode Module
        # By default uses the certificate returned by Get-UserCertificate
        $CertPath,

        # Whether wo should avoid using BurntToast to notify the user each time we sign something.
        [Switch]$NoNotify
    )

    if (!$NoNotify -and (Get-Module BurntToast -ListAvailable -ErrorAction 0)) {
        Import-Module BurntToast
    } else {
        $NoNotify = $false
    }

    $realItem = Get-Item $Path -ErrorAction Stop
    if (-not $realItem) {
        return
    }

    $Action = {
        ## Files that can't be signed show up as "UnknownError" with this message:
        $InvalidForm = "The form specified for the subject is not one supported or known by the specified trust provider"
        ## Files that are signed with a cert we don't trust also show up as UnknownError, but with different messages:
        # $UntrustedCert  = "A certificate chain could not be built to a trusted root authority"
        # $InvalidCert = "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"
        # $ExpiredCert = "A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file"

        foreach ($file in Get-ChildItem $eventArgs.FullPath | Get-AuthenticodeSignature |
            Where-Object { $_.Status -ne "Valid" -and $_.StatusMessage -ne $invalidForm } |
            Select-Object -ExpandProperty Path ) {
            if (!$NoNotify) {
                New-BurntToastNotification -Text "Signing File", "File $($eventArgs.ChangeType), signing:", "$file"
            }
            if ($CertPath) {
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