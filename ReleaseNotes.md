## Release Notes

#### 2.6.1-beta
    This version. Split for use with ModuleBuilder's Build-Module, and updated the doc comments a bit.
    I don't currently _have_ a valid code-signing certificate, so I'm not adding tests yet

#### 2.6
    Updated to work with PowerShell 5 (PowerShellGet) manifests without breaking things
    Made the Set-AuthenticodeSignature Path parameter support folders (recursively signs all PowerShell code and dll/exe files)

#### 2.5
    Added support for storing a different default cert per computer in the psd1
    Now I can sync from work to home, and still use the right cert in each place.

#### 2.4
    Added a -Module parameter to the Set-AuthenticodeSignature
    It will recursively sign all the signable files in a module...
    Tweaked Get-AuthenticodeCertificate to first search Cert:\CurrentUser\My ... It's much faster on my home PC this way

#### 2.3
    Reworked Get-UserCertificate and Get-AuthenticodeCertificate for better behavior

#### 2.2
    Added sorting and filtering the displayed certs, and the option to save your choice

#### 2.1
    Added some extra exports and aliases, and included my Start-AutoSign script...

#### 2.0
    Updated to work with PowerShell 2.0 RTM and add -TimeStampUrl support

#### 1.7
    Modified the reading of certs to better support people who only have one :)

#### 1.6
    Converted to work with CTP 3, and added function help comments

#### 1.5
    Moved the default certificate setting into the module info Authenticode.psd1 file
    Note: If you get this off PoshCode, you'll have to create it yourself, see below:

#### 1.4
    Moved the default certificate setting into an external psd1 file.

#### 1.3
    Fixed some bugs in If-Signed and renamed it to Select-AuthenticodeSigned
    Added -MineOnly and -NotMineOnly switches to Select-AuthenticodeSigned

#### 1.2
    Added a hack workaround to make it appear as though we can sign and check PSM1 files
    It's important to remember that the signatures are NOT checked by PowerShell yet...

#### 1.1
    Added a filter "If-Signed" that can be used like: ls | If-Signed
    With optional switches: ValidOnly, InvalidOnly, BrokenOnly, TrustedOnly, UnsignedOnly
    Commented out the default Certificate which won't work for "you"

#### 1.0
    First working version, includes wrappers for Get and Set