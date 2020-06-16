## Authenticode PowerShell Module

This module provides a wrapper for Set-AuthenticodeSignature which prompts you initially with the available code-signing certificates, remembers your selected code-signing certificate, and allows wildcard matching the thumbprint of the certificate.

The wrappers for Get-AuthenticodeSignature and Set-AuthenticodeSignature (which work all the way back to PowerShell 2) properly parse paths, support pipeline input, and support signing whole folders and modules at once.

The module also provides a few helper commands for listing Code Signing certificates from the machine, and for testing the authenticode status for a bunch of scripts all at once, so you can re-sign edited scripts or easily remove scripts which have been tampered with.

### Building the module

This module uses the [ModuleBuilder](https://github.com/PoshCode/ModuleBuilder), so to recreate the full module you need to run `Build-Module` in the root (against the `build.psd1` file) which will by default produce a versioned output folder _in the root_.

You can optionally specify `-OutputDirectory ..\Output` when calling `Build-Module` to put the output in a "Output" subfolder of the root (in ModuleBuilder, paths other than the `SourcePath` are relative to the module manifest, i.e. `.\source\Authenticode.psd1`).