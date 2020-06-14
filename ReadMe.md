## Authenticode PowerShell Module

This module provides a wrapper for Set-AuthenticodeCertificate which remembers your code-signing certificate, and prompts you initially with the available certs, and allows wildcard matching the thumbprint of the certificate.

The wrappers for Get-AuthenticodeCertificate and Set-AuthenticodeCertificate (which work all the way back to PowerShell 2) properly parse paths, support pipeline intput, and support signing whole folders and modules at once.

The module also provides a few helper commands for listing Code Signing certificates from the machine, and for testing the authenticode status for a bunch of scripts all at once, so you can re-sign edited scripts or easily remove scripts which have been tampered with.

