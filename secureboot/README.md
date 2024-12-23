# UEFI Secure Boot Customization
## Introduction
UEFI Secure Boot can be customized on most modern computing devices. Customization allows device owners to tailor boot security to their risk tolerance, add Secure Boot compatibility to boot binaries lacking signatures recognized by vendor factory configuration, and shrink or expand the influence of outside vendors regarding the trustworthiness of boot binaries. This repository is designed to complement the full NSA technical report titled [UEFI Secure Boot Customization](https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF).

Secure Boot utilizes the following value stores to make trustworthiness decisions at boot time:

**DBX -- Deny List Database** maintains a list of certificates and hashes that identify boot binaries that are untrusted. DBX is checked first. Binaries denied execution by the DBX do not necessarily halt the device's boot process.

**DB -- Allow List Database** maintains a list of certificates and hashes that identify trusted boot binaries. The DB usually contains one or more production CA certificates that enable Secure Boot to validate signatures on boot binaries from trusted sources.

**KEK -- Key Exchange Key** contains one or more certificates that authorize changes to the DB and DBX. KEKs are particularly useful when revoking trust from something listed in the DB. The KEK also allows vendors to migrate from expiring 2011 Secure Boot DB certificates to newer replacements established in 2023.

**PK -- Platform Key** contains only one certificate which authorizes changes to the KEKs. The PK is usually set by the device vendor.

## Important Customization Distinctions
Secure Boot customization usually takes one of the following forms:

**Partial Customization** involves adding content to the DB, DBX, and/or KEK. Some or all of the Secure Boot values set at the factory will be retained. Influence from system and software vendors is retained. Useful for Windows, Linux, and hypervisors. Great for adding support for unsigned drivers and custom kernels. Partial customization can also be used to react to boot threats prior to the release of patches in some situations.

**Full Customization** involves replacing the PK, KEK, and DB records to those created by the infrastructure administrators. All influence from the system vendor and software vendors is removed. Useful for Linux and hypervisors. Best solution for particularly sensitive organizations or those who compile their own custom operating systems. Full customization also requires significant administrative overhead since the organization will be vetting what is or is not trustworthy and will need to react to vulnerabilities affecting trusted binaries.

## Use Cases
Default configurations of Secure Boot focus on securing the boot chain of components in the Microsoft ecosystem. However, Secure Boot can be leveraged to accomplish many other mission objectives.

- [Plug and play compatibility](uccompatibility.md)
- [Custom live media, driver, and kernel support](uccompile.md)
- [Role separation or license enforcement](ucroles.md)
- [Hypothetical threat mitigation](uchypothetical.md)

## Windows
The Windows Secure Boot ecosystem is managed by Microsoft. Most machines feature a Microsoft KEK, Microsoft Windows Production
CA DB certificate, and UEFI Third Party Marketplace CA 2011 DB certificate. Certificates from 2011 are in the process of being phased out in favor of 2023 certificates. Both 2011 and 2023 certificates may coexist on devices during the transition. Most hardware and software intended for use with
Windows already come with compatibile Secure Boot signatures. Use customization commands in this section to:

- Add support for an operating system or hypervisor that lacks Secure Boot signatures (e.g. older versions of Windows; some Linux distributions)
- Add support for an unsigned driver
- Add DBX entries that may have been marked as optional Windows Updates or that the organization does not trust
- Add a new DB certificate to support a vendor that lacks Microsoft signatures
- Add DB records to trust binaries
- Migrate to or from a DB certificate
- Implement partial Secure Boot Customization

[Windows Secure Boot Customization Hub](Windows.md)

## Linux
Mainstream Linux distributions contain a pre-bootloader named Shim that features a Microsoft signature. Shim contains a
distribution certificate known as the Machine Owner Key (MOK). MOK acts like a software extension of Secure Boot's
firmware DB Allow List. A corresponding extension of the DBX Deny List is known as MOKX. Use the customization commands in this section to:

- Add support for an operating system, hypervisor, driver, bootloader, or other executable content denied by Secure Boot policy
- Add support for a software package that contains a kernel module
- Add DBX entries to distrust binaries
- Add DB entries to trust binaries
- Customize the PK, KEK, DB, DBX, MOK, and/or MOKX
- Reduce the influence of system and software vendors on a system's security posture
- Implement complete and total Secure Boot Customization
- Implement partial Secure Boot customization

[Linux Secure Boot Customization Hub](Linux.md)

## UEFI Configuration
Secure Boot can be customized via the boot-time UEFI configuration interface (most common on desktops, laptops, and tablets) or device management tools (common on servers and workstations). Most system vendors have mechanisms that allow a user/custom mode where the PK, KEK, DB, and/or DBX may be modified by the device owner. 

Server devices are most commonly customized. Additional documentation is available for [Dell EMC Servers](dellemc) and [HPE Servers](hpe).

## Helpful Scripts
### [hex-hashes-to-esl](hex-hashes-to-esl.c)
This hash handler differs from the utility offered in the efi-tools package by focusing on externally created hashes. Examples of hashes to input into this program include hashes produced by a UEFI configuration interface, hashes provided by a system vendor, and hashes copied from another machine. This program does not accept and hash EFI binaries -- all hashing operations must be done outside the program.

### ESL Parser
An ESL is an Extensible Firmware Interface (EFI) Signature List (ESL) file. Each ESL contains at least one certificate or hash used by UEFI Secure Boot. Some ESL files contain many certificates and hashes stored in ESL structures appended to each other. Tools exist to create ESL files or export Secure Boot data into ESL files. NSA has developed several ESL parsers to help with extracting certificates and hashes from ESL files.

- [Python ESL parser](esl-parser.py)
- [PowerShell ESL Parser](esl-parser.ps1) (Windows only)
- [C code ESL parser](esl-parser.c) (deprecated)

Each parser takes an ESL file as input. The parser will export certificates in DER format as well as hashes in HSH format (binary SHA-256). The parsers have been tested against ESL files generated by UEFI configuration interfaces, EFI boot utilities, and command line backup tools.
