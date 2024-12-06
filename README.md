
# Hardware and Firmware Security Guidance 

## Table of Contents
- 1\. [About this Repository](#1-about-this-repository)
- 2\. [Recommended Actions](#2-recommended-actions)
- 3\. [Device Configuration Guidance](#3-device-configuration-guidance)
    - 3\.1\. [Procurement and Acceptance Testing](#31-procurement-and-acceptance-testing)
    - 3\.2\. [Firmware Configuration and Hardening](#32-firmware-configuration-and-hardening)
    - 3\.3\. [UEFI Secure Boot](#33-uefi-secure-boot)
    - 3\.4\. [Zero Trust](#34-zero-trust)
    - 3\.5\. [Baseboard Management Controller](#35-baseboard-management-controller)
- 4\. [Boot Vulnerabilities](#4-boot-vulnerabilities)
    - 4\.1\. [PKFail](#41-pkfail)
    - 4\.2\. [Shim Shady](#41-shim-shady)
    - 4\.3\. [BlackLotus)](#43-BlackLotus)
    - 4\.4\. [BootHole](#44-boothole)
    - 4\.5\. [BootKitty](#45-bootkitty)
- 5\. [Firmware Vulnerabilities](#5-firmware-vulnerabilities)
    - 5\.1\. [LogoFail](#51-logofail)
    - 5\.2\. [Lojax](#52-lojax)
- 6\. [Physical Attack Vulnerabilities](#6-physical-attack-vulnerabilities)
    - 6\.1\. [Bitlocker dTPM Probing](#61-bitlocker-dtpm-probing)
- 7\. [Side Channel Vulnerabilities](#7-side-channel-vulnerabilities)
    - 7\.1\. [General Messaging](#71-general-messaging)
    - 7\.2\. [Historical Guidance](#72-historical-guidance)
- 8\. [Device Integrity](#8-device-integrity)
    - 8\.1\. [TPM Use Cases](#81-tpm-use-cases)
    - 8\.2\. [Reference Integrity Manifest](#82-reference-integrity-manifest)
    - 8\.3\. [Software Bill of Materials](#83-software-bill-of-materials)
- 9\. [Hardware Upgrade Guidance](#9-hardware-upgrade-guidance)
- 10\. [License](#10-license)
- 11\. [Contributing](#11-contributing)
- 12\. [Disclaimer](#12-disclaimer)

## 1. About this Repository
This repository provides content for aiding DoD administrators in verifying systems have applied and enabled mitigations for hardware, firmware, and supply chain vulnerabilities. The repository functions as a companion to NSA Cybersecurity Advisories such as [Cybersecurity Advisories and Guidance](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/). This repository is updated as new information, research, strategies, and guidance are developed.

## 2. Recommended Actions
Updated 12/6/2024 -- Organizations should integrate [acceptance testing](https://media.defense.gov/2023/Sep/28/2003310132/-1/-1/0/CSI_PROCUREMENT_ACCEPTANCE_TESTING_GUIDE.PDF) into their procurement processes. Acceptance testing guards against potential vulnerabilities like PKFail and weaknesses in the supply chain.

## 3. Device Configuration Guidance

### 3.1. Procurement and Acceptance Testing
Organizations should implement automated acceptance testing into their computing asset procurement processes. Acceptance testing assures that devices are received without tampering during the logistics transportation process, arrive with the expected hardware and firmware components, and are configured for secure integration into the enterprise's infrastructure. NSA recommends procuring devices that feature Trusted Platform Module (TPM), Unified Extensible Firmware Interface (UEFI) Secure Boot, and are preloaded with a Platform Certificate based off of Trusted Computing Group (TCG) standards. More detailed guidance can be accessed via [this NSA guidance document](https://media.defense.gov/2023/Sep/28/2003310132/-1/-1/0/CSI_PROCUREMENT_ACCEPTANCE_TESTING_GUIDE.PDF).

NSA also recommends organizations monitor Reference Integrity Manifest (RIM), Software Bill of Materials (SBOM), and Security Protocols and Data Models (SPDM). These technologies -- once adopted and deployed by industry vendors -- provide modern mechanisms to audit the hardware, firmware, and software integrity of enterprise computing devices.

### 3.2. Firmware Configuration and Hardening
Most organizations understand the importance of controlling access to administrative privileges in the operating system environment. However, many organizations overlook the administrative capabilities contained within a device's firmware. Most devices ship without a password applied to the Unified Extensible Firmware Interface (UEFI) configuration interface. NSA recommends organizations set a configuration password, restrict boot devices to only those appropriate for their infrastructure, and disable system components unsuitable for the office environment. Further guidance designed to harden the firmware security posture can be found at the following links:
- [UEFI Defensive Practices Technical Report](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/ctr-uefi-defensive-practices-guidance.pdf)
- [UEFI Lockdown Quick Guidance](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/csi-uefi-lockdown.pdf)
- [Boot Security Modes](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/csi-boot-security-modes-and-recommendations.pdf)

### 3.3. UEFI Secure Boot
Most enterprise-grade servers, laptops, desktops, and other personal computing devices ship with a preconfigured implementation of Unified Extensible Firmware Interface (UEFI) Secure Boot. The system vendor provides a Platform Key (PK), Microsoft provides a Key Exchange Key (KEK), and 2 additional Microsoft certificates -- the Microsoft Windows Production CA and Microsoft UEFI Third Party Marketplace CA -- are usually loaded into the allow list database (DB). The deny list database (DBX) may include hashes of revoked binaries. This standard implementation is usually sufficient for most use cases when properly configured (UEFI native mode with Secure Boot set to enabled in standard/deployed mode).

NSA has published advanced guidance covering how to customize UEFI Secure Boot. Customization may include backing up the existing Secure Boot certificates and hashes, creating new certificates and hashes, and loading custom values into the PK, KEK, DB, and DBX. Customization also implies that an organization will sign their own bootable binaries. Customization requires significant administrative overhead with the potential benefit of protecting against zero day attacks focused on boot security. The full [technical report for customization can be accessed via this link](https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF) with additional resources contained in the [Secure Boot section of this repository](./secureboot/README.md).

### 3.4. Zero Trust
Zero Trust -- a modernized cybersecurity framework -- integrates visibility from multiple vantage points, makes risk-aware access decisions, and automates detection and response. Implementing this framework places network defenders in a better position to secure sensitive data, systems, applications, and services. Device security is a critical pillar of the Zero Trust model. The device pillar builds upon the procurement and acceptance testing, firmware configuration and hardening, and UEFI Secure Boot initiatives identified above by adding automated device inventory, automated scanning of hardware and firmware and software integrity, automated vulnerability and patch management, and centralized device appraisal. There are also considerations for decommissioning devices to remove provisioned and protected data from devices.

Documentation regarding the Zero Trust device pillar [can be found at this NSA document](https://media.defense.gov/2023/Oct/19/2003323562/-1/-1/0/CSI-DEVICE-PILLAR-ZERO-TRUST.PDF). Additional Zero Trust resources and guidance regarding the other framework pillars [can be found via this NSA press release](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3833594/nsas-final-zero-trust-pillar-report-outlines-how-to-achieve-faster-threat-respo/).

### 3.5. Baseboard Management Controller
Baseboard Management Controller (BMC) is an administrative capability integrated into a device's hardware and firmware. BMC enables remote management of devices within an enterprise including if the device is powered off or in a low power state. Most BMC implementations contain the same capabilities as firmware configuration interfaces while adding additional features for managing the storage drives, software images, hardware resource allocation, and network connectivity of the device. A compromise of BMC affords malicious actors persistence in a highly privileged environment. Organizations must secure BMC credentials, limit physical and remote access to BMC, and routinely update BMC firmware -- things easy to overlook.

[NSA has published guidance regarding BMC](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF) and hardening methods. BMCs are most commonly found on server-class computing hardware. However, they may also be present on workstations and network infrastructure. Organizations should take steps to identify and secure all BMC resources within their networks.

## 4. Boot Vulnerabilities

### 4.1. PKFail
Devices affected by PKFail ship with a test certificate loaded as UEFI Secure Boot's Primary Key (PK). Test certificates are not intended for production use and feature weakly protected keys. An attacker with access to a compromised test key can sign malicious commands capable of poisoning or commandeering the Secure Boot process. A client affected by PKFail will accept the malicious commands. Affected systems may show no indicators of Secure Boot dysfunction with the exception of returning a test certificate when an administrator queries the value of the PK.

[Binarly has published extensive research into PKFail](https://www.binarly.io/pkfail) along with a list of known affected devices. NSA recommends acceptance testing as a mitigation to PKFail. Treat all new devices -- including those not yet listed as affected -- as potentially affected. Check the configuration of UEFI Secure Boot as part of an acceptance testing plan. **PKFail is an ongoing concern.**

### 4.2. Shim Shady
Shim is a boot loader used by Linux distributions to extend the Microsoft Secure Boot ecosystem. Shim executes prior to the main bootloader -- usually GRUB. A flaw in Shim allows attackers to perform main-in-the-middle attacks during network boot. Attackers can exploit out-of-bounds vulnerabilities to gain arbitrary code execution at boot time. Patches issued in early 2024 fix Shim Shady and other Shim vulnerabilities. Systems that rely upon Linux should check that the latest Shim version is installed. Windows system owners do not need to perform any action.

A full description of Shim Shady and related vulnerabilities can be found [via documentation posted by Eclypsium](https://eclypsium.com/blog/the-real-shim-shady-how-cve-2023-40547-impacts-most-linux-systems/). Shim Shady has been mitigated as of Q2 2024.

### 4.3. BlackLotus
BlackLotus is the name for malware that exploits a vulnerability named BatonDrop. Vulnerable boot managers for Windows 8, 10, and 11 drop/clear UEFI Secure Boot policy values and fail to enforce the normal verification of boot binaries when given a series of instructions at boot. Malicious actors may substitute their own Secure Boot values and make it falsely appear that a system booted securely. Microsoft has issued patches, revoked trust in affected boot managers, and implemented Code Integrity Boot Policy (CIBP) to mitigate the threat.

NSA recommends patching to the latest versions of Windows to mitigate the threat. Guidance produced prior to complete patching of BatonDrop and BlackLotus can be retrieved from our published [BlackLotus mitigation guide](https://media.defense.gov/2023/Jun/22/2003245723/-1/-1/0/CSI_BlackLotus_Mitigation_Guide.PDF). Additional resources are available from operating system vendors, system vendors, and cybersecurity researchers. BlackLotus has been mitigated as of early 2024.

### 4.4. BootHole
BootHole involves a memory exploit triggered by malicious GRUB configuration files. GRUB is a boot loader most commonly utilized for systems that boot a Linux distribution. The malicious configuration file could be utilized to give attackers arbitrary execution privileges at boot time. Affected versions of GRUB featured UEFI Secure Boot signatures meaning attackers could carry out exploits without encountering resistance from Secure Boot.

[Eclypsium has published deeper details about Boothole](https://eclypsium.com/research/theres-a-hole-in-the-boot/) as well as a list of affected bootloaders. NSA recommends patching to the latest version of actively supported Linux distributions. Supported distributions contain patches to mitigate the flaw and update Secure Boot Advanced Targeting (SBAT) to prevent execution of vulnerabile boot loaders. Guidance written by NSA near the time of disclosure of BootHole can be found at our published [BootHole vulnerability guide](https://www.nsa.gov/portals/75/documents/resources/cybersecurity-professionals/CSA_Mitigate_the_GRUB2_BootHole_Vulnerability_20200730_nsa_gov%20-%20Copy.pdf?ver=2020-07-30-170540-600). Boothole has been mitigated as of late 2020.

### 4.5. BootKitty
BootKitty is a proof-of-concept bootkit designed to execute at boot time and disable signature checking mechanisms within the Linux kernel prior to its initialization. BootKitty is not signed meaning that it is blocked by UEFI Secure Boot. However, BootKitty could be combined with other boot vulnerabilities to bypass Secure Boot protection. South Korea's Korea Information Technology Research Institute (KITRI) is credited for developing BootKitty.

A deeper dive into how BootKitty works can be found via [ESET's report available at this link](https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/). Administrators are reminded to check for firmware updates as part of a scheduled routine and validate that UEFI Secure Boot is configured and operating normally whether in the standard mode or custom mode. **BootKitty is not thought to be an active threat but may be productized in the future in much the same way BlackLotus appeared as a productized exploit of BatonDrop.**

## 5. Firmware Vulnerabilities

### 5.1. LogoFail
Devices affected by LogoFail combine the ability for a user to set a custom boot image with vulnerable image parsing code. Malicious actors can take advantage of the user boot logo customization to gain arbitrary execution at boot time via a malformed image file. Attackers can also leverage the boot environment to gain persistence and defeat several device security solutions. Affected manufacturers have released firmware updates to remove the vulnerability. NSA recommends device owners routinely check for firmware updates.

Additional resources and technical details can be found [on Binarly's LogoFail website](https://www.binarly.io/logofail). LogoFail has been mitigated as of late 2024.

### 5.2. LoJax
LoJax is a malicious modification of the legitimate anti-theft software known as LoJack. Both the malicious variant and the commercial software leverage a firmware module to establish persistence on computing devices. The legitimate commercial version installs an agent to the operating system that reports the device's location and may enable additional features such as remote disablement. The malicious variant installs a malicious agent to the operating system and obeys commands from known attackers. The agent is difficult to remove because it can be restored via the persistent firmware module. Mitigation requires patches to the device firmware which became widely available in early 2019. LoJax was a particularly dangerous threat given that it could bypass UEFI Secure Boot on many systems and restore itself despite intervention from anti-malware solutions in the software environment.

A full description of LoJax and details about the threat [were published by ESET](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/). LoJax has been mitigated since 2019.

## 6. Physical Attack Vulnerabilities

### 6.1. Bitlocker dTPM Probing
Sophisticated attackers with access to physical hardware may be able to defeat Full Disk Encryption (FDE) solutions that leverage discrete TPM (dTPM) -- defined as a discrete integrated circuit (chip) attached to a device's mainboard and wired into a communication bus. Communications between dTPM and the CPU may be vulnerable to eavesdropping when an attacker places probes on the electrical traces connecting the two components. Software and Virtual TPM (vTPM) as well as firmware and integrated TPM (iTPM) are not vulnerable to this attack.

Microsoft recommends deployment of [BitLocker with TPM + PIN enabled](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures) as an effective mitigation. A similar solution exists for the Linux ecosystem known as [Linux Unified Key Setup (LUKS) TPM2 + PIN](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/configuring-automated-unlocking-of-encrypted-volumes-using-policy-based-decryption_security-hardening#configuring-automated-unlocking-of-encrypted-volumes-using-policy-based-decryption_security-hardening). NSA recommends FDEs like BitLocker and LUKS over storage drive unlock passwords at boot time that can prevent a device from receiving critical updates when not unlocked. Robust physical security and access controls are another effective mitigation strategy. **Probing of dTPM communications is an active concern.**

## 7. Side-Channel Vulnerabilities

### 7.1. General Messaging
Most computing hardware produced since 2021 features hardware mitigations against the worst side channel vulnerabilities. Vendors have also issued firmware, microcode, and software patches where appropriate to minimize the threat. However, security researchers continue to discover novel methods of exploiting previously unknown side channels. No specific instructions or guidance is available to combat side channels at this time beyond **patch** (software and firmware), **protect** (monitor integrity, limit user access), and **purchase** (replace systems that are outside support timeframes).

### 6.2. Historical Guidance
Side-channel vulnerabilities, like Spectre and Meltdown, were a focus of this repository in the past. Processor and system vendors have produced hardware revisions and updated firmware to address vulnerabilities widely publicized in 2018 and 2019. NSA considers the original guidance no longer applicable to systems produced in 2021 and newer. [Historical NSA guidance regarding side-channel vulnerabilities can be found here](./sidechannel.md).

## 8. Device Integrity

### 8.1. TPM Use Cases
Trusted Platform Modules (TPMs) are components available on modern computing systems and intended to facilitate several cryptographic, protected storage, and integrity capabilities. NSA recommends acquiring TPMs of version 2.0 or later on devices that support them to be able to leverage their security capabilities for current and future use cases.

DoD Instruction 8500.1 requires inclusion of a TPM for DoD devices subject to DISA STIGs when user credentials and data-at-rest require protection. NSA advocates for several TPM use cases in addition to those required by STIGs, such as for asset management, hardware supply chain security, and boot integrity measurement. Future use cases for the TPM include software supply chain auditing, runtime integrity measurement, and authentication and provisioning to support Zero Trust efforts. TPMs should transition to quantum-resistant cryptography to provide the proper capabilities and assurance for these use cases into the future. As TPM-supporting technologies mature and dependencies are satisfied, these recommended and future use cases may become DoD requirements.

The complete NSA cybersecurity information sheet regarding TPM use cases can be found [at this NSA link](https://media.defense.gov/2024/Nov/06/2003579882/-1/-1/0/CSI-TPM-USE-CASES.PDF).

### 8.2. Reference Integrity Manifest
Reference Integrity Manifest (RIM) is a specification developed by the Trusted Computing Group (TCG). The goal of RIM is to empower administrators to compare the measurements collected by TPMs on devices to those provided by, signed, and assured as trustworthy by vendors. RIM focuses on firmware and software measured by TPMs making it ideal for assessing the integrity of the boot process for devices.

RIM is a prototype technology currently in development. Check out the [TCG's RIM documentation](https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/) for more details. A proof-of-concept implementation of TPM attestation with RIM support can be found in the [Host Integrity at Runtime and Startup (HIRS) project](https://github.com/nsacyber/HIRS).

### 8.3. Software Bill of Materials
Software Bill of Materials (SBOM) is a software mechanism for managing the integrity of software running within the operating system. The most common implementation of SBOM today periodically collects measurement hashes from software loaded onto a device and alerts on known outdated or vulnerable software. Some products have the ability to check the inclusions/dependencies of measured software. The ideal future implementation of SBOM utilizes signed measurement hashes direct from the vendor of software to allow administrators to match up what is running on a device with what the software vendor intended to provide.

SBOM is a relatively new and evolving technology. Check the [Cibersecurity and Infrastructure Security Agency's (CISA) SBOM resource page](https://www.cisa.gov/sbom) for more details about SBOM, specifications, use cases, products, deployment, and maintenance.

## 9. Hardware Upgrade Guidance
NSA does not endorse or promote specific products. See the [National Information Assurance Partnership (NIAP)](https://www.niap-ccevs.org/) for specific products that have been vetted for compliance to protection profiles endorsed by NSA. The following generic recommendations may also be treated as guidance:
1. Refresh workstations every 3 to 4 years and servers every 5 to 7 years. Look to stay within a vendor's firmware support timeframe.
2. Prefer processors that carry Intel's vPro branding, AMD's PRO branding, or ARM's Platform Security Architecture (PSA) capability for security capabilities beyond that of consumer-focused processors.
3. Look for devices that include Trusted Platform Module (TPM) 2.0 or later. The TPM may be dedicated/discrete (dTPM) or firmware/integrated (fTPM). ARM devices lacking a TPM may utilize Trust Zone as an alternative.
4. Prefer business and professional-oriented devices over devices intended for the consumer or gamer/enthusiast markets.

## 10. License
See [LICENSE](./LICENSE.md).

## 11. Contributing
See [CONTRIBUTING](./CONTRIBUTING.md).

## 12. Disclaimer
See [DISCLAIMER](./DISCLAIMER.md).
