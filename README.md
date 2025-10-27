 UnderByte — A Ransomware expirment using Alternate Data Streams 

**Repository purpose:** this research was to evaluate the feasiabilty of using Alternate Data Stream (ADS) in staging and conducting ransomware-esk behaviors and determine the defensive mechanisms in which defensive engineering products owners and/or SOC/SIEM products could imrpove their detections with this particular type of attack.  It is explicitly *not* intended to provide operational guidance, tools, or techniques for malicious use.

> **Important:** This project contains conceptual research only. Please don't be a goon and use it for some illiciate affairs. I didn't even code in a decryptor. You won't be doing anyone any favors. 

## Executive summary
This research explores how ADS (NTFS Alternate Data Streams) can be used to stage or hide artifacts on a host and how those behaviors may appear in host telemetry. The primary questions driving the work were: 
1) what are the observable signals associated with ADS read/write activity when used for ransomware, 
2) how reliably do common endpoint controls detect or block suspicious stream usage, and 
3) which telemetry correlations (process, parent, file target, timestamps) are most useful for triage.

High-level takeaways:
- ADS isn't common usage among generic files and if multiple ADS streams are created quickly it could be a good indicator of attempted use of the stream to store data
- Simple file-system-only monitoring yields many false positives; combining process lineage, command line, and stream-targeted heuristics improves signal-to-noise.
- Consumer grade endpoints and some Commerical grade endpoints do not detect the activity if the process of creating the ADS and copying over the main stream are conducted in two instances seperated by huamn reponse timing. I.e if the product runs at 1000 ops a second its detected, if it runs at 1-10 files per 10 seconds it does not.
- If a Kerenel Level protection systems do not appear to detect and prevent the ecrpytion of data when written into the main Data Stream. When copying the data from ADS into the main stream it prevents the action only upon several repeated steps. In testing at full speed (no sleep) I was able to encrypt roughly 20-100 files before the products would prevent further damage. 
- To be effective ransomawre needs to only encrpyt user maintained files. Restriction of use in the applcaiton or OS level is damaging, but presents more opportunites for discovery. 

## Scope & non-goals
**Scope**
- Defensive evaluation of ADS behavior in controlled labs for detection, telemetry mapping, and mitigation planning.
- Reporting non-actionable, vendor-ready findings and recommended telemetry.



## Lab safety & mandatory controls  

This is all AI written since I didn't want to say any of this but lets be real some people get mad when you share dangerous tools for bettering the publics ability to protect against them. 

Anyone performing related experiments should follow these controls. 

1. **Isolation:** Use air-gapped or VLAN-segmented VMs isolated from production and the Internet. Do not reuse production accounts.
2. **Authorization:** Only perform experiments on systems you own or have explicit written permission to test.
3. **Snapshots:** Take clean snapshots before each experiment and revert immediately after verification.
4. **Telemetry:** Collect host logs (Sysmon or equivalent), EDR capture, full process lineage, and network captures (if testing network effects). Keep timestamps and notes for reproducibility.
5. **No payloads:** Use only benign payloads (clearly labeled test artifacts). Do not deploy live ransomware or real malicious payloads.
6. **Disclosure:** Share findings with affected vendors before public release (see Responsible Disclosure below).

## High-level methodology (non-actionable)
- Establish a controlled baseline of legitimate ADS usage in test images and identify common benign patterns.
- Create focused experiments (lab-only) to observe telemetry when streams are written/read by benign and suspicious processes.
- Map telemetry artifacts to actionable detection rules (e.g., correlations between unexpected process writing to executable files, unusual stream names, or stream writes originating from non-standard parents).
- Validate detection rules across multiple EDRs and system configurations where possible.

## Detection & mitigation guidance (high level)
These recommendations are defensive and non-actionable:
- Instrument file system eventing to record stream write/read events when supported; augment with process and parent process telemetry.
- Alert on writes to streams attached to executable binaries or other sensitive file types, especially when the writing process is unexpected.
- Use EDR rules to flag or block processes writing binary content into streams in user-writable locations (Downloads, Desktop, Temp).
- Enforce application control (AppLocker / WDAC) to prevent execution from user-writable folders; maintain offline, immutable backups.
- Maintain inventories of legitimate ADS usage and whitelist known benign patterns to reduce false positives.

## Responsible disclosure
If you discover a product behavior that allows evasion or other issues during testing, follow responsible disclosure:
1. Notify the vendor privately with reproducible, non-exploitable evidence and suggested mitigations.
2. Provide reasonable time for vendor remediation before public disclosure.
3. Coordinate with the vendor and CVD/bug-bounty programs where available.

## Ethics & legal
This work is intended for defenders, auditors, and researchers. Do not use material from this repo for unauthorized testing, criminal activity, or any action that violates law or policy. 

## Contact


## License
This repository is provided for authorized research and defensive use only.
