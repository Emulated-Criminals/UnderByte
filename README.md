# UnderByte — A Ransomware expirment using Alternate Data Streams  (ADS)

**Repository purpose:** this research was to evaluate the feasiabilty of using Alternate Data Stream (ADS) in staging and conducting ransomware-esk behaviors and examines how well common endpoint controls detect or block those behaviors. This repo is explicitly *not* intended to provide operational guidance, tools, or techniques for malicious use.

> **Important:** This project contains conceptual research only. Please don't be a goon and use it for some illiciate affairs. I didn't even code in a decryptor. You won't be doing anyone any favors. 

## Summary
This research explores how ADS can be used to stage and execute a ransomware attack on a host and how those behaviors may appear in host telemetry. The primary questions driving the work were: 
1) what are the observable signals associated with ADS read/write activity when used for ransomware, 
2) how reliably do common endpoint controls detect or block suspicious stream usage, and 
3) which telemetry correlations (process, parent, file target, timestamps) are most useful for triage.

### High-level takeaways:
- Legitimate ADS usage is uncommon for many applications and generic files and if there is a stream of rapic creation of ADS streams across many files, particularly with non-decriptive and/or nonsensical names, it can be used as a good indicator of illicit behavior 
- Simple file-system-only monitoring yields many false positives; combining process lineage, command line, and stream-targeted heuristics improves signal-to-noise. 
- Most Consumer grade and some Commerical grade endpoint protection and AV products did not flag the activity of creating an ADS on user file. Despite the over use of the cryptography libaries within the OS the activity was not flagged malicious. Likely cause of the commerical grade alerts were due to modifications of canary files which could be esaily avoided.
- Alerting and prevention from security products, in-kernel and out, mostly occured during the tool's overwriting stage of the main data stream, but only when the overwriting activity was conducted in a manner beyond human input capability, i.e no sleep pattern implemented. This also only occured after many files were already encrpyted, from testing it was observed that this number fluctated between 20~ to 100~ files. 
- To be effective ransomware needs to only encrpyt user maintained files. Restriction of use in the applcaiton or OS level is damaging, but presents more opportunites for discovery. Focusing detections on these user writeable locations could be help reduce noise and over burdening of alerts to SIEM

### Longer Summary 

Underbyte abuses an NTFS feature called Alternate Data Streams (ADS). If you are unfamiliar with what an ADS is, it is a named data substream associated with a file's primary data stream, which is referred to as `$DATA`.  ADS is a useful tool because it allows software to attach additional data to a file without changing the file's visible size or primary contents in a typical file explorer, which can be helpful for benign tasks like metadata and indexing.  This creates an interesting attack vector for threat actors within NTFS systems, as the streams are not prominently visible in many standard user interfaces and are not noticeable to the average user. This means that we can store data within these streams, which, if wanted, can be executable, but that is not our intent for this research.  

Our intent with this research was to see if we could circumvent the detection capabilities of common EDRs/AVs for common ransomware techniques by removing a core component of detection: the call to a cryptographic library, followed by a call to write to a file without changing its name. To do this, we figured we could split our ransomware attack into a two-phase attack: the first phase was to create an alternate stream on each file in the user’s path (Documents/Desktops/Downloads/etc.) where we would place an encrypted copy of the file's data within that stream. Once completed, we would then go back through with a separate function that would copy the encrypted data in the ADS to the main `$DATA` stream, overwriting it. 
This approach to conducting a ransomware attack evaded all our consumer-grade products in our lab, but was insufficient against commercial-grade EDR/AVs. Though 'insufficient' would be a slight understatement, as every time there was a delay before the alert and eviction. Allowing for some damage against the host. This indicated that the likely cause of the attack detection was M/L for these products, noticing anomalous behavior consistent with ransomware. This created an interesting junction as the theory became, if we could slow the attack down so that the operations per second was set to 1, would the AV/EDRs alert because now the smash and grab tactic many Ransomware-as-a-Service (RaaS) products conduct would no longer apply, would we hit a threshold for maliciousness? The answer was sadly no. We believe that while there IS merit in taking the data hostage quickly, and it is an efficient mechanism for bringing an organization to its knees, as history has shown, in physical and logical examples,  the best methods for covert and complete takeover have always been slow and undetectable until there is no ability to prevent the methods from occurring. 

### How it works

Underbyte is simple in design. Our approach was to create a “fileless” malware variant that could run in “memory” and execute ransomware. The best approach to fileless and memory-based execution was to create this using a threat actor's favorite tool, PowerShell. PowerShell is perfect for this example as it is “scriptable .NET” and would provide us with all access to the Windows32API.

The simplicity of this attack is outlined by the fact that we used P/Invoke to include Kernel32.DLL and import `CreateFile` `ReadFile`, and `WriteFile` and from these three API functions we created `Read-NativeFile`, `Write-NativeFile`, `Read-ADS`, and `Write-ADS`. While we did not need to use `Write-NaviteFile `and `Read-ADS` in our final product, their functions were helpful during our enumeration process.

From there, we created the two phases of the ransomware. The first phase, which created the keys and an encrypted copy of the file data into an ADS, was called `StreamSmith`. It is responsible for creating the crypto streams and writing them to the ADS specified by $adsPath. While in our research we used a single, easily identifiable ADS name, it may be possible to use a pseudo-randomized naming convention to avoid repeated names.

The second phase function, called `RaiseTheByte` does not use any direct Win32API calls and instead uses a common PowerShell function `Set-Content`.  This function allows a power user to take the value of a variable, string, byte, etc., and apply it to a stream found in the file denoted in the `-Path` argument. When no `-Stream` argument is applied here, the function defaults to the `$data` main stream.  Initially, we did implement a sleep target here as we wanted to closely align with common activity, but by implementing even a randomized 0-5 sleep, we were able to complete our engagement on the host without detection. 
 
### Something for the defenders
Below are defender-friendly telemetry signals, heuristic rules, and playbook ideas you can implement or translate into SIEM/EDR rules. These are conceptual and we recommend tuning your thresholds and whitelists for your environment.
High-value signals/heuristics

•	Multiple stream writes across many user files in a short time window (e.g., tens of streams written in minutes) by the same process or lineage. The key metric is by the same process or lineage. Often, Ransomware is not executed in a multi-process application. Usually favoring threads over processes, as created threads typically carry the “trust” from its parent process. Regardless, we believe that if you can track lineage for file modification, you could likely detect and prevent this type of attack quickly. 

•	Writes to ADS attached to sensitive file types (executables, scripts, documents) where the writing process is not a known/expected application. Creating a general ADS baseline for files can help as well, whereas if there is an ADS created for that file that doesn’t match the baseline property, it should alert and prevent 

•	Presence of binary or high-entropy content inside a stream attached to otherwise textual files. Encryption will always have very high entropies. This is much more resource-intensive and is dependent on the security product's ability to conduct non-invasive entropy scanning. 

•	Any call from an ADS to overwrite the `$DATA` should be alerted upon. While we haven’t observed this, in theory, it's possible that general-use applications use ADS as an update mechanism to the main $DATA stream. Our recommendation is to implement the detection and dial back based on telemetry.

•	Unusual processes writing to user folders (Downloads, Desktop, Temp) that then write streams ,  especially if parent process or signer is unexpected.

•	Writes to streams followed by deletion or exclusion of those streams in standard file-listing tools (attempts to hide evidence).

•	Abnormal pattern of file metadata changes (timestamps, size discrepancies between visible size and underlying data seen by forensic tools).

**Triage playbook (how to investigate a hit)**
1.	Capture the timeline: process lineage, timestamps for stream creation, stream content hashes, primary stream write events.
2.	Snap the host and collect full forensic artifacts (ADS contents, USN journal).
3.	Identify the process binary and signer; check parent process and command line for anomalies.
4.	Correlate with network telemetry—outbound C2 or beacon patterns may indicate coordination.
5.	Determine scope: enumerate other files/hosts touched; check backups and restore points.
6.	If malicious, isolate the host and preserve artifacts for vendor reporting / CVE-style disclosure.

**Mitigations & hardening**

•	Enforce application control (AppLocker/WDAC) to prevent execution from user-writable directories.

•	Detect and block execution or write activity from processes that are not code-signed or not expected in user directories.

•	Maintain offline or immutable backups so even stealthy destructive actions can be recovered.

•	Implement tight monitoring of user folders (Desktop/Downloads) with process correlation and anomaly scoring rather than raw file-only alerts.

•	Build whitelists of legitimate ADS usage (where used for app indexing, etc.) to reduce noise. 

**False positives & tuning notes**

•	Many legitimate apps (backup/indexing/scanners) may use ADS for benign reasons. Use allow-listing and process context (who/what wrote the stream) to reduce false positives.

•	Entropy checks help but aren’t perfect, some compressed/encoded legitimate content will appear high-entropy. Combine with process lineage.

•	Tune N (files) and M (minutes) thresholds to match your environment’s normal behavior; cloud DaaS and collaboration apps produce different baselines.

#### Defender Reading
How the OS behaves (high level)

•	NTFS stores named streams as separate logical streams attached to the same file record. Each stream has its own bytes but is addressed as `C:\path\file:streamname`.

•	Reading/writing a stream or the primary `$DATA` stream is just a file I/O operation at the API level (e.g., `CreateFile` + `ReadFile`/`WriteFile`). A write to the main stream is indistinguishable from other writes unless your telemetry records the stream name or prior stream activity.

•	Tools like PowerShell `Get-Content -Stream` / `Set-Content -Stream` simply call file I/O for the named stream; `Set-Content` to the main stream is a write to `$DATA` and will generate file-write events.

**Telemetry sources you can use to detect the two-phase ADS pattern (Collect and correlate these,  no single one is sufficient)**
1.	File-system audit / Security SACLs
 o	Windows object-access auditing (Audit File System) can produce events when a file or stream is created/modified. In some configurations, the event’s object name will include the stream portion (e.g., `C:\path\file:streamname`), check your platform and audit format. Use SACLs to capture who and which process performed the operation.
2.	EDR / Sysmon / Endpoint telemetry
 o	Many EDRs and Sysmon-like sensors record file create/write events with process identity, PID, command line, and sometimes the full path. If the sensor captures the full path including the `:stream `suffix on stream writes, you get direct evidence of ADS activity. Even when the stream name is missing, seeing the same process do stream-like reads followed by a main-stream write is a correlation signal.
 o	Newer telemetry can capture stream-specific events or stream hashes; if available, those are high-value.
3.	USN Journal / NTFS change journal
 o	The USN journal records file change records. It doesn’t always include the stream name in a straightforward way, but it provides a timeline of many file modifications and can be used to trace bulk modifications and correlate them with process events.
4.	ETW / Kernel file I/O providers and ProcMon captures
 o	Kernel ETW providers, or a ProcMon capture, will show exact `CreateFile`/`ReadFile`/`WriteFile` calls and the full path used by the process (including `:stream` if that path was used). ProcMon-style traces are gold for forensic confirmation.
5.	Stream enumeration during triage
 o	If you suspect activity, enumerate ADS on affected files (`Get-Item -Path <file> -Stream *` in PowerShell, or use native APIs) and compute hashes of stream contents. If an ADS exists with an encrypted/high-entropy blob and the primary stream content now differs, that’s strong evidence of a staged stream → overwrite.

**Concrete detection approach (practical)**
1.	Capture process-centric file I/O events (process, PID, cmdline, timestamp, path). Prefer sensors that retain the full path string.
2.	Alert when you observe either:
o	Writes to `*:streamname` paths (direct stream write), or
o	A process that previously performed a stream write or stream read on a file (detected by path containing :) subsequently performs a write to the same file’s primary stream within a short window.
3.	Correlate on the same process identity (or same lineage) and short time delta, the two-phase correlation is a much higher-confidence signal than either event alone.
4.	If you can, compute and compare hashes: hash(ADS contents) == hash(primary contents after overwrite) is a definitive indicator that the ADS was copied into `$DATA`.

**Example indicators (defensive, conceptual)**

•	Process `P` wrote to `C:\Users\Alice\Desktop\invoice.docx:diddler` at t1, then Process `P` wrote to `C:\Users\Alice\Desktop\invoice.docx` at t2 (t2 > t1, t2 − t1 ≤ T). Correlate for many files.

•	Many files in a folder have new ADS names or high-entropy ADS content followed by main-stream writes by the same process within a window.

•	Hash of ADS content equals hash of new primary file content.

**Practical collection & tuning tips**

•	Ensure your endpoint agent captures full file path strings; configure Sysmon/EDR to include full paths and command lines. If the sensor strips stream suffixes, add kernel/ETW collection or ProcMon-style capture for deeper forensics.

•	Use an allowlist for known legitimate ADS use (indexers, backup/antivirus metadata) to reduce false positives.

•	Tune time windows (T) and volume thresholds (how many files) to avoid alert storms. A two-phase rule that requires both a stream write and a later main-stream overwrite will be far more high-fidelity than single-event rules.

Summary
A main-stream overwrite caused by copying from an ADS is a file-write event and will look like any other write to $DATA in raw file-write logs. To detect it, you need to capture/notice the earlier ADS activity (stream write/read) and correlate it to the subsequent main-stream write by process and time. Combining stream-aware telemetry (where available), USN/ETW traces, and process lineage correlation is the practical way to detect ADS→$DATA overwrites with low false positive rates.



## Responsible disclosure
If you discover a product behavior that allows evasion or other issues during testing, follow responsible disclosure:
1. Notify the vendor privately with reproducible, non-exploitable evidence and suggested mitigations.
2. Provide reasonable time for vendor remediation before public disclosure.
3. Coordinate with the vendor and CVD/bug-bounty programs where available.



## License
This repository is provided for authorized research and defensive use only.
