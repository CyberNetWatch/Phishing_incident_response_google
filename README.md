# SOC Level 1 Phishing Investigation: Malicious Email Attachment

## Overview

This repository documents a phishing incident response (google course lab) conducted by a Level 1 Security Operations Center (SOC) Analyst at a financial services company. The investigation was initiated based on an alert triggered by a suspicious email containing a potentially malicious attachment.

## Scenario

An email sent to the HR department included a suspicious attachment (`bfsvc.exe`) claimed to be a CV. The email contained multiple signs of phishing, including:

- Numerous spelling and grammatical errors
- A suspicious sender email address
- An uncommon `.exe` file masquerading as a CV
- A password-protected attachment to evade detection

## Investigation Summary

**Alert Ticket ID:** A-2703  
**Alert Type:** Phishing - Possible malware download  
**Severity:** Medium  
**Attachment:** `bfsvc.exe`  
**Hash:** `54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b`  

### Actions Taken

1. **Alert Evaluation:**  
   The email and its metadata were reviewed, including sender details, email content, and the nature of the attachment.

2. **Attachment Analysis:**  
   The file `bfsvc.exe` was analyzed using VirusTotal.  
   **Result:** 58 out of 72 security vendors flagged the file as malicious.  
   **Popular Detection Labels:**  
   - `trojan.flagpro/fragtor`
   - `Backdoor:Win32/Kryptik`
   - `Trojan.Agent.Flagpro`

3. **Conclusion:**  
   The email attachment is confirmed malicious. The phishing attempt was successful in bypassing initial detection and needs further investigation by a Level 2 SOC Analyst.

4. **Ticket Update:**  
   - The ticket was updated with all findings.
   - Status changed to: `Escalated`
   - Escalation made to SOC Level 2 for deeper analysis and containment actions.

## Tools Used

- [VirusTotal](https://www.virustotal.com) for file reputation check
- Internal ticketing system for documentation and escalation

## Next Steps

- SOC Level 2 to perform deeper forensics and determine potential impact or compromise.
- Review email filtering rules to detect similar threats in the future.
- Communicate with the affected user and ensure endpoint protection is up to date.

## License

This repository is for educational and documentation purposes only.
