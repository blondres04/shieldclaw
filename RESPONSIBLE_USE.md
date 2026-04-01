# Responsible Use Policy

Shield Claw is an automated offensive security research tool designed strictly for defensive DevSecOps pipelines. Because this tool autonomously generates and detonates exploit payloads, its use carries inherent risks. 

By using, cloning, or modifying this software, you agree to the following conditions:

## 1. Authorization Requirement
You may **only** run Shield Claw against repositories, codebases, networks, and infrastructure that you explicitly own or have documented, written permission to test. Unauthorized scanning or exploitation of third-party systems is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws in most jurisdictions.

## 2. Prohibited Uses
* **No Malicious Automation:** Do not use this tool to scan, exploit, or attack public open-source repositories without the maintainers' documented consent.
* **No Weaponization:** Do not use this tool to generate exploits for the purpose of attacking production systems, exfiltrating data, or causing harm.
* **No Restriction Removal:** Do not redistribute modified versions of this tool with the responsible-use constraints or ethical boundaries removed.

## 3. Ephemeral Sandboxing Constraints
Shield Claw executes payloads in Docker containers. However, the V0 architecture mounts the host Docker socket (`/var/run/docker.sock`) and requires outbound network access to clone repositories. **Do not run this tool on a production host** or against untrusted, malicious repositories that could perform sandbox escapes or pivot into your local network.

## 4. No Warranty
This software is provided "as is" for educational and defensive research purposes only. The creators and contributors accept no responsibility or liability for damage, data loss, or legal consequences resulting from the use or misuse of this software.

## 5. Reporting Misuse
If you observe Shield Claw being used maliciously or in violation of this policy, please report it immediately by contacting the repository owner.
