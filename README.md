## ICT Security Basics from Trust to Blockchain Course

### H1

#### Summary of Hutchins et al 2011: Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains paper.

- The paper presents a framework that can be used by both parties - attackers and defenders.
- The framework contains several steps that are organized in a chain, so if one step in this framework was missed, then the chain “breaks”. To perform successful attack or defense all these steps should be taken in an order that they are described. 

**Framework includes 7 steps:**
1. Reconnaissance - research and information gathering.
2. Weaponization - for example pairing remote access trojan and a payload.
3. Delivery - delivering payload to the target, for example via USB stick that can be dropped on the street or handled to the target, or a malicious link that victim clicks.
4. Exploitation - for example with a USB stick, the mallwear that installed on the USB stick can start to execute automatically after it was inserted into the computer aka USB Rubber Ducky. (Source: https://shop.hak5.org/blogs/usb-rubber-ducky)
5. Installation - installation of the backdoor that an attacker can use for remote access.
6. Command and Control (C2) - establishing the connection between the attacked target and command control server.
7. Actions on Objectives - at this stage actual goals can be achieved: stealing or destroying the data etc.

#### Comparison of Cyber Kill Chain and ATT&CK Enterprise matrix

First of all, the ATT&CK Enterprise matrix is more detailed, it contains more steps in the chain and also possible techniques and sub-techniques. But the Cyber Kill Chain and ATT&CK Enterprise matrix have the same backbone, the difference is just ATT&CK Enterprise matrix has several steps that can fit in one in the Cyber Kill Chain. 

Another difference is that the Cyber Kill Chain has a defined order, "where adversaries are expected to move linearly from one phase to another. 
The MITRE ATT&CK Framework is deliberately unordered to acknowledge that an adversary may move through Tactics out of order, skip some Tactics, and revisit some Tactics multiple times throughout the course of an attack." (Poston, H. 2020. How to Use the MITRE ATT&CK® Framework and the Lockheed Martin Cyber Kill Chain Together, https://resources.infosecinstitute.com/topic/how-to-use-the-mitre-attck-framework-and-the-lockheed-martin-cyber-kill-chain-together/)

I think that both attackers and defenders can benefit from these models. As well as other stakeholders of the business. In my opinion MITRE ATT&CK Framework could be useful in learning what kind of attacks are possible and what are the risks of the business.

##### Table 1. Mitre Att&ck Framework Summary. Source: What is Mitre Att&ck Framework? - Definition (cyberark.com)

| Tactic       | The Adversary is Trying to: |
|--------------|----------------------------------------------------------------|
| Reconnaissance |Gather information they can use to plan future operations     |
| Resource Development | Establish resources they can use to support operations |
| Initial Access | Get into your network                                        |
| Execution | Run malicious code |
| Persistence | Maintain their foothold |
| Privilege Escalation | Gain higher-level permissions |
| Defense Evasion | Avoid being detected |
| Credential Access | Steal account names and passwords |
| Discovery | Figure out your environment |
| Lateral Movement | Move through your environment |
| Collection | Gather data of interest to their goal |
| Command and Control | Communicate with compromised systems to control them |
| Exfiltration | Steal data |
| Impact | Manipulate, interrupt, or destroy your systems and data |

#### Security incident description and analisys
##### Cloud Hopper, episode 103, Darknet Diaries.

Source: [https://darknetdiaries.com/episode/103/](https://darknetdiaries.com/episode/103/)

Some company was informed by the Swedish Security Service that their computer was reaching out to some known bad source. Turned out that it was the jump server of the MSP, the server that was used to manage many customers, was reaching out to some command and control server.

MSP works by taking on other enterprises as clients, they monitor and patch their services if needed. [Source](https://www.gartner.com/en/information-technology/glossary/msp-management-service-provider) 
So finding a breach in such a thing as a jump server was a really bad thing for the MSP.

>“A jump server is defined as a system on a network that accesses and manages all the devices in a different zone of security.” - [Source](https://www.javatpoint.com/what-is-a-jump-server)

To start the investigation, a threat analyst from Truesec received disc images and a memory dump from the attacked server. Because the antivirus didn’t trigger, he started to check manually. The first thing he checked was the /temp folder. Temp folder is used to store temporary files. [Source VG. 2012](https://www.askvg.com/where-does-windows-store-temporary-files-and-how-to-change-temp-folder-location/#:~:text=%E2%80%9CTEMP%E2%80%9D%20folder%2C%20as%20the%20name%20suggests%2C%20is%20used,are%20temporary%2C%20its%20absolutely%20safe%20to%20remove%20them)

The file that was the output of the mimikatz software was discovered in the temp folder. Mimikatz is used to extract pins, hashes and passwords from the memory. [Source](https://github.com/gentilkiwi/mimikatz). And it was a Windows server, which has a known vulnerability. It keeps passwords that are used to login in the memory, sometimes in plain text.

After scanning memory and disc for the IP address that was given to them by Swedish Security Service of this malicious command and control server. They found a process that was connected to this server. It was a legitimate software that scans for rootkits. But it was in an unusual location. And next to that file there were several dll files. So threat analysts suspected dll side-loading. 

>“DLL side loading is an attack where malware places a spoofed malicious DLL file in a Windows directory so that the operating system loads it instead of the legitimate file.” [Source](https://www.mandiant.com/resources/dll-side-loading-a-thorn-in-the-side-of-the-anti-virus-industry#:~:text=%20Dynamic-link%20library%20%28DLL%29%20side-loading%20is%20an%20increasingly,system%20loads%20it%20instead%20of%20the%20legitimate%20file.)

Also they found an executable file - nbt.exe, it’s a legitimate file that is used to scan networks and it’s how windows computers connect to shared network drives. Another file had a list of public IP addresses that were scanned. Turned out that some of these IP addresses belonged to the US Department of Defense.
Another malware was found on the server and it was PlugX, PlugX is a known RAT (Remote Access Trojan) and it can control the computer remotely.

Also they found out that the attack was running for weeks. And because the attack was running already for a long time. They tried not to reveal that they found out the breach and didn’t kill the process, because it’s easy to work on an attack that is ongoing, and attackers won’t be able to react.

In the end it turned out that somebody planted the malware from the MSP premises using stolen credentials of the MSP employee.

In short, the threat actor wanted to get into the US Department of Defense network, so they decided to hack MSP, hoping that some of the MSP customers would be connected by NetBIOS to the US Department of Defense, so they could get access. So the attackers did have an advanced persistent threat or APT.

>“Advanced persistent threat is a covert cyber attack on a computer network where the attacker gains and maintains unauthorized access to the targeted network and remains undetected for a significant period”. - [Cisco. What Is an Advanced Persistent Threat (APT)](https://www.cisco.com/c/en/us/products/security/advanced-persistent-threat.html)

The hack was associated with the Apt10 group. [Source](https://www.fbi.gov/wanted/cyber/apt-10-group). Thousands of social security numbers were stolen, as well intellectual property in order to gain the competitive advantage.

To fix the breach MSP had to change all the passwords, which took lots of time and effort.

#### Analisys

**Reconnaissance**
There is no information about the Reconnaissance phase, but threat actors definitely conducted Active Scanning and Gathering Victim Host Information to define that the target server was running Windows, it helped them to plant mimikatz, the software that targets Windows systems. 

**Resource Development**
Also we know that credentials for the jump station were compromised from the MSP employee, so probably it was done by using some Phishing techniques. Credentials of the jump station were stolen to plant mimikatz.

**Initial Access**
At this stage attacks used the Valid account of the MSP employee.

**Execution**
At this point attackers were collecting credentials of users that were connecting to other servers via this jump station. So attackers needed some User Execution. For the second stage, when attackers used a DLL loading attack, the Shared Modules technique was used.
Persistence
Attackers were really successful at this stage. The attack was running for several weeks without being noticed. Hijack Execution flow was used when malicious dll was placed using Valid Account.

**Privilege escalation**
Attackers used Create or Modify System Process technique and Hijack Execution flow, when they installed mimikatz, rootkit and RAT using Valid Account and RAT.

**Defence evasion**
Trusted Developer Utilities Proxy Execution was used. Payloads that were placed on the target server were legitimate software. Also valid account credentials were used.

**Credential Access**
Input capture was used to get credentials for other servers that were accessed via compromised jump server. The first login to the jump server was done from MSP premises using stolen credentials of the MSP employee.

**Discovery**
To attack the jump server, threat actors might have used System owner/user discovery to steal MSP employee credentials. For the next stage of the attack Network Service Scanning was used to see if there are servers in this Network that are connected to the Department of Defense.

**Lateral Movement**
Attackes used Remote Services to connect to the server. (PlugX trojan)

**Collection**
Input Capture was used to steal credentials via keyloggers. Data From Local System, the file with credentials that was created by mimikatz was accessed.

**Command and Control**
Remote Access Software was used, particularly PlugX trojan.

**Exfiltration**
Exfiltration Over C2 Channel was used.

**Impact**
Various data was stolen from customers of the attacked MSP. As well as data from the Department of Defense including social security numbers of the US Navy. (For some reason MITRE Matricx doesn’t have anything about stealing the data).


#### Install Debian on VM

![VirtualBox_CS-course_01_04_2022_14_46_04](https://user-images.githubusercontent.com/102544139/161257628-eccc1604-df5a-498d-b110-7879f97bebd0.png)


