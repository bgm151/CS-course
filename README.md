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

#### Mitre Att&ck Framework
Mitre Att&ck Framework is more detailed and describes different tecniques and sub-tenchinques. It's not strictly stuctured as Cyber Kill Chain. Also it containes different Matrixes for different entities, such as separate Enterprise Matrix that contains sub-categories such as Windows, macOS ets. Mitre Att&ck Framework has separate Matrix for Mobile and Matrix for Industrial Control Systems.

##### Table 1. Mitre Att&ck Framework Enterprise Matrix Summary. Source: What is Mitre Att&ck Framework? - Definition (cyberark.com)

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

#### Comparison of Cyber Kill Chain and ATT&CK Enterprise matrix

First of all, the ATT&CK Enterprise matrix is more detailed, it contains more steps in the chain and also possible techniques and sub-techniques. But the Cyber Kill Chain and ATT&CK Enterprise matrix have the same backbone, the difference is just ATT&CK Enterprise matrix has several steps that can fit in one in the Cyber Kill Chain. 

Another difference is that the Cyber Kill Chain has a defined order, "where adversaries are expected to move linearly from one phase to another. 
The MITRE ATT&CK Framework is deliberately unordered to acknowledge that an adversary may move through Tactics out of order, skip some Tactics, and revisit some Tactics multiple times throughout the course of an attack." (Poston, H. 2020. How to Use the MITRE ATT&CK® Framework and the Lockheed Martin Cyber Kill Chain Together, https://resources.infosecinstitute.com/topic/how-to-use-the-mitre-attck-framework-and-the-lockheed-martin-cyber-kill-chain-together/)

I think that both attackers and defenders can benefit from these models. As well as other stakeholders of the business. In my opinion MITRE ATT&CK Framework could be useful in learning what kind of attacks are possible and what are the risks of the business.

**What is missing from these models?** I couldn't find a step in the MITRE ATT&CK Matrix about stealing the data.

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

#### Analysis

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

### H2
#### Summary of Santos et al 2017: Security Penetration Testing - The Art of Hacking Series LiveLessons: Lesson 6: Hacking User Credentials

##### Vulnerable passwords are:
- Default passwords, passwords that products are shipped with, for example modem or switch passwords. **Default passwords must be changed**
- Simple passwords. For example: cat, qwerty, 12345678, date of birth. **Longer and more randomized passwords with special characters must be used as well as two factor authentication if it's available**
- Reused passwords. Using the same passwords across different accounts is not secure. **Using different passwords for different account** 
- Admin password. After cracking the admin password, access to the whole system will be compromised. **Using secure admin password, change it regularly, use two factor authentication**

##### Ways of stealing the password
- Wifi spot in the hotel or cafe, we don't know how the network is set up, when we are visiting a hotel or a cafe and using their password. There are several types of attacks that could be conducted. For example traffic sniffing and man-in-the-middle attacks. _I was wondering about this, isn't it really difficult to do nowadays (I'm not talking about websites that still use http), because all the traffic should be encrypted and while sniffing traffic you just get bits and pieces of information? For example when using nmap. Is there really a way to make sense of that easily?_
- SSL spoofing
- SSH downgrade
- Compromising switch or modem (for example using the default password)

##### Why is it easy to crack passwords?
- Using modern CPUs and GPUs made the process of cracking password hashes faster
- We can use distribution between machines nowadays.
- Dictionaries. There are many password dictionaries out there. They are collected from the most used passwords and password breaches.
- Weak algorithms. For example Windows' nt hash and lm hash. Or not using the salt in passwords. (Using salt in passwords will prevent two users having the same password hashes if they have the same password)

##### How to improve password security?
Consumer:
- Use two factor authentication
- Use certificate based authentication
- Use better longer passwords

Company:
- Use encryption
- Use hashing
- Use salt
- Secure password storage
- Support longer passwords with special characters

#### Cracking hashes
- 21232f297a57a5a743894a0e4a801fc3 = admin
- f2477a144dff4f216ab81f2ac3e3207d = monkey
- $2y$18$axMtQ4N8j/NQVItQJed9uORfsUK667RAWfycwFMtDBD6zAo1Se2eu. Hash is bcrypt $2*$, Blowfish (Unix). Hashcat mode: 3200. Estimated time for cracking with VM box id 7 years :)
![screes](https://user-images.githubusercontent.com/102544139/162403093-42547e1a-f519-4686-84e4-0feb621058b4.png)

- I don't have any physical linux machine right now to test how hashcat uses GPU. Tried with my Raspberry Pi400, but didn't work, the error was _No devices found_, the command I tried to use was _hashcat -m 0 -d 2 'somehash' rockyou.txt -o solve_, where -d 2 is specifying device type GPU.
- Tried to crack sha256 hash of simple password that I found in the dictionary "happy5", so Raspberry Pi400 cracked it straight away. Was having problems in the beginning, forgot to use -n when hashing. 

#### Something to think about: we just learned that hashing is a one-way function. If this is true, why can you crack the hash and find out the original password?
Because we are not cracking the hash itself, but using the hash algorithm to hash password from the pasword lists and then comparing these two hashes.

#### Summary of Schneier 2015: Applied Cryptography: Chapter 2 - Protocol Building Blocks
- Protocol is a predefined chain of steps, that should be accomplished by at least two parties.
- There are three types of protocols: 
  -  Arbitrated. When parties use some trusted third party that will verify the data.
  -  Adjudicated. When parties use a trusted third party to solve the conflict in the case if one of the parties cheated.
  -  Self-enforcing. Cheating of any party included in the communication is immediately detected.
- Types of protocol attacks: 
  - Active attack - requires active intervention. Corrupting data, gaining unauthorised access to resources. Follow the protocol, but try to obtain more information than protocol allows.
  - Passive attack - collect information about communicating parties, capturing messages. Disrupt protocol.

#### Public-key cryptography
The protocol was designed by Whitfield Diffie and Martin Hellman in 1976 and it changed that paradigm of cryptography forever.

##### Key exchange process

![Public area](https://user-images.githubusercontent.com/102544139/162615554-778b9bdc-36a5-4005-a5f7-f90f2a34a883.png)

- First user A and user B use public variables and combine their private key with the generator.  So user A will have A + G = AG and user B B + G = BG.
- Exchange these variables AG and BG. So user A gets BG and user B gets AG.
- User A takes BG and combines it with his private key. And user B combines AG with his private key. So user A now has BGA and user B AGB.
- Now this key can be used for further communicaton.

**Nothing from the public area can be combined to get the private key value. And the private key is never shared or never gets into the public area.**

Source: Secret Key Exchange (Diffie-Hellman) - Computerphile https://www.youtube.com/watch?v=NmM9HA2MQGI 




