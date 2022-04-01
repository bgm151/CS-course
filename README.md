## ICT Security Basics from Trust to Blockchain Course

### H1

#### Summary of Hutchins et al 2011: Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains paper.

- The paper presents a framework that can be used by both parties - attackers and defenders.
- The framework contains several steps that are organized in a chain, so if one step in this framework was missed, then the chain “breaks”. To perform successful attack or defense all these steps should  be taken in an order that they are described. 

**Framework includes 7 steps:**
1. Reconnaissance - research and information gathering.
2. Weaponization - for example pairing remote access trojan and payload.
3. Delivery - delivering payload to the target, for example via USB stick that can be dropped on the street or handled to the target, or a malicious link that victim clicks.
4. Exploitation - for example with a USB stick, the mallwear that installed on the USB stick can start to execute automatically after it was inserted into the computer aka USB Rubber Ducky. (Source: https://shop.hak5.org/blogs/usb-rubber-ducky)
5. Installation - installation of the backdoor that an attacker can use for remote access.
6. Command and Control (C2) - establishing the connection between the attacked target abn command control server.
7. Actions on Objectives - at this stage actual goals can be achieved: stealing or destroying the data etc.

#### Comparison of Cyber Kill Chain and ATT&CK Enterprise matrix

First of all, the ATT&CK Enterprise matrix is more detailed, it contains more steps in the chain and also possible techniques and sub-techniques. But the Cyber Kill Chain and ATT&CK Enterprise matrix have the same backbone, the difference is just ATT&CK Enterprise matrix has several steps that can fit in one in the Cyber Kill Chain. 

Another difference is that theCyber Kill Chain has a defined order, where adversaries are expected to move linearly from one phase to another. 
The MITRE ATT&CK Framework is deliberately unordered to acknowledge that an adversary may move through Tactics out of order, skip some Tactics, and revisit some Tactics multiple times throughout the course of an attack. (Poston, H. 2020. How to Use the MITRE ATT&CK® Framework and the Lockheed Martin Cyber Kill Chain Together, https://resources.infosecinstitute.com/topic/how-to-use-the-mitre-attck-framework-and-the-lockheed-martin-cyber-kill-chain-together/)

I think that both attackers and defenders can benefit from these models. As well as other stakeholders of the business. In my opinion MITRE ATT&CK Framework could be useful in learning what kind of attacks are possible and what are the risks of the business.

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

#### Install Debian on VM

![VirtualBox_CS-course_01_04_2022_14_46_04](https://user-images.githubusercontent.com/102544139/161257628-eccc1604-df5a-498d-b110-7879f97bebd0.png)


