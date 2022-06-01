---
title: HackTheBox - Resolute
date: 2022-06-01 02:00:00
categories: [HackTheBox, Machines]
tags: [hackthebox, resolute, ldap, active_directory, rpc, smb, evil-winrm, bloodhound, dns, msfvenom]     # TAG names should always be lowercase
img_path: /assets/img/HackTheBox/Resolute
---
![Resolute](htb_resolute.png "Resolute")
_HackTheBox Resolute_

**Resolute** is a retired medium **Active Directory** machine on HackTheBox, expanding on my Active Directory
experience from the previous machine **Intelligence**.

---
# Enumeration

Initially we can scan the full range and specify interesting ports for a more thorough scan.<br>
```sh
nmap -p- 10.10.10.169
```

**Scan:**
```sh
nmap -Pn -sC -sV -oA nmap -p 88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.10.10.169
```

**Results:**
```
Nmap scan report for 10.10.10.169
Host is up (0.050s latency).
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-04-13 14:40:06Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       .NET Message Framing
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2022-04-13T07:40:08-07:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h27m03s, deviation: 4h02m29s, median: 7m02s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2022-04-13T14:40:11
|_  start_date: 2022-04-13T14:36:00
```

It is typical of medium Linux machines on HackTheBox to be vulnerable through a web server. Active Directory machines have
a lot of other services to be enumerated for an initial foothold and don't strictly rely on web vulnerabilities, hence
the absence of an active port 80 this time around.

---
# SMB

First stop is attempting an anonymous login to the machine's SMB server and seeing what shares are accessible without
credentials.

```sh
smbclient -L \\\\10.10.10.169\\
```
![SMB](htb_smb.png "SMB")
_No Shares_

We find there is no shares available for anonymous enumeration, we can move onto RPC.

---
# RPC

Like SMB, we'll try get anonymous access to RPC.

```sh
rpcclient -U="" 10.10.10.169 -N
```
![RPC](htb_rpc.png "RPC")
_Success_

With anonymous access to RPC, we can run `enumdomusers` to get a list of users registered on the domain.

![enumdomusers](htb_enumdomusers.png "enumdomusers")
_enumdomusers_

We can take these users and put them into a usable list for later password-spraying.

![userlist](htb_userlist.png "userlist")
_users.txt_

We've now got a list of users with no passwords. We can move onto LDAP to try find a password to use.

---
# LDAP

To search LDAP, we must first get the naming context of the domain to enumerate. We can get the naming context with:<br>

```sh
ldapsearch -h 10.10.10.169 -x -s base namingcontexts
```
![namingcontext](htb_ldapsearch.png "Naming Contexts")
_Naming Contexts_

We can now refine our search to the relevant naming context and then refine it further down to person objects in the domain.<br>

```sh
ldapsearch -h 10.10.10.169 -x -b "DC=megabank,DC=local" "(objectClass=person)" > ldapPeople.txt
```
This command dumps an overwhelming amount of information regarding people in the domain, we can use grep to sort through
this wall of text for meaningful information.
```sh
cat ldapPeople.txt | grep -i "pw\|pwd\|pass\|password"
```
![Password](htb_defaultpassword.png "Password")
_Welcome123!_

The grep filter worked flawlessly and we have found a default password of `Welcome123!`<br>

We now have a list of users and a default password.<br>

We can begin password-spraying. I use the `smb_login` Metasploit module for this.
![Password-Spraying](htb_passwordspraying.png "Password Spraying")
_melanie:Welcome123!_

We now have a valid set of credentials to access the domain with. I tried using this user to find SMB shares but didn't
find anything of interest. It turns out Melanie is a member of the Remote Management group and we can immediately get
an `Evil-WinRM` session going.

---
# Evil-WinRM

Getting user is as easy as getting an `Evil-WinRM` session with Melanie and reading the user flag from the desktop:
![User.txt](htb_evilwinrm.png "User.txt")
_User.txt_

---
# Root

With the Evil-WinRM session, I searched around the file system for anything of interest and I found it in the root of the
C drive with `dir -force` to reveal hidden directories.
![PSTranscripts](htb_dirforce.png "PSTranscripts")
_PSTranscripts_

PSTranscripts sounds interesting, by following through the subdirectories we eventually come to:<br>
`PowerShell_transcript.RESOLUTE.OjuoBGhU.20191203063201.txt`<br>
Inside this PowerShell transcript, we find another set of credentials, this time for the ryan user:<br>

![Ryan](htb_ryan.png "Ryan")
_Serv3r4Admin4cc123!_

We can end our Evil-WinRM session with Melanie and start one up with Ryan.
![Timer](htb_timer.png "Timer")
_note.txt_

We find a file on Ryan's desktop called `note.txt` that notifies the team that any system change apart from those to the
administrator account will be automatically reverted within 1 minute.<br>

We might get a clearer path forward by using Bloodhound.

---
# Bloodhound

We can use `Bloodhound-Python` to gather up all the information we need from the domain with our current access as Ryan.<br>
```sh
bloodhound-python -c all -u ryan -p "Serv3r4Admin4cc123!" -ns 10.10.10.169 -d MEGABANK
```

Importing the generated JSON files into Bloodhound, it makes our path forward clearer than just enumerating information
in Evil-WinRM.<br>
![Bloodhound](htb_bloodhound.png "Bloodhound")
_DNSAdmins_

Ryan is a member of the `Contractors` group which in turn makes Ryan a member of the `DNSAdmins` group. Doing a quick search
for `DNSAdmins privilege escalation`, we come across [this post](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)
which is detailing the path from `DNSAdmins` to `SYSTEM`. This abuse of `dnscmd` is also detailed on its **LOLBAS** entry [here.](https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/)<br>

As a member of the `DNSAdmins` group, Ryan has permissions to load arbitrary DLLs from attacker-controlled shares as a plugin
to the DNS service. This approach to SYSTEM makes the earlier note on Ryan's desktop clearer. It presumably prevents the box
from locking up in a botched attempt. The problem with this is mainly the fact that loading a DLL reverse shell straight from
the likes of MSFVenom will hang the DNS service on the domain while the shell is active.<br>

For a CTF, we can hang the DNS service without consequence. In a live environment, hanging the DNS service might result in a bad
day in the office. IppSec has a great walkthrough of crafting a reverse shell that loads on a separate thread to keep DNS
functionality while the shell is active which you can find timestamped [here.](https://youtu.be/8KJebvmd1Fk?t=3289)<br>

With that out of the way, we can just hang the service while we grab `root.txt`

---
# Exploit

We will begin by generating a simple reverse shell DLL with MSFVenom:<br>
![MSFVenom](htb_msfvenom.png "MSFVenom")
_MSFVenom_

We will then setup a SMB Server with Impacket's `smbserver.py`:<br>
![SMB Server](htb_smbserver.png "SMB Server")
_SMB Server_

Now with our SMB server hosting our malicious DLL, we can setup a listener on our machine to catch our SYSTEM shell and move
back to Ryan's Evil-WinRM session.<br>

As per the note earlier, we have to call down our reverse shell and load it into the DNS service in the space of 1 minute.<br>
![DNS Restart](htb_dnsrestart.png "DNS Restart")
_Plugin Loaded_

Back on our machine, we get confirmation that our DLL was served and loaded with the DNS restart. We now have our SYSTEM shell
to retrieve the flag.<br>
![Root](htb_root.png "Root")
_root.txt_

On account of using the MSFVenom shell, the DNS service is inactive while our shell is active:<br>
![DNS Dead](htb_hungdns.png "DNS Dead")
_DNS Timeout_

However, upon closing our shell, the DNS service springs back to life:<br>
![DNS Alive](htb_livedns.png "DNS Alive")
_DNS Active_

# :)
