---
title: HackTheBox - Intelligence
date: 2022-05-05 17:30:00
categories: [HackTheBox, Machines]
tags: [hackthebox, intelligence, active_directory, exiftool, scripting, smb, responder, bloodhound, silver_ticket]     # TAG names should always be lowercase
img_path: /assets/img/HackTheBox/Intelligence
---

![Intelligence](htb_intelligence.png "Intelligence")
_HackTheBox Intelligence_

**Intelligence** is a retired medium **Active Directory** machine on HackTheBox, this machine was my first real
dive into Active Directory exploitation and it was the perfect machine to do it with, I had a lot of fun working through
this one.

---
# Enumeration

Active Directory machines have a **lot** of ports open on them. We can just do a thorough scan of the results of:<br>
`nmap -p- 10.10.10.248`<br>

**Scan:**
```bash
nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA nmap 10.10.10.248
```
**Results:**
```
Nmap scan report for 10.10.10.248
Host is up (0.044s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-10 23:27:52Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2022-04-10T23:29:21+00:00; +7h00m02s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T23:29:21+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T23:29:21+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T23:29:21+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
```
We have our hostname of `intelligence.htb`, we can add that to `/etc/hosts` and continue on to Port 80.

---
# Port 80
![Landing Page](htb_landingpage.png "Landing Page")
_http://intelligence.htb/_

This page is very simple, there isn't a whole lot going on. Scrolling down on the landing page, there are
two PDF files available for download.

![Documents](htb_documentdownload.png "Documents")
_http://intelligence.htb/_

These documents listed for download are simply just full of [Lorem Ipsum](https://en.wikipedia.org/wiki/Lorem_ipsum).
The naming convention of these files however are far more interesting: `YYYY-MM-DD-upload.pdf`<br><br>

We can scan for that, but before we do, we should make sure these documents are definitely useless by extracting their
metadata using a tool called `exiftool`.

![Exiftool](htb_exiftool.png "Exiftool")
_exiftool 2020-01-01-upload.pdf_

Good thing we checked, we are given a username in the `Creator` field that we can assume to be Active Directory usernames.
We have our first one, `William.Lee`. Now we have a clear goal in mind.<br>
* Generate a list of possible filenames using the naming convention discovered above,<br> 
* Fuzz the server for them,<br>
* Download the ones that exist,<br> 
* Extract their creators,<br>
* Scan all the documents for keywords because there's no way they're all just Lorem Ipsum.<br>

First off, generating the list of possible filenames.
![Script](htb_docscript.png "Document Script")
_dateGen.py_

I am far from proud of this script and there is certainly a far better way but hey, it works and I'm already finished with it.
We're left with a file full of all the possible names for files on the server. (I also checked 2019 and 2021; nothing there.)

![Documents](htb_documentlist.png "Document List")
_PDF Fuzzing List_

Writing this up, I've just realized my script missed `2020-01-10` and presumably others. Serves me right for writing that abomination. 
Good thing I didn't need them. Anyway, with this list, we can find what files are hiding on the server.

![Fuzzing](htb_fuzzingdocs.png "Fuzzing Documents")
_Fuzzing Documents_

`wfuzz` did not want to give me a list I could use, so I can just copy the output and use `awk`
to liberate the filenames into a format I can actually use.

![awk](htb_founddocs.png "awk")
_Bash Magic_

Now that we have a list of real PDFs, we can use another Bash one-liner to fetch all of them.

![wget](htb_wget.png "wget")
![79 PDFs](htb_pdfs.png "79 PDFs")

Now that we've retrieved all of our PDFs we can harvest the names of all their creators to use for later spraying.

![User Harvesting](htb_users.png "User Harvesting")
![User List](htb_userlist.png "User List")
_79 Creators Harvested_

Some of these creators may appear across multiple documents and consequentially, appear multiple times in this list.
For our purposes in this CTF, there's no need to filter them out. Now that we have our usernames, we just have to
scan these documents for keywords to make sure we haven't missed anything. The documents are currently in PDF format.
We need to first get them into a more friendly format to scan them, thankfully, `pdftotext` exists. `pdftotext` doesn't
seem to like multiple inputs so we can simply just Bash loop them in.

![pdftotext](htb_pdftotext.png "pdftotext")
![text list](htb_txtlist.png "text list")
_79 Text Files_

Smooth sailing from here. Simply `cat *`, pass it to grep with some keywords and see what falls on our lap.

![Scan Documents](htb_scandoc.png "Scan Documents")
_NewIntelligenceCorpUser9876_

There we have it. Some diamonds in the rough. We have a default domain password, an extensive list of usernames and
an internal IT update we'll see more of in the root portion of this box. Now we can get to the password-spraying.
For this I like to use Metasploit, more specifically: `auxiliary/scanner/smb/smb_login`. With this module, I pass
in `RHOSTS`, `SMBDomain`, `USER_FILE`, `PASS_FILE` and run the scanner.

![User](htb_smbbrute.png "User")
_Tiffany.Molina:NewIntelligenceCorpUser9876_

In a sea of invalid credentials, `Tiffany.Molina` is still using the default password and is our ticket into the
domain.

---
# SMBClient

Authenticating into the SMB as `Tiffany.Molina`, we get a list of shares she has access to. 

![SMB](htb_tiffanysmb.png "Tiffany SMB")
_Tiffany - SMBClient_

Navigating to the `Users` share, we see `Ted.Graves` who is presumably our root target and `Tiffany.Molina` who 
we will retrieve our user flag from. Navigate to her desktop and there it is.

![User.txt](htb_user.png "User.txt")
_User.txt_

---
# System

This part is where things started to get a little bit confusing for me on account of being relatively new to Windows
machines on HackTheBox. Despite not having the knowledge necessary to see this machine through to the end on my own,
in the interest of learning how it's done, I am using [oxdf's writeup](https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html)
of this machine as a reference to practice Active Directory exploitation.<br><br>

Remembering back earlier, we found the **Internal IT Update** in the documents regarding Ted's script. As Tiffany,
we have access to the IT SMB share so we can see what it's all about. Connecting to the IT share, we find the script
referenced earlier: `downdetector.ps1`

![Found DownDetector.ps1](htb_founddowndetector.png "Found DownDetector.ps1")

Downloading `DownDetector.ps1`, it's relatively easy to decipher what it's doing.

![DownDetector.ps1](htb_downdetector.png "DownDetector.ps1")
_DownDetector.ps1_

This script:
* Fetches every domain object beginning with `web*`,
* Makes a web request to each domain object beginning with `web*` (Using Ted's credentials),
* If the server doesn't respond, the script sends Ted an email informing him of the outage.

Fortunately, [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) exists. With this tool,
we can create a DNS record, name the record something to match the criteria like `webSlimicide`, resolve it to my
TUN0 IP and capture Ted's NTLMv2 hash with `Responder`.

![DNSTool / Responder](htb_responder.png "DNSTool / Responder")
_dnstool.py // responder_

```
dnstool.py parameters
---------------------
-u = username
-p = password
-a = action
-r = record name
-d = record data
-t = record type
```
The security on this box is incredible.<br>
By the time the script runs, the intruder will be long dead of old age.<br>
Eventually, we catch Ted's NTLMv2 hash.

![Responded](htb_responded.png "Responded")
_Ted.Graves NTLMv2 Hash_

You can't see it in that screenshot, but trust me, it's there. Upon capturing this hash, we can head over to HashCat
and see if we can crack it. Using `RockYou.txt`, the hash cracks almost instantly and we are left with a new set of
credentials: `Ted.Graves:Mr.Teddy`.<br>

We have now compromised two accounts in this domain. Time to go see what new permissions are afforded to us courtesy
of Ted Graves. Easiest way to do this is to call in the Bloodhound.

---
# Bloodhound

Using Bloodhound-Python, we can authenticate into the domain and Bloodhound will collect all the information it can
and bundle it into a nice little JSON file to be imported into Bloodhound's GUI. For good measure, we'll run
Bloodhound-Python on both `Ted.Graves` and `Tiffany.Molina`.<br><br>

After importing the information provided to us by Bloodhound-Python and analysing the permissions of our compromised
users, we discover that `Ted.Graves` is a member of the IT Support group in the domain and as a member of that group,
he consequentially has permissions to read the GMSA password of `SVC_INT`.

![Bloodhound](htb_bloodhound.png "Bloodhound")
_ReadGMSAPassword_

GMSA Accounts are automated service accounts necessary for the fulfilment of tasks in their respective domains, these
accounts must also authenticate themselves when performing their tasks and so being able to read the GMSA's password
is great for us. We get a silver-ticket, not so great for the domain.

After searching for a tool which may be able to read this password for us, we come across a GitHub repository for
[gMSADumper](https://github.com/micahvandeusen/gMSADumper). Running this tool, we're given the password hash for 
`svc_int`:

![gMSADumper](htb_svchash.png "gMSADumper")
_svc\_int_

With the password hash of a service account, we can now use `GetST.py` from Impacket to generate a silver-ticket to
impersonate `Administrator`. Doing this requires us to sync our system's time to the server. In some cases like mine,
if you are running a VirtualBox VM, you will first have to do:<br>
`sudo service virtualbox-guest-utils stop`<br>
To prevent VirtualBox from automatically resetting your time. After stopping that service, you then run:<br>
`sudo ntpdate 10.10.10.248`<br>
To sync up with the server.<br><br>

With all that out of the way, we can generate our silver-ticket.
```bash
sudo python3 getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :a5fd76c71109b0b483abe309fbc92ccb -impersonate Administrator intelligence.htb/svc_int
```
```
-------------------------------------------------------------------
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```
`getST.py` has saved our ticket to `Administrator.ccache`, we create the `KRB5CCNAME` environment variable,
(which is typically used to authenticate service accounts) and point it towards our silver-ticket. We can then run Impacket's
`wmiexec.py` using Kerberos authentication with our new shiny silver-ticket and we successfully have logged into the
domain as `Administrator`

![Administrator](htb_silverticket.png "Administrator")
_Administrator_

Navigate to `C:\Users\Administrator\Desktop` and claim the root flag.

![Root](htb_root.png "Root")
_root.txt_

# :)
