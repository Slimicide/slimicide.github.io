---
title: HackTheBox - Forge
date: 2022-05-03 14:30:00
categories: [HackTheBox, Machines]
tags: [hackthebox, forge, ssrf, upload, pdb]     # TAG names should always be lowercase
img_path: /assets/img/HackTheBox/Forge
---

![Forge](htb_forge.png "Forge")
_HackTheBox Forge_

**Forge** is a retired medium machine on HackTheBox, it is the machine that made me want to create writeups
originally. After subscribing to HackTheBox and gaining access to retired machines, it's finally time to do it.<br>

---
# Enumeration

**Scan:**
```bash
nmap -sC -sV -oA nmap_initial 10.10.11.111
```
**Results:**
```
Nmap scan report for 10.10.11.111
Host is up (0.035s latency).
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://forge.htb
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr  9 17:33:23 2022 -- 1 IP address (1 host up) scanned in 9.78 seconds
```
We get this machine's hostname of `forge.htb`.<br>
Add it to `/etc/hosts` and move on. There is an FTP service active but not currently accessible to us meaning
we will begin with **Port 80**

---
# Port 80

![Landing](htb_landing.png "Landing Page")
_http://forge.htb/_

It seems to be a very simple image upload page where we can upload our own image using the button in the upper right.
Clicking `Upload an Image` brings us to `http://forge.htb/upload`, it will allow us to upload through either local
file upload or upload from URL.

![Upload](htb_uploadpage.png "Upload Page")
_http://forge.htb/upload_

We'll see what happens when we upload an image of our own. Upon uploading the image, we're given a link to where it
was uploaded on the server.

![Uploaded](htb_uploaded.png "Uploaded")
_Successful Upload_

If we follow that link, it does in fact bring us to our perfect test image: `low_intelligence.png`. It has arrived
safetly onto the server and it is on display in all its glory.

![Low_Intelligence](htb_low_intelligence.png "Low_Intelligence")
_low\_intelligence.png_

Who would have guessed? The image upload site allows image uploads. What happens when we upload something that
isn't an image? We'll upload a simple text file to find out.

![No Display](htb_textfile.png "No Display")

The server loads images via `<img src="link">` and I presume that is why it will not display. Although the content
isn't displayed on the page, it is visible in the server response.

![Test File](htb_response.png "Test File")
_This is a test file._

The server allows us to read the contents of files despite them not being images. Interesting. We'll come back to this
later.

---
# Gobuster

We'll start by enumerating vhosts.

**Scan:**
```bash
gobuster vhost -u forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt  -o gobuster-vhost-forge.htb
```

The server just spits out every request as a status 302, in order to identify the real vhosts, we can simply grep 
inverse search `302` from our gobuster output.

```bash
cat gobuster-vhost-forge-htb | grep -v 302
```

With this, we find only one valid vhost: `admin.forge.htb` and it is suspiciously small, only being `[Size: 27]`.<br>
Add it to `/etc/hosts` and we'll find out why.<br>

We arrive on `admin.forge.htb` and we are given an explanation for the size of the page. It simply says:<br> 
`Only localhost is allowed!`. Not only does it explain the size of the page, it makes our target very clear.
We need to exploit a SSRF vulnerability from the server's `Upload from URL` input in order to read `http://admin.forge.htb/`

---
# SSRF

Server-Side Request Forgery aka SSRF is a vulnerability in which we can exploit a server to make requests on our behalf.
In this instance, `admin.forge.htb` is only accepting requests from `localhost`, we cannot access it from outside.
However with SSRF, we can tell the parts of the server we can access to make that request for us as `localhost`.<br><br>

Luckily, I'm in the mood to create a MS-Paint ***masterpiece***.

![SSRF](htb_masterpiece.png "SSRF")
_SSRF - Forge_
I hope you like it, took me a few minutes.<br>

Trying to access `http://admin.forge.htb/` normally through `/upload`, we learn there is a blacklist in place to try
and mitigate SSRF by blocking requests to `localhost`, `127.0.0.1` and other popular loopback addresses such as `0.0.0.0`.

![Blacklist](htb_blacklist.png "Blacklist")
_URL contains a blacklisted address!_

After trying out different SSRF payloads and bypasses, I have discovered two that work, one of them is much less annoying
than the other.<br>

The more annoying bypass is URL encoding `http://admin.forge.htb/` and submitting that.<br>

The easy bypass is simply submitting `http://ADMIN.FORGE.HTB/` because the blacklist seems to only block its lowercase
equivalent. With this, we can submit the index page of `admin.forge.htb` to `Upload from URL` and read it from the server
response.

![Admin](htb_admin.png "admin.forge.htb")
_http://ADMIN.FORGE.HTB/_

Through the page source, we learn of the existence of:<br>
**1)** `http://admin.forge.htb/upload`<br>
**2)** `http://admin.forge.htb/announcements`<br><br>
Both of which we can read using this SSRF. We'll start with reading the admin's announcements.

![Announcements](htb_announcements.png "Announcements")
_http://ADMIN.FORGE.HTB/announcements/_

Here is our explanation for the inaccessible FTP server. We can access the FTP server through the admin's `/upload`
endpoint using the provided credentials as a GET parameter. We'll go and see what files are available through our 
externally accessible `/upload` endpoint using our payload:
```
http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@LOCALHOST
```

![FTP](htb_ftp.png "FTP")
_Success_

The FTP seems to be inside the user's home directory judging by the presence of `user.txt`. We now know what to add
on to our request to gain SSH access as `user`:<br>
```
http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@LOCALHOST/.ssh/id_rsa
```

![SSH](htb_idrsa.png "id_rsa")
_id_rsa_

By copying the SSH key to my local machine and setting the correct permissions, we now have SSH access as `user`.

![user](htb_user.png "user")
_user.txt_

---
# Root

We don't have to do a lot of searching to find our privilege escalation vector. By running `sudo -l`, we are told we
have permission to execute a Python script as root.

![Sudo python](htb_privesc.png "Sudo python")
_sudo -l_

Running the script, it opens up a TCP listener, in order to interact with it, we can just open a second SSH session
and we can then connect to the port specified by the script using `nc` already on the box. Upon connecting to the box,
we are prompted to enter a "secret password".

![Enter the secret password](htb_secretpass.png "Enter the secret password")
_Enter the secret password_

It's just a Python script, we can read it to find the password it's looking for.

![Secret Password](htb_secretpass1.png "Secret Password")
_secretadminpassword_

Makes sense.<br>
After entering the password, we're prompted with a menu.

![Menu](htb_menu.png "Menu")
_Admin Menu_

Reading the script, we know that options 1-4 are boring. However, throwing an exception might be interesting
because it gets the Python debugger involved. As the client, we select the non-existant option `a` and sure enough,
the process dies and we're given a pdb shell.

![pdb](htb_pdb.png "pdb")
_pdb_

Typing help, we're given a list of commands we can run.

![help](htb_help.png "help")
_help_

We can use the `interact` command and it puts us into a Python interpreter. From here, we can simply:
```python
import os
os.system('/bin/bash')
```
We now have a bash shell as root which we can use to read the root flag.

![root](htb_root.png "root")
_root.txt_

I have finished a handful of HackTheBox machines but Forge remains as a clear favorite. It is relatively
straight-forward as far as medium boxes go and it is immensely satisfying.

# :)
