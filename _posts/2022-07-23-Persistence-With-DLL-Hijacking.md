---
title: Persistence with DLL Hijacking
date: 2022-07-23 12:00:00
categories: [Research, Windows]
tags: [persistence, dll-hijacking]     # TAG names should always be lowercase
img_path: /assets/img/Other/DLL-Hijacking
---
Recently I've been playing around with Procmon from SysInternals to try and find interesting DLL Hijacking opportunities.
While exploring different software and seeing what would fall into my Procmon filter, I decided that I wanted to write about it
and take a break from more or less exclusively writing up HackTheBox machines and instead write up something I'm actively looking into.
I found a particularly interesting hijack that has **NO** security implications (probably) but I thought it would make a great example to show this off.<br>

That said, I should clarify this is something I'm actively looking into and learning about. There may be things I leave out or 
there may be things I get wrong. This is all for fun, seeing where things go and loosely how they work.<br>

# What is DLL Hijacking?
---
DLL Hijacking is essentially tricking a process to run a malicious DLL file over the legitimate one it's looking for. It can potentially be
a privilege escalation vector if you can get a high privilege process to load your DLL from a low privilege account or it can be used
to maintain persistence on a machine.<br>

Typically what it comes down to is having write permissions for a folder containing a DLL loaded by a target process.<br>

# What DLLs are being loaded?
---
Using a tool called Procmon from SysInternals, you are shown events created by processes running on your system. Included in these events 
are processes creating handles into DLLs to load. Using Procmon's filters, it is very easy to specifically capture the loading of DLLs.
It's good to know what DLLs are being loaded, you might get lucky with weak folder permissions, but it's far more interesting looking 
into DLLs that are missing. DLLs turning up missing could potentially be a sign that the process is turning to the [DLL Search Order](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#standard-search-order-for-desktop-applications)
to be loaded. This offers a much more likely chance that it can be hijacked so it is worth filtering for this first.

![Procmon Filter](procmonFilter.png "Procmon Filter")
_Procmon Filter_

With this filter in place, we can load up whatever process we want and capture it trying to load a non-existent DLL.
I let this filter run in the background while playing around with different processes and I went back to look through it and found something
that caught my eye.

# Brave
---

![Brave Missing](braveMissing.png "Brave Missing")
_C:\Program Files (x86)\BraveSoftware\Update\goopdate.dll_

This is also a good place to say it's probably not a good idea to specifically filter by process name. Had I specifically filtered for
`brave.exe` I would have missed this. It initially looks exciting but here's why I prefaced the post by saying there is **NO** security
implications. The folder is protected, you need administrator permissions to write to it and if you already have administrator, there
isn't a whole lot to escalate to. (Not to mention I couldn't get it to execute as SYSTEM in the end anyway but that's beside the point.)

![Administrator Required](adminRequired.png "Administrator Required")
_Administrator Required_

![Read Execute](readExecute.png "Read Execute")
_Read/Execute_

Low-privileged users are only permitted to read the folder and execute files within it.
Who'd have known, one of the most popular browsers out there doesn't have a low-hanging fruit privilege escalation vector... but what
*can* we do with it? Had this been a privilege escalation vector, what would it enable us to do? We can build some of our own DLLs and
find out. I found that visiting `brave://settings/help` in the Brave browser triggers the search for the missing DLL so it's an easy
way to test things out. We can start off by checking if it'll even execute what we write in our DLL.

![Calc.exe](codeCalc.png "Calc.exe")
_calc.exe_

Good thing `WinExec()` is as straight forward as it is or I'd be on StackOverflow for the foreseeable future. We can build that DLL,
quietly grant ourselves the permissions required to write to the folder and place it in there named `goopdate.dll` just like it was
looking for in Procmon. With the DLL planted, we can navigate to `brave://settings/help` in the Brave browser and...

![Pop](calc.png "Pop")
_Success_

We can generate DLLs to do pretty much whatever we want. Anything we execute within our DLLs will be executed with the permissions Brave
is running with, in this specific context we can't execute anything with a DLL we couldn't execute ourselves but if this was a process
running with higher privileges we could run DLLs with, it's an easy privilege escalation vector.

![Permissions](permissions.png "Permissions")
_Running as Current User_

# Persistence
---
Thinking about stuff to do with it, I decided to see how it would work out as a persistence mechanism. I wrote a new DLL to send a shell
over Netcat to my Kali machine.

![Netcat](codeShell.png "Netcat")
_ncat.exe_

Sure enough, I replaced the target DLL with my new one, reloaded the trigger on Brave and the shell arrived without a problem.

![Shell](shell.png "Shell")
_Shell Received_

Great, so every time that specific page in the depth of Brave's settings is loaded, I'll catch a shell. Not a great mechanism yet.
After looking back at the Procmon capture that inititally showed this missing DLL, it seems like `BraveUpdateBroker.exe` is responsible
for kicking off the search for the missing DLL. That page doesn't necessarily have to be visited, `BraveUpdateBroker.exe` just needs to run.
Being an updater, it doesn't seem like it'd be too out of place being a startup application or a scheduled task, at least compared to
finding `TotallyNotMalware.exe` as a startup application or a scheduled task. After all, `BraveUpdateBroker.exe` does have a valid signature.

![Signature](signature.png "Signature")
_Valid Signature_

I decided to plant it in the startup folder as a shortcut.

![Startup](startup.png "Startup")
_Startup_

I started a listener on my Kali machine, logged out of Windows and logged back in and sure enough, the shell arrived.

![Persistence](persistence.png "Persistence")
_Persistence_

Just to reiterate, none of this is possible without already having administrator permissions, I just thought it was a fun train of thought
to explore and write about what would be possible had there been a genuine privilege escalation vector available.<br>

# :)
