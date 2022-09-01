---
title: CSCG 2022 - Intro to Pwn 1
date: 2052-05-02 22:15:00 +/-TTTT
categories: [CSCG 2022, Pwn]
tags: [cscg2022, pwn]     # TAG names should always be lowercase
img_path: /assets/img/CSCG2022/
---
Binary exploitation has been something I’ve been interested in since I started learning different aspects 
of InfoSec. Until now I haven’t touched it because I’ve been busy learning the fundamentals of other topics 
and frankly, it looks confusing.<br>

Then I found the [CSCG 2022 CTF](https://earth.cscg.live/) and decided there's no time like the present,
with the [official event write-up](https://static.cscg.live/08d62c58a28bf48f18b148418182c90fbf213b505ef9186adf9980dda18711fb/writeup-pwn1.pdf)
as my guide and [pwndbg](https://github.com/pwndbg/pwndbg) as my tool of choice, I managed to exploit my first
binary, [Intro to Pwn1](https://earth.cscg.live/tasks/intro-pwn-1)<br>

Downloading the associated zip, we've got a Dockerfile, the binary and the binary source code.<br>
![IntroToPwn1.zip](itp1_zip.png "IntroToPwn1.zip")_IntroToPwn1.zip_

Running the binary, we find that it prints lyrics from an Eminem song, gives us a hex value
(presumably a memory address) and allows us to "Enter your shot". I enter "AAAA" and receive a segfault for
my troubles.<br>

![Segmentation Fault](itp1_segfault.png "Segmentation Fault")_Segmentation Fault_

We go to our provided source code to see if we can get more answers, our only relevant function being `one_shot()`
which prints the memory address of the `setvbuf` function and expects us to give it another address to jump to.

![Pwn1.c](itp1_pwn1c.png "Pwn1.c")_Pwn1.c_

Time to see what protections are on the binary by running `checksec`, a feature of `pwntools`.
It seems like the binary has some relatively heavy protections enabled, the most detrimental ones being:<br>

```
Stack Canary: There is a value placed somewhere in the stack, if this variable is overwritten
	      the binary will exit. We probably won't be doing any stack-smashing.

PIE:	      "Position Independent Executables" loads binaries and their dependencies at 
	      randomized base addresses. Memory addresses will shift every single time the
	      binary is run. We have to leak offsets.

NX:	      NX marks the stack as Non-Executable. We won't be running any shellcode this
	      time around.
```

The simplicity of the binary helps crossing possible attack vectors off the list, there is no buffers to be
overflowed, the canary will not tolerate any smashing of the stack and we can't possibly execute any shellcode
on the stack. However, we do have a free `PIE` bypass in the form of our `setvbuf` address.<br>

To confirm our suspicions, it is time to load up `gdb`. To start things off, we'll simply run and hang the binary.<br><br>
![SIGINT](itp1_hang.png "SIGINT")_SIGINT_

While we hold it in binary purgatory, we can grab some values we need from memory, starting by confirming our
supplied function address.<br><br>
![setvbuf](itp1_setvbuf.png "setvbuf")_setvbuf_

There it is, our binary supplied address of `7ffff7e4c4f0` matches the function address in memory. Great.
Now we can run `vmmap` to find our current libc base address.<br>

![vmmap](itp1_vmmap.png "vmmap")_vmmap_

Our current libc base is `7ffff7dd6000`. With `PIE` enabled, this won't always be the case. What will always be
the case however (at least with this version of libc), is the offset between the base address and the `setvbuf`
function. Finding the offset at this point is trivial, simply run: 
```bash
python3 -c 'print(hex(0x7ffff7e4c4f0 - 0x7ffff7dd6000))'
```
Offset = `0x764f0`<br>
With this offset, we can find the libc base address every single time without dissecting the memory.
When we run the binary the next time, we simply take the address it gives us and pop it into the `setvbuf`
variable below:
```python
libcOffset = 0x764f0
setvbuf = #Binary-Supplied Address beginning with "0x"

libcBase = hex(setvbuf - libcOffset)
```
Now, onto confirming the binary will jump to whatever address we provide it with. `gdb` has a `disable-randomization`
feature we can use to just find the exit address without having to mess around with other offsets we won't need.
With our binary still hanging in tight, just like we printed `setvbuf` we can print `exit`. With this exit address,
we can run the binary again and supply it as our input.

![exit](itp1_exit.png "exit")_print exit_

There it is, the binary simply jumped to the exit and closed itself instead of crashing in a firey inferno as it
tries to jump to "AAAA". Nice change of pace.

# -Exploit

Now that we have a method of finding the base address of libc and the power to jump to whatever address we want, we
can use a tool called [one_gadget](https://github.com/david942j/one_gadget). `one_gadget` is a tool dedicated to
finding addresses in libc we can use to achieve RCE by hijacking an internal use of shell executions for our own
purposes. We simply must supply `one_gadget` with our target libc file, find an address with some empty registers
and use that address in our exploit. Looking back at our vmmap, we know the path of our libc version.

![one_gadget](itp1_onegadget.png "one_gadget")_one\_gadget_

Output from `one_gadget` is given as an offset to the libc base. `0xcb5d0` looks like it'll serve our purpose.
There isn't any need to bother making an exploit script for this considering it's just two calculations, so I'm
just going to use the Python interpreter. Here we go:

![success](itp1_success.png "success")_Success!_

Supplying the binary with the address of a shell execution has, to nobody's surprise, given us RCE.
It is important to note that because we are working with offsets. These offsets were generated using 
`libc-2.33.so` and these offsets will change between libc versions. However the methodology for finding them
remains the same. To get the real flag, we can spin up the supplied Docker instance and find the offsets using
the challenge's libc (<i>which I probably should have done from the start, but here we are</i>)

# :)
