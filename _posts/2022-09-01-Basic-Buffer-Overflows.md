---
title: Basic Buffer Overflows
date: 2022-09-01 20:00:00
categories: [Research, Exploits]
tags: [buffer-overflow, exploit, python, pwntools, picoctf]     # TAG names should always be lowercase
img_path: /assets/img/Other/Buffer-Overflow
---
Binary exploitation has always interested me. Anything low-level does. You always hear about ROPs and NOPs, Overflows and Shellcode.
It's definitely a very exciting and rewarding skill to learn. Like with all things, but especially low-level things; you have to start
small. For binary exploitation, that means beginning with the humble Buffer Overflow.<br>

With this post, I'll be attempting to create the resource I wish I had stumbled upon when I was first getting started.
That said, it's important to note that I'm still relatively new to all of this, I can't do anything much more exciting than reliably
exploiting buffer overflows. Fortunately, that's all this post is going to be about.<br>

The target for this post is **Buffer Overflow 1** from [PicoCTF](https://www.picoctf.org/)<br>

---
# Buffer Overflow 1

For this challenge, we're supplied with two things; the ELF binary and the source code.<br>
There's a few things we need to check in no particular order so we can begin by simply running the binary like normal.

![vuln](vuln_elf.png "vuln")
_./vuln_
We're prompted for input and the binary jumps to `0x804932f` where it can continue and complete normal execution.<br>

Our second stop is going to be running `checksec` from `pwntools` on the binary in order to see what security features are enabled.

![checksec](checksec.png "checksec")
_checksec_
This a very simple buffer overflow and so naturally there aren't any meaningful security protections involved this time around. For the sake of
completion, we can define them and what they mean anyway.
```
Arch:     i386-32-little
   Architecture: 32-bit, Little-Endian.
RELRO:    Partial RELRO
   Makes the Global Offset Table (GOT) Read-Only.
Stack:    No canary found
   Places a random value in the stack, if the value is overwritten, the binary exits.
NX:       NX disabled
   Marks the stack as No eXecute meaning no instructions inside will be executed by the CPU.
PIE:      No PIE (0x8048000)
   The base address of the binary is randomized. Exploits require addresses to be leaked.
RWX:      Has RWX segments
   The binary has segments which are writable and executable.
```
Now that that's out of the way, we can look at the provided **vuln.c** source code and get an idea of what's going on.

---
# Source Code
![main](main.png "main")
_main_
Inside main, there's some setup presumably for the binary running remotely on PicoCTF. **vuln** is what we're interested in.

![vuln](vuln_func.png "vuln")
_vuln_
A buffer is created and then **gets** is called to enter our input into the newly created buffer. After looking up the man page
for it, it turns out **gets** is more than a little unsafe.

![gets](gets.png "gets")
_gets_
Here is where the Buffer Overflow name comes from. **gets** does not care about the size of the buffer
provided to it; it will store input exceeding that buffer, overflowing and overwriting other data on the stack. At the top
of the source code, the buffer size is defined at 32 bytes. Anything in excess of that will overflow the buffer and overwrite
adjacent data.

![buffer size](buffer_size.png "buffer size")
_Buffer Size_
That seems to be it, after the dangerous call to **gets**, the binary seems like it's finished despite there being one more function
present in the source code which is never called... The **win** function.

![win](win_func.png "win")
_win_
Looks like this is the function that will read out the flag. It is never called during regular execution. The story so far is:<br>

We have a binary that accepts user input,<br>
Passes it to a function known to overflow buffers,<br>
We are told the return address (which wouldn't change during regular execution),<br>
The binary exits.<br>

This paints a good picture as to what is expected of us.<br>

Now that we have all the information required to attempt an exploit, we can fire up a debugger (in my case pwndbg) and see what's 
going on. We know from reading the source code that the **vuln** function is where we should be looking.

![Disassembled Vuln](vuln_disass.png "Disassembled Vuln")
_disass vuln_
We can assume that we're supposed to overflow the buffer and overwrite the mentioned instruction pointer (**EIP**). In order
to know where to place a breakpoint to get a better look, we need to understand how **EIP** works in the context of functions. <br>

---
# EIP and Stack Frames
**EIP** is known as the instruction pointer; its job is to keep track of what address to execute instructions at next. During function
calls, we enter what is known as a new **stack frame** where all the instructions for that function reside. But when that function
is finished execution, we need to know what instruction to execute next. For this reason, the old instruction pointer is saved to
the stack just below the newly allocated stack frame. Once the function is finished, we leave the stack frame, collect our old
instruction pointer and jump back to the place the function was initially called from and continue on regular execution.<br>

In conclusion, if you can overwrite data on the stack while inside a function and consequentially overwrite the instruction pointer;
you get to control where the binary jumps after said function is finished executing. This will become clearer later if it isn't clear
right now.<br>

---
# Debugging

We now know that our old instruction pointer is vulnerable on the stack and it is restored as we leave the current function's
stack frame. For this reason, we can put a breakpoint on the `leave` instruction inside **vuln**. Looking at the screenshot above,
that is located at `0x080492c2`, we can set a breakpoint run the binary and take a look at what we're working with.

![Breakpoint](breakpoint.png "Breakpoint")
_Breakpoint_
I entered in "Win!" as my input in this case

![Stack](stack.png "Stack")
_Stack_
Here is what the stack looks like just before we leave the **vuln** function. There are two important things to take note of here.
We have our user input sitting at the very top of the stack and we have our old instruction pointer saved at the bottom. 
(of the screenshot, this isn't actually the bottom of the stack.) `info frame` confirms this address as our "saved EIP".<br>

With the source code, we know our buffer size is 32 bytes; let's fill it.

![Full Buffer](full_buffer.png "Full Buffer")
_Full Buffer_
There it is, perfectly handled inside its buffer, storing 4 bytes per address. `0xffffcfc0` and `0xffffcfc4` are occupied with 
other unrelated binary data. Time to throw caution to the wind and overflow this buffer with 8 more bytes to overwrite those
two mentioned addresses just to get a visual representation of what's happening here.

![Overflow](buffer_overflow.png "Overflow")
_Overflow_
We have now proven we can break out of the buffer and overwrite adjacent data on the stack. We're really close to reaching that
saved instruction pointer. We can add another 4 bytes to close the gap and the next 4 bytes we enter after that will overwrite
the instruction pointer.<br>

To be conclusive on the numbers; the buffer is 32 bytes, then there's 3 more addresses (12 bytes) we need to overwrite to reach
the instruction pointer. We need to supply 44 bytes of junk data and the next 4 bytes will be our new instruction pointer.

![Segmentation Fault](segfault.png "Segmentation Fault")
_Segmentation Fault_
The binary confirms the instruction pointer was overwritten and crashes trying to access `0x45444342` ("BCDE" in Little Endian).
The final step is to supply the binary with the bytes required to construct the address to the **win** function.
This is probably best done through a Python script considering the bytes we are required to supply aren't exactly input we can
normally provide with a keyboard.<br>

To achieve this, we can use `pwntools` and the **pack** function from `struct`.
```python
#!/bin/env python3

from pwn import *
from struct import pack

# Pack will take the given address and morph it into a bytes
# "<i" means Little-Endian Integer
win = pack("<i", 0x080491f6)

# Amount of junk data required to reach instruction pointer
offset = 44

#Payloads for binaries must be supplied as bytes (b"A")
payload = b"A" * offset + win

# Pwntools will start the local process
p = process("./vuln")
# Go through the binary until the input section
p.recvuntil(b"")
# Send our offset + win address
p.sendline(payload)
# Easy way to receive all further data from the binary
p.interactive()
```

![Won](won.png "Won")
_Won_
We conclusively enter the **win** function evident by the reading of `flag.txt`. As far as Buffer Overflows go, this one cannot
be easier. There are a few more obstacles that may manifest themselves in other situations. The purpose of this binary and of this
post is to understand the fundamental principles of how this attack vector exists and how you can exploit it.

# :)
