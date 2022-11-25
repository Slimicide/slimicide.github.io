---
title: Poison Null Byte - Forging a LIBC Leak
date: 2022-11-25 12:00:00
categories: [Research, Exploits]
tags: [exploit, python, pwntools, heap-overflow]     # TAG names should always be lowercase
img_path: /assets/img/Other/PoisonNull
---

I've been doing a lot of work recently on learning the heap and the techniques leveraged 
to exploit it through `HeapLAB` by Max Kamper. Particularly the heap as it pertains to Linux with 
GLIBC. One such technique is known as the Poison Null Byte.

The Poison Null Byte is a technique in which a heap overflow of just a single byte
allows for the manipulation of heap metadata and ultimately, enables the potential to leak
sensitive memory addresses such as that of either GLIBC's base or a heap address, both of which
are subject to ASLR and randomized at run-time; they are different on every execution. Hard-coding
values subject to ASLR into exploits will not work, they must be resolved at run-time.

This is where the leak comes in. By forcing a binary to disclose an address while it's running,
that address can be leveraged in further exploitation such as calculating the address for a
`one_gadget` for example.

This is where I had the problem of wanting to write about this technique but also not wanting to
use a binary from the `HeapLAB` course considering those are paid course materials, I don't want
to be showcasing them for free. In the end, I figured that I would just write my own vulnerable
binary and get a little bit more experience working with C. 

This way, if my binary is written poorly, it's actually a bug AND a feature. Win/Win

# 1-Note
---

Note: `1-Note` is linked to an old version of GLIBC: `libc-2.25.so`. The `tcache` was introduced in
`libc-2.26.so` and changes the behavior of core mechanisms behind this bug.

When writing `1-Note`, I wanted to try and make the binary seem benign in its operations. I tried
to come up with normal reasons to make it perform the operations I wanted it to perform. Eventually,
I canned that idea after realizing there was no real logical justification for making the allocations
I wanted to make without massively over-engineering it for the showcase of a single bug.

`1-Note` is a binary that does exactly what it says on the box. It holds one note. Here is the menu:

```
0) Read note.
1) Change note title.
2) Change note contents.
3) Malloc / Free 0x88.
4) Malloc / Free 0xf8 #1.
5) Malloc / Free 0xf8 #2.
6) Change note author.
7) Delete note contents.
8) Exit 1-Note. (Seriously, not *that* OneNote.)
```

Aside from oddly specific, ominous malloc and free calls, it seems relatively harmless. You can change the
note's title, the note's author and of course the note's contents, but there is a problem. The inputs
to change these data fields suffer from a single byte overflow:

```c
case '1':
	if(title == NULL){
		title = malloc(0x18);
	}
	printf("\nNew title: ");
	fgets(title, 0x18+1, stdin); //HERE
	break;
```

The final character read in by `fgets()` will be the string's null terminator: `\0`. By filling the
chunk with `0x18` bytes of user data, an additional null byte will be appended, overflow and land in
the first byte of the succeeding chunk's `size_field`. 

The `size_field` is a crucial part of heap metadata. Its role is to tell malloc how far down this
one specific chunk goes. Various flags can be set on it too to give a little bit more context on the
current state of the chunk such as if the previous chunk is free with the `prev_in_use` flag: `0x01`. 

The smallest size a malloc chunk can be is `0x20` (32 bytes). `0x8` (8 bytes) of it is reserved for
the chunk's size field, the remaining `0x18` (24 bytes) is to be filled with user data.

The bottom of the heap contains what is known as the `top_chunk`. The `top_chunk`'s job is to provide
new chunks with their memory when they're being allocated. The value of the `top_chunk` is the size of 
memory it's prepared to allocate whenever it's needed.

Here's what that looks like: 

![Title](title_chunk.png)
_Title Chunk_

Ignore the pink quadword. That belongs to the previous chunk which is not involved. Everything
in the green belongs to the newly allocated title chunk after choosing the `1) Change note title.` option.

The title chunk is a `0x20` sized chunk and the chunk behind it isn't free so the `prev_in_use` 
(`0x01`) flag is set. This makes its `size_field`: `0x21`

The succeeding blue quadword is actually the `top_chunk`. By overflowing the title chunk, an
additional null byte is going to overwrite the first byte of the `top_chunk`:

![Overflow](title_chunk_overflow.png)
_Poison Null Byte_

After filling the title chunk with 'A's (`0x41`), we see the `top_chunk` now holds `0x20700` instead
of the previous `0x207c1`. `0xc1` has been overwritten with `0x00`. You'll notice the final quadword
of title's user data has turned the same color as the `top_chunk`. This is because in overwriting the
first byte of the `top_chunk`, we actually cleared its `prev_in_use` flag (`0x01`). More on this later.

It's probably time to address the purpose of the `prev_in_use` flag and what it does.
Like I said earlier, the `prev_in_use` flag indicates whether or not the previous chunk is... in use.
Malloc needs this information so it can be efficient in how it manages the heap, specifically, free
chunks. 

For example, imagine there are two `0x90`-sized chunks: 
```
Irrelevant_Previous_Chunk - ALLOCATED

Chunk_A - FREE
	size_field: 0x91

Chunk_B - ALLOCATED
	size_field: 0x90
```
In malloc's eyes, Chunk_A is a free chunk because Chunk_B's `size_field` says so. If Chunk_B is
now freed, malloc will read Chunk_B's `size_field`, notice the previous chunk is also free and
consolidate them together into one single free chunk with a `size_field` of `0x121` (`0x90` + `0x90`).

Note: If a chunk adjacent to the `top_chunk` is freed, it will immediately be dissolved and the size
will be added to the `top_chunk`.

How it achieves the consolidation is related to why the final quadword of our title chunk turned the 
same color as the `top_chunk` earlier. When a chunk is freed, two main things happen:

```
1: 
The prev_in_use flag of the succeeding chunk is cleared to reflect the current free chunk.

2: 
The final quadword of the current chunk's user data gets repurposed as a prev_size field.
```

The `prev_size` field is simply the size from the same chunk's `size_field` copied into the final
quadword of user data minus the flags. That way when consolidating, malloc can simply read the 
`prev_size` field of the previous quadword to the current target's `size_field` and know how far 
back to consolidate.

That was a lot of prerequisite but it is required to appreciate what happens in this technique.
Now, as long as the victim of the overflow has a `size_field` of at least `0x110`, we can make
some modifications to the heap that we shouldn't be allowed to make. Anything less than 
a size of `0x100` and we wipe out the `size_field` altogether, that won't help.

The question is, what now? How does wiping the first byte of a `size_field` result in the leak
of a sensitive address? It has to do with how free chunks are stored and protected. Much like the
reasoning behind free chunk consolidation, malloc is all about efficiency. When a chunk is freed,
it will be stored in its respective `bin`. 

For this binary, it is the `UnsortedBin` that concerns us. When a chunk is being newly allocated, 
it will first search the bins to see if it can reuse a previously freed chunk instead of allocating 
a brand new one from the `top_chunk`. The `UnsortedBin` is a doubly linked list that resides in a place 
called the `main_arena`. The `main_arena` is located at a fixed offset from the base of LIBC. The linking
process is tricky to describe but essentially it involves a:
```
FD (forward pointer)
BK (backward pointer)
```
Important to note, when malloc is accessing a chunk, it points `0x10` bytes before the user data begins.

The `FD` resides in the first quadword of a free chunk's userdata. The `BK` resides in the second.

I'll free a chunk and follow the `UnsortedBin` `FD` to show how it works:

![FD](main_arena_diagram.png)
_UnsortedBin_

The important part to take away is the chunk placed behind the `main_arena` in the `UnsortedBin` 
will always hold the address of the `main_arena` in its `FD`. When there is only one chunk in the 
`UnsortedBin`, both the `FD` and `BK` will point to the `main_arena`. The `main_arena` is a good 
target because although the addresses are randomized, the offsets stay consistent. If we can leak 
the `main_arena` address, we can subtract the known offset and get the LIBC base address. There's 
just one problem. After the chunk is freed and the `main_arena`'s address gets written to the chunk, 
we can no longer read it due to nulling the pointers to free memory after freeing it within the binary:

```c
case '7':
	if(contents != NULL){
		free(contents);
		contents = NULL;
		break;
	}else{
		printf("\nYour note is already empty.\n");
		break;
	}
```

If we could read chunks which were freed from within the binary, this technique wouldn't be leveraged, 
it would be a simple Use-After-Free bug. This is where the poison null byte comes in.

# The Exploit
---

The goal is to read a `main_arena` address which is written to a chunk by freeing it. The caveat
being, you can't read *directly* from free chunks. So what can we read from? There is only one menu
option for reading memory and it's option: `0) Read note.` Using Pwndbg, it's easy to see what that
would look like. 

By choosing `2) Change note contents.` and writing some data to the note, this is what it looks like 
on the heap.

![Note Contents](note_contents.png)
_Note Contents_

Choosing `0) Read note.` now outputs:

![Note Output](note_output.png)
_Note_

Ok, great. It will read whatever data is written to it. It will also read the other fields which accept 
input such as the title and the author, although those aren't important here:

```c
case '0':
	if(title != NULL){
		printf("\nTitle: %s\n", (char*)title);
	}else{
		printf("\nTitle: Untitled\n");
	}
	if(contents != NULL){
		printf("%s", (char*)contents);
	}else{
		printf("Empty Note");
	}
	if(author != NULL){
		printf("\nAuthor: %s\n", (char*)author);
	}else{
		printf("\nAuthor: Anonymous\n");
	}
	break;
```

We're going to begin exploiting this binary by firstly allocating the chunks which the read option is is looking for
so it will actually include them in the read.

Use options:

```
1) Change note title.
2) Change note contents.
3) Malloc / Free 0x88.
6) Change note author.
```

Option 4 & 5 have been intentionally ignored for now. There's some setup to do. As it stands, the `contents`
chunk is size `0x210` with the additional `prev_in_use` flag making it `0x211`. 

By now choosing option `7) Delete note contents.`, this will free the `contents` chunk, linking it into the 
`UnsortedBin` and writing the associated `FD` and `BK` to its first two quadwords of user data. 

Now that the `contents` chunk is free, we can use option `1) Change note title.` and fill it to trigger
the poison null byte overflow. It was freed as a `0x210`-sized chunk, now it is a free `0x200`-sized chunk as a
result of the overflow. This will have its consequences later on, there are `0x10` bytes which are now unaccounted 
for.

There is one more concept to understand before completing this exploit and that is `remaindering`. 
Remaindering is simply malloc splitting apart a free chunk so it can service a request for an allocation of a size
smaller than the chunk being split.

For example, if there is a free chunk of size `0x200` sitting in the `UnsortedBin` and a request is made for a new
allocation of size `0x110`, the `0x200`-sized chunk will be split to allocate a `0x110`-sized chunk, the remaining
`0x90` of the chunk is going to remain in the `UnsortedBin` so it can be reused in a different request.

Now that that's out of the way, it's time to recognize what we have in front of us. A `0x200`-sized chunk is now
sitting in the `UnsortedBin`, holding a `main_arena` address waiting to be remaindered. We cannot read from it
because we freed it and nulled the pointer we used to have to it. We're going to have to do something else.

![Free Contents](free_contents.png)
_Free Contents_ 

As luck would have it, options 4 & 5 happen to split that
chunk really nicely, `0xf8` will allocate a chunk of size `0x100` which just so happens to be half of the chunk
being split. 

We'll use option `4) Malloc / Free 0xf8 #1.` and see what happens to the heap.

![Remaindered](remaindered_1.png)
_Remaindered_

It's at this point that I realize there is an unintended way to read the leak that essentially undermines the whole
point of this binary. Turns out I'm really good at writing vulnerable binaries; surprise features are showing up.
Pretending there isn't an alternative path, we'll carry on as normal.

By this point, the problem has revealed itself on the heap. `vis` no longer displays the full heap on account of the
heap being misaligned. Our remaindered chunk is falling short of the next `size_field` (chunk generated from Option 3).
By pushing that poison null byte earlier and turning a chunk of size `0x210` to that of a `0x200`, `0x10` was lost in
the process. That missing `0x10` is what is causing the current misalignment. In order to read the full heap now, we'll
have to use `dq mp_.sbrk_base 400` to dump 400 quadwords from the default heap. This works fine, it's just not 
color-coded.

Here is what's going on at the bottom of our remaindered chunk currently sitting in the `UnsortedBin`: 

![Misaligned](misaligned.png)
_Misaligned_

That `0x90` at the bottom is actually the `0x88` chunk's size field which was allocated after we allocated the original 
`0x210` `contents` chunk. When we freed that `contents` chunk, it wrote its `prev_size` field of `0x210` in its final 
quadword of user data. Now that we're missing `0x10` from pushing the poison null byte, the remaindered chunk's 
`prev_size` field has landed `0x10` bytes short. It should be before the succeeding chunk's `size_field`. This is 
a pretty big problem for reasons we'll see after our next allocation.

Using option `5) Malloc / Free 0xf8 #2.`, we allocate the remaindered chunk and dive into the heap to see what effect 
it had:

![Missed prev_in_use](missed_prev_in_use.png)
_Missed prev_in_use_

After allocating the previously remaindered chunk, it's no longer free. As such, malloc has attempted to flip the
`prev_in_use` flag onto the succeeding chunk's `size_field`. For reasons explained above, this flag misses its target.
As far as malloc is aware, according to the `0x90` chunk, the previous chunk is still free despite us just having
allocated it. This makes it a candidate for heap consolidation should we choose to free adjacent chunks.

By using option `4) Malloc / Free 0xf8 #1.`, we free the chunk formerly occupied by `contents`.

Now, by using option `3) Malloc / Free 0x88.`, it frees the `0x90` chunk, the `0x90` chunk notices from its `size_field`
that the previous chunk is also free considering the `0x90` chunk doesn't have a `prev_in_use` flag. It reads its
`prev_size` field to see how far back it can consolidate (`0x210`). This consolidates everything back up the former
`contents` chunk, leaving an unallocated chunk of size `0x2a0`:

![0x2a0](0x2a0.png)
_0x2a0_

Like all free chunks linked into the `UnsortedBin`, this chunk holds the `main_arena` address of the `UnsortedBin`.
`0x2a0` is plenty of room to squeeze in a new `contents` chunk.

By using option `2) Change note contents.` and supplying it with no data, we now have a functional `contents` pointer.

By using option `0) Read note.`, it leaks the address. This address contains non-ascii characters printed as an ascii
string. It will not output correctly but it will output. The address can be decoded in an exploit script.

![leaked](leaked.png)
_Leaked_

Here is the result of the exploit script. To avoid cluttering up this post, I'll leave the source code for the binary
and the exploit script [here](https://github.com/Slimicide/1-Note/) on my GitHub if you're interested.

![Exploit](exploit.png)
_Exploited_

# :)