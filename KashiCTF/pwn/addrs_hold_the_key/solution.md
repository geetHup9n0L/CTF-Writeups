
## Challenge information:
### Tags: `ret2win`

Unzip the `chall.zip` from challenge, we have:
```c
└─$ ls
Dockerfile  vuln
```
**File info:**
```c
└─$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=373683834dc189e87b8e7ce568bad8d163aedcbd, for GNU/Linux 3.2.0, not stripped
```
```c                                                                                           
└─$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   44 Symbols  No     0               0               vuln
```
* `Partial RELRO`: GOT is overwritable
* `No canary`: No check for overflow
* `No pie`: binary address is fixed

___
Code from ghidra: `vuln`

`main()`:
```c
undefined8 main(void)
{
  int input;
  int idx;
  undefined1 value [44];
  int i;
  
  setup();
  puts("How many times you want to change the array");
  scanf(&"%d",&input);
  for (i = 0; i < input; i = i + 1) {
    puts("Indices allowed btw. 0 to 9");
    puts("Index: ");
    scanf(&"%d",&idx);
    puts("Value: ");
    scanf(&"%d",value + (long)idx * 4);
  }
  puts("Bye lmao nothing happened");
  return 0;
}
```
* On the stack, we have `value`, `idx`, `input`
  * `input`, `idx` is 4 bytes in mem
  * `value` is an array of 4 bytes, make total of 44 bytes 
* `input` is the how many times we want to interact with the array `value[]` on stack
* Next, is the snippet inside the forloop:
  ```c
    puts("Indices allowed btw. 0 to 9");
    puts("Index: ");
    scanf(&"%d",&idx);
    puts("Value: ");
    scanf(&"%d",value + (long)idx * 4);
  ```
  * The code let us write into `array[idx]` with numerical values
  * There is no logical check for input index beside the text warning in `puts(text)`

    ==> This means we can move outside the scope of `array[]` memory, with potential arbitrary write - a OOB (out of bound) bug

`print_flag()`:
```c
void print_flag(void)
{
  int iVar1;
  FILE *__stream;
  
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Error opening file.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    iVar1 = fgetc(__stream);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
* This is a hidden function that isnt called anywhere in `main()`
* Indicating a `ret2win` type of challenge

___
### Exploit:

As we analyzed, the challenge has an `OOB` bug and requires `ret2win` technique

First, since the challenge doesnt have PIE enabled, address of `print_flag()` is known:

<img width="801" height="90" alt="image" src="https://github.com/user-attachments/assets/633a3094-c596-4ccc-a591-96af413ab1a9" />

Our goal is to inject this address into RIP, so when the program returns - it triggers `print_flag()` function which prints out the flag

Parsing through the asm code on gdb, we found the exact offset of our local variables on the stack frame of `win()`:

```asm
input: [rbp-0x38]
idx:   [rbp-0x34]
value: [rbp-0x30]
```

Visualizing it on the stack, we have:

```asm



