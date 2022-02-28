Author's cmt from discord:

wxrdnx:
I can tell you my intended solution XD

Bacteria -> use ret2dlresolve to overwrite read with write and leak libc address. After that, it becomes traditional ropping.

Virus -> try letting rax into 0 to perform multiple read. Construct a SROP payload that execute execve("/bin/sh").

For the virus challenge, it seems that there's an unintended solution:
The vdso section contains pop rdi gadgets. However, you might need to guess the offset because vdso section is kernel specific.
