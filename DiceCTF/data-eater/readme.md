```R
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
```C
int main(int argc, const char **argv, const char **envp)
{
  const char **v3; // rax
  const char **v4; // rax
  char s[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  while ( *argv ){
    v3 = argv++;
    *v3 = 0LL;
  }
  
  while ( *envp ){
    v4 = envp++;
    *v4 = 0LL;
  }
  
  fgets(s, 8, stdin);
  __isoc99_scanf(s, &buf); //.bss:0x601080
  memset(&buf, 0, 0x20uLL);
  return 0;
}
```
The program starts by clearing all arguments and environment variables.
Then it allows us to write 8 bytes to a local variable using fgets.
The result of this is used as the format string for a scanf call immediately after

Having control over the first argument of `scanf` means we can write anything we want. However, we need pointers to the addresses we want to write to. The program already sets the second argument to `buf` for us, so we can always write here. But to take control of RIP, we need to write to the stack. Let's take a look at the stack and registers before the call to `scanf`


## solution:
There’s usually a pointer to `link_map` on the stack somewhere, so just write some data to `buf` and overwrite the `DT_STRTAB` pointer in `link_map->l_info`.

The offset to `link_map` varies a little bit but this should cover most of the possibilities.

https://github.com/Green-Avocado/CTF/tree/main/dicectf2022/pwn/data-eater
