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
There’s usually a pointer to `link_map` on the stack somewhere, so just write some data to `buf` and overwrite the `DT_STRTAB` pointer in `link_map->l_info`.

The offset to `link_map` varies a little bit but this should cover most of the possibilities.
