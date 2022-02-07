There’s usually a pointer to `link_map` on the stack somewhere, so just write some data to `buf` and overwrite the `DT_STRTAB` pointer in `link_map->l_info`.

The offset to `link_map` varies a little bit but this should cover most of the possibilities.
