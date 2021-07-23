# Regions that are not affected by FG_KASL
- The functions from _text base to __x86_retpoline_r15, which is _text+0x400dc6 are unaffected
- KPTI trampoline swapgs_restore_regs_and_return_to_usermode() is unaffected.
- The kernel symbol table ksymtab, starts at _text+0xf85198 is unaffected
