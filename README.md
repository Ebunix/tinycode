# tinycode
Collection of things that make code smol

## tinystub
tinystub is a PE exe file stub. It creates an executable from a bunch of assembly code and embeds a secondary executable inside that gets loaded and executed. For the future I want to add compression to the secondary exe, so it doesn't take up even less space.

### Compiling
tinystub uses NASM syntax. Simply compile it by running `nasm stub.asm -o stub.exe` in a command propmt or terminal.
This will only produce a PE exe file. There is no proper way to compile binaries for Linux with this, it's Windows only.

### Current issues/limits
- No relocations
  - This stub doesn't handle relocations at all. If your secondary exe contains any `.reloc` section the stub will bail out and do nothing. Relocation fixups are not on my list of todos at the moment as they would make the resulting stub even larger.
- Base address
  - The included secondary exe must have the same base address as the stub. This can be set at compile time for both of them (see the `stub.asm` header). For the MSVC compiler that means the linker needs to be passed the following switches: `/DYNAMICBASE:NO /FIXED /BASE:"0x00400000"` (Base address may vary)
- Size
  - The function import code is massive (~50% of the stub). Make that bullshit smaller somehow!
- Filename
  - The filename is fixed for the time being and needs to be set at compile time (see the `stub.asm` header). You can changethe target filename there, but once you compiled the program you can't rename the exe file. Renaming it will prevent the program from working at all and nothing will happen.
