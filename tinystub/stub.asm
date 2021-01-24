%define BASE 0x00400000
%define APPNAME 'stub.exe'

[BITS 32]
[ORG BASE]

; === WINDOWS EXE HEADER STUB ===

db 'MZ'
db 'EBUNIXLMAO'

; PE File Header
db 'PE',0,0		; PE signature
dw 0x014C		; Machine (i386)
dw 0x0001		; Section count
dd 0x00000000		; Timestamp
dd 0x00000000		; Symbol table ptr
dd 0x00000000		; Symbol count
dw 0x00E0		; Optional header Size
dw 0x0103		; Caracteristics

; PE Optional Header
dw 0x010B		; Magic (PE32)
dw 0x0000		; Linker Version
ImageSize: dd 0x00FFFFFF ; Size of code
dd 0x00000000		; Size of InitData
dd 0x00000000		; Size of UnInitData
dd _main - BASE		; Address of entry point
dd 0x00001000		; Base of code
dd 0x0000000C		; Base of data (Overlapped with PE eader offset from DOS header)
dd BASE			; Image base address
dd 0x00001000		; Section alignment
dd 0x00000200		; File alignment
dd 0x00000006		; OS version
dd 0x00000000		; Image version
dd 0x00000006		; Subsystem version
dd 0x00000000		; Win32 version
dd 0x02000000		; Image size
dd 0x00001000		; Total header size
dd 0x00000000		; Checksum
dw 0x0002		; Subsystem (GUI)
dw 0x0000		; DLL characteristics
dd 0x00100000		; Stack reserve
dd 0x00001000		; Stack commit
dd 0x00100000		; Heap reserve
dd 0x00001000		; Heap commit
dd 0x00000000		; Loader flags
dd 0x00000010		; Number of RVAs

dd 0, 0	; Empty directories
dd __idata - BASE, __idata_end - __idata	; Imports
times 14 dd 0, 0

; Main Section
db 'SECTNAME'		; Section name
dd 0x00FFFFFF		; Virtual size
dd 0x00001000		; Virtual address
dd __end - __sect_start	; Raw size 
dd 0x00001000		; Raw address
dd 0x00000000		; Reloc address
dd 0x00000000		; Linenumbers
dw 0x0000		; Reloc address count
dw 0x0000		; Linenumbers count
dd 0xe0000060		; Characteristics

; Compressed data
__data: incbin 'data.bin',0,3796
__sect_start:
incbin 'data.bin',3796

__datasize: dd __datasize - __data

%include 'main.asm'

__idata:
dd __thunk - BASE	; Characteristics
dd 0x00000000		; Timestamp
dd 0x00000000		; Forwarder chain
dd __kernel32 - BASE	; Import name
dd __thunk - BASE	; First thunk

times 20 db 0
__idata_end:

__thunk:
GetProcAddress: dd __getproc - BASE
LoadLibraryA: dd __loadlib - BASE
dd 0

__kernel32: db 'KERNEL32.DLL',0
__getproc: db 0,0,'GetProcAddress',0
__loadlib: db 0,0,'LoadLibraryA',0

__end:
