global _start

section .text
_start:
	; write
	mov rax, 1
	mov rdi, 1
	mov rsi, hello
	mov rdx, len
	syscall

	; exit
	mov rax, 60
	mov rdi, 0
	syscall
	
section .rodata
	hello: db "Hello, world!", 10
	len: equ $ - hello
