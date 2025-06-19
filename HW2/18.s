    mov edi, 22
    call r
    jmp end
r:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov [rbp - 4], edi
    
    cmp edi, 0
    je zero
    cmp edi, 1
    je one

    mov edi, [rbp - 4]
    sub edi, 1
    call r
    mov rbx, 2
    mul rbx
    mov [rbp - 12], rax

    mov edi, [rbp - 4]
    sub edi, 2
    call r
    mov rcx, 3
    mul rcx

    mov rbx, [rbp - 12]
    add rax, rbx

    jmp rend
zero:
    mov rax, 0
    jmp rend
one:
    mov rax, 1
    jmp rend
rend:
    leave
    ret
end: