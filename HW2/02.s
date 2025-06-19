    mov eax, 10

outer_loop:
    dec eax
    jz end

    mov ebx, 0
    mov ecx, 0

inner_loop:
    mov edx, [0x600000 + ebx * 4]
    cmp edx, [0x600000 + ebx * 4 + 4]
    jle no_swap

    mov ecx, [0x600000 + ebx * 4 + 4]
    mov [0x600000 + ebx * 4], ecx
    mov [0x600000 + ebx * 4 + 4], edx
    mov ecx, 1

no_swap:
    inc ebx
    cmp ebx, eax
    jne inner_loop

    cmp ecx, 0
    je end

    jmp outer_loop

end: