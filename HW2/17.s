    cmp eax, 0
    jge pos_a
    mov eax, -1
    mov [0x600000], eax
    jmp cmp_b
pos_a:
    mov eax, 1
    mov [0x600000], eax

cmp_b:
    cmp ebx, 0
    jge pos_b
    mov ebx, -1
    mov [0x600004], ebx
    jmp cmp_c
pos_b:
    mov ebx, 1
    mov [0x600004], ebx

cmp_c:
    cmp ecx, 0
    jge pos_c
    mov ecx, -1
    mov [0x600008], ecx
    jmp cmp_d
pos_c:
    mov ecx, 1
    mov [0x600008], ecx

cmp_d:
    cmp edx, 0
    jge pos_d
    mov edx, -1
    mov [0x60000c], edx
    jmp end
pos_d:
    mov edx, 1
    mov [0x60000c], edx

end: