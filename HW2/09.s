    mov ecx, 16

Loop:
    mov al, [0x600000 + ecx - 1]
    
    cmp al, 0
    jz next

    cmp al, 'a'
    jge next

    add al, 32

next:
    mov [0x600010 + ecx - 1], al
    loop Loop