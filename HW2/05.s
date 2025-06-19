    mov ecx, 16
    mov bl, '0'

Loop:
    shr ax, 1
    jc set_bit

    mov bl, '0'
    mov [0x600000 + ecx - 1], bl
    jmp next

set_bit:
    mov bl, '1'
    mov [0x600000 + ecx - 1], bl

next:
    inc edx
    loop Loop