mov eax, [0x600004]
neg eax
mov ecx, [0x600008]
cdq
idiv ecx
mov ebx, edx
mov eax, [0x600000]
mov ecx, -5
imul ecx
cdq
idiv ebx
mov [0x60000c], eax