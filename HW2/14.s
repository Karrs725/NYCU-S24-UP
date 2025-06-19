mov eax, [0x600000]
mov ecx, [0x600004]
neg ecx
imul ecx
mov edx, [0x600008]
sub edx, ebx
mov ecx, edx
cdq
idiv ecx
mov [0x600008], eax