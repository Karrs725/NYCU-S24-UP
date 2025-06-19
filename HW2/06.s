mov eax, [0x600004]
sub eax, [0x600008]
mov ebx, [0x600000]
neg ebx
add ebx, eax
mov [0x60000c], ebx