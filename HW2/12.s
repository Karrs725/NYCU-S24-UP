mov eax, [0x600000]
mov ecx, 5
mul ecx
mov edx, 0
mov ebx, [0x600004]
sub eax, 3
div ebx
mov [0x600008], eax