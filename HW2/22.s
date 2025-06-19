    cmp ch, 'a'
    jge ltou
    add ch, 32
    jmp end
ltou:
    sub ch, 32
end: