PeekMessageW:
    mov eax, [DWORD PTR 0xf0300000]
    mov ecx, [DWORD PTR 0xf0300004]
    test eax, eax
    jz loopend
    test ecx, ecx
    jz loopend
    mov esi, 0xf0300008
loopp:
    push ecx
    push eax
    push [esi+12]
    push [esi+8]
    push [esi+4]
    push [esi]
    call eax
    pop eax
    pop ecx
    add esi, 16
    loop loopp
    mov [DWORD PTR 0xf0300004], 0
    
loopend:
    mov ecx, [DWORD PTR 0xf0302008]
    test ecx, ecx
    jz looptend
    mov esi, 0xf0302018

loopt:
    mov eax, [esi]
    cmp eax, 0
    je looptdstart
    cmp eax, 1
    je looptdmove
    cmp eax, 2
    je looptdend
    jmp looptfal
    
looptdstart:
    mov eax, [DWORD PTR 0xf030200c]
    test eax, eax
    jz looptfal
    jmp looptcall

looptdmove:
    mov eax, [DWORD PTR 0xf0302010]
    test eax, eax
    jz looptfal
    jmp looptcall

looptdend:
    mov eax, [DWORD PTR 0xf0302014]
    test eax, eax
    jz looptfal

looptcall:
    push ecx
    push eax
    push [esi+8]
    push [esi+4]
    call eax
    pop eax
    pop ecx
    add esi, 12

looptfal:
    loop loopt
    mov [DWORD PTR 0xf0302008], 0

looptend:
    xor eax, eax
    ret 20