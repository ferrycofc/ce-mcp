.code
ALIGN 16
inject_wide PROC
    mov eax, edx
    add eax, 12345678h
    mov DWORD PTR [rcx], eax
    ret
inject_wide ENDP
END
