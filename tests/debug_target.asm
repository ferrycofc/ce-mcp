; Fixed instructions give an independent oracle for post-instruction RIP correction.
.code
ALIGN 16
writer_a PROC
    mov DWORD PTR [rcx], edx
    ret
writer_a ENDP
ALIGN 16
writer_b PROC
    mov DWORD PTR [rcx], edx
    ret
writer_b ENDP
ALIGN 16
reader_a PROC
    mov eax, DWORD PTR [rcx]
    ret
reader_a ENDP
END
