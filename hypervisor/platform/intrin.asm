section .text

global __readcs

__readcs:
    mov ax, cs
    ret