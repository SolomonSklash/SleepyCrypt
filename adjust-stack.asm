; This code is borrowed from https://github.com/paranoidninja/PIC-Get-Privileges

extern run
global alignstack

segment .text

alignstack:
    push rdi                    ; backup rdi since we will be using this as our main register
    mov rdi, rsp                ; save stack pointer to rdi
    and rsp, byte -0x10         ; align stack with 16 bytes
    sub rsp, byte +0x20         ; allocate some space for our C function

    ; If we have a single params pointer argument in rcx, we should be able to just 
    ; use it immediately in run()

    call run                    ; call the C function
    mov rsp, rdi                ; restore stack pointer
    pop rdi                     ; restore rdi
    ret                         ; return where we left
