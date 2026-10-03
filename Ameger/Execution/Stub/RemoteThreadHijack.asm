INCLUDE RemoteShell.inc

REMOTE_THREAD SEGMENT ALIGN(16) 'CODE'

PUBLIC RemoteThreadHijackBegin
PUBLIC RemoteThreadHijackEnd
PUBLIC RemoteThreadReturnTarget
PUBLIC RemoteThreadState

RemoteThreadHijackBegin:
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    lea rbx, [RemoteThreadState]
    mov r12, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 128

    movdqu [rsp+20h], xmm0
    movdqu [rsp+30h], xmm1
    movdqu [rsp+40h], xmm2
    movdqu [rsp+50h], xmm3
    movdqu [rsp+60h], xmm4
    movdqu [rsp+70h], xmm5

    mov rax, [rbx+SR_ROUTINE]
    mov rcx, [rbx+SR_ARG]
    mov qword ptr [rbx+SR_STATE], 1
    call rax
    mov [rbx+SR_RET], eax
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_LAST_ERROR], r11d
    mov qword ptr [rbx+SR_STATE], 2

    movdqu xmm0, [rsp+20h]
    movdqu xmm1, [rsp+30h]
    movdqu xmm2, [rsp+40h]
    movdqu xmm3, [rsp+50h]
    movdqu xmm4, [rsp+60h]
    movdqu xmm5, [rsp+70h]
    mov rsp, r12

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    jmp qword ptr [RemoteThreadReturnTarget]

ALIGN 16
RemoteThreadState:
RemoteThreadStateFlag    DQ 0
RemoteThreadRet          DD 0
RemoteThreadPad1         DD 0
RemoteThreadLastError    DD 0
RemoteThreadPad2         DD 0
RemoteThreadArg          DQ 0
RemoteThreadRoutine      DQ 0
RemoteThreadBuffer       DQ 0
RemoteThreadReturnTarget DQ 0

RemoteThreadHijackEnd:

REMOTE_THREAD ENDS

END
