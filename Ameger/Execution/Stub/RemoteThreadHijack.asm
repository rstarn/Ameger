INCLUDE RemoteShell.inc

REMOTE_THREAD SEGMENT ALIGN(16) 'CODE'

PUBLIC RemoteThreadHijackBegin
PUBLIC RemoteThreadHijackEnd
PUBLIC RemoteThreadReturnTarget
PUBLIC RemoteThreadState

; ---------------------------------------------------------------------------
; Per-build stub byte variance. AMEGER_STUB_SEED is supplied by this project's
; MASM PreprocessorDefinitions (AMEGER_STUB_SEED=$(AmegerStubSeed)); Create.bat
; draws a fresh value every build. Each bit below independently selects between
; two byte-encodings of the SAME instruction:
;   bit 0 - XMM save    : 0 = movdqu, 1 = movups
;   bit 1 - XMM restore : 0 = movdqu, 1 = movups
;   bit 2 - RSP capture : 0 = mov r12,rsp, 1 = lea r12,[rsp]
; Every pair is a pure encoding substitution: no flag, register, stack, memory
; or control-flow effect differs, so register/stack discipline, the exit state,
; the TEB LastError write and the jmp [ReturnTarget] return are unchanged. The
; RSP capture runs before the alignment/sub, and the XMM slots are addressed
; off the aligned rsp (never off a saved register), so no variant shifts any
; offset and no push order is permuted. STUB_SEED is 0 when no per-build seed
; reached this project, and 0 selects every legacy encoding, so the stub
; assembles byte-for-byte to the pre-variance bytes.
; ---------------------------------------------------------------------------
IFDEF AMEGER_STUB_SEED
STUB_SEED EQU AMEGER_STUB_SEED
ELSE
STUB_SEED EQU 0
ENDIF
STUB_XMM_SAVE    EQU (STUB_SEED AND 1)
STUB_XMM_RESTORE EQU (STUB_SEED AND 2)
STUB_RSP_CAPTURE EQU (STUB_SEED AND 4)

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
IF STUB_RSP_CAPTURE
    lea r12, [rsp]
ELSE
    mov r12, rsp
ENDIF
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 128

IF STUB_XMM_SAVE
    movups [rsp+20h], xmm0
    movups [rsp+30h], xmm1
    movups [rsp+40h], xmm2
    movups [rsp+50h], xmm3
    movups [rsp+60h], xmm4
    movups [rsp+70h], xmm5
ELSE
    movdqu [rsp+20h], xmm0
    movdqu [rsp+30h], xmm1
    movdqu [rsp+40h], xmm2
    movdqu [rsp+50h], xmm3
    movdqu [rsp+60h], xmm4
    movdqu [rsp+70h], xmm5
ENDIF

    mov rax, [rbx+SR_ROUTINE]
    mov rcx, [rbx+SR_ARG]
    mov qword ptr [rbx+SR_STATE], 1
    call rax
    mov [rbx+SR_RET], eax
    mov r11d, gs:[TEB_LAST_ERROR]
    mov [rbx+SR_LAST_ERROR], r11d
    mov qword ptr [rbx+SR_STATE], 2

IF STUB_XMM_RESTORE
    movups xmm0, [rsp+20h]
    movups xmm1, [rsp+30h]
    movups xmm2, [rsp+40h]
    movups xmm3, [rsp+50h]
    movups xmm4, [rsp+60h]
    movups xmm5, [rsp+70h]
ELSE
    movdqu xmm0, [rsp+20h]
    movdqu xmm1, [rsp+30h]
    movdqu xmm2, [rsp+40h]
    movdqu xmm3, [rsp+50h]
    movdqu xmm4, [rsp+60h]
    movdqu xmm5, [rsp+70h]
ENDIF
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
