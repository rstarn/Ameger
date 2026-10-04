SR_STATE EQU 0
SR_RET EQU 8
SR_LAST_ERROR EQU 16
SR_ARG EQU 24
SR_ROUTINE EQU 32
SR_BUFFER EQU 40

; Assemble-time placeholder only: MASM needs a constant for the gs:[disp32]
; encoding, and 68H is the legacy TEB::LastErrorValue. The host OVERWRITES
; this disp32 in its staged copy with g_DynamicOffsets.TebLastErrorValue
; (PDB TEB::LastErrorValue) before the stub runs, and fails closed
; (SR_HT_ERR_STUB_PATCH_FAIL) if the 65 44 8B 1C 25 pattern is absent or the
; resolved value is 0. 68H is therefore never executed; never rely on it.
TEB_LAST_ERROR EQU 68H
