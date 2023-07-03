        .global next_trampoline_slot
next_trampoline_slot:
        .word 0

        .global trampoline
trampoline:
        STMFD sp!, {r0-r12}
        ADD r4, sp, #52
        MOV r5, lr
        LDR r6, trampoline.old_pc
        STMFD sp!, {r4-r6}

        MOV r10, sp
        LDR r12, trampoline.dest_loc
        MRS r4, CPSR
        AND r4, r4, #0x1F
        CMP r4, #0x10
        BEQ trampoline.escalate

        ADR lr, trampoline.handler_return
        MOV pc, r12

 trampoline.escalate:
        SVC 0x600
        B trampoline.handler_return

 trampoline.handler_return:
        LDMFD sp!, {r0-r2}
        MOV lr, r1
        LDMFD sp!, {r0-r12}

        .global trampoline.old_instr
 trampoline.old_instr:
        .word 0
        LDR pc, trampoline.ret_loc



        .global trampoline.dest_loc
trampoline.dest_loc:
        .word 0

        .global trampoline.ret_loc
trampoline.ret_loc:
        .word 0

        .global trampoline.old_pc
trampoline.old_pc:
        .word 0

        .global trampoline.end
trampoline.end:
