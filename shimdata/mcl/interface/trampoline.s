        .global next_trampoline_slot
next_trampoline_slot:
        .word 0

        .global trampoline
trampoline:
        PUSH {r0}
        PUSH {r0-r7}
        ADD r4, sp, #36
        MOV r5, lr
        LDR r6, trampoline.old_pc
        PUSH {r4-r6}

        MOV r0, sp
        SUB r4, r4, #4
        LDR r2, trampoline.ret_loc
        MOV r3, #1
        ORR r2, r3
        STR r2, [r4]
        LDR r1, trampoline.dest_loc

        BLX r1

        POP {r0-r2}
        MOV lr, r1
        POP {r0-r7}

        ADD sp, sp, #4
        .global trampoline.old_instr
 trampoline.old_instr:
        .word 0
        SUB sp, sp, #4
        POP {pc}

        .align 4

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
