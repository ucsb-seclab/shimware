        .section .text
        .code 32

        .org 0x0

        .global checkpoint
checkpoint:
        STMFD sp!, {lr}
        BL is_recv_ready
        BEQ checkpoint.ret

        SUB sp, sp, #4
        MOV r0, sp
        MOV r1, #1
        BL recv

        LDRB r0, [sp]
        ADD sp, sp, #4

        CMP r0, #'B'
        LDMEQFD sp!, {lr}
        BEQ breakpoint.go

 checkpoint.ret:
        LDMFD sp!, {pc}

break_as_check:
        .word 0                 @ If non zero, treat breakpoints as catchpoints

        .global breakpoint
breakpoint:
        LDR r0, break_as_check
        CMP r0, #0
        BEQ breakpoint.go
        B checkpoint

 breakpoint.go:
        STMFD sp!, {r4-r12, lr}
        SUB sp, sp, #0x40

        MOV r0, #0x0
        BL internal_set_interrupts
        MOV r7, r0

        MOV r0, #0xC0
        BL set_interrupts_cpsr
        MOV r8, r0

        MOV r0, #0
        BL set_clock_divisor
        MOV r9, r0

        BL set_force_light

        BL configure

        ADR r0, prompt_str
        MOV r1, #4
        BL send

        B breakpoint.regs

 breakpoint.get_command:
        MOV r0, sp
        MOV r1, #1
        BL recv

        LDRB r2, [sp]

        CMP r2, #'R'
        BEQ breakpoint.read

        CMP r2, #'W'
        BEQ breakpoint.write

        CMP r2, #'G'
        BEQ breakpoint.regs

        CMP r2, #'P'
        BEQ breakpoint.pc

        CMP r2, #'C'
        BEQ breakpoint.continue

        CMP r2, #'E'
        BEQ breakpoint.echo

        CMP r2, #'Q'
        BEQ breakpoint.act_as_check

        CMP r2, #'K'
        BEQ breakpoint.act_as_break

        CMP r2, #'S'
        BEQ breakpoint.get_sr

        CMP r2, #'U'
        BEQ breakpoint.send_coproc

        ADR r0, unk_str
        MOV r1, #4
        BL send

        B breakpoint.get_command

 breakpoint.read:
        MOV r0, sp
        MOV r1, #8
        BL recv

        LDR r0, [sp]
        LDR r1, [sp, #4]
        BL send

        B breakpoint.fin

 breakpoint.write:
        MOV r0, sp
        MOV r1, #8
        BL recv

        LDR r0, [sp]
        LDR r1, [sp, #4]
        STR r1, [r0]

        B breakpoint.fin

 breakpoint.regs:
        MOV r0, r10
        MOV r1, #64             @ 4 bytes x 16 registers
        BL send

        B breakpoint.fin

 breakpoint.pc:
        STR pc, [sp]
        MOV r0, sp
        MOV r1, #4
        BL send

        B breakpoint.fin

 breakpoint.continue:
        ADR r0, con_str
        MOV r1, #4
        BL send

        B breakpoint.ret

 breakpoint.echo:
        B breakpoint.fin

 breakpoint.act_as_check:
        ADR r0, break_as_check
        MOV r1, #1
        STR r1, [r0]

        B breakpoint.fin

 breakpoint.act_as_break:
        ADR r0, break_as_check
        MOV r1, #0
        STR r1, [r0]

        B breakpoint.fin

 breakpoint.get_sr:
        MRS r0, cpsr
        MRS r1, spsr
        STR r0, [sp]
        STR r1, [sp, #4]

        MOV r0, sp
        MOV r1, #8
        BL send

        B breakpoint.fin

 breakpoint.send_coproc:
        STC p2, c0, [sp]
        STC p2, c4, [sp, #4]
        STC p2, c12, [sp, #8]

        MOV r0, sp
        MOV r1, #0xC
        BL send

        B breakpoint.fin

 breakpoint.fin:
        ADR r0, fin_str
        MOV r1, #4
        BL send

        B breakpoint.get_command

 breakpoint.ret:
        BL clear_force_light

        MOV r0, r9
        BL set_clock_divisor

        MOV r0, r8
        BL set_interrupts_cpsr

        MOV r0, r7
        BL internal_set_interrupts

        ADD sp, sp, #0x40
        LDMFD sp!, {r4-r12, lr}
        MOV pc, lr



        .global add_trampoline  @ void add_trampoline(void *loc@<r0>, void *dest@<r1>,
                                @                     void *ret@<r2>, int old_inst@<r3>)
add_trampoline:


fin_str:
        .asciz "FIN"
con_str:
        .asciz "CON"
prompt_str:
        .asciz ">>>"
unk_str:
        .asciz "UNK"

        .global next_trampoline
next_trampoline:
        .word 0
