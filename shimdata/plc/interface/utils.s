        .global enable_interrupts
enable_interrupts:
        LDR r0, interrupt_mmio
        LDR r1, [r0]
        ORR r1, r1, #3
        STR r1, [r0]
        MOV pc, lr

        .global disable_interrupts
disable_interrupts:
        LDR r0, interrupt_mmio
        LDR r1, [r0]
        BIC r1, r1, #1
        STR r1, [r0]
        NOP
        NOP
        MOV pc, lr

        .global set_interrupts
set_interrupts:                 @ pass a bool: 1 = enable, 0 = disable. returns previous state.
        MOV r2, lr
        LDR r1, interrupt_mmio
        LDR r1, [r1]
        AND r1, r1, #1
        CMP r1, #0
        BEQ set_interrupts.currently_off

 set_interrupts.currently_on:
        CMP r0, #0
        BNE set_interrupts.ret  @ already on!

        BL disable_interrupts
        B set_interrupts.ret

 set_interrupts.currently_off:
        CMP r0, #0
        BEQ set_interrupts.ret   @ already off!

        BL enable_interrupts
        B set_interrupts.ret

 set_interrupts.ret:
        MOV r0, r1
        MOV pc, r2


        .global internal_set_interrupts
internal_set_interrupts:
        LDR r1, interrupt_mmio
        LDR r2, [r1]
        MOV r3, r2
        STR r0, [r1]
        MOV r0, r3
        MOV pc, lr

        .global set_interrupts_cpsr
set_interrupts_cpsr:
        MRS r1, CPSR

        AND r2, r1, #0xC0
        BIC r1, r1, #0xC0

        ORR r1, r1, r0

        MSR CPSR, r1

        NOP
        NOP
        NOP
        NOP

        MOV r0, r2
        MOV pc, lr


        .global set_clock_divisor
set_clock_divisor:
        LDR r1, clock_divisor
        LDR r2, [r1]
        STR r0, [r1]
        MOV r0, r2
        MOV pc, lr


        .global set_force_light
set_force_light:
        LDR r0, led_mmio
        MOV r1, #0x4000
        ORR r1, r1, #0x80
        STR r1, [r0]
        MOV pc, lr

        .global clear_force_light
clear_force_light:
        LDR r0, led_mmio
        MOV r1, #0x4000
        STR r1, [r0]
        MOV pc, lr

interrupt_mmio:
        .word 0x08010210

io_config_flags:
        .word 0x08010280
clock_divisor:
        .word 0x080102A0
led_mmio:
        .word 0x4C000000
