        .global is_recv_ready
is_recv_ready:
        LDR r0, serial_addr
        LDR r0, [r0, #0x14]
        AND r0, r0, #1
        MOV pc, lr



        .global recv            @ void recv(char *dest@<r0>, int num_bytes@<r1>)
recv:
        STMFD sp!, {r2-r9, lr}
        MOV r4, r0              @ current_dest = dest
        ADD r5, r4, r1          @ compute final addr: when current_dest == r5, terminate
        LDR r6, serial_addr     @ prep mmio addr

 recv.check_size:
        CMP r4, r5              @ if current_dest = end, terminate
        BEQ recv.ret

 recv.wait:
        BL is_recv_ready        @ loop until is_recv_ready
        CMP r0, #0
        BEQ recv.wait

        LDRB r8, [r6]           @ load and store
        STRB r8, [r4]

        ADD r4, r4, #1          @ increment dest
        B recv.check_size           @ run the size check

 recv.ret:
        LDMFD sp!, {r2-r9, pc}




        .global is_send_ready
is_send_ready:
        LDR r0, serial_addr
        LDR r0, [r0, #0x14]
        AND r0, r0, #0x20
        MOV pc, lr



        .global send            @ void send(char *src@<r0>, int num_bytes@<r1>)
send:
        STMFD sp!, {r2-r9, lr}
        MOV r4, r0              @ current_send = send
        ADD r5, r4, r1          @ compute final addr: when current_send == r5, terminate
        LDR r6, serial_addr     @ prep mmio addr

 send.check_size:
        CMP r4, r5              @ if current_dest = end, terminate
        BEQ send.ret

 send.wait:
        BL is_send_ready        @ loop until is_recv_ready
        CMP r0, #0
        BEQ send.wait

        LDRB r8, [r4]           @ load and store
        STRB r8, [r6]

        ADD r4, r4, #1          @ increment dest
        B send.check_size       @ run the size check

 send.ret:
        BL is_send_ready
        CMP r0, #0
        BEQ send.ret

        LDMFD sp!, {r2-r9, pc}


        .global configure
configure:
        STMFD sp!, {lr}

        LDR r0, serial_addr

        @ disable all interrupts
        MOV r1, #0
        STRB r1, [r0, #0x4]

        @ enable DLAB
        MOV r1, #0x80
        STRB r1, [r0, #0xC]

        @ set baud to 115200 (div = 0x2b)
        MOV r1, #0x2b
        STRB r1, [r0]
        MOV r1, #0
        STRB r1, [r0, #0x4]

        @ disable DLAB, set word length = 8, stop bits = 1, parity = off
        MOV r1, #0x03
        STRB r1, [r0, #0xC]

        @ enable FIFO (64 bytes), clear buffer (both tx and rx)
        MOV r1, #0x07
        STRB r1, [r0, #0x8]

        LDMFD sp!, {pc}


        .global serial_addr
serial_addr:
        .word 0x08010080
