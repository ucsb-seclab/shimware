#!/bin/sh

./mmio_finder_elf.sh --model MK64F12 ./dataset/easy/uart_polling.elf

./mmio_finder_elf.sh --model STM32F401 ./dataset/easy/st-plc.elf

./mmio_finder_elf.sh --model STM32F469 ./dataset/easy/stm32_udp_echo_client.elf
./mmio_finder_elf.sh --model STM32F469 ./dataset/easy/stm32_udp_echo_server.elf
./mmio_finder_elf.sh --model STM32F469 ./dataset/easy/stm32_tcp_echo_client.elf
./mmio_finder_elf.sh --model STM32F469 ./dataset/easy/stm32_tcp_echo_server.elf

./mmio_finder_elf.sh --model STM32F429 ./dataset/easy/p2im_cnc.elf
./mmio_finder_elf.sh --model STM32F103xx ./dataset/easy/p2im_drone.elf
./mmio_finder_elf.sh --model STM32F103xx ./dataset/easy/p2im_robot.elf
./mmio_finder_elf.sh --model STM32F103xx ./dataset/easy/p2im_soldering_iron.elf

./mmio_finder_elf.sh --model ATSAMR21G18A ./dataset/medium/samr21_http.elf
./mmio_finder_elf.sh --model ATSAMR21G18A ./dataset/medium/atmel_6lowpan_udp_rx.elf
./mmio_finder_elf.sh --model ATSAMR21G18A ./dataset/medium/atmel_6lowpan_udp_tx.elf

