UTILS = arm-none-eabi-
CC = $(UTILS)gcc
LD = $(UTILS)ld
OBJCOPY = $(UTILS)objcopy

OUTDIR = "build"
OUTFILE = "interface"
OUTELF = $(OUTDIR)/$(OUTFILE).elf
OUTBIN = $(OUTDIR)/$(OUTFILE).bin

sources := $(wildcard *.s *.c)

binary: elfs
	$(OBJCOPY) -O binary -j .text -j .rodata -j .data -j .bss $(OUTELF) $(OUTBIN)

elfs: $(sources) outdir
	$(CC) -march=armv7-m -mthumb -std=c99 -O4 -flto -fPIC -nostdlib -static \
		-T linker.lds \
		$(sources) -lgcc -o $(OUTELF)

outdir: clean
	mkdir $(OUTDIR)

clean:
	rm -rf $(OUTDIR)
