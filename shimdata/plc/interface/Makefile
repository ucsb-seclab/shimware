UTILS = arm-linux-gnueabi-
CC = $(UTILS)gcc
LD = $(UTILS)ld
OBJCOPY = $(UTILS)objcopy

OUTDIR = "build"
OUTFILE = "interface"
OUTELF = $(OUTDIR)/$(OUTFILE).elf
OUTTMP = $(OUTDIR)/$(OUTFILE).tmp
OUTBIN = $(OUTDIR)/$(OUTFILE).bin

sources := $(wildcard *.s *.c)

binary: elfs
	$(OBJCOPY) -O binary -j .text -j .rodata -j .data -j .bss -j firewall $(OUTELF) $(OUTTMP)
	cat $(OUTTMP) $(OUTDIR)/firewall.fwo > $(OUTBIN)

elfs: $(sources) outdir $(OUTDIR)/firewall.fwo
	$(CC) -march=armv4 -std=c99 -O4 -flto -fPIC -nostdlib -static \
		-T linker.lds \
		$(sources) -lgcc -o $(OUTELF)

$(OUTDIR)/firewall.fwo:
	python firewall_compiler.py filter_descriptors.yml firewall.yml $(OUTDIR)/firewall.fwo

outdir: clean
	mkdir $(OUTDIR)

clean:
	rm -rf $(OUTDIR)
