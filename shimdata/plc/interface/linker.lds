SECTIONS
{
  . = 0x370800;
  .text : { *(.text*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) }
  .rodata : { *(.rodata*) }
  firewall : { *(.firewall) }
}
