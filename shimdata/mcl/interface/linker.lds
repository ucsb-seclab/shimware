SECTIONS
{
  . = 0x0800085C;
  .text : { *(.text*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) }
  .rodata : { *(.rodata*) }
}
