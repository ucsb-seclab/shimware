SECTIONS
{
  . = 0x0800bf4c;
  .text : { *(.text*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) }
  .rodata : { *(.rodata*) }
}
