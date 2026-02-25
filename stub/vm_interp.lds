/* vm_interp.lds — 将所有 sections 合并到一个可执行段 */
SECTIONS {
  . = 0;
  .text : {
    *(.text.entry)
    *(.text*)
    *(.rodata*)
    *(.data*)
    *(.bss*)
  }
  /DISCARD/ : {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
    *(.ARM.*)
  }
}
