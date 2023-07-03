#include <stdint.h>

#define OFFSET_OF_MAX 0x38
#define OFFSET_OF_VALUE 0x30

struct reg_state {
  uint32_t sp;
  uint32_t lr;
  uint32_t pc;
  uint32_t r0;
  uint32_t r1;
  uint32_t r2;
  uint32_t r3;
  uint32_t r4;
  uint32_t r5;
  uint32_t r6;
  uint32_t r7;
};

// Just past the end of the bss
uint8_t *flag_byte = (uint8_t *)0x20001600;

void __attribute__((used)) enter_set_param() {
  *flag_byte = 1;
}

void __attribute__((used)) check_voltage_setpoint(struct reg_state *s) {
  if (*flag_byte) {
    s->r3 = *(uint32_t *)(s->r0 + OFFSET_OF_VALUE);
  } else {
    s->r3 = *(uint32_t *)(s->r0 + OFFSET_OF_MAX);
  }
}

void __attribute__((used)) leave_set_param() {
  *flag_byte = 0;
}
