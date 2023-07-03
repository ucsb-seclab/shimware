#include <stdint.h>

struct reg_state {
  uint32_t pc;
  uint32_t lr;
  uint32_t sp;
  uint32_t r7;
  uint32_t r6;
  uint32_t r5;
  uint32_t r4;
  uint32_t r3;
  uint32_t r2;
  uint32_t r1;
  uint32_t r0;
};

struct packet {
  uint8_t src;
  uint8_t msg_type;
  uint8_t flags;
  uint8_t dst;
  uint16_t length;
  uint8_t data[2];
};

void __attribute__((used)) ensure_not_auth_failure(struct reg_state *s) {
  uint32_t len = s->r1;
  if (len < 16) {
    return;
  }
  struct packet *p = (struct packet *)(s->r0 + 13);
  if (p->src == 0x31
      && p->msg_type == 0x2
      && p->dst == 0x11
      && p->data[1] == 0x3) {
    __asm__ ("udf #0");
  }
}
