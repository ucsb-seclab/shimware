#include <stdint.h>


void send(const char *data, int length);
void configure();

void *memcpy(void *dest, const void *src, int n) {
  uint8_t *d = (uint8_t *)dest;
  uint8_t *s = (uint8_t *)src;
  for (int i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dest;
}

int memeq(const char *str1, const char *str2, int n) {
  for (int i = 0; i < n; i++) {
    if (str1[i] != str2[i]) {
      return 0;
    }
  }
  return 1;
}

int strlen(const char *s) {
  int c = 0;
  while (s[c]) {
    c++;
  }
  return c;
}

int sendstr(const char *s) {
  int len = strlen(s);
  send(s, len);
  return len;
}

void sendhexchar(uint8_t val) {
  char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char str[2];
  str[0] = digits[(val >> 4) & 0xF];
  str[1] = digits[(val >> 0) & 0xF];
  send(str, 2);
}

void sendhexstr(const uint8_t *src, int len) {
  for (int i = 0; i < len; i++) {
    sendhexchar(src[i]);
  }
}

void sendhexuint(uint32_t val) {
  for (int i = sizeof(uint32_t) - 1; i >= 0; i--) {
    sendhexchar((val >> (8 * i)) & 0xFF);
  }
}

void sendline(const char *s) {
  sendstr(s);
  sendstr("\r\n");
}
