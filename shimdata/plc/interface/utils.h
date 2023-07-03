void send(const char *data, int length);
void configure();

void *memcpy(void *dest, const void *src, int n);
int memeq(const char *str1, const char *str2, int n);
int strlen(const char *s);
int sendstr(const char *s);
void sendhexchar(uint8_t val);
void sendhexstr(const uint8_t *src, int len);
void sendhexuint(uint32_t val);
void sendline(const char *s);
