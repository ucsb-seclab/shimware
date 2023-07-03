void send(char *data, int length);
void configure();

void network_dumper(char *data) {
  char *copy = data;
  configure();
  send("START\xFF\xFF\xFF", 8);
  send((char *)&copy, 4);
  send(data - 4, 388);
  char *payload = *(char **)&data[0x20];
  if ((int)payload & 0xFF000000 == 0x0C000000) {
    send(payload, 388);
  } else {
    for (int i = 0; i < (388 / 4); i++) {
      send((char *)&i, 4);
    }
  }
  send("END\xFF\xFF\xFF\xFF\xFF", 8);
}
