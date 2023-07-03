#include <stdint.h>
#include "utils.h"
#include "ab_constants.h"
#include "network_filters.h"



filter_response_t filter_tag_write_clamp(char *data, char *extra_data_base, void *params) {
  uint8_t path_length;
  uint8_t *payload;
  char *tag_name;
  int name_len;
  const tag_write_clamp_info_t *p = params;
  uint16_t type_offset;
  uint16_t packet_tag_type;

  if (!(data[5] == 1 && data[-2] == 2)) { // connected CIP
    return FILTER_NOMATCH;
  }

  payload = *(uint8_t **)&data[0x20];
  if (payload[0] != CIP_TAG_WRITE) { // tag write
    return FILTER_NOMATCH;
  }

  path_length = payload[1];
  tag_name = p->tag_name_offset + extra_data_base;
  name_len = strlen(tag_name);
  if (!(payload[2] == PATH_SYMBOLIC_SEGMENT &&
        payload[3] == name_len &&
        memeq(tag_name, &payload[4], name_len))) {
    return FILTER_NOMATCH;
  }

  type_offset = 2 + ((uint16_t)path_length * 2);
  packet_tag_type = *(uint16_t *)&payload[type_offset];
  if (packet_tag_type != p->tag_type) {
    return FILTER_NOMATCH;
  }

  uint8_t *new_val = &payload[type_offset + 4];

  switch (packet_tag_type) {
  case TAG_TYPE_BOOL:
    sendline("Can't handle type BOOL in tag_write_clamp");
    return FILTER_ERR;
  case TAG_TYPE_SINT:;
    int8_t new_sint;
    memcpy(&new_sint, new_val, sizeof(new_sint));
    sendstr("Matched write to SINT for tag ");
    sendline(tag_name);
    if (new_sint < p->min.v.sint) {
      sendline("Clamping to min.");
      memcpy(new_val, &p->min.v.sint, sizeof(new_sint));
    }
    else if (new_sint > p->max.v.sint) {
      sendline("Clamping to max.");
      memcpy(new_val, &p->max.v.sint, sizeof(new_sint));
    }
    return FILTER_MATCH;
  case TAG_TYPE_INT:;
    int16_t new_int;
    memcpy(&new_int, new_val, sizeof(new_int));
    sendstr("Matched write to  INT for tag ");
    sendline(tag_name);
    if (new_int < p->min.v._int) {
      sendline("Clamping to min.");
      memcpy(new_val, &p->min.v._int, sizeof(new_int));
    }
    else if (new_int > p->max.v._int) {
      sendline("Clamping to max.");
      memcpy(new_val, &p->max.v._int, sizeof(new_int));
    }
    return FILTER_MATCH;
  case TAG_TYPE_DINT:;
    int32_t new_dint;
    memcpy(&new_dint, new_val, sizeof(new_dint));
    sendstr("Matched write to DINT for tag ");
    sendline(tag_name);
    sendstr("Requested value: ");
    sendhexuint(new_dint);
    sendstr(", min: ");
    sendhexuint(p->min.v.dint);
    sendstr(", max: ");
    sendhexuint(p->max.v.dint);
    sendline(".");
    if (new_dint < p->min.v.dint) {
      sendline("Clamping to min.");
      memcpy(new_val, &p->min.v.dint, sizeof(new_dint));
    }
    else if (new_dint > p->max.v.dint) {
      sendline("Clamping to max.");
      memcpy(new_val, &p->max.v.dint, sizeof(new_dint));
    }
    return FILTER_MATCH;
  case TAG_TYPE_LINT:;
    int64_t new_lint;
    memcpy(&new_lint, new_val, sizeof(new_lint));
    sendstr("Matched write to LINT for tag ");
    sendline(tag_name);
    if (new_lint < p->min.v.lint) {
      sendline("Clamping to min.");
      memcpy(new_val, &p->min.v.lint, sizeof(new_lint));
    }
    else if (new_lint > p->max.v.lint) {
      sendline("Clamping to max.");
      memcpy(new_val, &p->max.v.lint, sizeof(new_lint));
    }
    return FILTER_MATCH;
  case TAG_TYPE_REAL:;
    float new_real;
    memcpy(&new_real, new_val, sizeof(new_real));
    sendstr("Matched write to REAL for tag ");
    sendline(tag_name);
    if (new_real < p->min.v.real) {
      sendline("Clamping to min.");
      memcpy(new_val, &p->min.v.real, sizeof(new_real));
    }
    else if (new_real > p->max.v.real) {
      sendline("Clamping to max.");
      memcpy(new_val, &p->max.v.real, sizeof(new_real));
    }
    return FILTER_MATCH;
  default:
    sendline("Unknown type in tag_write_clamp");
    return FILTER_ERR;
  }
}

filter_response_t filter_always_match(char *data, char *extra_data_base, void *params) {
  return FILTER_MATCH;
}
