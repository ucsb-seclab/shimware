#include <stdint.h>
#include "utils.h"
#include "network_filter.h"
#include "network_filters.h"


#define FIREWALL_SYMBOL_NAME firewall_data
uint8_t __attribute__((section ("firewall"))) FIREWALL_SYMBOL_NAME[0];

void __attribute__((used)) network_filter(char *data) {
  filter_function_t filters[] = {
    filter_tag_write_clamp,
    filter_always_match
  };

  configure();
  sendline("\r\nEntry.");
  firewall_header_t *header = (firewall_header_t *)FIREWALL_SYMBOL_NAME;

  firewall_rule_t *rules = (firewall_rule_t *)(FIREWALL_SYMBOL_NAME + header->rules_start);
  uint8_t *args_data = (uint8_t *)(FIREWALL_SYMBOL_NAME + header->args_start);
  uint8_t *extra_data = (uint8_t *)(FIREWALL_SYMBOL_NAME + header->extra_start);

  for (uint16_t i = 0; i < header->num_rules; i++) {
    uint16_t filter_id = rules[i].filter;
    if (filter_id >= sizeof(filters) / sizeof(filters[0])) {
      sendline("Corrupt filter.");
      continue;
    }
    filter_function_t func = filters[filter_id];
    uint8_t *args = args_data + rules[i].args_offset;
    filter_response_t res = func(data, extra_data, args);

    uint8_t action;
    switch (res) {
    case FILTER_ERR:
      sendline("Error.");
      action = rules[i].on_err;
      break;
    case FILTER_NOMATCH:
      action = rules[i].on_nomatch;
      break;
    case FILTER_MATCH:
      action = rules[i].on_match;
      break;
    default:
      sendline("Bad ret.");
      action = ACTION_DROP;
    }

    if (action == ACTION_CONTINUE) {
      sendline("Continue.");
      continue;
    }
    else if (action == ACTION_DROP) {
      sendline("TODO: drop");
      break;
    }
    else if (action == ACTION_ACCEPT) {
      sendline("Accept.");
      break;
    }
    else {
      sendline("TODO: error");
      break;
    }
  }
}
