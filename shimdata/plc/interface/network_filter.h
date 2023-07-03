#pragma pack(push, 1)
typedef struct {
  char magic[4];
  uint64_t time;
  uint16_t num_rules;
  uint32_t rules_start;
  uint32_t args_start;
  uint32_t extra_start;
} firewall_header_t;

typedef struct {
  uint16_t filter;
  uint32_t args_offset;
  uint8_t on_err;
  uint8_t on_nomatch;
  uint8_t on_match;
} firewall_rule_t;
#pragma pack(pop)

typedef enum {
  ACTION_CONTINUE = 0,
  ACTION_DROP = 1,
  ACTION_ACCEPT = 2
} firewall_action_t;
