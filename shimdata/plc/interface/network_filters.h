
typedef enum {
  FILTER_ERR,
  FILTER_NOMATCH,
  FILTER_MATCH
} filter_response_t;

typedef filter_response_t (*filter_function_t)(char *data, char *extra_data_base, void *params);

filter_response_t filter_tag_write_clamp(char *data, char *extra_data_base, void *params);
filter_response_t filter_always_match(char *data, char *extra_data_base, void *params);

#pragma pack(push, 1)

// This union must be inside a packed struct in order to communicate to GCC that the data inside
// may be unaligned, as unaligned accesses have strange behavior on ARMv4.
typedef struct {
  union {
    int8_t sint;
    int16_t _int;
    int32_t dint;
    int64_t lint;
    float real;
  } v;
} tag_val_t;

typedef struct {
  uint32_t tag_name_offset;
  uint16_t tag_type;
  tag_val_t min;
  tag_val_t max;
} tag_write_clamp_info_t;



#pragma pack(pop)
