#define ERC20_ABI                                \
  ABI_METHOD("pause",   "\x84\x56\xcb\x59", 0, ) \
  ABI_METHOD("unpause", "\x3f\x4b\xa8\x3a", 0, ) \
  ABI_METHOD("burn",    "\x42\x96\x6c\x68", 1,   \
    ABI_PARAMETER("amount"))

struct contract_endpoint_param {
  char *name;
};

#define ABI_MAX_PARAMETERS 1

struct contract_endpoint {
  char *method_name;
  uint8_t selector[4];
  uint8_t parameters_count;
  struct contract_endpoint_param parameters[ABI_MAX_PARAMETERS];
};

static const struct contract_endpoint known_endpoints[] = {
#define ABI_PARAMETER(name_)   \
  { .name = name_ },

#define ABI_METHOD(name_, selector_, parameters_count_, parameters_...) \
  { .method_name = name_,                                               \
    .selector = selector_,                                              \
    .parameters_count = parameters_count_,                              \
    .parameters = {parameters_},                                        \
  },

  ERC20_ABI
#undef ABI_METHOD
#undef ABI_PARAMETER
};

#define ABI_PARAMETER(name_) \
  _Static_assert(sizeof(name_) <= PROMPT_WIDTH + 1 /*null byte*/,  name_ " won't fit in the UI prompt.");

#define ABI_METHOD(name_, selector_, parameters_count_, parameters_...) \
  ABI_PARAMETER(name_) \
  parameters_

  ERC20_ABI
#undef ABI_METHOD
#undef ABI_PARAMETER
#undef ERC20_ABI
