#define ERC20_METHODS                   \
  X("pause",   "\x84\x56\xcb\x59", 0, ) \
  X("unpause", "\x3f\x4b\xa8\x3a", 0, ) \

enum abi_type {
  ABI_TYPE_UINT256
};

#define MAX_PARAMS 1

struct contract_endpoint {
  char *method_name;
  uint8_t selector[4];
  uint8_t parameters_count;
  enum abi_type parameters[MAX_PARAMS];
};

static const struct contract_endpoint known_endpoints[] = {
#define X(method_name_, selector_, parameters_count_, parameters_...) \
  { .method_name = method_name_,                                      \
    .selector = selector_,                                            \
    .parameters_count = parameters_count_,                            \
    .parameters = {parameters_},                                      \
  },

  ERC20_METHODS
#undef X
};

#define X(method_name_, selector_, parameters_count_, parameters_...) \
  _Static_assert(sizeof(method_name_) <= PROMPT_WIDTH + 1 /*null byte*/,  method_name_ " won't fit in the UI prompt.");

  ERC20_METHODS
#undef X
