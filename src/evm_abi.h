static void output_evm_amount_to_string(char *const out, size_t const out_size, output_prompt_t const *const in);
static void output_evm_address_to_string(char *const out, size_t const out_size, output_prompt_t const *const in);
static void setup_prompt_evm_address(uint8_t *buffer, output_prompt_t const *const prompt);
static void setup_prompt_evm_amount(uint8_t *buffer, output_prompt_t const *const prompt);

// require('keccak256')('mint(address, uint256)').slice(0,4).toString('hex')

#define ABI_ADDRESS(name) \
  ABI_PARAMETER(name, setup_prompt_evm_address, output_evm_address_to_string) \

#define ABI_AMOUNT(name) \
  ABI_PARAMETER(name, setup_prompt_evm_amount, output_evm_amount_to_string) \

#define ERC20_ABI                                                       \
  ABI_METHOD("\x84\x56\xcb\x59", 0,                                     \
             "pause",                                                   \
             )                                                          \
  ABI_METHOD("\x3f\x4b\xa8\x3a", 0,                                     \
             "unpause",                                                 \
             )                                                          \
  ABI_METHOD("\x42\x96\x6c\x68", 1,                                     \
             "burn",                                                    \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x36\xe5\x9c\x31", 2,                                     \
             "mint",                                                    \
             ABI_ADDRESS("to")                                          \
             ABI_AMOUNT("amount")                                       \
             )                                                          \
  ABI_METHOD("\x9d\x61\xd2\x34", 2,                                     \
             "transfer",                                                \
             ABI_ADDRESS("recipient")                                   \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x32\x90\x2f\xff", 2,                                     \
             "burnFrom",                                                \
             ABI_ADDRESS("account")                                     \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x8b\x06\x9f\x2a", 2,                                     \
             "approve",                                                 \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x05\x53\xe3\x95", 2,                                     \
             "increaseAllowance",                                       \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("addedValue"))                                  \
  ABI_METHOD("\x26\x44\x4a\xcc", 2,                                     \
             "decreaseAllowance",                                       \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("subtractedValue"))                             \

struct contract_endpoint_param {
  char *name;
  void (*setup_prompt)(struct FixedState* buffer, output_prompt_t const *const prompt);
  void (*output_prompt)(*const out, size_t const out_size, output_prompt_t const *const in);
};

#define ABI_MAX_PARAMETERS 2

struct contract_endpoint {
  char *method_name;
  uint8_t selector[4];
  uint8_t parameters_count;
  struct contract_endpoint_param parameters[ABI_MAX_PARAMETERS];
};

static const struct contract_endpoint known_endpoints[] = {
#define ABI_PARAMETER(name_, setup_prompt_, output_prompt_)   \
  { .name = name_,                                            \
    .setup_prompt = setup_prompt_,                            \
    .output_prompt = output_prompt_,                          \
  },

#define ABI_METHOD(selector_, parameters_count_, name_, parameters_...) \
  { .method_name = name_,                                               \
    .selector = selector_,                                              \
    .parameters_count = parameters_count_,                              \
    .parameters = {parameters_},                                        \
  },

  ERC20_ABI
#undef ABI_METHOD
#undef ABI_PARAMETER
};

#define ABI_PARAMETER(name_, setup_prompt_, output_prompt_)            \
  _Static_assert(sizeof(name_) <= PROMPT_WIDTH + 1 /*null byte*/,  name_ " won't fit in the UI prompt.");

#define ABI_METHOD(selector_, parameters_count_, name_, parameters_...) \
  ABI_PARAMETER(name_, ,) \
  parameters_

  ERC20_ABI
#undef ABI_METHOD
#undef ABI_PARAMETER

#undef ERC20_ABI
#undef ABI_ADDRESS
#undef ABI_AMOUNT
