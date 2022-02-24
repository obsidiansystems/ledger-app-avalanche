static void output_evm_amount_to_string(char *const out, size_t const out_size, output_prompt_t const *const in);
static void output_evm_address_to_string(char *const out, size_t const out_size, output_prompt_t const *const in);
static void output_evm_bytes32_to_string(char *const out, size_t const out_size, output_prompt_t const *const in);
static void setup_prompt_evm_address(uint8_t *buffer, output_prompt_t *const prompt);
static void setup_prompt_evm_amount(uint8_t *buffer, output_prompt_t *const prompt);
static void setup_prompt_evm_bytes32(uint8_t *buffer, output_prompt_t *const prompt);

#define ABI_ADDRESS(name) \
  ABI_PARAMETER(name, setup_prompt_evm_address, output_evm_address_to_string)

#define ABI_AMOUNT(name) \
  ABI_PARAMETER(name, setup_prompt_evm_amount, output_evm_amount_to_string)

#define ABI_BYTES32(name) \
  ABI_PARAMETER(name, setup_prompt_evm_bytes32, output_evm_bytes32_to_string)

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
  ABI_METHOD("\x40\xc1\x0f\x19", 2,                                     \
             "mint",                                                    \
             ABI_ADDRESS("to")                                          \
             ABI_AMOUNT("amount")                                       \
             )                                                          \
  ABI_METHOD("\xa9\x05\x9c\xbb", 2,                                     \
             "transfer",                                                \
             ABI_ADDRESS("recipient")                                   \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x79\xcc\x67\x90", 2,                                     \
             "burnFrom",                                                \
             ABI_ADDRESS("account")                                     \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x09\x5e\xa7\xb3", 2,                                     \
             "approve",                                                 \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x39\x50\x93\x51", 2,                                     \
             "increaseAllowance",                                       \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("addedValue"))                                  \
  ABI_METHOD("\xa4\x57\xc2\xd7", 2,                                     \
             "decreaseAllowance",                                       \
             ABI_ADDRESS("spender")                                     \
             ABI_AMOUNT("subtractedValue"))                             \
  ABI_METHOD("\x23\xb8\x72\xdd", 3,                                     \
             "transferFrom",                                            \
             ABI_ADDRESS("sender")                                      \
             ABI_ADDRESS("recipient")                                   \
             ABI_AMOUNT("amount"))                                      \
  ABI_METHOD("\x2f\x2f\xf1\x5d", 2,                                     \
             "grantRole",                                               \
             ABI_BYTES32("role")                                        \
             ABI_ADDRESS("account"))                                    \
  ABI_METHOD("\x36\x56\x8a\xbe", 2,                                     \
             "renounceRole",                                            \
             ABI_BYTES32("role")                                        \
             ABI_ADDRESS("account"))                                    \
  ABI_METHOD("\xd5\x47\x74\x1f", 2,                                     \
             "revokeRole",                                              \
             ABI_BYTES32("role")                                        \
             ABI_ADDRESS("account"))                                    \

typedef void (*setup_prompt_fun_t)(
    uint8_t *buffer, output_prompt_t *const prompt);

typedef void (*output_prompt_fun_t)(
    char *const out, size_t const out_size, output_prompt_t const *const in);

struct contract_endpoint_param {
  char *name;
  setup_prompt_fun_t setup_prompt;
  output_prompt_fun_t output_prompt;
};

#define ABI_MAX_PARAMETERS 3

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
#undef ABI_BYTES32
