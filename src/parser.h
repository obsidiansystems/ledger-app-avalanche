#pragma once

#include "types.h"
#include "uint256.h"
#include "network_info.h"

// some global definitions
enum parse_rv {
    PARSE_RV_INVALID = 0,
    PARSE_RV_NEED_MORE,
    PARSE_RV_PROMPT,
    PARSE_RV_DONE,
};

struct FixedState {
    size_t filledTo;
    uint8_t buffer[1]; // Actually bigger.
};
#define DEFINE_FIXED(name) \
  struct name ## _state { \
    union { \
      struct FixedState fixedState; \
      struct { \
        int state; \
        union { \
            name val; \
            uint8_t buf[sizeof(name)]; \
        }; \
      }; \
    }; \
  };
#define DEFINE_FIXED_BE(name) \
  struct name ## _state { \
    union { \
      struct FixedState fixedState; \
      struct { \
        int state; \
        uint8_t buf[sizeof(name)]; \
        name val; \
      }; \
    }; \
  };

#define IMPL_FIXED(name) \
    inline enum parse_rv parse_ ## name (struct name ## _state *const state, parser_meta_state_t *const meta) { \
        return parseFixed((struct FixedState *const)state, &meta->input, sizeof(name));\
    } \
    inline void init_ ## name (struct name ## _state *const state) { \
        return initFixed((struct FixedState *const)state, sizeof(state)); \
    }
#define DEFINE_ARRAY(name) \
    struct name ## s_state { \
        int state; \
        uint32_t len; \
        uint32_t i; \
        union { \
            struct uint32_t_state len_state;\
            struct name ## _state item; \
        }; \
    };

DEFINE_FIXED_BE(uint16_t);
DEFINE_FIXED_BE(uint32_t);
DEFINE_FIXED_BE(uint64_t);
DEFINE_FIXED_BE(uint256_t);

typedef struct {
    uint8_t val[32];
} Id32;

DEFINE_FIXED(Id32);

typedef struct {
    public_key_hash_t val;
} Address;

DEFINE_FIXED(Address);

#define NUMBER_STATES struct uint32_t_state uint32State; struct uint64_t_state uint64State

struct SECP256K1TransferOutput_state {
    int state;
    uint32_t address_n;
    uint32_t address_i;
    union {
        NUMBER_STATES;
        struct Address_state addressState;
    };
};

struct SECP256K1OutputOwners_state {
    int state;
    uint32_t address_n;
    uint32_t address_i;
    union {
        NUMBER_STATES;
        struct Address_state addressState;
    };
};

struct StakeableLockOutput_state {
    int state;
    uint64_t locktime;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferOutput_state secp256k1TransferOutput;
    };
};

struct Output_state {
    int state;
    uint32_t type;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferOutput_state secp256k1TransferOutput;
        struct StakeableLockOutput_state stakeableLockOutput;
    };
};

struct TransferableOutput_state {
    int state;
    union {
        struct Id32_state id32State;
        struct Output_state outputState;
    };
};

DEFINE_ARRAY(TransferableOutput);

struct SECP256K1TransferInput_state {
    int state;
    uint32_t address_index_n;
    uint32_t address_index_i;
    union {
        NUMBER_STATES;
        struct Address_state addressState;
    };
};

struct StakeableLockInput_state {
    int state;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferInput_state secp256k1TransferInput;
    };
};

struct Input_state {
    int state;
    uint32_t type;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferInput_state secp256k1TransferInput;
        struct StakeableLockInput_state stakeableLockInput;
    };
};

struct TransferableInput_state {
    int state;
    union {
        NUMBER_STATES;
        struct Id32_state id32State;
        struct Input_state inputState;
    };
};


DEFINE_ARRAY(TransferableInput);

struct EVMOutput_state {
    int state;
    struct Address_state addressState;
    union {
        NUMBER_STATES;
        struct Id32_state id32State;
    };
};

DEFINE_ARRAY(EVMOutput);

struct EVMInput_state {
    int state;
    union {
        NUMBER_STATES;
        struct Id32_state id32State;
        struct Address_state addressState;
    };
};

DEFINE_ARRAY(EVMInput);

struct Memo_state {
    int state;
    uint32_t n;
    uint32_t i;
    union {
        NUMBER_STATES;
    };
};

enum BaseTransactionHeaderSteps {
    BTSH_NetworkId = 0,
    BTSH_BlockchainId,
    BTSH_Done
};

struct BaseTransactionHeaderState {
    enum BaseTransactionHeaderSteps state;
    union {
        struct uint16_t_state uint16State;
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
    };
};

enum BaseTransactionSteps {
  BTS_Outputs=0,
  BTS_Inputs,
  BTS_Memo,
  BTS_Done
};

struct BaseTransactionState {
    enum BaseTransactionSteps state;
    union {
        struct uint16_t_state uint16State;
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
        struct TransferableInputs_state inputsState;
        struct Memo_state memoState;
    };
};

struct CChainImportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableInputs_state inputsState;
        struct EVMOutputs_state evmOutputsState;
  };
};

struct CChainExportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
        struct EVMInputs_state inputsState;
  };
};

struct ImportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableInputs_state inputsState;
  };
};

struct ExportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
  };
};
struct Validator_state {
  int state;
  union {
    struct Address_state addressState;
    struct uint64_t_state uint64State;
  };
};

struct AddValidatorTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;

        struct Validator_state validatorState;
        struct SECP256K1OutputOwners_state ownersState;
  };
};

struct AddDelegatorTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
  };
};

struct TransactionState {
  int state;
  uint32_t type;
  cx_sha256_t hash_state;
  union {
    struct uint16_t_state uint16State;
    struct uint32_t_state uint32State;
    struct BaseTransactionHeaderState baseTxHdrState;
    struct BaseTransactionState baseTxState;
    struct ImportTransactionState importTxState;
    struct ExportTransactionState exportTxState;
    struct AddValidatorTransactionState addValidatorTxState;
    struct AddDelegatorTransactionState addDelegatorTxState;
    struct CChainImportTransactionState cChainImportState;
    struct CChainExportTransactionState cChainExportState;
  };
};

typedef struct {
    uint8_t const *src;
    size_t consumed;
    size_t length;
} parser_input_meta_state_t;

#define MAX_CALLDATA_PREVIEW 20

typedef struct {
  union {
    uint64_t fee;
    uint64_t amount;
    uint256_t amount_big;
    uint64_t start_gas;
    struct {
      uint256_t amount;
      uint256_t assetID;
    } assetCall;
    struct {
      bool cropped;
      size_t count;
      uint8_t buffer[MAX_CALLDATA_PREVIEW];
    } calldata_preview;
    uint8_t bytes32[32]; // ABI
  };
  network_id_t network_id;
  Address address;
} output_prompt_t;

typedef struct {
    network_id_t network_id;
    Address address;
} address_prompt_t;

typedef struct {
    uint64_t amount;
    uint64_t until;
} locked_prompt_t;

typedef struct {
    string_generation_callback to_string;
    union {
        char const *str; // pointer to static null-terminated string
        uint32_t uint32; // network
        uint64_t uint64; // amount / fee
        Address address;
        //TODO: Now that weve added this, do we need the ones above?
        output_prompt_t output_prompt;
    } data;
} prompt_entry_t;

#define TRANSACTION_PROMPT_MAX_BATCH_SIZE 2

enum transaction_type_id_t {
    TRANSACTION_TYPE_ID_BASE = 0,
    TRANSACTION_TYPE_ID_IMPORT = 3,
    TRANSACTION_TYPE_ID_EXPORT = 4,
    TRANSACTION_TYPE_ID_ADD_VALIDATOR = 0x0c,
    TRANSACTION_TYPE_ID_ADD_DELEGATOR = 0x0e,
    TRANSACTION_TYPE_ID_PLATFORM_IMPORT = 0x11,
    TRANSACTION_TYPE_ID_PLATFORM_EXPORT = 0x12,
    TRANSACTION_TYPE_ID_C_CHAIN_IMPORT = 0x00, // Yes, this is duplicate with BASE.
    TRANSACTION_TYPE_ID_C_CHAIN_EXPORT = 0x01
};

enum SwapCounterpartChain {
  SWAPCOUNTERPARTCHAIN_C = 1,
  SWAPCOUNTERPARTCHAIN_P = 2,
};

typedef struct  {
  size_t count;
  size_t flushIndex;
  char const *labels[TRANSACTION_PROMPT_MAX_BATCH_SIZE + 1]; // For NULL at end
  prompt_entry_t entries[TRANSACTION_PROMPT_MAX_BATCH_SIZE];
} prompt_batch_t;

typedef struct {
    parser_input_meta_state_t input;
    prompt_batch_t prompt;
    uint32_t raw_type_id;
    enum transaction_type_id_t type_id;
    bool is_p_chain;
    bool is_x_chain;
    bool is_c_chain;
    enum SwapCounterpartChain swapCounterpartChain;
    bool swap_output;
    uint64_t last_output_amount;
    network_id_t network_id;
    uint64_t sum_of_inputs;
    uint64_t sum_of_outputs;
    uint64_t staking_weight;
    uint64_t staked;


} parser_meta_state_t;

// EVM stuff below this line

union EVM_endpoint_argument_states {
  struct FixedState fixedState;
  struct uint256_t_state uint256_state;
  struct Address_state address_state;
};

enum assetCall_state_t {
    ASSETCALL_ADDRESS,
    ASSETCALL_ASSETID,
    ASSETCALL_AMOUNT,
    ASSETCALL_DATA,
    ASSETCALL_DONE,
};

struct EVM_assetCall_state {
  enum assetCall_state_t state;
  uint64_t data_length;
    union {
        struct Id32_state id32_state;
        struct uint256_t_state uint256_state;
        struct uint32_t_state selector_state;
        struct {
            struct Address_state address_state;
            parser_input_meta_state_t chunk;
            // union EVM_endpoint_states endpoint_state;
        };
    };
};

enum abi_state_t {
  ABISTATE_SELECTOR,
  ABISTATE_ARGUMENTS,
  ABISTATE_UNRECOGNIZED,
  ABISTATE_DONE,
};

struct EVM_ABI_state {
  enum abi_state_t state;
  size_t argument_index;
  size_t data_length;
  union {
    struct uint32_t_state selector_state;
    union EVM_endpoint_argument_states argument_state;
  };
};

union EVM_endpoint_states {
    struct EVM_ABI_state abi_state;
    struct EVM_assetCall_state assetCall_state;
};

struct struct_evm_parser_meta_state_t;
typedef struct struct_evm_parser_meta_state_t evm_parser_meta_state_t;

typedef enum parse_rv (*known_destination_init)(union EVM_endpoint_states *const state, uint64_t length);
typedef enum parse_rv (*known_destination_parser)(union EVM_endpoint_states *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta);

struct known_destination {
  uint8_t to[20];
  known_destination_init init_value;
  known_destination_parser handle_value;
  known_destination_init init_data;
  known_destination_parser handle_data;
};

struct struct_evm_parser_meta_state_t {
    parser_input_meta_state_t input;
    uint8_t chainIdLowByte;
    struct known_destination const *known_destination;
    struct contract_endpoint const *known_endpoint;
    prompt_batch_t prompt;
};

void initTransaction(struct TransactionState *const state);

enum parse_rv parseTransaction(struct TransactionState *const state, parser_meta_state_t *const meta);

#define MAX_EVM_BUFFER 20

struct EVM_RLP_item_state {
    int state;
    uint64_t length;
    uint64_t current;
    uint8_t len_len;
    bool do_init;
    union {
        struct uint64_t_state uint64_state;
        uint8_t buffer[MAX_EVM_BUFFER];
        struct {
            parser_input_meta_state_t chunk;
            union EVM_endpoint_states endpoint_state;
        };
    };
};

struct EVM_RLP_list_state {
    int state;
    uint64_t remaining;
    uint8_t len_len;
    uint8_t item_index;
    bool hasTo;
    bool hasData;
    uint64_t startGas;
    uint64_t gasPrice;
    uint256_t value;
    union {
        struct uint64_t_state uint64_state;
        struct EVM_RLP_item_state rlpItem_state;
    };
};

void initFixed(struct FixedState *const state, size_t const len);

enum parse_rv parseFixed(struct FixedState *const state, parser_input_meta_state_t *const input, size_t const len);

void init_rlp_list(struct EVM_RLP_list_state *const state);

enum parse_rv parse_rlp_txn(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta);

void strcpy_prompt(char *const out, size_t const out_size, char const *const in);

bool should_flush(prompt_batch_t prompt);

void set_next_batch_size(prompt_batch_t *const prompt, size_t size);
