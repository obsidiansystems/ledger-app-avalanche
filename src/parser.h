#pragma once

#include "types.h"
#include "identifier.h"
#include "uint256.h"
#include "network_info.h"

// some global definitions
enum parse_rv {
    PARSE_RV_INVALID = 0,
    PARSE_RV_NEED_MORE,
    PARSE_RV_PROMPT,
    PARSE_RV_DONE,
};

// This will be casted to a FixedState elsewhere
struct FixedState0 {
    size_t filledTo_;
    uint8_t buffer_[0];
};

#define DEFINE_FIXED(name) \
  struct name ## _state { \
    union { \
      struct FixedState0 fixed_state; \
      struct { \
        size_t padding_; \
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
      struct FixedState0 fixed_state; \
      struct { \
        size_t padding_; \
        uint8_t buf[sizeof(name)]; \
      }; \
    }; \
    name val; \
  };

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

DEFINE_FIXED(uint8_t);
DEFINE_FIXED_BE(uint16_t);
DEFINE_FIXED_BE(uint32_t);
DEFINE_FIXED_BE(uint64_t);
DEFINE_FIXED_BE(uint256_t);

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

struct SubnetAuth_state {
  int state;
  uint32_t sigindices_i;
  uint32_t sigindices_n;
  union {
      NUMBER_STATES;
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

DEFINE_FIXED(blockchain_id_t);

#define GEN_HASH_SIZE 32

typedef uint8_t genhash_t[GEN_HASH_SIZE];

struct Genesis_state {
  int state;
  union {
    struct uint32_t_state gen_n_state;
    struct {
      size_t gen_n;
      size_t gen_i;
      cx_sha256_t genhash_state;
    };
  };
};

#define CHAIN_NAME_MAX_SIZE 128

typedef struct {
    size_t buffer_size;
    uint8_t buffer[CHAIN_NAME_MAX_SIZE];
} chainname_prompt_t;

struct ChainName_state{
  int state;
  union {
    struct uint16_t_state uint16State;
    struct {
      chainname_prompt_t name;
      uint16_t chainN_i;
    };
  };
};


struct TransferableOutput_state {
    int state;
    union {
        struct Id32_state id32State;
        struct blockchain_id_t_state bidState;
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
        struct blockchain_id_t_state bidState;
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
        struct blockchain_id_t_state bidState;
        struct TransferableInputs_state inputsState;
        struct EVMOutputs_state evmOutputsState;
  };
};

struct CChainExportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct blockchain_id_t_state bidState;
        struct TransferableOutputs_state outputsState;
        struct EVMInputs_state inputsState;
  };
};

struct ImportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct blockchain_id_t_state bidState;
        struct TransferableInputs_state inputsState;
  };
};

struct ExportTransactionState {
  int state;
  union {
        struct uint32_t_state uint32State;
        struct blockchain_id_t_state bidState;
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

struct AddSNValidatorTransactionState {
  int state;
  union {
        struct Validator_state validatorState;
        struct Id32_state id32State;
        struct SubnetAuth_state subnetauthState;
  };
};

struct CreateSubnetTransactionState {
  int state;
  union {
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

struct CreateChainTransactionState {
  int state;
  uint32_t fxid_n;
  uint32_t fxid_i;
  union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct ChainName_state  chainnameState;
        struct Genesis_state genesisState;
        struct SubnetAuth_state subnetauthState;
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
    struct AddSNValidatorTransactionState addSNValidatorTxState;
    struct CreateChainTransactionState createChainTxState;
    struct CreateSubnetTransactionState createSubnetTxState;
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
    uint8_t buffer[GEN_HASH_SIZE];
} gendata_prompt_t;

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

#ifndef PROMPT_MAX_BATCH_SIZE
#  error "PROMPT_MAX_BATCH_SIZE not set!"
#endif

enum transaction_x_chain_type_id_t {
    TRANSACTION_X_CHAIN_TYPE_ID_BASE            = 0x00,
    TRANSACTION_X_CHAIN_TYPE_ID_IMPORT          = 0x03,
    TRANSACTION_X_CHAIN_TYPE_ID_EXPORT          = 0x04
};

enum transaction_p_chain_type_id_t {
    TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR    = 0x0c,
    TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR    = 0x0e,
    TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR = 0x0d,
    TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN     = 0x0f,
    TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET    = 0x10,
    TRANSACTION_P_CHAIN_TYPE_ID_IMPORT           = 0x11,
    TRANSACTION_P_CHAIN_TYPE_ID_EXPORT           = 0x12
};

enum transaction_c_chain_type_id_t {
    TRANSACTION_C_CHAIN_TYPE_ID_IMPORT          = 0x00,
    TRANSACTION_C_CHAIN_TYPE_ID_EXPORT          = 0x01
};

union transaction_type_id_t {
    enum transaction_x_chain_type_id_t x;
    enum transaction_p_chain_type_id_t p;
    enum transaction_c_chain_type_id_t c;
};

enum chain_role {
  CHAIN_X = 0,
  CHAIN_P = 1,
  CHAIN_C = 2,
};

typedef struct  {
  size_t count;
  size_t flushIndex;
  char const *labels[PROMPT_MAX_BATCH_SIZE + 1]; // For NULL at end
  prompt_entry_t entries[PROMPT_MAX_BATCH_SIZE];
} prompt_batch_t;

typedef struct {
    parser_input_meta_state_t input;
    prompt_batch_t prompt;
    uint32_t raw_type_id;
    union transaction_type_id_t type_id;
    enum chain_role chain;
    enum chain_role swapCounterpartChain;
    bool swap_output;
    uint64_t last_output_amount;
    network_id_t network_id;
    uint64_t sum_of_inputs;
    uint64_t sum_of_outputs;
    uint64_t staking_weight;
    uint64_t staked;


} parser_meta_state_t;

void set_next_batch_size(prompt_batch_t *const prompt, size_t size);
