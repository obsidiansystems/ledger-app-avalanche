#pragma once

#include "parser.h"

union EVM_endpoint_argument_states {
  struct FixedState0 fixed_state;
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

struct evm_parser_meta_state_t;
typedef struct evm_parser_meta_state evm_parser_meta_state_t;

typedef enum parse_rv (*known_destination_init)(union EVM_endpoint_states *const state, uint64_t length);
typedef enum parse_rv (*known_destination_parser)(union EVM_endpoint_states *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta);

struct known_destination {
  uint8_t to[20];
  known_destination_init init_value;
  known_destination_parser handle_value;
  known_destination_init init_data;
  known_destination_parser handle_data;
};

struct evm_parser_meta_state {
    parser_input_meta_state_t input;
    uint8_t chainIdLowByte;
    struct known_destination const *known_destination;
    struct contract_endpoint const *known_endpoint;
    prompt_batch_t prompt;
};

void initTransaction(struct TransactionState *const state);

enum parse_rv parseTransaction(struct TransactionState *const state, parser_meta_state_t *const meta);

#define MAX_EVM_BUFFER 32

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

enum txn_being_parsed_t {
  LEGACY,
  EIP1559
};

enum TxnDataSort {
  TXN_DATA_UNSET,
  TXN_DATA_CONTRACT_CALL_KNOWN_DEST,
  TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST,
  TXN_DATA_DEPLOY,
  TXN_DATA_PLAIN_TRANSFER,
};

struct EVM_RLP_txn_state {
    int state;
    uint64_t remaining;
    uint8_t len_len;
    uint8_t item_index;
    struct {
      uint8_t per_item_prompt;
      enum TxnDataSort sort;
      enum parse_rv item_rv;
    };
    bool hasTo;
    bool hasData;
    uint64_t gasLimit;
    uint64_t priorityFeePerGas;
    uint64_t baseFeePerGas;
    uint256_t value;
    union {
        struct uint64_t_state uint64_state;
        struct EVM_RLP_item_state rlpItem_state;
    };
};

struct EVM_txn_state {
    int state; // what step of parsing we are on
    enum txn_being_parsed_t type; 
    union {
      struct uint8_t_state transaction_envelope_type;
      struct EVM_RLP_txn_state txn_state;
    };
};

void init_rlp_list(struct EVM_RLP_txn_state *const state);

void init_evm_txn(struct EVM_txn_state *const state);

enum parse_rv parse_evm_txn(struct EVM_txn_state *const state, evm_parser_meta_state_t *const meta);

enum parse_rv parse_eip1559_rlp_txn(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta);

enum parse_rv parse_legacy_rlp_txn(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta);

void strcpy_prompt(char *const out, size_t const out_size, char const *const in);

bool should_flush(const prompt_batch_t *const prompt);
