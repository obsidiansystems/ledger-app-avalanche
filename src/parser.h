#pragma once

#include "types.h"

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
        int state; \
        union { \
            name val; \
            uint8_t buf[sizeof(name)]; \
        }; \
    }
#define DEFINE_FIXED_BE(name) \
    struct name ## _state { \
        int state; \
        uint8_t buf[sizeof(name)]; \
        name val; \
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

struct Output_state {
    int state;
    uint32_t type;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferOutput_state secp256k1TransferOutput;
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

struct Input_state {
    int state;
    uint32_t type;
    union {
        NUMBER_STATES;
        struct SECP256K1TransferInput_state secp256k1TransferInput;
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

struct Memo_state {
    int state;
    uint32_t n;
    uint32_t i;
    union {
        NUMBER_STATES;
    };
};

typedef enum {
    NETWORK_ID_UNSET    = 0,
    NETWORK_ID_MAINNET  = 1,
    NETWORK_ID_CASCADE  = 2,
    NETWORK_ID_DENALI   = 3,
    NETWORK_ID_EVEREST  = 4,
    NETWORK_ID_LOCAL    = 12345,
    NETWORK_ID_UNITTEST = 10,
} network_id_t;

static inline network_id_t parse_network_id(uint32_t const val) {
    switch (val) {
        case 0: return NETWORK_ID_UNSET;
        case 1: return NETWORK_ID_MAINNET;
        case 2: return NETWORK_ID_CASCADE;
        case 3: return NETWORK_ID_DENALI;
        case 4: return NETWORK_ID_EVEREST;
        case 12345: return NETWORK_ID_LOCAL;
        case 10: return NETWORK_ID_UNITTEST;
        default: THROW(EXC_PARSE_ERROR);
    }
}

struct TransactionState {
    int state;
    uint32_t type;
    network_id_t network_id;
    union {
        struct uint16_t_state uint16State;
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
        struct TransferableInputs_state inputsState;
        struct Memo_state memoState;
    };
    cx_sha256_t hash_state;
};

typedef struct {
    uint8_t const *src;
    size_t consumed;
    size_t length;
} parser_input_meta_state_t;

typedef struct {
    string_generation_callback to_string;
    union {
        char const *str; // pointer to static null-terminated string
        uint32_t uint32; // network
        uint64_t uint64; // amount / fee
        Address address;
    } data;
} prompt_entry_t;

#define TRANSACTION_PROMPT_BATCH_SIZE 1
typedef struct {
    parser_input_meta_state_t input;
    struct {
        size_t count;
        char const *labels[TRANSACTION_PROMPT_BATCH_SIZE + 1]; // For NULL at end
        prompt_entry_t entries[TRANSACTION_PROMPT_BATCH_SIZE];
    } prompt;
    bool first_asset_id_found;
    Id32 first_asset_id;
    uint64_t sum_of_inputs;
    uint64_t sum_of_outputs;
} parser_meta_state_t;

char const *network_id_string(network_id_t const network_id);
Id32 const *blockchain_id_for_network(network_id_t const network_id);

void initTransaction(struct TransactionState *const state);

enum parse_rv parseTransaction(struct TransactionState *const state, parser_meta_state_t *const meta);
