#pragma once

// some global definitions
typedef struct {
    uint8_t const *src;
    size_t consumed;
    size_t length;
} input_buf_t;

enum parse_rv {
    PARSE_RV_INVALID = 0,
    PARSE_RV_NEED_MORE,
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

DEFINE_FIXED_BE(uint32_t);
DEFINE_FIXED_BE(uint64_t);

typedef struct {
    uint8_t val[32];
} Id32;

DEFINE_FIXED(Id32);

typedef struct {
    uint8_t val[20];
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

struct TransactionState {
    int state;
    uint32_t type;
    union {
        struct uint32_t_state uint32State;
        struct Id32_state id32State;
        struct TransferableOutputs_state outputsState;
        struct TransferableInputs_state inputsState;
        struct Memo_state memoState;
    };
    cx_sha256_t hash_state;
};

void initTransaction(struct TransactionState *const state);

enum parse_rv parseTransaction(struct TransactionState *const state, input_buf_t *const buf);


