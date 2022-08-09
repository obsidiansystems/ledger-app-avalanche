#pragma once

#include "bolos_target.h"
#include "parser.h"
#include "evm_parse.h"
#include "types.h"

// Zeros out all globals that can keep track of APDU instruction state.
// Notably this does *not* include UI state.
void clear_apdu_globals(void);

// Zeros out all application-specific globals and SDK-specific UI/exchange buffers.
void init_globals(void);

#define MAX_APDU_SIZE 230 // Maximum number of bytes in a single APDU

#define MAX_SIGNATURE_SIZE 100

typedef struct {
    uint8_t requested_num_signatures;
    bip32_path_t bip32_path_prefix;
    sign_hash_t final_hash;
    buffer_t final_hash_as_buffer;

    public_key_hash_t change_address;

    uint8_t num_signatures_left;

    struct {
        struct TransactionState state;
        parser_meta_state_t meta_state;
        bool is_last_message;
    } parser;
} apdu_sign_state_t;

typedef struct {
    bip32_path_t bip32_path;
    sign_hash_t final_hash;
    buffer_t final_hash_as_buffer;
    cx_sha3_t tx_hash_state;
    struct {
        struct EVM_txn_state state;
        evm_parser_meta_state_t meta_state;
    };
} apdu_evm_sign_state_t;

enum pubkey_state_type {
    PUBKEY_STATE_AVM,
    PUBKEY_STATE_EVM
};

typedef struct {
    bip32_path_t bip32_path;
    extended_public_key_t ext_public_key;
    public_key_hash_t pkh;
    ascii_hrp_t hrp;
    size_t hrp_len;
    enum pubkey_state_type type;
} apdu_pubkey_state_t;

typedef struct {
    void *stack_root;

    struct {
        ui_callback_t ok_callback;
        ui_callback_t cxl_callback;
        char accept_prompt_str[PROMPT_WIDTH + 1];

        uint32_t ux_step;
        uint32_t ux_step_count;

        uint32_t timeout_cycle_count;
        void (*switch_screen)(uint32_t which);

        struct {
            string_generation_callback callbacks[MAX_SCREEN_COUNT];
            const void *callback_data[MAX_SCREEN_COUNT];

            char active_prompt[PROMPT_WIDTH + 1];
            char active_value[VALUE_WIDTH + 1];

            // This will and must always be static memory full of constants
            const char *const *prompts;
            size_t offset;
        } prompt;
    } ui;

    struct {
        union {
            apdu_pubkey_state_t pubkey;
            apdu_sign_state_t sign;
            apdu_evm_sign_state_t evm_sign;
        } u;
    } apdu;

    uint8_t latest_apdu_instruction; // For detecting when a sequence of requests to the same APDU ends
    uint8_t latest_apdu_cla; // For detecting when a sequence of requests to the same APDU ends
    nvram_data new_data;
} globals_t;

extern globals_t global;

extern unsigned int volatile app_stack_canary; // From SDK

// Used by macros that we don't control.
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
extern ux_state_t G_ux;
extern bolos_ux_params_t G_ux_params;
#else
extern ux_state_t ux;
#endif
extern unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

static inline void throw_stack_size(void) {
    uint8_t st;
    // uint32_t tmp1 = (uint32_t)&st - (uint32_t)&app_stack_canary;
    uint32_t tmp2 = (uint32_t)global.stack_root - (uint32_t)&st;
    THROW(0x9000 + tmp2);
}

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    extern nvram_data const N_data_real;
#   define N_data (*(volatile nvram_data *)PIC(&N_data_real))
#else
    extern nvram_data N_data_real;
#   define N_data (*(nvram_data*)PIC(&N_data_real))
#endif


// Properly updates NVRAM data to prevent any clobbering of data.
// 'out_param' defines the name of a pointer to the nvram_data struct
// that 'body' can change to apply updates.
#define UPDATE_NVRAM(out_name, body)                                                                  \
    ({                                                                                                \
        nvram_data *const out_name = &global.new_data;                                                \
        memcpy(&global.new_data, (nvram_data const *const) & N_data,                                  \
               sizeof(global.new_data));                                                              \
        body;                                                                                         \
        nvm_write((void *)&N_data, &global.new_data, sizeof(N_data));                                 \
    })

#ifdef AVA_DEBUG
// Aid for tracking down app crashes
#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY(x)
#define AT           __FILE__ ":" TOSTRING(__LINE__)
void dbgout(char *at);
#define DBGOUT() dbgout(AT)
#endif
