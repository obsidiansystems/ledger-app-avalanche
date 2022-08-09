#pragma once

#include "exception.h"
#include "os.h"
#include "cx.h"
#include "ux.h"
#include "os_io_seproxyhal.h"

#include <stdbool.h>
#include <string.h>

// Type-safe versions of true/false
#undef true
#define true ((bool)1)
#undef false
#define false ((bool)0)

// Return number of bytes to transmit (tx)
typedef size_t (*apdu_handler)(void);

#define MAX_INT_DIGITS 20

#define ROOT_PATH_0 0x8000002C
#define ROOT_PATH_1 0x80002328

typedef struct {
    size_t length;
    size_t size;
    uint8_t *bytes;
} buffer_t;

// UI
typedef bool (*ui_callback_t)(void); // return true to go back to idle screen

// Uses K&R style declaration to avoid being stuck on const void *, to avoid having to cast the
// function pointers.
typedef void (*string_generation_callback)(/* char *out, size_t out_size, void const *const in */);

// Keys
typedef struct {
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;
} key_pair_t;

#define CHAIN_CODE_DATA_SIZE 32

typedef struct {
    cx_ecfp_public_key_t public_key;
    uint8_t chain_code[CHAIN_CODE_DATA_SIZE];
} extended_public_key_t;

typedef struct {
    key_pair_t key_pair;
    uint8_t chain_code[CHAIN_CODE_DATA_SIZE];
} extended_key_pair_t;

#define MAX_BIP32_PATH 6

typedef struct {
    uint8_t length;
    uint32_t components[MAX_BIP32_PATH];
} bip32_path_t;

static inline void copy_bip32_path(bip32_path_t *const out, bip32_path_t volatile const *const in) {
    check_null(out);
    check_null(in);
    memcpy(out->components, (void *)in->components, in->length * sizeof(*in->components));
    out->length = in->length;
}

static inline bool bip32_paths_eq(bip32_path_t volatile const *const a, bip32_path_t volatile const *const b) {
    return a == b ||
           (a != NULL && b != NULL && a->length == b->length &&
            memcmp((void const *)a->components, (void const *)b->components, a->length * sizeof(*a->components)) == 0);
}

#define SIGN_HASH_SIZE 32 // TODO: Rename or use a different constant.

typedef uint8_t sign_hash_t[SIGN_HASH_SIZE];

#define MAX_SCREEN_COUNT 7 // Current maximum usage
#define PROMPT_WIDTH     17
#define VALUE_WIDTH      256 // Needs to hold an assetCall prompt

// Macros to wrap a static prompt and value strings and ensure they aren't too long.
#define PROMPT(str)                                                                                                    \
    ({                                                                                                                 \
        _Static_assert(sizeof(str) <= PROMPT_WIDTH + 1 /*null byte*/, str " won't fit in the UI prompt.");             \
        str;                                                                                                           \
    })

#define STATIC_UI_VALUE(str)                                                                                           \
    ({                                                                                                                 \
        _Static_assert(sizeof(str) <= VALUE_WIDTH + 1 /*null byte*/, str " won't fit in the UI.");                     \
        str;                                                                                                           \
    })

typedef uint8_t public_key_hash_t[CX_RIPEMD160_SIZE];

#define ASCII_HRP_MAX_SIZE 24
#define ASCII_ADDRESS_MAX_SIZE 64

typedef char ascii_adddress_t[ASCII_ADDRESS_MAX_SIZE];
typedef char ascii_hrp_t[ASCII_HRP_MAX_SIZE];


#define STRCPY(buff, x)                                                                                                \
    ({                                                                                                                 \
        _Static_assert(sizeof(buff) >= sizeof(x) && sizeof(*x) == sizeof(char), "String won't fit in buffer");         \
        strcpy(buff, x);                                                                                               \
    })

 #if __has_attribute(__fallthrough__)
 # define fallthrough __attribute__((__fallthrough__))
 #else
 # define fallthrough do {} while (0)  /* fallthrough */
 #endif

#undef MAX
#define MAX(a, b)                                                                                                      \
    ({                                                                                                                 \
        __typeof__(a) ____a_ = (a);                                                                                    \
        __typeof__(b) ____b_ = (b);                                                                                    \
        ____a_ > ____b_ ? ____a_ : ____b_;                                                                             \
    })

#undef MIN
#define MIN(a, b)                                                                                                      \
    ({                                                                                                                 \
        __typeof__(a) ____a_ = (a);                                                                                    \
        __typeof__(b) ____b_ = (b);                                                                                    \
        ____a_ < ____b_ ? ____a_ : ____b_;                                                                             \
    })

typedef enum {
    WARN_ON_SIGN_HASH=0,
    DISALLOW_ON_SIGN_HASH,
    ALLOW_ON_SIGN_HASH,
} sign_hash_policy_t;

typedef struct {
    bool initialized;
    sign_hash_policy_t sign_hash_policy;
    char sign_hash_policy_prompt[20];
} nvram_data;
