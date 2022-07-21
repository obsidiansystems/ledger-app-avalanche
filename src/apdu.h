#pragma once

#include "exception.h"
#include "types.h"
#include "ui.h"
#include "apdu_sign.h"

#include <stdbool.h>
#include <stdint.h>

#include "apdu_pubkey.h"

#if CX_APILEVEL < 8
#error "May only compile with API level 8 or higher; requires newer firmware"
#endif

#define OFFSET_CLA   0
#define OFFSET_INS   1 // instruction code
#define OFFSET_P1    2 // user-defined 1-byte parameter
#define OFFSET_P2    3 // user-defined 1-byte parameter
#define OFFSET_LC    4 // length of CDATA
#define OFFSET_CDATA 5 // payload

struct handlers {
    apdu_handler const (* handlers)[];
    uint8_t handlers_size;
};

struct app_handlers {
    struct handlers avm;
    struct handlers evm;
};

__attribute__((noreturn)) void main_loop(struct app_handlers const *const handlers);

static inline size_t finalize_successful_send(size_t tx) {
    if (tx + 2 > IO_APDU_BUFFER_SIZE) {
        PRINTF("-- ERR in finalize_successful_send: %d\n", tx);
        THROW(EXC_MEMORY_ERROR);
    }
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    return tx;
}

// Send back response; do not restart the event loop
static inline void delayed_send(size_t tx) {
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
}

static inline bool delay_reject(void) {
    size_t tx = 0;
    G_io_apdu_buffer[tx++] = EXC_REJECT >> 8;
    G_io_apdu_buffer[tx++] = EXC_REJECT & 0xFF;
    delayed_send(tx);
    return true;
}

static inline void require_hid(void) {
    if (G_io_apdu_media != IO_APDU_MEDIA_USB_HID) {
        THROW(EXC_HID_REQUIRED);
    }
}

size_t provide_address(uint8_t *const io_buffer, public_key_hash_t const *const pubkey_hash);
size_t provide_ext_pubkey(uint8_t *const io_buffer, extended_public_key_t const *const pubkey);
size_t provide_evm_address(uint8_t *const io_buffer, extended_public_key_t const *const pubkey, public_key_hash_t const *const pubkey_hash, bool include_chain_code);

size_t handle_apdu_version(void);
size_t handle_apdu_get_wallet_id(void);
size_t handle_apdu_sign_hash(void);

size_t handle_apdu_error(void);
