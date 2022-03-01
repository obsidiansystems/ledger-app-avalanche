#include "apdu_pubkey.h"

#include "apdu.h"
#include "cx.h"
#include "globals.h"
#include "keys.h"
#include "key_macros.h"
#include "protocol.h"
#include "to_string.h"
#include "ui.h"

#include <string.h>

#define G global.apdu.u.pubkey

static bool address_ok(void) {
    switch(G.type) {
      case PUBKEY_STATE_AVM:
        provide_address(G_io_apdu_buffer, &G.pkh);
        break;
      case PUBKEY_STATE_EVM:
        provide_evm_address(G_io_apdu_buffer, &G.ext_public_key, &G.pkh, true);
        break;
    }
    return true;
}

static bool ext_pubkey_ok(void) {
    provide_ext_pubkey(G_io_apdu_buffer, &G.ext_public_key);
    return true;
}

static void apdu_pubkey_state_to_string
   (char *out, size_t out_size,
    const apdu_pubkey_state_t *const payload) {
  switch (payload->type) {
    case PUBKEY_STATE_AVM:
      pkh_to_string(out, out_size, payload->hrp, payload->hrp_len, &payload->pkh);
      break;
    case PUBKEY_STATE_EVM:
      // [0] aids in array pointer decay
      bin_to_hex_lc(out, out_size, &payload->pkh[0], 20);
      break;
  }
}

__attribute__((noreturn)) size_t handle_apdu_get_public_key_impl(bool const prompt_ext) {
    const uint8_t *const buffer = G_io_apdu_buffer;

    const uint8_t p1 = buffer[OFFSET_P1];
    const uint8_t p2 = buffer[OFFSET_P2];
    const size_t cdata_size = buffer[OFFSET_LC];
    const uint8_t *const hrp = buffer + OFFSET_CDATA;

    if (p1 > ASCII_HRP_MAX_SIZE || p1 >= cdata_size) {
      THROW(EXC_WRONG_PARAM);
    }
    const uint8_t *const bip32_path = hrp + p1;

    if (p2 != 0) {
      THROW(EXC_WRONG_PARAM);
    }

    if (p1 == 0) {
      static const char default_hrp[] = "avax";
      G.hrp_len = sizeof(default_hrp) - 1;
      memcpy(G.hrp, default_hrp, G.hrp_len);
    } else {
      G.hrp_len = p1;
      memcpy(G.hrp, hrp, G.hrp_len);
    }

    read_bip32_path(&G.bip32_path, bip32_path, cdata_size);
    generate_extended_public_key(&G.ext_public_key, &G.bip32_path);
    generate_pkh_for_pubkey(&G.ext_public_key.public_key, &G.pkh);
    PRINTF("public key hash: %.*h\n", 20, G.pkh);

    if (prompt_ext) {
        check_bip32(&G.bip32_path, false);
        ext_pubkey_ok();
    } else {
        check_bip32(&G.bip32_path, true);
        address_ok();
    }
}


__attribute__((noreturn)) size_t handle_apdu_get_public_key(void) {
    handle_apdu_get_public_key_impl(false);
}

__attribute__((noreturn)) size_t handle_apdu_evm_get_address(void) {
    const uint8_t *const buffer = G_io_apdu_buffer;

    const uint8_t p1 = buffer[OFFSET_P1];
    const uint8_t p2 = buffer[OFFSET_P2];
    const size_t cdata_size = buffer[OFFSET_LC];

    if (p1 > 1 || p2 > 1) {
      THROW(EXC_WRONG_PARAM);
    }

    read_bip32_path(&G.bip32_path, buffer+OFFSET_CDATA, cdata_size);
    generate_extended_public_key(&G.ext_public_key, &G.bip32_path);

    generate_evm_pkh_for_pubkey(&G.ext_public_key.public_key, &G.pkh);

    G.type = PUBKEY_STATE_EVM;

    check_bip32(&G.bip32_path, false);
    address_ok();
}

__attribute__((noreturn)) size_t handle_apdu_get_public_key_ext(void) {
    handle_apdu_get_public_key_impl(true);
}
