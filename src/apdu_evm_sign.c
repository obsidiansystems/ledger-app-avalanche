#include "apdu_sign.h"

#include "apdu.h"
#include "globals.h"
#include "key_macros.h"
#include "keys.h"
#include "memory.h"
#include "to_string.h"
#include "protocol.h"
#include "ui.h"
#include "cx.h"

#include <string.h>

#define G global.apdu.u.evm_sign

bool evm_sign_ok() {
    uint8_t *const out = G_io_apdu_buffer;
    uint8_t buf[MAX_SIGNATURE_SIZE];
    size_t const tx = WITH_EXTENDED_KEY_PAIR(G.bip32_path, it, size_t, ({
        sign(buf, MAX_SIGNATURE_SIZE, &it->key_pair, G.final_hash, sizeof(G.final_hash));
    }));

    memcpy(out+1, buf, 64);
    // Ethereum doesn't handle the 4-address case and the protocol only allows one byte; signature will need repair after hw-app-eth has it. 
    out[0] = (buf[64]&0x01) + (G.meta_state.chainIdLowByte<<1) + 35;
    
    memset(&G, 0, sizeof(G));
    delayed_send(finalize_successful_send(tx));
    return true;
}

static bool evm_sign_reject(void) {
    memset(&G, 0, sizeof(G));
    delay_reject();
    return true; // Return to idle
}

void sign_evm_complete() {
    static uint32_t const TYPE_INDEX = 0;
    static uint32_t const DRV_PREFIX_INDEX = 1;
    static uint32_t const HASH_INDEX = 2;
    G.final_hash_as_buffer.bytes = &G.final_hash[0];
    G.final_hash_as_buffer.length = sizeof(G.final_hash);
    G.final_hash_as_buffer.size = sizeof(G.final_hash);

    static char const *const transaction_prompts[] = {
        PROMPT("Sign"),
        PROMPT("Derivation"),
        PROMPT("Hash"),
        NULL,
    };
    REGISTER_STATIC_UI_VALUE(TYPE_INDEX, "EVM Hash");

    register_ui_callback(DRV_PREFIX_INDEX, bip32_path_to_string, &G.bip32_path);

    register_ui_callback(HASH_INDEX, buffer_to_hex, &G.final_hash_as_buffer);

    ui_prompt(transaction_prompts, evm_sign_ok, evm_sign_reject);
}

size_t handle_apdu_sign_evm_transaction(void) {
    uint8_t const *const in = &G_io_apdu_buffer[OFFSET_CDATA];
    uint8_t const in_size = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (in_size > MAX_APDU_SIZE)
        THROW(EXC_WRONG_LENGTH_FOR_INS);
    uint8_t const p1 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]);
    uint8_t const p2 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P2]);

    size_t ix = 0;

    switch (p1) {
      case 0x00: {
          memset(&G, 0, sizeof(G));

          if (ix + sizeof(uint8_t) > in_size) THROW_(EXC_WRONG_LENGTH, "Input too small");
          ix += read_bip32_path(&G.bip32_path, &in[ix], in_size - ix);
          check_bip32(&G.bip32_path, false);
          if (G.bip32_path.length < 3) THROW_(EXC_SECURITY, "Signing path not long enough");
          init_rlp_list(&G.state);
          cx_keccak_init(&G.tx_hash_state, 256);
      }
      case 0x80: {
          G.meta_state.input.src = in+ix;
          G.meta_state.input.consumed=0;
          G.meta_state.input.length=in_size-ix;
          if(G.meta_state.input.length == 0) return finalize_successful_send(0);
          enum parse_rv result = parse_rlp_txn(&G.state, &G.meta_state);

          cx_hash((cx_hash_t *)&G.tx_hash_state, 0, G.meta_state.input.src, G.meta_state.input.consumed, NULL, 0);

          if(result != PARSE_RV_DONE) return finalize_successful_send(0);

          cx_hash((cx_hash_t *)&G.tx_hash_state, CX_LAST, NULL, 0, G.final_hash, sizeof(G.final_hash));

          sign_evm_complete();

      }
    }
    return finalize_successful_send(0);
}

size_t handle_apdu_provide_erc20(void) {
    return finalize_successful_send(0);
}
