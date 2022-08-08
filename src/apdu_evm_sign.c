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
#include "hash.h"

#include <string.h>

#define G global.apdu.u.evm_sign

bool evm_sign_ok() {
    uint8_t *const out = G_io_apdu_buffer;
    uint8_t buf[MAX_SIGNATURE_SIZE];
    size_t const tx = WITH_EXTENDED_KEY_PAIR(G.bip32_path, it, size_t, ({
        sign(buf, MAX_SIGNATURE_SIZE, &it->key_pair, G.final_hash, sizeof(G.final_hash));
    }));

    memcpy(out+1, buf, 64);

    if (G.meta_state.chainIdLowByte == 0) {
        // we are signing a non-Legacy transaction
        out[0] = (buf[64]&0x01);
    } else {
        // Ethereum doesn't handle the 4-address case and the protocol only allows one byte; signature will need repair after hw-app-eth has it.
        out[0] = (buf[64]&0x01) + (G.meta_state.chainIdLowByte<<1) + 35;
    }


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

    // TODO: this seems dead code - confirm and remove any transitively dead code
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

static size_t next_parse(bool const is_reentry);

static bool continue_parsing(void) {
    PRINTF("Continue parsing\n");
    memset(&G.meta_state.prompt, 0, sizeof(G.meta_state.prompt));

    BEGIN_TRY {
        TRY {
          // Call next_parse, which calls this function recursively...
            next_parse(true);
        }
        CATCH(ASYNC_EXCEPTION) {
            // requested another prompt
            PRINTF("Caught nested ASYNC exception\n");
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {}
    }
    END_TRY;
    return true;
}

static void transaction_complete_prompt(void) {
    static uint32_t const TYPE_INDEX = 0;

    static char const *const transaction_prompts[] = {
        PROMPT("Finalize"),
        NULL,
    };
    REGISTER_STATIC_UI_VALUE(TYPE_INDEX, "Transaction");

    ui_prompt(transaction_prompts, evm_sign_ok, evm_sign_reject);
}

static inline size_t reply_maybe_delayed(bool const is_reentry, size_t const tx) {
    if (is_reentry) {
        delayed_send(tx);
    }
    return tx;
}

static void empty_prompt_queue(void) {
    if (G.meta_state.prompt.count > 0) {
        PRINTF("Prompting for %d fields\n", G.meta_state.prompt.count);

        for (size_t i = 0; i < G.meta_state.prompt.count; i++) {
            register_ui_callback(
                i,
                G.meta_state.prompt.entries[i].to_string,
                &G.meta_state.prompt.entries[i].data
            );
        }
        ui_prompt_with(ASYNC_EXCEPTION, "Next", G.meta_state.prompt.labels, continue_parsing, evm_sign_reject);
    }
}

static size_t next_parse(bool const is_reentry) {
    PRINTF("Next parse\n");
    enum parse_rv rv = PARSE_RV_INVALID;
    BEGIN_TRY {
      TRY {
        set_next_batch_size(&G.meta_state.prompt, PROMPT_MAX_BATCH_SIZE);
        rv = parse_evm_txn(&G.state, &G.meta_state);
      }
      FINALLY {
        switch (rv) {
        case PARSE_RV_NEED_MORE:
          break;
        case PARSE_RV_INVALID:
          //peek_prompt_queue_reject();
          //break;
        case PARSE_RV_PROMPT:
        case PARSE_RV_DONE:
          empty_prompt_queue();
          break;
        }
      }
    }
    END_TRY;

    if ((rv == PARSE_RV_DONE || rv == PARSE_RV_NEED_MORE) &&
        G.meta_state.input.consumed != G.meta_state.input.length)
    {
        PRINTF("Not all input was parsed: %d %d %d\n", rv, G.meta_state.input.consumed, G.meta_state.input.length);
        THROW(EXC_PARSE_ERROR);
    }

    if (rv == PARSE_RV_NEED_MORE) {
        PRINTF("Need more\n");
        return reply_maybe_delayed(is_reentry, finalize_successful_send(0));
    }

    if (rv == PARSE_RV_DONE) {
        PRINTF("Parser signaled done; sending final prompt\n");
        finish_hash((cx_hash_t *const)&G.tx_hash_state, &G.final_hash);
        PRINTF("G.final_hash: %.*h\n", sizeof(G.final_hash), G.final_hash);
        transaction_complete_prompt();
    }

    PRINTF("Parse error: rv=%d consumed=%d length=%d\n",
      rv,
      G.meta_state.input.consumed,
      G.meta_state.input.length);
    THROW(EXC_PARSE_ERROR);
}

size_t handle_apdu_sign_evm_transaction(void) {
    uint8_t const *const in = &G_io_apdu_buffer[OFFSET_CDATA];
    uint8_t const in_size = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (in_size > MAX_APDU_SIZE)
        THROW(EXC_WRONG_LENGTH_FOR_INS);
    uint8_t const p1 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]);

    size_t ix = 0;

    switch (p1) {
      case 0x00: {
          memset(&G, 0, sizeof(G));

          if (ix + sizeof(uint8_t) > in_size) THROW_(EXC_WRONG_LENGTH, "Input too small");
          ix += read_bip32_path(&G.bip32_path, &in[ix], in_size - ix);
          check_bip32(&G.bip32_path, false);
          if (G.bip32_path.length < 3) THROW_(EXC_SECURITY, "Signing path not long enough");
          init_evm_txn(&G.state);
          cx_keccak_init(&G.tx_hash_state, 256);
      }
      fallthrough;
      case 0x80: {
          G.meta_state.input.src = in+ix;
          G.meta_state.input.consumed=0;
          G.meta_state.input.length=in_size-ix;
          if(G.meta_state.input.length == 0) return finalize_successful_send(0);

          PRINTF("HASH BUFFER %.*h\n", G.meta_state.input.length, G.meta_state.input.src);
          cx_hash((cx_hash_t *)&G.tx_hash_state, 0, G.meta_state.input.src, G.meta_state.input.length, NULL, 0);

          return next_parse(false);
      }
    }
    return finalize_successful_send(0);
}

size_t handle_apdu_provide_erc20(void) {
    return finalize_successful_send(0);
}
