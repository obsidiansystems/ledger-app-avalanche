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

#define G global.apdu.u.sign

static inline void clear_data(void) {
    PRINTF("Clearing sign APDU state\n");
    memset(&G, 0, sizeof(G));
}

static bool sign_ok(void) {
    G.num_signatures_left = G.requested_num_signatures;

    size_t tx = 0;
    memcpy(&G_io_apdu_buffer[tx], G.final_hash, sizeof(G.final_hash));
    tx += sizeof(G.final_hash);

    delayed_send(finalize_successful_send(tx));
    return true;
}

static bool sign_reject(void) {
    PRINTF("Sign reject\n");
    clear_data();
    delay_reject();
    return true; // Return to idle
}

static size_t sign_complete(void) {
    static uint32_t const TYPE_INDEX = 0;
    static uint32_t const DRV_PREFIX_INDEX = 1;
    static uint32_t const HASH_INDEX = 2;

    static char const *const transaction_prompts[] = {
        PROMPT("Sign"),
        PROMPT("Derivation Prefix"),
        PROMPT("Hash"),
        NULL
    };
    REGISTER_STATIC_UI_VALUE(TYPE_INDEX, "Hash");

    register_ui_callback(DRV_PREFIX_INDEX, bip32_path_to_string, &G.bip32_path_prefix);

    G.final_hash_as_buffer.bytes = &G.final_hash[0];
    G.final_hash_as_buffer.length = sizeof(G.final_hash);
    G.final_hash_as_buffer.size = sizeof(G.final_hash);
    register_ui_callback(HASH_INDEX, buffer_to_hex, &G.final_hash_as_buffer);

    ui_prompt(transaction_prompts, sign_ok, sign_reject);
}

static size_t sign_hash_impl(
    uint8_t const *const in,
    uint8_t const in_size,
    bool const isFirstMessage,
    bool const isLastMessage
) {
    if (isFirstMessage) {
        size_t ix = 0;

        // 1 byte - requested_num_signatures
        G.requested_num_signatures = CONSUME_UNALIGNED_BIG_ENDIAN(ix, uint8_t, &in[ix]);

        // sizeof(G.final_hash) bytes - hash to sign
        if (ix + sizeof(G.final_hash) > in_size) {
            THROW(EXC_WRONG_LENGTH);
        }
        memmove(G.final_hash, &in[ix], sizeof(G.final_hash));
        ix += sizeof(G.final_hash);

        // N bytes - BIP-32 path prefix for future signature requests
        ix += read_bip32_path(&G.bip32_path_prefix, &in[ix], in_size - ix);

        // TODO: Make sure the prefix actually starts with the thing we care about
        if (G.bip32_path_prefix.length < 3) {
            THROW(EXC_SECURITY);
        }

        PRINTF("First signing message: requested_num_signatures = %d\n", G.requested_num_signatures);

        return sign_complete();
    } else {
        PRINTF("Next signing message: num_signatures_left = %d of requested_num_signatures = %d\n", G.num_signatures_left, G.requested_num_signatures);
        if (G.num_signatures_left == 0 || G.num_signatures_left > G.requested_num_signatures) {
            THROW(EXC_SECURITY);
        }
        G.num_signatures_left = isLastMessage ? 0 : G.num_signatures_left - 1;

        bip32_path_t bip32_path_suffix;
        memset(&bip32_path_suffix, 0, sizeof(bip32_path_suffix));
        read_bip32_path(&bip32_path_suffix, in, in_size);

        // TODO: Ensure the suffix path is the right length, etc.
        bip32_path_t bip32_path;
        memcpy(&bip32_path, &G.bip32_path_prefix, sizeof(G.bip32_path_prefix));
        concat_bip32_path(&bip32_path, &bip32_path_suffix);

#if defined(AVA_DEBUG)
        char pathstr[100];
        bip32_path_to_string(pathstr, sizeof(pathstr), &bip32_path);
        PRINTF("Signing with %s\n", pathstr);
        PRINTF("Signing hash = %.*h\n", sizeof(G.final_hash), G.final_hash);
#endif

        size_t const tx = WITH_EXTENDED_KEY_PAIR(bip32_path, it, size_t, ({
            sign(G_io_apdu_buffer, MAX_SIGNATURE_SIZE, &it->key_pair, G.final_hash, sizeof(G.final_hash));
        }));

        if (G.num_signatures_left == 0) {
            clear_data();
        }
        return finalize_successful_send(tx);
    }
}

#define P1_NEXT       0x01
#define P1_LAST       0x80

size_t handle_apdu_sign_hash(void) {
    uint8_t const buff_size = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (buff_size > MAX_APDU_SIZE)
        THROW(EXC_WRONG_LENGTH_FOR_INS);
    uint8_t const p1 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]);

    bool const isFirstMessage = (p1 & P1_NEXT) == 0;
    bool const isLastMessage = (p1 & P1_LAST) != 0;

    if (isFirstMessage) {
        clear_data();
    }

    uint8_t const *const buff = &G_io_apdu_buffer[OFFSET_CDATA];
    return sign_hash_impl(buff, buff_size, isFirstMessage, isLastMessage);
}

static size_t next_parse(bool const is_reentry);

static bool continue_parsing(void) {
    PRINTF("Continue parsing\n");
    memset(&G.parser.meta_state.prompt, 0, sizeof(G.parser.meta_state.prompt));

    BEGIN_TRY {
        TRY {
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

static inline size_t reply_maybe_delayed(bool const is_reentry, size_t const tx) {
    if (is_reentry) {
        delayed_send(tx);
    }
    return tx;
}

static void empty_prompt_queue(void) {
    if (G.parser.meta_state.prompt.count > 0) {
        PRINTF("Prompting for %d fields\n", G.parser.meta_state.prompt.count);

        for (size_t i = 0; i < G.parser.meta_state.prompt.count; i++) {
            register_ui_callback(
                i,
                G.parser.meta_state.prompt.entries[i].to_string,
                &G.parser.meta_state.prompt.entries[i].data
            );
        }
        ui_prompt(G.parser.meta_state.prompt.labels, continue_parsing, sign_reject);
    }
}

static size_t next_parse(bool const is_reentry) {
    PRINTF("Next parse\n");
    enum parse_rv const rv = parseTransaction(&G.parser.state, &G.parser.meta_state);

    empty_prompt_queue();

    if (rv == PARSE_RV_DONE || rv == PARSE_RV_NEED_MORE) {
        if (G.parser.meta_state.input.consumed != G.parser.meta_state.input.length) {
            PRINTF("Not all input was parsed: %d %d %d\n", rv, G.parser.meta_state.input.consumed, G.parser.meta_state.input.length);
            THROW(EXC_PARSE_ERROR);
        }

        if (rv == PARSE_RV_NEED_MORE) {
            if (G.parser.is_last_message) {
                PRINTF("Sender claimed last message and we aren't done\n");
                THROW(EXC_PARSE_ERROR);
            }
            PRINTF("Need more\n");
            return reply_maybe_delayed(is_reentry, finalize_successful_send(0));
        }

        if (rv == PARSE_RV_DONE) {
            if (!G.parser.is_last_message) {
                PRINTF("Sender claims there is more but we are done\n");
                THROW(EXC_PARSE_ERROR);
            }

            PRINTF("Parser signaled done; sending final hash\n");
            cx_hash((cx_hash_t *const)&G.parser.state.hash_state, CX_LAST, NULL, 0, G.final_hash, sizeof(G.final_hash));
            G.num_signatures_left = G.requested_num_signatures;

            size_t tx = 0;
            memcpy(&G_io_apdu_buffer[tx], G.final_hash, sizeof(G.final_hash));
            tx += sizeof(G.final_hash);

            return reply_maybe_delayed(is_reentry, finalize_successful_send(tx));
        }
    }

    PRINTF("Parse error: %d %d %d\n", rv, G.parser.meta_state.input.consumed, G.parser.meta_state.input.length);
    THROW(EXC_PARSE_ERROR);
}

size_t handle_apdu_sign_transaction(void) {
    uint8_t const *const in = &G_io_apdu_buffer[OFFSET_CDATA];
    uint8_t const in_size = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (in_size > MAX_APDU_SIZE)
        THROW(EXC_WRONG_LENGTH_FOR_INS);
    uint8_t const p1 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]);

    bool const is_first_message = (p1 & P1_NEXT) == 0;
    bool const is_last_message = (p1 & P1_LAST) != 0;

    if (is_first_message) {
        clear_data();
        read_bip32_path(&G.bip32_path_prefix, in, in_size);

        initTransaction(&G.parser.state);

        return finalize_successful_send(0);
    }

    G.parser.is_last_message = is_last_message;
    G.parser.meta_state.input.consumed = 0;
    G.parser.meta_state.input.src = in;
    G.parser.meta_state.input.length = in_size;

    return next_parse(false);
}
