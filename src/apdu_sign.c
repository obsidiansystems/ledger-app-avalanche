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

__attribute__((noreturn))
static size_t sign_hash_complete(void) {
    G.final_hash_as_buffer.bytes = &G.final_hash[0];
    G.final_hash_as_buffer.length = sizeof(G.final_hash);
    G.final_hash_as_buffer.size = sizeof(G.final_hash);

    if (N_data.sign_hash_policy == WARN_ON_SIGN_HASH) {
        static uint32_t const TYPE_INDEX = 0;
        static uint32_t const DANGER_INDEX = 1;
        static uint32_t const DRV_PREFIX_INDEX = 2;
        static uint32_t const HASH_INDEX = 3;
        static uint32_t const ARE_YOU_SURE_INDEX = 4;

        static char const *const transaction_prompts[] = {
            PROMPT("Sign"),
            PROMPT("DANGER!"),
            PROMPT("Derivation Prefix"),
            PROMPT("Hash"),
            PROMPT("Are you sure?"),
            NULL,
        };
        REGISTER_STATIC_UI_VALUE(TYPE_INDEX, "Hash");
        REGISTER_STATIC_UI_VALUE(DANGER_INDEX, "YOU MUST verify this manually!!!");

        register_ui_callback(DRV_PREFIX_INDEX, bip32_path_to_string, &G.bip32_path_prefix);

        register_ui_callback(HASH_INDEX, buffer_to_hex, &G.final_hash_as_buffer);

        REGISTER_STATIC_UI_VALUE(ARE_YOU_SURE_INDEX, "This is very dangerous!");

        ui_prompt(transaction_prompts, sign_ok, sign_reject);
    } else { // no warnings
        static uint32_t const TYPE_INDEX = 0;
        static uint32_t const DRV_PREFIX_INDEX = 1;
        static uint32_t const HASH_INDEX = 2;

        static char const *const transaction_prompts[] = {
            PROMPT("Sign"),
            PROMPT("Derivation Prefix"),
            PROMPT("Hash"),
            NULL,
        };
        REGISTER_STATIC_UI_VALUE(TYPE_INDEX, "Hash");

        register_ui_callback(DRV_PREFIX_INDEX, bip32_path_to_string, &G.bip32_path_prefix);

        register_ui_callback(HASH_INDEX, buffer_to_hex, &G.final_hash_as_buffer);

        ui_prompt(transaction_prompts, sign_ok, sign_reject);
    }

}

void __attribute__ ((noinline)) print_ava_debug(bip32_path_t bip32_path) {
    char path_str[100];
    bip32_path_to_string(path_str, sizeof(path_str), &bip32_path);
    PRINTF("Signing hash %.*h with %s\n", sizeof(G.final_hash), G.final_hash, path_str);
}

static size_t sign_hash_with_suffix(uint8_t *const out, bool const is_last_signature, uint8_t const *const in, size_t const in_size) {
    PRINTF("Signing hash: num_signatures_left = %d of requested_num_signatures = %d%s\n", G.num_signatures_left, G.requested_num_signatures, is_last_signature ? ", last signature" : "");
    if (G.num_signatures_left == 0 || G.num_signatures_left > G.requested_num_signatures) THROW(EXC_SECURITY);
    G.num_signatures_left = is_last_signature ? 0 : G.num_signatures_left - 1;

    bip32_path_t bip32_path_suffix;
    memset(&bip32_path_suffix, 0, sizeof(bip32_path_suffix));
    read_bip32_path(&bip32_path_suffix, in, in_size);

    // TODO: Ensure the suffix path is the right length, etc.
    bip32_path_t bip32_path;
    memcpy(&bip32_path, &G.bip32_path_prefix, sizeof(G.bip32_path_prefix));
    concat_bip32_path(&bip32_path, &bip32_path_suffix);

#if defined(AVA_DEBUG)
    print_ava_debug(bip32_path);
#endif

    size_t const tx = WITH_EXTENDED_KEY_PAIR(bip32_path, it, size_t, ({
        sign(out, MAX_SIGNATURE_SIZE, &it->key_pair, G.final_hash, sizeof(G.final_hash));
    }));

    if (G.num_signatures_left == 0) {
        clear_data();
    }

    return tx;
}


static size_t sign_hash_impl(
    uint8_t const *const in,
    uint8_t const in_size,
    bool const is_first_message,
    bool const is_last_message
) {
    if (is_first_message) {
        size_t ix = 0;

        // 1 byte - requested_num_signatures
        if (ix + sizeof(uint8_t) > in_size) THROW_(EXC_WRONG_LENGTH, "Input too small");
        G.requested_num_signatures = CONSUME_UNALIGNED_BIG_ENDIAN(ix, uint8_t, &in[ix]);
        if (G.requested_num_signatures == 0) THROW_(EXC_WRONG_PARAM, "Sender requested 0 signatures");

        // sizeof(G.final_hash) bytes - hash to sign
        if (ix + sizeof(G.final_hash) > in_size) THROW_(EXC_WRONG_LENGTH, "Input too small");
        memmove(G.final_hash, &in[ix], sizeof(G.final_hash));
        ix += sizeof(G.final_hash);

        // N bytes - BIP-32 path prefix for future signature requests
        read_bip32_path(&G.bip32_path_prefix, &in[ix], in_size - ix);

        // TODO: Make sure the prefix actually starts with the thing we care about
        if (G.bip32_path_prefix.length < 3) THROW(EXC_SECURITY);

        PRINTF("First signing message: requested_num_signatures = %d\n", G.requested_num_signatures);

        return sign_hash_complete();
    } else {
        return finalize_successful_send(
            sign_hash_with_suffix(G_io_apdu_buffer, is_last_message, in, in_size)
        );
    }
}

#define P1_NEXT       0x01
#define P1_LAST       0x80

size_t handle_apdu_sign_hash(void) {
    if (N_data.sign_hash_policy == DISALLOW_ON_SIGN_HASH) {
        PRINTF("Rejecting due to disallowed sign hash in configuration\n");
        THROW(EXC_REJECT);
    }

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

    ui_prompt(transaction_prompts, sign_ok, sign_reject);
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
        ui_prompt_with(ASYNC_EXCEPTION, "Next", G.parser.meta_state.prompt.labels, continue_parsing, sign_reject);
    }
}

static size_t next_parse(bool const is_reentry) {
    PRINTF("Next parse\n");
    enum parse_rv rv = PARSE_RV_INVALID;
    BEGIN_TRY {
      TRY {
        set_next_batch_size(&G.parser.meta_state.prompt, PROMPT_MAX_BATCH_SIZE);
        rv = parseTransaction(&G.parser.state, &G.parser.meta_state);
      }
      FINALLY {
        switch (rv) {
        case PARSE_RV_NEED_MORE:
          break;
        case PARSE_RV_INVALID:
        case PARSE_RV_PROMPT:
        case PARSE_RV_DONE:
          empty_prompt_queue();
          break;
        }
      }
    }
    END_TRY;

    if ((rv == PARSE_RV_DONE || rv == PARSE_RV_NEED_MORE) &&
        G.parser.meta_state.input.consumed != G.parser.meta_state.input.length)
    {
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

        PRINTF("Parser signaled done; sending final prompt\n");
        finish_hash((cx_hash_t *const)&G.parser.state.hash_state, &G.final_hash);
        transaction_complete_prompt();
    }


    PRINTF("Parse error: %d %d %d\n", rv, G.parser.meta_state.input.consumed, G.parser.meta_state.input.length);
    THROW(EXC_PARSE_ERROR);
}

#define SIGN_TRANSACTION_SECTION_PREAMBLE            0x00
#define SIGN_TRANSACTION_SECTION_PAYLOAD_CHUNK       0x01
#define SIGN_TRANSACTION_SECTION_PAYLOAD_CHUNK_LAST  0x81
#define SIGN_TRANSACTION_SECTION_SIGN_WITH_PATH      0x02
#define SIGN_TRANSACTION_SECTION_SIGN_WITH_PATH_LAST 0x82

#define P2_HAS_CHANGE_PATH 0x01

void __attribute__ ((noinline)) handle_has_change_path(size_t ix, uint8_t const *const in, uint8_t const in_size) {
    bip32_path_t change_path;
    memset(&change_path, 0, sizeof(change_path));
    read_bip32_path(&change_path, &in[ix], in_size - ix);

    if (change_path.length != 5) {
        THROW(EXC_WRONG_LENGTH);
    }

    check_bip32(&change_path, true);
    extended_public_key_t ext_public_key;
    generate_extended_public_key(&ext_public_key, &change_path);
    generate_pkh_for_pubkey(&ext_public_key.public_key, &G.change_address);
}

size_t handle_apdu_sign_transaction(void) {
    uint8_t const *const in = &G_io_apdu_buffer[OFFSET_CDATA];
    uint8_t const in_size = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_LC]);
    if (in_size > MAX_APDU_SIZE)
        THROW(EXC_WRONG_LENGTH_FOR_INS);
    uint8_t const p1 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P1]);
    uint8_t const p2 = READ_UNALIGNED_BIG_ENDIAN(uint8_t, &G_io_apdu_buffer[OFFSET_P2]);
    bool const hasChangePath = (p2 & P2_HAS_CHANGE_PATH) != 0;

    switch (p1) {
        case SIGN_TRANSACTION_SECTION_PREAMBLE: {
            clear_data();

            size_t ix = 0;
            if (ix + sizeof(uint8_t) > in_size) THROW_(EXC_WRONG_LENGTH, "Input too small");
            G.requested_num_signatures = CONSUME_UNALIGNED_BIG_ENDIAN(ix, uint8_t, &in[ix]);
            if (G.requested_num_signatures == 0) THROW_(EXC_WRONG_PARAM, "Sender requested 0 signatures");

            ix += read_bip32_path(&G.bip32_path_prefix, &in[ix], in_size - ix);
            check_bip32(&G.bip32_path_prefix, false);
            if (G.bip32_path_prefix.length < 3) THROW_(EXC_SECURITY, "Signing prefix path not long enough");

            if (hasChangePath) {
                handle_has_change_path(ix, in, in_size);
            }

            initTransaction(&G.parser.state);
            return finalize_successful_send(0);
        }

        case SIGN_TRANSACTION_SECTION_PAYLOAD_CHUNK_LAST:
        case SIGN_TRANSACTION_SECTION_PAYLOAD_CHUNK:
            if (G.num_signatures_left > 0) THROW_(EXC_SECURITY, "Sender broke protocol order by going backward");
            if (G.requested_num_signatures == 0) THROW_(EXC_WRONG_PARAM, "Sender broke protocol order by going forward");
            G.parser.is_last_message = p1 == SIGN_TRANSACTION_SECTION_PAYLOAD_CHUNK_LAST;
            G.parser.meta_state.input.consumed = 0;
            G.parser.meta_state.input.src = in;
            G.parser.meta_state.input.length = in_size;
            return next_parse(false);

        case SIGN_TRANSACTION_SECTION_SIGN_WITH_PATH_LAST:
        case SIGN_TRANSACTION_SECTION_SIGN_WITH_PATH:
            return finalize_successful_send(
                sign_hash_with_suffix(G_io_apdu_buffer, p1 == SIGN_TRANSACTION_SECTION_SIGN_WITH_PATH_LAST, in, in_size)
            );

        default: THROW_(EXC_WRONG_PARAM, "Unrecognized P1 %d", p1);
    }
}
