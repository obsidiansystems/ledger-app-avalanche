#include "apdu.h"
#include "globals.h"
#include "memory.h"
static const apdu_handler avm_handlers[] = {
    handle_apdu_version,             // 0x00
    handle_apdu_get_wallet_id,       // 0x01
    handle_apdu_get_public_key,      // 0x02
    handle_apdu_get_public_key_ext,  // 0x03
    handle_apdu_sign_hash,           // 0x04
    handle_apdu_sign_transaction,    // 0x05
};

static const apdu_handler evm_handlers[] = {
    [2] = (apdu_handler)handle_apdu_evm_get_address,
    [4] = (apdu_handler)handle_apdu_sign_evm_transaction,
    [0x0a] = (apdu_handler)handle_apdu_provide_erc20
};

static const struct app_handlers g_handlers = {
    .avm = {
        .handlers = &avm_handlers,
        .handlers_size = NUM_ELEMENTS(avm_handlers)
    },
    .evm = {
        .handlers = &evm_handlers,
        .handlers_size = NUM_ELEMENTS(evm_handlers)
    }
};

__attribute__((noreturn)) void app_main(void) {

    if (!N_data.initialized) {
        nvram_data data = {
            .initialized = true,
            .sign_hash_policy = WARN_ON_SIGN_HASH,
            .sign_hash_policy_prompt = "Allow with warning",
        };
        nvm_write((void*)&N_data, (void*)&data, sizeof(N_data));
    }

    main_loop(PIC(&g_handlers));
}
