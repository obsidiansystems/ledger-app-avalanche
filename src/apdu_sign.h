#pragma once

#include "apdu.h"

size_t handle_apdu_sign_hash(void);
size_t handle_apdu_sign_transaction(void);
size_t handle_apdu_sign_evm_transaction(void);
size_t handle_apdu_provide_erc20(void);
