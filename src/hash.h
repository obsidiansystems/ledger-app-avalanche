#pragma once

#include "types.h"

static inline void update_hash(cx_sha256_t *const state, uint8_t const *const src, size_t const length) {
    PRINTF("HASH DATA: %d bytes: %.*h\n", length, length, src);
    cx_hash((cx_hash_t *const)state, 0, src, length, NULL, 0);
}

static inline void finish_hash(cx_hash_t *const state, sign_hash_t *const dst) {
    cx_hash(state, CX_LAST, NULL, 0, &(*dst[0]), sizeof(*dst));
}
