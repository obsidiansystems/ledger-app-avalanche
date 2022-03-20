#pragma once

#include "parser.h"

struct FixedState {
    size_t filledTo;
    uint8_t buffer[];
};

void initFixed(struct FixedState *const state, size_t const len);

enum parse_rv parseFixed(struct FixedState *const state, parser_input_meta_state_t *const input, size_t const len);

enum parse_rv skipBytes(struct FixedState *const state, parser_input_meta_state_t *const input, size_t const len);

////

static inline struct FixedState * fixed_state_con(struct FixedState0 * p) {
    return (struct FixedState *)p;
}

#define fs(p) fixed_state_con(&(p)->fixed_state)

#define ASSERT_FIXED(name) \
  _Static_assert( \
    ( \
      offsetof(struct name ## _state, buf) \
      == \
      offsetof(struct name ## _state, fixed_state.buffer_) \
    ), \
    "buffers do not line up in " # name "_state");

#define IMPL_FIXED(name) \
    static inline enum parse_rv parse_core_ ## name ( \
        struct name ## _state *const state, \
        parser_input_meta_state_t *const meta) \
    { \
        return parseFixed(fs(state), meta, sizeof(name));\
    } \
    \
    static inline enum parse_rv parse_ ## name ( \
        struct name ## _state *const state, \
        parser_meta_state_t *const meta) \
    { \
        return parse_core_ ## name (state, &meta->input); \
    } \
    \
    static inline void init_ ## name (struct name ## _state *const state) { \
        return initFixed(fs(state), sizeof(*state)); \
    } \
    \
    ASSERT_FIXED(name)

#define IMPL_FIXED_BE(name) \
    static inline enum parse_rv parse_ ## name (struct name ## _state *const state, parser_meta_state_t *const meta) { \
        enum parse_rv sub_rv = PARSE_RV_INVALID; \
        sub_rv = parseFixed(fs(state), &meta->input, sizeof(name)); \
        if (sub_rv == PARSE_RV_DONE) { \
            state->val = READ_UNALIGNED_BIG_ENDIAN(name, state->buf); \
        } \
        return sub_rv; \
    } \
    static inline void init_ ## name (struct name ## _state *const state) { \
        return initFixed(fs(state), sizeof(*state)); \
    }\
    \
    ASSERT_FIXED(name)

IMPL_FIXED(uint8_t);

#define RET_IF_NOT_DONE \
    if (sub_rv != PARSE_RV_DONE) return sub_rv

#define BREAK_IF_NOT_DONE \
    if (sub_rv != PARSE_RV_DONE) break

#define RET_IF_PROMPT_FLUSH \
    if (sub_rv == PARSE_RV_PROMPT) return sub_rv

#define BREAK_IF_PROMPT_FLUSH \
    if (sub_rv == PARSE_RV_PROMPT) break
