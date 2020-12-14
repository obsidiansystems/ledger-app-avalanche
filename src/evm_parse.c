#include "exception.h"
#include "globals.h"
#include "parser.h"
#include "protocol.h"
#include "to_string.h"
#include "types.h"

void init_rlp_list(struct EVM_RLP_list_state *const state) {
    memset(state, 0, sizeof(*state));
}

void init_rlp_item(struct EVM_RLP_item_state *const state) {
    memset(state, 0, sizeof(*state));
}

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW_(EXC_PARSE_ERROR, "Rejected"); }

enum parse_rv parse_rlp_item(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta);

enum parse_rv parse_rlp_txn(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv rv;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t first = meta->input.src[meta->input.consumed++];
          if(first < 0xc0) REJECT("Transaction not an RLP list");
          if(first < 0xf8) {
              state->remaining = first - 0xc0;
              state->state=2;
          } else {
              state->len_len = first - 0xf7;
              state->state=1;
          }
      }
      case 1:
        if(state->state==1) {
            rv = parseFixed(&state->uint64_state, meta, state->len_len);
            if(rv != PARSE_RV_DONE) return rv;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[sizeof(uint64_t)-i];
            }
        }
        init_rlp_item(&state->rlpItem_state);
      case 2: // Now parse items.
        // Change this when a more general parser is built.
        while(1) {
            uint8_t itemStartIdx = meta->input.consumed;

            if( (rv = parse_rlp_item(&state->rlpItem_state, meta)) != PARSE_RV_DONE ) return rv;
            state->remaining -= meta->input.consumed - itemStartIdx;
            state->item_index++;
            if(state->item_index == 7) {
                meta->chainIdLowByte = meta->input.src[meta->input.consumed-1];
                PRINTF("Chain ID low byte: %x", meta->chainIdLowByte);
                PRINTF("Chain ID: %.*h", meta->input.consumed-itemStartIdx, &meta->input.src[itemStartIdx]);
            }

            init_rlp_item(&state->rlpItem_state);

            if(state->remaining == 0) {
                state->state=3;

                return PARSE_RV_DONE;
            }
        }
    }
}

enum parse_rv parse_rlp_item(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv rv;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t first = meta->input.src[meta->input.consumed++];
          if(first <= 0x7f) {
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->remaining=first - 0x80;
              state->state=2;
          } else if (first < 0xc0) {
              state->remaining=first - 0xbf;
              state->state=1;
          } else if(first < 0xf8) {
              state->remaining = first - 0xc0;
              state->state=2;
          } else {
              state->len_len = first - 0xf7;
              state->state=1;
          }
      }
      case 1:
        rv = parseFixed(&state->uint64_state, meta, state->len_len);
        if(rv != PARSE_RV_DONE) return rv;
        for(size_t i = 0; i < state->len_len; i++) {
            ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[sizeof(uint64_t)-i];
        }
      case 2:
        if(state->remaining <= meta->input.length-meta->input.consumed) {
            state->state=3;
            meta->input.consumed+=state->remaining;

            return PARSE_RV_DONE;
        } else {
            meta->input.consumed=meta->input.length;
            return PARSE_RV_NEED_MORE;
        }
    }
}

