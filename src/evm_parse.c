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

#define SET_PROMPT_VALUE(setter) ({ \
    if(meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries)) THROW_(EXC_MEMORY_ERROR, "Tried to add a prompt value to full queue"); \
    prompt_entry_t *entry = &meta->prompt.entries[meta->prompt.count];\
    setter;\
    })

#define ADD_ACCUM_PROMPT(label_, to_string_) ({ \
        if (meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries)) THROW_(EXC_MEMORY_ERROR, "Tried to add a prompt to full queue"); \
        sub_rv = PARSE_RV_PROMPT; \
        meta->prompt.labels[meta->prompt.count] = PROMPT(label_); \
        meta->prompt.entries[meta->prompt.count].to_string = to_string_; \
        meta->prompt.count++; \
        meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries); \
    })

#define ADD_PROMPT(label_, data_, size_, to_string_) ({\
    SET_PROMPT_VALUE(memcpy(entry, data_, size_));\
    ADD_ACCUM_PROMPT(label_, to_string_);\
    })

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW_(EXC_PARSE_ERROR, "Rejected"); }

// Fix this.
static void output_evm_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
    check_null(out);
    check_null(in);
    network_info_t const *const network_info = network_info_from_network_id(in->network_id);
    if (network_info == NULL) REJECT("Can't determine network HRP for addresses");
    char const *const hrp = network_info->hrp;

    size_t ix = nano_avax_to_string(out, out_size, in->amount);

    static char const to[] = " to ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    ix += pkh_to_string(&out[ix], out_size - ix, hrp, strlen(hrp), &in->address.val);
}

enum parse_rv parse_rlp_item(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta);
enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta);

enum eth_txn_items {
  EVM_TXN_NONCE,
  EVM_TXN_GASPRICE,
  EVM_TXN_STARTGAS,
  EVM_TXN_TO,
  EVM_TXN_VALUE,
  EVM_TXN_DATA,
  EVM_TXN_CHAINID,
  EVM_TXN_SIG_R,
  EVM_TXN_SIG_S
};

enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta);

const static struct known_destination precompiled[] = {
  //{ .to = { 0 }, .handle_data = handle_contract_creation },
  //{ .to = { [18] = 0xde, [19] = 0xad }, .handle_data = handle_burn },
  //{ .to = { [0] = 0x01, [19] = 0x01 }, .handle_data = reject_txn },
  { .to = { [0] = 0x01, [19] = 0x02 }, .handle_data = (known_destination_parser)parse_assetCall_data }
};

enum abi_type {
    ABI_TYPE_UINT256
};

#define MAX_PARAMS 1

struct contract_endpoints {
  uint32_t selector;
  uint8_t parameter_count;
  enum abi_type parameters[MAX_PARAMS];
};

static const struct contract_endpoints known_endpoints[] = {
  { .selector = 0xdeadbeef // DEPOSIT; needs the real one here.
      , .parameter_count=1,
        .parameters = { ABI_TYPE_UINT256 } }
};

static const uint32_t known_endpoints_size=sizeof(known_endpoints)/sizeof(known_endpoints[0]);

/*
enum parse_rv parse_evm_abi_data(evm_parser_meta_state_t *const meta) {
  enum parse_rv rv;
  switch(state->state) {
    case 0: { // Read the selector.
        CALL_SUBPARSER(uint32State, uint32_t);
        for(int i=0;i<known_endpoints_size;i++) { // TODO: if this becomes large sort and binary search.
            if(known_endpoints[i].selector == state->uint32State.buf) {
                state->endpoint_num = i;
            }
        }
        state->state++;
    }
    case 1: {

    }
  }
}
*/

debug_parser_input_meta_state(parser_input_meta_state_t *const state) {
  PRINTF("DEBUG parser_input_meta_state\n");
//  PRINTF("src\n");//  uint8_t const *src;
  PRINTF("consumed %u\n", state->consumed);
  PRINTF("length %u\n", state->length);
}

debug_EVM_RLP_list_state(struct EVM_RLP_list_state *const state) {
  PRINTF("DEBUG EVM_RLP_list_state\n");
//  PRINTF("state %d\n", state->state);
  PRINTF("remaining %.*h\n", 8, &state->remaining);
  PRINTF("len_len %.*h\n", 1, &state->len_len);
  PRINTF("item_index %.*h\n", 1, &state->item_index);
}

debug_EVM_RLP_item_state(struct EVM_RLP_item_state *const state) {
  PRINTF("DEBUG EVM_RLP_item_state\n");
  PRINTF("state %u\n", state->state);
  PRINTF("length %.*h\n", 8, &state->length);
  PRINTF("current %.*h\n", 8, &state->current);
  PRINTF("len_len %u\n", state->len_len);
}

enum parse_rv parse_rlp_txn(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    debug_EVM_RLP_list_state(state);
    PRINTF("consumed %u\n", meta->input.consumed);
    PRINTF("length %u\n", meta->input.length);
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
            // Max length we could get for this value is 8 bytes so uint64_state is appropriate.
            sub_rv = parseFixed(((struct FixedState*)&state->uint64_state), &meta->input, state->len_len);
            if(sub_rv != PARSE_RV_DONE) return sub_rv;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[sizeof(uint64_t)-i];
            }
        }
        init_rlp_item(&state->rlpItem_state);
      case 2: { // Now parse items.
          uint8_t itemStartIdx;
          switch(state->item_index) {
#define PARSE_ITEM(ITEM, save) \
            case ITEM: {\
                itemStartIdx = meta->input.consumed; \
                PRINTF("%u\n", state->item_index); \
                sub_rv = parse_rlp_item ## save(&state->rlpItem_state, meta); \
                state->remaining -= meta->input.consumed - itemStartIdx; \
            } (void)0
#define FINISH_ITEM_CHUNK() \
            if(sub_rv != PARSE_RV_DONE) break;                          \
            state->item_index++;                                        \
            init_rlp_item(&state->rlpItem_state);

            PARSE_ITEM(EVM_TXN_NONCE, );
            FINISH_ITEM_CHUNK();
            // Don't need to do anything in particular with the nonce.
            // In particular, all values are at least plausible here. We could show it perhaps.
            PARSE_ITEM(EVM_TXN_GASPRICE, _to_buffer);
            FINISH_ITEM_CHUNK();
            // Probably needs saved and/or prompted here
            PARSE_ITEM(EVM_TXN_STARTGAS, _to_buffer);
            FINISH_ITEM_CHUNK();
            // Probably needs saved and/or prompted here
            PARSE_ITEM(EVM_TXN_TO, _to_buffer);

            if(state->rlpItem_state.length != 20) REJECT("Destination address not 20 bytes");

            for(uint64_t i = 0; i < sizeof(precompiled) / sizeof(struct known_destination); i++) {
                if(!memcmp(precompiled[i].to, state->rlpItem_state.buffer, 20)) {
                    meta->known_destination = &precompiled[i];
                    break;
                }
            }
            if(!meta->known_destination) {
                SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->rlpItem_state.buffer, 20));
            }

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_VALUE, _to_buffer);

            uint64_t value = 0; // FIXME: support bigger numbers.
            if(state->rlpItem_state.length > 8) REJECT("Can't support large numbers (yet)") // Fix this.
            for(uint64_t i = 0; i < state->rlpItem_state.length; i++) // Should be a function.
                ((uint8_t*)(&value))[i] = state->rlpItem_state.buffer[state->rlpItem_state.length-i];
            SET_PROMPT_VALUE(entry->data.output_prompt.amount = value);
            /*
            if(ADD_ACCUM_PROMPT(
                "Transfer",
                output_evm_prompt_to_string // Needs tweaked to be EVM addresses
                )) return PARSE_RV_PROMPT;
            */

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_DATA, );

            if(meta->known_destination) {
                sub_rv = meta->known_destination->handle_data(&(state->rlpItem_state.endpoint_state), &(state->rlpItem_state.chunk), meta);
            } else if(state->rlpItem_state.length != 0) {
                // Probably we have to allow this, as the metamask constraint means _this_ endpoint will be getting stuff it doesn't understand a lot.
                static char const isPresentLabel[]="Is Present";
                if(ADD_PROMPT("Contract Data", isPresentLabel, sizeof(isPresentLabel), strcpy_prompt)) return PARSE_RV_PROMPT;
            }

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_CHAINID, _to_buffer);

            if(state->rlpItem_state.length != 2
               || state->rlpItem_state.buffer[0] != 0xa8
               || (state->rlpItem_state.buffer[1] != 0x69 && state->rlpItem_state.buffer[1] != 0x6a))
                REJECT("Chain ID incorrect for the Avalanche C chain");
            meta->chainIdLowByte = state->rlpItem_state.buffer[state->rlpItem_state.length-1];
            PRINTF("Chain ID low byte: %x\n", meta->chainIdLowByte);

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_SIG_R, _to_buffer);

            if(state->rlpItem_state.length != 0) REJECT("R value must be 0 for signing with EIP-155.");

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_SIG_S, _to_buffer);

            if(state->rlpItem_state.length != 0) REJECT("S value must be 0 for signing with EIP-155.");
            FINISH_ITEM_CHUNK();
          }
          state->state++;

          if(state->remaining == 0) {
              state->state = 3;
              return PARSE_RV_DONE;
          } else {
              PRINTF("%u\n", state->remaining);
              REJECT("Reported total size of transaction did not match sum of pieces");
          }
      }
      case 3:
        sub_rv = PARSE_RV_DONE;
      default:
        REJECT("Transaction parser in supposedly unreachable state");
    }
    return sub_rv;
}

enum parse_rv parse_rlp_item(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t first = meta->input.src[meta->input.consumed++];
          PRINTF("parse_rlp_item first: %u\n", first);
          if(first <= 0x7f) {
              state->chunk.src = &meta->input.src[meta->input.consumed-1];
              state->chunk.consumed = 0;
              state->chunk.length = 1;
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->length = first - 0x80;
              state->state = 2;
          } else if (first < 0xc0) {
              state->length = first - 0xbf;
              state->state = 1;
          } else if(first < 0xf8) {
              state->length = first - 0xc0;
              state->state = 2;
          } else {
              state->len_len = first - 0xf7;
              state->state = 1;
          }
      }
      case 1:
        if(state->state == 1) {
            sub_rv = parseFixed((struct FixedState*) &state->uint64_state, &meta->input, state->len_len);
            if(sub_rv != PARSE_RV_DONE) break;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->length))[i] = state->uint64_state.buf[sizeof(uint64_t)-i];
            }
        }
      case 2: {
          uint64_t remaining = state->length-state->current;
          uint64_t available = meta->input.length - meta->input.consumed;

          debug_EVM_RLP_item_state(state);
          PRINTF("parse_rlp_item_to_buffer available %.*h\n", 8, &available);
          PRINTF("parse_rlp_item_to_buffer remaining %.*h\n", 8, &remaining);

          state->chunk.src=&meta->input.src[meta->input.consumed];
          state->chunk.consumed = 0;
          if(remaining <= available) {
              state->chunk.length=remaining;
              state->state = 3;
              state->current = state->length;
              meta->input.consumed += remaining;

              sub_rv=PARSE_RV_DONE;
          } else {
              state->chunk.length = available;
              state->current += available;
              meta->input.consumed = meta->input.length;
              sub_rv = PARSE_RV_NEED_MORE;
          }
      }
    }
    return sub_rv;
}

enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t first = meta->input.src[meta->input.consumed++];
          PRINTF("parse_rlp_item_to_buffer first: %u\n", first);
          if(first <= 0x7f) {
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->length = first - 0x80;
              state->state = 2;
          } else if (first < 0xc0) {
              state->length = first - 0xbf;
              state->state = 1;
          } else if(first < 0xf8) {
              state->length = first - 0xc0;
              state->state = 2;
          } else {
              state->len_len = first - 0xf7;
              state->state = 1;
          }
      }
      case 1:
        if(state->state == 1) {
            sub_rv = parseFixed((struct FixedState *)&state->uint64_state, &meta->input, state->len_len);
            if(sub_rv != PARSE_RV_DONE) return sub_rv;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->length))[i] = state->uint64_state.buf[sizeof(uint64_t)-i];
            }
        }
        if(state->length>MAX_EVM_BUFFER) REJECT("RLP field too large for buffer");
      case 2: {
          uint64_t remaining = state->length-state->current;
          uint64_t available = meta->input.length - meta->input.consumed;
          debug_EVM_RLP_item_state(state);

          PRINTF("parse_rlp_item_to_buffer available %.*h\n", 8, &available);
          PRINTF("parse_rlp_item_to_buffer remaining %.*h\n", 8, &remaining);
          if(remaining <= available) {
              state->state=3;
              memcpy(state->buffer+state->current, meta->input.src + meta->input.consumed, remaining);
              meta->input.consumed += remaining;
              return PARSE_RV_DONE;
          } else {
              memcpy(state->buffer+state->current, meta->input.src + meta->input.consumed, available);
              state->current += available;
              meta->input.consumed = meta->input.length;
              return PARSE_RV_NEED_MORE;
          }
      }
      default:
        return PARSE_RV_DONE;
    }
}

enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;

    REJECT("assetCall is not yet supported");
}
