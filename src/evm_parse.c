#include "cb58.h"
#include "exception.h"
#include "globals.h"
#include "parser.h"
#include "protocol.h"
#include "to_string.h"
#include "types.h"

#define ETHEREUM_ADDRESS_SIZE 20

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
    SET_PROMPT_VALUE(memcpy(&entry->data, data_, size_));\
    ADD_ACCUM_PROMPT(label_, to_string_);\
    })

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW_(EXC_PARSE_ERROR, "Rejected"); }

static void output_evm_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
    check_null(out);
    check_null(in);
    size_t ix = nano_avax_to_string(out, out_size, in->amount);

    static char const to[] = " to ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    out[ix] = '0'; ix++;
    out[ix] = 'x'; ix++;
    bin_to_hex_lc(&out[ix], out_size - ix, &in->address.val, ETHEREUM_ADDRESS_SIZE);
    ix += 2 * ETHEREUM_ADDRESS_SIZE + 1;
}

static void output_assetCall_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  check_null(out);
  check_null(in);
  size_t ix = 0;

  bin_to_hex_lc(out, out_size, &in->assetCall.amount, 32);
  ix += 64;

  static char const of[] = " of ";
  if (ix + sizeof(of) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' of ' into prompt value string");
  memcpy(&out[ix], of, sizeof(of));
  ix += sizeof(of) - 1;

  size_t b58sz = out_size - ix;
  if (!cb58enc(&out[ix], &b58sz, (const void*)&in->assetCall.assetID, 32))
    THROW(EXC_MEMORY_ERROR);
  ix += b58sz - 1;

  static char const to[] = " to ";
  if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
  memcpy(&out[ix], to, sizeof(to));
  ix += sizeof(to) - 1;

  out[ix] = '0'; ix++;
  out[ix] = 'x'; ix++;
  bin_to_hex_lc(&out[ix], out_size - ix, &in->address.val, ETHEREUM_ADDRESS_SIZE);
  ix += 2 * ETHEREUM_ADDRESS_SIZE + 1;
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

void init_assetCall_data(struct EVM_assetCall_state *const state, uint64_t length);
enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta);

const static struct known_destination precompiled[] = {
  { .to = { [0] = 0x01, [19] = 0x02 },
    .init_data=(known_destination_init)init_assetCall_data,
    .handle_data = (known_destination_parser)parse_assetCall_data
  }
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

// keccak256('deposit()')
#define DEPOSIT_SELECTOR 0xd0e30db0

static const struct contract_endpoints known_endpoints[] = {
  { .selector = DEPOSIT_SELECTOR
      , .parameter_count=1,
        .parameters = { ABI_TYPE_UINT256 } }
};

static const uint32_t known_endpoints_size=sizeof(known_endpoints)/sizeof(known_endpoints[0]);

enum parse_rv parse_rlp_txn(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
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
                ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[state->len_len-i-1];
            }
        }
        init_rlp_item(&state->rlpItem_state);
        state->state = 2;
      case 2: { // Now parse items.
          uint8_t itemStartIdx;
          switch(state->item_index) {
#define PARSE_ITEM(ITEM, save) \
            case ITEM: {\
                itemStartIdx = meta->input.consumed; \
                PRINTF("Entering " #ITEM "\n");                          \
                sub_rv = parse_rlp_item ## save(&state->rlpItem_state, meta); \
                PRINTF("Exiting " #ITEM "\n");                          \
                state->remaining -= meta->input.consumed - itemStartIdx; \
            } (void)0
#define FINISH_ITEM_CHUNK() \
            if(sub_rv != PARSE_RV_DONE) return sub_rv;                  \
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

            if(state->rlpItem_state.length != ETHEREUM_ADDRESS_SIZE)
              REJECT("Destination address not %d bytes", ETHEREUM_ADDRESS_SIZE);

            for(uint64_t i = 0; i < sizeof(precompiled) / sizeof(struct known_destination); i++) {
                if(!memcmp(precompiled[i].to, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE)) {
                    meta->known_destination = &precompiled[i];
                    break;
                }
            }
            if(!meta->known_destination)
                SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE));

            FINISH_ITEM_CHUNK();
            PARSE_ITEM(EVM_TXN_VALUE, _to_buffer);

            uint64_t value = 0; // FIXME: support bigger numbers.
            if(state->rlpItem_state.length > 8) REJECT("Can't support large numbers (yet)") // Fix this.
            for(uint64_t i = 0; i < state->rlpItem_state.length; i++) // Should be a function.
                ((uint8_t*)(&value))[i] = state->rlpItem_state.buffer[state->rlpItem_state.length-i-1];
            SET_PROMPT_VALUE(entry->data.output_prompt.amount = value);

            FINISH_ITEM_CHUNK();

            if(!meta->known_destination) {
                if(ADD_ACCUM_PROMPT(
                      "Transfer",
                      output_evm_prompt_to_string
                      )) return PARSE_RV_PROMPT;
            }

            PARSE_ITEM(EVM_TXN_DATA, );

            if(meta->known_destination) {
                if(state->rlpItem_state.do_init && meta->known_destination->init_data)
                  ((known_destination_init)PIC(meta->known_destination->init_data))(&(state->rlpItem_state.endpoint_state), state->rlpItem_state.length);
                PRINTF("INIT: %u\n", state->rlpItem_state.do_init);
                PRINTF("Chunk: [%u] %.*h\n", state->rlpItem_state.chunk.length, state->rlpItem_state.chunk.length, state->rlpItem_state.chunk.src);
                if(meta->known_destination->handle_data) {
                  PRINTF("HANDLING DATA\n");
                  sub_rv = ((known_destination_parser)PIC(meta->known_destination->handle_data))(&(state->rlpItem_state.endpoint_state), &(state->rlpItem_state.chunk), meta);
                }
                PRINTF("PARSER CALLED [sub_rv: %u]\n", sub_rv);
                if(sub_rv != PARSE_RV_DONE) return sub_rv;
            }

            // Can't use the macro here because we need to do a prompt in the middle of it.
            if(sub_rv != PARSE_RV_DONE) return sub_rv;
            state->item_index++;
            uint64_t len=state->rlpItem_state.length;
            init_rlp_item(&state->rlpItem_state);

            if(!meta->known_destination && len != 0) {
                // Probably we have to allow this, as the metamask constraint means _this_ endpoint will be getting stuff it doesn't understand a lot.
                static char const isPresentLabel[]="Is Present (unsafe)";
                if(ADD_PROMPT("Contract Data", isPresentLabel, sizeof(isPresentLabel), strcpy_prompt))
                    return PARSE_RV_PROMPT;
            }

            PARSE_ITEM(EVM_TXN_CHAINID, _to_buffer);

            if(state->rlpItem_state.length != 2
               || state->rlpItem_state.buffer[0] != 0xa8
               || (state->rlpItem_state.buffer[1] != 0x68
                   && state->rlpItem_state.buffer[1] != 0x69
                   && state->rlpItem_state.buffer[1] != 0x6a))
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

          if(state->remaining == 0) {
              state->state = 3;
              return PARSE_RV_DONE;
          } else
              REJECT("Reported total size of transaction did not match sum of pieces");
      }
      case 3:
        sub_rv = PARSE_RV_DONE;
        return sub_rv;
      default:
        REJECT("Transaction parser in supposedly unreachable state");
    }
    return sub_rv;
}

enum parse_rv parse_rlp_item(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    state->chunk.src=0;
    state->chunk.length=0;
    state->chunk.consumed=0;
    state->do_init=false;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t first = meta->input.src[meta->input.consumed++];
          if(first <= 0x7f) {
              state->chunk.src = &meta->input.src[meta->input.consumed-1];
              state->chunk.consumed = 0;
              state->chunk.length = 1;
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->length = first - 0x80;
              state->state = 2;
          } else if (first < 0xc0) {
              state->len_len = first - 0xb7;
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
                ((uint8_t*)(&state->length))[i] = state->uint64_state.buf[state->len_len-i-1];
            }
        }
        state->do_init=true;
        state->state = 2;
      case 2: {
          uint64_t remaining = state->length-state->current;
          uint64_t available = meta->input.length - meta->input.consumed;

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
          if(first <= 0x7f) {
              state->buffer[0] = first;
              state->length = 1;
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->length = first - 0x80;
              state->state = 2;
          } else if (first < 0xc0) {
              state->len_len = first - 0xb7;
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
                ((uint8_t*)(&state->length))[i] = state->uint64_state.buf[state->len_len-i-1];
            }
        }
        if(state->length>MAX_EVM_BUFFER) REJECT("RLP field too large for buffer");
        state->state = 2;
      case 2: {
          uint64_t remaining = state->length-state->current;
          uint64_t available = meta->input.length - meta->input.consumed;
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

IMPL_FIXED(uint256_t);

#define ASSETCALL_FIXED_DATA_WIDTH (20 + 32 + 32)

void init_assetCall_data(struct EVM_assetCall_state *const state, uint64_t length) {
    state->state=0;
    PRINTF("Initing assetCall Data\n");
    if(length < ASSETCALL_FIXED_DATA_WIDTH)
      REJECT("Calldata too small for assetCall");
    state->data_length = length - ASSETCALL_FIXED_DATA_WIDTH;
    initFixed(&state->address_state, sizeof(state->address_state));
    PRINTF("Initing assetCall Data\n");
}

enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    bool expectingDeposit = state->data_length > 0;

    PRINTF("AssetCall Data: %.*h\n", input->length, input->src);
    PRINTF("expectingDeposit: %u, input length %u, state->data_length %.*h\n", expectingDeposit, input->length, 8, &state->data_length);
    PRINTF("state: %u\n", state->state);
    switch(state->state) {
    case ASSETCALL_ADDRESS:
      sub_rv = parseFixed(&state->address_state, input, ETHEREUM_ADDRESS_SIZE);
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->address_state.buf, ETHEREUM_ADDRESS_SIZE));
      PRINTF("Address: %.*h\n", ETHEREUM_ADDRESS_SIZE, state->address_state.buf);
      state->state++;
      initFixed(&state->id32_state, sizeof(state->id32_state));
    case ASSETCALL_ASSETID:
      sub_rv = parseFixed(&state->id32_state, input, 32);
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(memcpy(&entry->data.output_prompt.assetCall.assetID, state->id32_state.buf, 32));
      PRINTF("Asset: %.*h\n", 32, state->id32_state.buf);
      state->state++;
      initFixed(&state->uint256_state, sizeof(state->uint256_state));
    case ASSETCALL_AMOUNT:
      sub_rv = parseFixed(&state->uint256_state, input, 32);
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(memcpy(&entry->data.output_prompt.assetCall.amount, state->uint256_state.buf, 32));
      PRINTF("Amount: %.*h\n", 32, state->uint256_state.buf);
      state->state++;

      if(state->data_length==0) {
        PRINTF("Plain non-avax transfer\n");
        state->state = ASSETCALL_DONE;
        if(ADD_ACCUM_PROMPT("Transfer", output_assetCall_prompt_to_string))
          return PARSE_RV_PROMPT;
        return PARSE_RV_DONE;
      }
      if (state->data_length != 4) {
        REJECT("unsupported assetCall length");
      }
      initFixed(&state->selector_state, sizeof(state->selector_state));
    case ASSETCALL_DATA:
      sub_rv = parseFixed(&state->selector_state, input, 4);
      if(sub_rv != PARSE_RV_DONE) return sub_rv;

      static const uint8_t depositSelectorBytes [4] = { 0xd0, 0xe3, 0x0d, 0xb0 };
      if(memcmp(PIC(depositSelectorBytes), state->selector_state.buf, 4))
        REJECT("unsupported assetCall selector");

      PRINTF("Selector %.*h\n", 4, state->selector_state.buf);

      state->state++;
      if (expectingDeposit) {
        if(ADD_ACCUM_PROMPT("Deposit", output_assetCall_prompt_to_string))
          return PARSE_RV_PROMPT;
      }

    case ASSETCALL_DONE:
      return PARSE_RV_DONE;
    }
}
