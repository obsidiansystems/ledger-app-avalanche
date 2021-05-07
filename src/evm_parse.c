#include "cb58.h"
#include "exception.h"
#include "globals.h"
#include "parser.h"
#include "protocol.h"
#include "to_string.h"
#include "types.h"
#include "evm_abi.h"

#define ETHEREUM_ADDRESS_SIZE 20
#define ETHEREUM_SELECTOR_SIZE 4
#define ETHEREUM_WORD_SIZE 32

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

#define ADD_ACCUM_PROMPT_ABI(label_, to_string_) ({                     \
      if (meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries)) THROW_(EXC_MEMORY_ERROR, "Tried to add a prompt to full queue"); \
      meta->prompt.labels[meta->prompt.count] = label_;                 \
      meta->prompt.entries[meta->prompt.count].to_string = to_string_;  \
      meta->prompt.count++;                                             \
      should_flush(meta->prompt);                                       \
    })

#define ADD_ACCUM_PROMPT(label_, to_string_) \
  ADD_ACCUM_PROMPT_ABI(PROMPT(label_), to_string_)

#define ADD_PROMPT(label_, data_, size_, to_string_) ({\
    SET_PROMPT_VALUE(memcpy(&entry->data, data_, size_));\
    ADD_ACCUM_PROMPT(label_, to_string_);\
    })

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW_(EXC_PARSE_ERROR, "Rejected"); }

static void setup_prompt_evm_address(uint8_t *buffer, output_prompt_t *const prompt) {
  size_t padding = ETHEREUM_WORD_SIZE - ETHEREUM_ADDRESS_SIZE;
  memcpy(prompt->address.val, &buffer[padding], ETHEREUM_ADDRESS_SIZE);
}
static void setup_prompt_evm_amount(uint8_t *buffer, output_prompt_t *const prompt) {
  readu256BE(buffer, &prompt->amount_big);
}
static void setup_prompt_evm_bytes32(uint8_t *buffer, output_prompt_t *const prompt) {
  memcpy(prompt->bytes32, buffer, 32);
}

static size_t output_hex_to_string(char *const out, size_t const out_size, output_prompt_t const *const in, size_t in_size) {
  size_t ix = 0;
  out[ix] = '0'; ix++;
  out[ix] = 'x'; ix++;
  bin_to_hex_lc(&out[ix], out_size - ix, in, in_size);
  ix += 2 * in_size;
  return ix;
}

static void output_evm_calldata_preview_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  size_t ix = output_hex_to_string(out, out_size, &in->calldata_preview.buffer, in->calldata_preview.count);
  if(in->calldata_preview.cropped) {
    if (ix + 3 > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit into prompt value string");
    out[ix] = '.'; ix++;
    out[ix] = '.'; ix++;
    out[ix] = '.'; ix++;
  }
  out[ix] = '\0';
}

static void output_evm_gas_limit_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  number_to_string(out, in->start_gas);
}
static void output_evm_amount_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  wei_to_gwei_string256(out, out_size, &in->amount_big);
}
static void output_evm_fee_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  wei_to_gwei_string(out, out_size, in->fee);
}
static void output_evm_fund_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  wei_to_navax_string_256(out, out_size, &in->amount_big);
}
static void output_evm_address_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  output_hex_to_string(out, out_size, &in->address.val, ETHEREUM_ADDRESS_SIZE);
}
static void output_evm_bytes32_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  output_hex_to_string(out, out_size, in->bytes32, 32);
}

static void output_evm_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
    size_t ix = wei_to_navax_string_256(out, out_size, &in->amount_big);

    static char const to[] = " to ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    output_evm_address_to_string(&out[ix], out_size - ix, in);
}

static void output_assetCall_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
  size_t ix = 0;

  out[ix] = '0'; ix++;
  out[ix] = 'x'; ix++;
  if(zero256(&in->assetCall.amount)) {
    out[ix] = '0'; ix++;
  } else {
    size_t res = tostring256(&in->assetCall.amount, 16, &out[ix], out_size - ix);
    if (res == (size_t)(-1))
      REJECT("Failed to render amount");
    ix += res;
  }

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

  output_evm_address_to_string(&out[ix], out_size - ix, in);
}

enum parse_rv parse_rlp_item(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta);
enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta);
enum parse_rv parse_rlp_item_data(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta);

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

void init_abi_call_data(struct EVM_ABI_state *const state, uint64_t length);
enum parse_rv parse_abi_call_data(struct EVM_ABI_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta, bool hasValue);

uint64_t enforceParsedScalarFits64Bits(struct EVM_RLP_item_state *const state) {
  uint64_t value = 0;
  if(state->length > sizeof(uint64_t))
    REJECT("Can't support > 64-bit large numbers (yet)");
  for(size_t i = 0; i < state->length; i++)
    ((uint8_t*)(&value))[i] = state->buffer[state->length-i-1];
  return value;
}

uint256_t enforceParsedScalarFits256Bits(struct EVM_RLP_item_state *const state) {
  uint256_t value = {{ {{ 0, 0 }}, {{ 0, 0 }} }};
  if(state->length > sizeof(uint256_t))
    REJECT("Can't support > 256-bit large numbers (yet)");
  for(size_t i = 0; i < state->length; i++) {
    const size_t numSuperWords = 2;
    const size_t numWords = 2;
    size_t superWord = numSuperWords - 1 - i / 16;
    size_t word = numWords - 1 - (i % 16) / 8;
    size_t byte = (i % 16) % 8;
    ((uint8_t *)&(value.elements[superWord].elements[word]))[byte] = state->buffer[state->length - 1 - i];
  }
  return value;
}

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
                sub_rv = parse_rlp_item ## save(state, meta); \
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
            uint64_t gasPrice = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            size_t gasPriceLength = state->rlpItem_state.length;
            state->gasPrice = gasPrice;
            FINISH_ITEM_CHUNK();

            PARSE_ITEM(EVM_TXN_STARTGAS, _to_buffer);
            uint64_t startGas = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            size_t startGasLength = state->rlpItem_state.length;
            state->startGas = startGas;
            // TODO: We don't currently support the C-chain gas limit of 100 million,
            // which would have a fee larger than what fits in a word
            if(gasPriceLength + startGasLength > 8)
              REJECT("Fee too large");
            FINISH_ITEM_CHUNK();

            PARSE_ITEM(EVM_TXN_TO, _to_buffer);

            switch (state->rlpItem_state.length) {
            case 0:
              state->hasTo = false;
              break;
            case ETHEREUM_ADDRESS_SIZE:
              state->hasTo = true;
              break;
            default:
              REJECT("When present, destination address must have exactly %u bytes", ETHEREUM_ADDRESS_SIZE);
            }

            if(state->hasTo) {
              for(size_t i = 0; i < NUM_ELEMENTS(precompiled); i++) {
                if(!memcmp(precompiled[i].to, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE)) {
                  meta->known_destination = &precompiled[i];
                  break;
                }
              }
              if(!meta->known_destination)
                SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE));
              FINISH_ITEM_CHUNK();
            }
            else {
              FINISH_ITEM_CHUNK();
              static char const label []="Creation";
              set_next_batch_size(&meta->prompt, 2);
              if(({
                  ADD_PROMPT("Contract", label, sizeof(label), strcpy_prompt);
                  SET_PROMPT_VALUE(entry->data.output_prompt.start_gas = state->startGas);
                  ADD_ACCUM_PROMPT("Gas Limit", output_evm_gas_limit_to_string);
                }))
                return PARSE_RV_PROMPT;
            }

            PARSE_ITEM(EVM_TXN_VALUE, _to_buffer);

            state->value = enforceParsedScalarFits256Bits(&state->rlpItem_state);
            SET_PROMPT_VALUE(entry->data.output_prompt.amount_big = state->value);

            FINISH_ITEM_CHUNK();

            if(state->hasTo) {
              // As of now, there is no known reason to send AVAX to any precompiled contract we support
              // Given that, we take the less risky action with the intent of protecting from unintended transfers
              if(meta->known_destination) {
                if (!zero256(&state->value))
                  REJECT("Transactions sent to precompiled contracts must have an amount of 0 WEI");
              }
            } else {
              if(!zero256(&state->value))
                if(ADD_ACCUM_PROMPT("Funding Contract", output_evm_fund_to_string)) return PARSE_RV_PROMPT;
            }

            PARSE_ITEM(EVM_TXN_DATA, _data);

            // If data field can't possibly fit in the transaction, the rlp is malformed
            if(state->rlpItem_state.len_len > state->remaining)
              REJECT("Malformed data length. Expected length of length %u", state->rlpItem_state.len_len);

            // If we exhaust the apdu while parsing the length, there's nothing yet to hand to the subparser
            if(state->rlpItem_state.state < 2)
              return sub_rv;

            if(state->hasTo) {
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
              }
              else {
                struct EVM_RLP_item_state *const item_state = &state->rlpItem_state;
                struct EVM_ABI_state *const abi_state = &item_state->endpoint_state.abi_state;
                if(item_state->do_init)
                  init_abi_call_data(abi_state, item_state->length);

                if(abi_state->data_length == 0) {
                  sub_rv = PARSE_RV_DONE;
                  state->item_index++;
                  init_rlp_item(&state->rlpItem_state);
                  ADD_ACCUM_PROMPT("Transfer", output_evm_prompt_to_string);
                  return PARSE_RV_PROMPT;
                }
                else {
                  sub_rv = parse_abi_call_data(abi_state,
                                               &item_state->chunk,
                                               meta,
                                               !zero256(&state->value));
                }
              }
            }

            // Can't use the macro here because we need to do a prompt in the middle of it.
            if(sub_rv != PARSE_RV_DONE) return sub_rv;
            state->item_index++;
            uint64_t len = state->rlpItem_state.length;
            if(!state->hasTo) {
              SET_PROMPT_VALUE(entry->data.output_prompt.calldata_preview.cropped = len > MAX_CALLDATA_PREVIEW);
              SET_PROMPT_VALUE(entry->data.output_prompt.calldata_preview.count = MIN(len, (uint64_t)MAX_CALLDATA_PREVIEW));
              SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.calldata_preview.buffer,
                                      &state->rlpItem_state.buffer,
                                      entry->data.output_prompt.calldata_preview.count));
            }
            state->hasData = len > 0;
            init_rlp_item(&state->rlpItem_state);

            if(!state->hasTo) {
              if(ADD_ACCUM_PROMPT("Data", output_evm_calldata_preview_to_string))
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

            SET_PROMPT_VALUE(entry->data.output_prompt.fee = state->gasPrice * state->startGas);
            if(state->hasData) {
              if(ADD_ACCUM_PROMPT("Maximum Fee", output_evm_fee_to_string))
                return PARSE_RV_PROMPT;
            }
            else {
              if(ADD_ACCUM_PROMPT("Fee", output_evm_fee_to_string))
                return PARSE_RV_PROMPT;
            }

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

enum parse_rv impl_parse_rlp_item(struct EVM_RLP_item_state *const state, evm_parser_meta_state_t *const meta, size_t max_bytes_to_buffer) {
    enum parse_rv sub_rv;
    state->do_init = false;
    switch(state->state) {
      case 0: {
          if(meta->input.consumed >= meta->input.length) return PARSE_RV_NEED_MORE;
          uint8_t const* first_ptr = &meta->input.src[meta->input.consumed++];
          uint8_t first = *first_ptr;
          if(first <= 0x7f) {
              if(max_bytes_to_buffer) {
                state->buffer[0] = first;
                state->length = 1;
              }
              else {
                state->chunk.src = first_ptr;
                state->chunk.consumed = 0;
                state->chunk.length = 1;
              }
              return PARSE_RV_DONE;
          } else if (first < 0xb8) {
              state->length = first - 0x80;
              state->do_init = !max_bytes_to_buffer;
              state->state = 2;
          } else if (first < 0xc0) {
              state->len_len = first - 0xb7;
              state->state = 1;
          } else if(first < 0xf8) {
              state->length = first - 0xc0;
              state->do_init = !max_bytes_to_buffer;
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
        if(max_bytes_to_buffer) {
          if(MIN(state->length, max_bytes_to_buffer) > NUM_ELEMENTS(state->buffer)) REJECT("RLP field too large for buffer");
        }

        state->do_init = !max_bytes_to_buffer;
        state->state = 2;
      case 2: {
          uint64_t
            remaining = state->length-state->current,
            available = meta->input.length - meta->input.consumed,
            consumable = MIN(remaining, available),
            bufferable = MIN(state->length, max_bytes_to_buffer),
            unbuffered = MAX(0, (int64_t)bufferable - (int64_t)state->current);

          if(max_bytes_to_buffer)
            memcpy(state->buffer+state->current, meta->input.src + meta->input.consumed, MIN(consumable, unbuffered));
          else {
            if(state->chunk.consumed >= state->chunk.length) {
              state->chunk.src=&meta->input.src[meta->input.consumed];
              state->chunk.consumed = 0;
              state->chunk.length = consumable;
            }
          }

          meta->input.consumed += consumable;
          state->current += consumable;

          if(remaining <= available) {
            state->state = 3;
            return PARSE_RV_DONE;
          } else {
            return PARSE_RV_NEED_MORE;
          }
      }
    }
    return sub_rv;
}

enum parse_rv parse_rlp_item(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, 0);
}

enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, NUM_ELEMENTS(state->rlpItem_state.buffer));
}
enum parse_rv parse_rlp_item_data(struct EVM_RLP_list_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, state->hasTo ? 0 : MAX_CALLDATA_PREVIEW);
}

IMPL_FIXED(uint256_t);

#define ASSETCALL_FIXED_DATA_WIDTH (20 + 32 + 32)

void init_assetCall_data(struct EVM_assetCall_state *const state, uint64_t length) {
    state->state = 0;
    PRINTF("Initing assetCall Data\n");
    if(length < ASSETCALL_FIXED_DATA_WIDTH)
      REJECT("Calldata too small for assetCall");
    state->data_length = length - ASSETCALL_FIXED_DATA_WIDTH;
    initFixed(&state->address_state.fixedState, sizeof(state->address_state));
    PRINTF("Initing assetCall Data\n");
}

void init_abi_call_data(struct EVM_ABI_state *const state, uint64_t length) {
  state->state = ABISTATE_SELECTOR;
  state->argument_index = 0;
  state->data_length = length;
  initFixed(&state->argument_state.fixedState, sizeof(state->argument_state));
}

enum parse_rv parse_abi_call_data(struct EVM_ABI_state *const state,
                                  parser_input_meta_state_t *const input,
                                  evm_parser_meta_state_t *const meta,
                                  bool hasValue) {
  if(state->data_length < ETHEREUM_SELECTOR_SIZE) REJECT("When present, calldata must have at least %u bytes", ETHEREUM_SELECTOR_SIZE);

  enum parse_rv sub_rv;
  switch(state->state) {
  case ABISTATE_SELECTOR: {
    sub_rv = parseFixed(&state->selector_state.fixedState, input, ETHEREUM_SELECTOR_SIZE);
    if(sub_rv != PARSE_RV_DONE) return sub_rv;
    for(size_t i = 0; i < NUM_ELEMENTS(known_endpoints); i++) {
      if(!memcmp(&known_endpoints[i].selector, state->selector_state.buf, ETHEREUM_SELECTOR_SIZE)) {
        meta->known_endpoint = &known_endpoints[i];
        break;
      }
    }

    if(meta->known_endpoint) {
      state->state = ABISTATE_ARGUMENTS;
      initFixed(&state->argument_state.fixedState, sizeof(state->argument_state));
      if(hasValue) REJECT("No currently supported methods are marked as 'payable'");
      char *method_name = PIC(meta->known_endpoint->method_name);
      ADD_PROMPT("Contract Call", method_name, strlen(method_name), strcpy_prompt);
    } else {
      state->state = ABISTATE_UNRECOGNIZED;
      ADD_ACCUM_PROMPT("Transfer", output_evm_prompt_to_string);
    }

    return PARSE_RV_PROMPT;
  }

  case ABISTATE_ARGUMENTS: {
    if(state->argument_index >= meta->known_endpoint->parameters_count)
      return PARSE_RV_DONE;
    sub_rv = parseFixed(&state->argument_state.fixedState, input, ETHEREUM_WORD_SIZE); // TODO: non-word size values
    if(sub_rv != PARSE_RV_DONE) return sub_rv;
    const struct contract_endpoint_param parameter = meta->known_endpoint->parameters[state->argument_index++];
    char *argument_name = PIC(parameter.name);
    void (*setup_prompt)(uint8_t *buffer, output_prompt_t const *const prompt) = PIC(parameter.setup_prompt);
    SET_PROMPT_VALUE(setup_prompt(((struct FixedState*)(&state->argument_state))->buffer,
                                  &entry->data.output_prompt));
    initFixed(&state->argument_state.fixedState, sizeof(state->argument_state));
    ADD_ACCUM_PROMPT_ABI(argument_name, PIC(parameter.output_prompt));
    return PARSE_RV_PROMPT;
  }

  // Probably we have to allow this, as the metamask constraint means _this_ endpoint will be getting stuff it doesn't understand a lot.
  case ABISTATE_UNRECOGNIZED: {
    sub_rv = skipBytes(&state->argument_state.fixedState, input, state->data_length);
    if(sub_rv != PARSE_RV_DONE) return sub_rv;
    state->state = ABISTATE_DONE;
    static char const isPresentLabel[]="Is Present (unsafe)";
    ADD_PROMPT("Contract Data", isPresentLabel, sizeof(isPresentLabel), strcpy_prompt);
    return PARSE_RV_PROMPT;
  }

  case ABISTATE_DONE:
    return PARSE_RV_DONE;
  }
}

enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv;
    bool expectingDeposit = state->data_length > 0;

    PRINTF("AssetCall Data: %.*h\n", input->length, input->src);
    PRINTF("expectingDeposit: %u, input length %u, state->data_length %.*h\n", expectingDeposit, input->length, 8, &state->data_length);
    PRINTF("state: %u\n", state->state);
    switch(state->state) {
    case ASSETCALL_ADDRESS:
      sub_rv = parseFixed(&state->address_state.fixedState, input, ETHEREUM_ADDRESS_SIZE);
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->address_state.buf, ETHEREUM_ADDRESS_SIZE));
      PRINTF("Address: %.*h\n", ETHEREUM_ADDRESS_SIZE, state->address_state.buf);
      state->state++;
      initFixed(&state->id32_state.fixedState, sizeof(state->id32_state));
    case ASSETCALL_ASSETID:
      sub_rv = parseFixed(&state->id32_state.fixedState, input, sizeof(Id32));
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(memcpy(&entry->data.output_prompt.assetCall.assetID, state->id32_state.buf, sizeof(uint256_t)));
      PRINTF("Asset: %.*h\n", 32, state->id32_state.buf);
      state->state++;
      initFixed(&state->uint256_state.fixedState, sizeof(state->uint256_state));
    case ASSETCALL_AMOUNT:
      sub_rv = parseFixed(&state->uint256_state.fixedState, input, sizeof(uint256_t));
      if(sub_rv != PARSE_RV_DONE) return sub_rv;
      SET_PROMPT_VALUE(readu256BE(state->uint256_state.buf, &entry->data.output_prompt.assetCall.amount));
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
      initFixed(&state->selector_state.fixedState, sizeof(state->selector_state));
    case ASSETCALL_DATA:
      sub_rv = parseFixed(&state->selector_state.fixedState, input, 4);
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
