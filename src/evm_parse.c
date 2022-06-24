#include "cb58.h"
#include "exception.h"
#include "globals.h"
#include "evm_parse.h"
#include "parser-impl.h"
#include "protocol.h"
#include "to_string.h"
#include "types.h"
#include "evm_abi.h"

#define ETHEREUM_ADDRESS_SIZE 20
#define ETHEREUM_SELECTOR_SIZE 4
#define ETHEREUM_WORD_SIZE 32

void init_rlp_list(struct EVM_RLP_txn_state *const state) {
    memset(state, 0, sizeof(*state)); // sizeof == 224UL
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
      if (should_flush(&meta->prompt)) {                                \
        sub_rv = PARSE_RV_PROMPT;                                       \
      }                                                                 \
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

static size_t output_hex_to_string(
  char out[const], size_t const out_size,
  uint8_t const in[const], size_t in_size)
{
  size_t ix = 0;
  out[ix] = '0'; ix++;
  out[ix] = 'x'; ix++;
  bin_to_hex_lc(&out[ix], out_size - ix, in, in_size);
  ix += 2 * in_size;
  return ix;
}

static void output_evm_calldata_preview_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  size_t ix = output_hex_to_string(
    out, out_size,
    // [0] aids in array pointer decay
    &in->calldata_preview.buffer[0], in->calldata_preview.count);
  if(in->calldata_preview.cropped) {
    if (ix + 3 > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit into prompt value string");
    out[ix] = '.'; ix++;
    out[ix] = '.'; ix++;
    out[ix] = '.'; ix++;
  }
  out[ix] = '\0';
}

static void output_evm_gas_limit_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  (void)out_size;
  number_to_string(out, in->start_gas);
}

static void output_evm_amount_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  wei_to_gwei_string_256(out, out_size, &in->amount_big);
}

static void output_evm_fee_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  wei_to_gwei_string(out, out_size, in->fee);
}

static void output_evm_fund_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  wei_to_avax_or_navax_string_256(out, out_size, &in->amount_big);
}

#define output_hex_to_string_size(out, out_size, in) \
  /* [0] aids in array pointer decay */ \
  output_hex_to_string(out, out_size, &in[0], sizeof(in))

static void output_evm_address_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  output_hex_to_string_size(out, out_size, in->address.val);
}

static void output_evm_bytes32_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
  output_hex_to_string_size(out, out_size, in->bytes32);
}

static void output_evm_prompt_to_string(
    char out[const], size_t const out_size, output_prompt_t const *const in) {
    size_t ix = wei_to_avax_or_navax_string_256(out, out_size, &in->amount_big);

    static char const to[] = " to ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    output_evm_address_to_string(&out[ix], out_size - ix, in);
}

static void output_assetCall_prompt_to_string(
  char out[const], size_t const out_size,
  output_prompt_t const *const in)
{
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

enum parse_rv parse_rlp_item(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta);
enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta);
enum parse_rv parse_rlp_item_data(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta);

enum eth_legacy_txn_items {
  EVM_LEGACY_TXN_NONCE,
  EVM_LEGACY_TXN_GASPRICE,
  EVM_LEGACY_TXN_STARTGAS,
  EVM_LEGACY_TXN_TO,
  EVM_LEGACY_TXN_VALUE,
  EVM_LEGACY_TXN_DATA,
  EVM_LEGACY_TXN_CHAINID,
  EVM_LEGACY_TXN_SIG_R,
  EVM_LEGACY_TXN_SIG_S
};

enum eth_eip1559_txn_items {
  EVM_EIP1559_TXN_CHAINID,
  EVM_EIP1559_TXN_NONCE,
  EVM_EIP1559_TXN_MAX_PRIORITY_FEE_PER_GAS,
  EVM_EIP1559_TXN_MAX_FEE_PER_GAS,
  EVM_EIP1559_TXN_GAS_LIMIT,
  EVM_EIP1559_TXN_TO,
  EVM_EIP1559_TXN_VALUE,
  EVM_EIP1559_TXN_DATA,
  EVM_EIP1559_TXN_ACCESS_LIST
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


const uint8_t EIP1559_TYPE_VALUE = 0x02;

void checkDataFieldLengthFitsTransaction(struct EVM_RLP_txn_state *const state) {
  // If data field can't possibly fit in the transaction, the rlp is malformed
  if(state->rlpItem_state.len_len > state->remaining)
    REJECT("Malformed data length. Expected length of length %u", state->rlpItem_state.len_len);
}

enum parse_rv parse_evm_txn(struct EVM_txn_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
      case 0: {
        sub_rv = parse_core_uint8_t(&state->transaction_envelope_type, &meta->input);
        RET_IF_NOT_DONE;
        if (state->transaction_envelope_type.val == EIP1559_TYPE_VALUE) {
          state->type = EIP1559;
          init_rlp_list(&state->txn_state); // could technically be a different init in each case, so we repeat ourselves
        } else {
          state->type = LEGACY;
          init_rlp_list(&state->txn_state); // could technically be a different init in each case, so we repeat ourselves
          // we consumed a byte that the Legacy parser was expecting, so decrement before legacy parser begins
          if (meta->input.consumed < 1) {
            REJECT("a byte was consumed but this was not reflected in the \"input consumed bytes\" counter") // should be impossible
          }
          meta->input.consumed--;
        }
        state->state++;
      } fallthrough;
      case 1: {
        switch (state->type) {
          case EIP1559: {
            sub_rv = parse_eip1559_rlp_txn(&state->txn_state, meta);
            RET_IF_NOT_DONE;
            break;
          }
          case LEGACY: {
            sub_rv = parse_legacy_rlp_txn(&state->txn_state, meta);
            RET_IF_NOT_DONE;
            break;
          }
        } // end switch state->type
      }
    } // end switch state->state
    return sub_rv;
}

void init_evm_txn(struct EVM_txn_state *const state) {
  state->state = 0;
  init_uint8_t(&state->transaction_envelope_type);
}

#define PARSE_ITEM(ITEM, save) \
  /* NOTE! */                  \
  fallthrough;                 \
  PARSE_ITEM_FIRST(ITEM, save)

// No fallthrough, so we don't get warning
#define PARSE_ITEM_FIRST(ITEM, save)                         \
  case ITEM:                                                 \
  JUST_PARSE_ITEM(ITEM, save)

#define JUST_PARSE_ITEM(ITEM, save)                          \
  {                                                          \
    itemStartIdx = meta->input.consumed;                     \
    PRINTF("Entering " #ITEM "\n");                          \
    sub_rv = parse_rlp_item ## save(state, meta);            \
    PRINTF("Exiting " #ITEM "\n");                           \
    size_t to_sub = meta->input.consumed - itemStartIdx;     \
    if (to_sub > state->remaining) {                         \
      REJECT(                                                \
        "consumed too much parsing item: remaining: %d, this item: %d", \
        state->remaining, to_sub); \
    } \
    state->remaining -= to_sub;                              \
  } (void)0

#define ITEM_ADVANCE                                         \
  PRINTF("Getting ready to advance to next item\n");         \
  state->item_index++;                                       \
  state->per_item_prompt = 0

#define FINISH_ITEM_CHUNK()                                  \
  ITEM_ADVANCE;                                              \
  init_rlp_item(&state->rlpItem_state);

void parse_value_from_txn(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
  state->value = enforceParsedScalarFits256Bits(&state->rlpItem_state);
  SET_PROMPT_VALUE(entry->data.output_prompt.amount_big = state->value);
}

static inline void check_whether_has_calldata(struct EVM_RLP_txn_state *const state) {
  uint64_t len = state->rlpItem_state.length;
  state->hasData = len > 0;
}

void prompt_calldata_preview(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
  uint64_t len = state->rlpItem_state.length;
  SET_PROMPT_VALUE(entry->data.output_prompt.calldata_preview.cropped = len > MAX_CALLDATA_PREVIEW);
  SET_PROMPT_VALUE(entry->data.output_prompt.calldata_preview.count = MIN(len, (uint64_t)MAX_CALLDATA_PREVIEW));
  SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.calldata_preview.buffer,
                          &state->rlpItem_state.buffer,
                          entry->data.output_prompt.calldata_preview.count));
}

enum parse_rv parse_legacy_rlp_txn(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch(state->state) {
      case 0: {
          // cautionary, shouldn't reach greater than
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
        fallthrough; // NOTE
      case 1:
        if(state->state==1) {
            // Max length we could get for this value is 8 bytes so uint64_state is appropriate.
            sub_rv = parseFixed(fs(&state->uint64_state), &meta->input, state->len_len);
            RET_IF_NOT_DONE;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[state->len_len-i-1];
            }
        }
        init_rlp_item(&state->rlpItem_state);
        state->state = 2;
        fallthrough; // NOTE
      case 2: { // Now parse items.
          uint8_t itemStartIdx;
          size_t gasPriceLength = 0;
          switch(state->item_index) {

            //
            PARSE_ITEM_FIRST(EVM_LEGACY_TXN_NONCE, );
            RET_IF_NOT_DONE;
            //

            FINISH_ITEM_CHUNK();

            //TODO: now that there's 256 bit support,
            // rather than enforcing the length requirement,
            // the below code block could instead load the values into
            // 256 bit values before multiplication.
            // Getting rid of the intermediate lengths would also allow
            // sharing the code between PARSE_ITEM and FINISH_ITEM_CHUNK
            // between legacy and non-legacy transaction parsers.
            PARSE_ITEM(EVM_LEGACY_TXN_GASPRICE, _to_buffer);
            RET_IF_NOT_DONE;
            //

            uint64_t gasPrice = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            gasPriceLength = state->rlpItem_state.length;
            state->priorityFeePerGas = gasPrice;
            FINISH_ITEM_CHUNK();

            //
            PARSE_ITEM(EVM_LEGACY_TXN_STARTGAS, _to_buffer);
            RET_IF_NOT_DONE;
            //

            uint64_t gasLimit = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            size_t gasLimitLength = state->rlpItem_state.length;
            state->gasLimit = gasLimit;
            // TODO: We don't currently support the C-chain gas limit of 100 million,
            // which would have a fee larger than what fits in a word
            if(gasPriceLength + gasLimitLength > 8)
              REJECT("Fee too large");
            FINISH_ITEM_CHUNK();

            //
            fallthrough;
          case EVM_LEGACY_TXN_TO: {
            //

            switch (state->per_item_prompt) {

            case 0:
              JUST_PARSE_ITEM(EVM_LEGACY_TXN_TO, _to_buffer);
              RET_IF_NEED_MORE;
              state->per_item_prompt++;
              RET_IF_PROMPT_FLUSH;
              fallthrough;

            case 1:
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
              } else {
                static char const label []="Creation";
                ADD_PROMPT("Contract", label, sizeof(label), strcpy_prompt);
              }
              state->per_item_prompt++;
              RET_IF_PROMPT_FLUSH;
              fallthrough;

            case 2:
              if (!state->hasTo) {
                SET_PROMPT_VALUE(entry->data.output_prompt.start_gas = state->gasLimit);
                ADD_ACCUM_PROMPT("Gas Limit", output_evm_gas_limit_to_string);
              }
            }

            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;
          }

            //
            PARSE_ITEM(EVM_LEGACY_TXN_VALUE, _to_buffer);
            RET_IF_NOT_DONE;
            //

            parse_value_from_txn(state, meta);

            if(state->hasTo) {
              // As of now, there is no known reason to send AVAX to any precompiled contract we support
              // Given that, we take the less risky action with the intent of protecting from unintended transfers
              if(meta->known_destination) {
                if (!zero256(&state->value))
                  REJECT("Transactions sent to precompiled contracts must have an amount of 0 WEI");
              }
            } else {
              if (!zero256(&state->value)) {
                ADD_ACCUM_PROMPT("Funding Contract", output_evm_fund_to_string);
              }
            }

            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;

            //
            fallthrough;
          case EVM_LEGACY_TXN_DATA: {
            // Instead of waiting for a complete item parse, do some of the
            // actions below every time.
            //

            switch (state->per_item_prompt) {
            case 0:
              state->item_rv = PARSE_RV_INVALID;
              state->sort = TXN_DATA_UNSET;
              JUST_PARSE_ITEM(EVM_LEGACY_TXN_DATA, _data);
              state->item_rv = sub_rv;
              sub_rv = PARSE_RV_INVALID;
              state->per_item_prompt++;
              fallthrough;
            case 1:
              // Only continue if the initial parse got sufficiently far.
              checkDataFieldLengthFitsTransaction(state);
              if (state->rlpItem_state.state < 2) {
                state->per_item_prompt = 0;
                return state->item_rv;
              }

              check_whether_has_calldata(state);

              if (state->sort == TXN_DATA_UNSET) {
                if(state->hasTo) {
                  if(meta->known_destination) {
                    state->sort = TXN_DATA_CONTRACT_CALL_KNOWN_DEST;
                  } else {
                    if (state->hasData)
                      state->sort = TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST;
                    else {
                      state->sort = TXN_DATA_PLAIN_TRANSFER;
                    }
                  }
                } else {
                  state->sort = TXN_DATA_DEPLOY;
                }
              }

              state->per_item_prompt++;
              fallthrough;
            case 2:

              switch (state->sort) {
              case TXN_DATA_UNSET:
                REJECT("should be known by now");

              case TXN_DATA_CONTRACT_CALL_KNOWN_DEST: {
                struct EVM_RLP_item_state *const item_state = &state->rlpItem_state;
                if(item_state->do_init && meta->known_destination->init_data) {
                  PIC(meta->known_destination->init_data)(
                    &item_state->endpoint_state,
                    item_state->length);
                  item_state->do_init = false;
                }
                PRINTF("INIT: %u\n", item_state->do_init);
                PRINTF("Chunk: [%u] %.*h\n",
                  item_state->chunk.length,
                  item_state->chunk.length, item_state->chunk.src);
                if(meta->known_destination->handle_data) {
                  sub_rv = PIC(meta->known_destination->handle_data)(
                    &item_state->endpoint_state,
                    &item_state->chunk,
                    meta);
                }
                break;
              }

              case TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST: {
                struct EVM_RLP_item_state *const item_state = &state->rlpItem_state;
                struct EVM_ABI_state *const abi_state = &item_state->endpoint_state.abi_state;
                if(item_state->do_init) {
                  init_abi_call_data(abi_state, item_state->length);
                  item_state->do_init = false;
                }

                sub_rv = parse_abi_call_data(
                  abi_state,
                  &item_state->chunk,
                  meta,
                  !zero256(&state->value));
                break;
              }

              case TXN_DATA_DEPLOY:
              case TXN_DATA_PLAIN_TRANSFER:
                // Nothing to do each parse
                break;
              }

              // At this point we are longer doing *per* chunk work, but back to
              // the usual case of just doing itmes after the parse before has
              // completed.
              if (sub_rv == PARSE_RV_PROMPT) {
                // DON'T reset per_item_prompt;
                return PARSE_RV_PROMPT;
              } else if (sub_rv == PARSE_RV_NEED_MORE) {
                state->per_item_prompt = 0;
                return PARSE_RV_NEED_MORE;
              } else if (state->item_rv == PARSE_RV_PROMPT) {
                state->per_item_prompt = 3; // Advance to next step!
                return PARSE_RV_PROMPT;
              } else if (state->item_rv == PARSE_RV_NEED_MORE) {
                state->per_item_prompt = 0;
                return PARSE_RV_NEED_MORE;
              }

              state->per_item_prompt++;
              fallthrough;
            case 3:
              switch (state->sort) {
              case TXN_DATA_UNSET:
                REJECT("should be known by now");

              case TXN_DATA_PLAIN_TRANSFER: {
                ADD_ACCUM_PROMPT("Transfer", output_evm_prompt_to_string);
                break;
              }

              case TXN_DATA_DEPLOY: {
                prompt_calldata_preview(state, meta);
                ADD_ACCUM_PROMPT("Data", output_evm_calldata_preview_to_string);
                break;
              }

              default:
                break;
              }

              FINISH_ITEM_CHUNK();
              RET_IF_PROMPT_FLUSH;
            }
          }

            //
            PARSE_ITEM(EVM_LEGACY_TXN_CHAINID, _to_buffer);
            RET_IF_NOT_DONE;
            //

            meta->chainIdLowByte = state->rlpItem_state.buffer[state->rlpItem_state.length-1];
            PRINTF("Chain ID low byte: %x\n", meta->chainIdLowByte);

            SET_PROMPT_VALUE(entry->data.output_prompt.fee = state->priorityFeePerGas * state->gasLimit);
            if(state->hasData) {
              ADD_ACCUM_PROMPT("Maximum Fee", output_evm_fee_to_string);
            }
            else {
              ADD_ACCUM_PROMPT("Fee", output_evm_fee_to_string);
            }

            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;

            //
            PARSE_ITEM(EVM_LEGACY_TXN_SIG_R, _to_buffer);
            RET_IF_NOT_DONE;
            //

            if(state->rlpItem_state.length != 0) REJECT("R value must be 0 for signing with EIP-155.");

            FINISH_ITEM_CHUNK();

            //
            PARSE_ITEM(EVM_LEGACY_TXN_SIG_S, _to_buffer);
            RET_IF_NOT_DONE;
            //

            if(state->rlpItem_state.length != 0) REJECT("S value must be 0 for signing with EIP-155.");
            FINISH_ITEM_CHUNK();
          }

          if(state->remaining == 0) {
              state->state = 3;
              return PARSE_RV_DONE;
          } else {
              REJECT("Reported total size of transaction did not match sum of pieces, remaining: %d", state->remaining);
          }
      }
      case 3:
        sub_rv = PARSE_RV_DONE;
        return sub_rv;
      default:
        REJECT("Transaction parser in supposedly unreachable state");
    }
    return sub_rv;
}

enum parse_rv parse_eip1559_rlp_txn(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
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
        fallthrough;
      case 1:
        if(state->state==1) {
            // Max length we could get for this value is 8 bytes so uint64_state is appropriate.
            sub_rv = parseFixed(fs(&state->uint64_state), &meta->input, state->len_len);
            RET_IF_NOT_DONE;
            for(size_t i = 0; i < state->len_len; i++) {
                ((uint8_t*)(&state->remaining))[i] = state->uint64_state.buf[state->len_len-i-1];
            }
        }
        init_rlp_item(&state->rlpItem_state);
        state->state = 2;
        fallthrough;
      case 2: { // Now parse items.
          uint8_t itemStartIdx;
          switch(state->item_index) {
            //
            PARSE_ITEM_FIRST(EVM_EIP1559_TXN_CHAINID, _to_buffer);
            RET_IF_NOT_DONE;
            //

            if(state->rlpItem_state.length != 2
               || state->rlpItem_state.buffer[0] != 0xa8
               || (state->rlpItem_state.buffer[1] != 0x68
                   && state->rlpItem_state.buffer[1] != 0x69
                   && state->rlpItem_state.buffer[1] != 0x6a))
                REJECT("Chain ID incorrect for the Avalanche C chain");
            meta->chainIdLowByte = 0; // explicitly clear chain ID low byte for EIP1559 transactions - only legacy transactions needed to include it

            FINISH_ITEM_CHUNK();

            //
            PARSE_ITEM(EVM_EIP1559_TXN_NONCE, );
            RET_IF_NOT_DONE;
            //

            FINISH_ITEM_CHUNK();

            //TODO: now that there's 256 bit support,
            // rather than enforcing the length requirement,
            // the below code block could instead load the values into
            // 256 bit values before multiplication.
            // Getting rid of the intermediate lengths would also allow
            // sharing the code between PARSE_ITEM and FINISH_ITEM_CHUNK
            // between legacy and non-legacy transaction parsers.
            PARSE_ITEM(EVM_EIP1559_TXN_MAX_PRIORITY_FEE_PER_GAS, _to_buffer);
            RET_IF_NOT_DONE;
            //
            uint64_t maxFeePerGas = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            state->priorityFeePerGas = maxFeePerGas;
            FINISH_ITEM_CHUNK();

            //
            PARSE_ITEM(EVM_EIP1559_TXN_MAX_FEE_PER_GAS, _to_buffer);
            RET_IF_NOT_DONE;
            //
            uint64_t baseFeePerGas = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            state->baseFeePerGas = baseFeePerGas;
            FINISH_ITEM_CHUNK();

            //
            PARSE_ITEM(EVM_EIP1559_TXN_GAS_LIMIT, _to_buffer);
            RET_IF_NOT_DONE;
            //
            uint64_t gasLimit = enforceParsedScalarFits64Bits(&state->rlpItem_state);
            state->gasLimit = gasLimit;

            {
              uint64_t feeDummy = 0;
              if(__builtin_mul_overflow(state->priorityFeePerGas + state->baseFeePerGas, state->gasLimit, &feeDummy))
                REJECT("Fee calculation overflowed");
            }

            FINISH_ITEM_CHUNK();

            //
            fallthrough;
          case EVM_EIP1559_TXN_TO:
            // Instead of waiting for a complete item parse, do some of the
            // actions below every time.
            //

            switch (state->per_item_prompt) {
            case 0:
              JUST_PARSE_ITEM(EVM_EIP1559_TXN_TO, _to_buffer);
              RET_IF_NEED_MORE;
              state->per_item_prompt++;
              RET_IF_PROMPT_FLUSH;
              fallthrough;
            case 1:
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
              state->per_item_prompt++;
              fallthrough;
            case 2:
              if(state->hasTo) {
                for(size_t i = 0; i < NUM_ELEMENTS(precompiled); i++) {
                  if(!memcmp(precompiled[i].to, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE)) {
                    meta->known_destination = &precompiled[i];
                    break;
                  }
                }
                if(!meta->known_destination)
                  SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->rlpItem_state.buffer, ETHEREUM_ADDRESS_SIZE));
              }
              else {
                static char const label []="Creation";
                ADD_PROMPT("Contract", label, sizeof(label), strcpy_prompt);
              }
              state->per_item_prompt++;
              RET_IF_PROMPT_FLUSH;
              fallthrough;
            case 3:
              if (!state->hasTo) {
                SET_PROMPT_VALUE(entry->data.output_prompt.start_gas = state->gasLimit);
                ADD_ACCUM_PROMPT("Gas Limit", output_evm_gas_limit_to_string);
              }
            }

            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;

            //
            PARSE_ITEM(EVM_EIP1559_TXN_VALUE, _to_buffer);
            RET_IF_NOT_DONE;
            //

            parse_value_from_txn(state, meta);

            if(state->hasTo) {
              // As of now, there is no known reason to send AVAX to any precompiled contract we support
              // Given that, we take the less risky action with the intent of protecting from unintended transfers
              if(meta->known_destination) {
                if (!zero256(&state->value))
                  REJECT("Transactions sent to precompiled contracts must have an amount of 0 WEI");
              }
            } else {
              if (!zero256(&state->value)) {
                ADD_ACCUM_PROMPT("Funding Contract", output_evm_fund_to_string);
              }
            }
            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;

            //
            fallthrough;
          case EVM_EIP1559_TXN_DATA: {
            // Instead of waiting for a complete item parse, do some of the
            // actions below every time.
            //

            switch (state->per_item_prompt) {
            case 0:
              state->item_rv = PARSE_RV_INVALID;
              state->sort = TXN_DATA_UNSET;
              JUST_PARSE_ITEM(EVM_EIP1559_TXN_DATA, _data);
              state->item_rv = sub_rv;
              sub_rv = PARSE_RV_INVALID;
              state->per_item_prompt++;
              fallthrough;
            case 1:
              // Only continue if the initial parse got sufficiently far.
              if (state->rlpItem_state.state < 2) {
                state->per_item_prompt = 0;
                return state->item_rv;
              }

              check_whether_has_calldata(state);

              if (state->sort == TXN_DATA_UNSET) {
                if(state->hasTo) {
                  if(meta->known_destination) {
                    state->sort = TXN_DATA_CONTRACT_CALL_KNOWN_DEST;
                  } else {
                    if (state->hasData)
                      state->sort = TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST;
                    else {
                      state->sort = TXN_DATA_PLAIN_TRANSFER;
                    }
                  }
                } else {
                  state->sort = TXN_DATA_DEPLOY;
                }
              }

              state->per_item_prompt++;
              fallthrough;
            case 2:

              switch (state->sort) {
              case TXN_DATA_UNSET:
                REJECT("should be known by now");

              case TXN_DATA_CONTRACT_CALL_KNOWN_DEST: {
                // state has To and the destination is known
                struct EVM_RLP_item_state *const item_state = &state->rlpItem_state;
                if (item_state->do_init && meta->known_destination->init_data) {
                  PIC(meta->known_destination->init_data)(
                    &item_state->endpoint_state,
                    item_state->length);
                  item_state->do_init = false;
                }
                PRINTF("INIT: %u\n", item_state->do_init);
                PRINTF("Chunk: [%u] %.*h\n", item_state->chunk.length, item_state->chunk.length, item_state->chunk.src);
                if(meta->known_destination->handle_data) {
                  PRINTF("HANDLING DATA\n");
                  sub_rv = PIC(meta->known_destination->handle_data)(
                    &item_state->endpoint_state,
                    &item_state->chunk,
                    meta);
                }
                PRINTF("PARSER CALLED [sub_rv: %u]\n", sub_rv);
                break;
              }
              case TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST: {
                struct EVM_RLP_item_state *const item_state = &state->rlpItem_state;
                struct EVM_ABI_state *const abi_state = &item_state->endpoint_state.abi_state;
                if(item_state->do_init) {
                  init_abi_call_data(abi_state, item_state->length);
                  item_state->do_init = false;
                }

                sub_rv = parse_abi_call_data(abi_state,
                                             &item_state->chunk,
                                             meta,
                                             !zero256(&state->value));
                PRINTF("PARSER CALLED [sub_rv: %u]\n", sub_rv);
                break;
              }

              case TXN_DATA_DEPLOY:
              case TXN_DATA_PLAIN_TRANSFER:
                // Nothing to do each parse
                break;
              }

              // At this point we are longer doing *per* chunk work, but back to
              // the usual case of just doing itmes after the parse before has
              // completed.
              if (sub_rv == PARSE_RV_PROMPT) {
                // DON'T reset per_item_prompt;
                return PARSE_RV_PROMPT;
              } else if (sub_rv == PARSE_RV_NEED_MORE) {
                state->per_item_prompt = 0;
                return PARSE_RV_NEED_MORE;
              } else if (state->item_rv == PARSE_RV_NEED_MORE) {
                state->per_item_prompt = 0;
                return PARSE_RV_NEED_MORE;
              } else if (state->item_rv == PARSE_RV_PROMPT) {
                // DON'T reset per_item_prompt;
                return PARSE_RV_PROMPT;
              }

              state->per_item_prompt++;
              fallthrough;
            case 3:

#             define CALC_FEE { \
                uint64_t feeDummy = 0; \
                __builtin_mul_overflow(state->priorityFeePerGas + state->baseFeePerGas, state->gasLimit, &feeDummy); \
                SET_PROMPT_VALUE(entry->data.output_prompt.fee = feeDummy); \
              }

              switch (state->sort) {
              case TXN_DATA_UNSET:
                REJECT("should be known by now");

              case TXN_DATA_PLAIN_TRANSFER: {
                ADD_ACCUM_PROMPT("Transfer", output_evm_prompt_to_string);
                break;
              }

              case TXN_DATA_DEPLOY: {
                prompt_calldata_preview(state, meta);
                ADD_ACCUM_PROMPT("Data", output_evm_calldata_preview_to_string);
                break;
              }

              default:
                break;
              }

              state->per_item_prompt++;
              RET_IF_PROMPT_FLUSH;
              fallthrough;
            case 4:

              switch (state->sort) {
              case TXN_DATA_UNSET:
                REJECT("should be known by now");

              case TXN_DATA_PLAIN_TRANSFER: {
                CALC_FEE;
                ADD_ACCUM_PROMPT("Fee", output_evm_fee_to_string);
                break;
              }

              case TXN_DATA_DEPLOY:
              case TXN_DATA_CONTRACT_CALL_KNOWN_DEST:
              case TXN_DATA_CONTRACT_CALL_UNKNOWN_DEST: {
                CALC_FEE;
                ADD_ACCUM_PROMPT("Maximum Fee", output_evm_fee_to_string);
                break;
              }
              }

            }

            FINISH_ITEM_CHUNK();
            RET_IF_PROMPT_FLUSH;
          }

            //
            PARSE_ITEM(EVM_EIP1559_TXN_ACCESS_LIST, );
            RET_IF_NOT_DONE;
            //

            // just ignore this access list
            FINISH_ITEM_CHUNK();
          }

          if(state->remaining == 0) {
              state->state = 3;
              return PARSE_RV_DONE;
          } else {
              REJECT("Reported total size of transaction did not match sum of pieces, remaining: %d", state->remaining);
          }
      }
      case 3:
        sub_rv = PARSE_RV_DONE;
        return sub_rv;
      default:
        REJECT("Transaction parser in supposedly unreachable state");
    }
    return sub_rv;
}

enum parse_rv impl_parse_rlp_item(
  struct EVM_RLP_item_state *const state,
  evm_parser_meta_state_t *const meta,
  size_t max_bytes_to_buffer)
{
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    state->do_init = false;
 rebranch:
    PRINTF("impl_parse_rlp_item %d\n", state->state);
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
          goto rebranch;
      };
      case 1: {
        sub_rv = parseFixed(fs(&state->uint64_state), &meta->input, state->len_len);
        BREAK_IF_NOT_DONE;
        for(size_t i = 0; i < state->len_len; i++) {
            ((uint8_t*)(&state->length))[i] = state->uint64_state.buf[state->len_len-i-1];
        }
        state->state++;
      } fallthrough;
      case 2:
        if(max_bytes_to_buffer) {
          if(MIN(state->length, max_bytes_to_buffer) > NUM_ELEMENTS(state->buffer)) REJECT("RLP field too large for buffer");
        }
        state->do_init = !max_bytes_to_buffer;
        state->state++;
        fallthrough;
      case 3: {
        uint64_t
          remaining = state->length-state->current,
          available = meta->input.length - meta->input.consumed,
          consumable = MIN(remaining, available),
          bufferable = MIN(state->length, max_bytes_to_buffer),
          unbuffered = MAX(0, (int64_t)bufferable - (int64_t)state->current);

        if(max_bytes_to_buffer) {
          memcpy(state->buffer+state->current, meta->input.src + meta->input.consumed, MIN(consumable, unbuffered));
        } else {
          if(state->chunk.consumed >= state->chunk.length) {
            state->chunk.src=&meta->input.src[meta->input.consumed];
            state->chunk.consumed = 0;
            state->chunk.length = consumable;
          }
        }

        meta->input.consumed += consumable;
        state->current += consumable;

        if(remaining <= available) {
          state->state = 4;
          sub_rv = PARSE_RV_DONE;
        } else {
          sub_rv = PARSE_RV_NEED_MORE;
        }
        break;
      }
    default:
      REJECT("should not happen, already finished parsing RLP\n");
    }
    return sub_rv;
}

enum parse_rv parse_rlp_item(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, 0);
}

enum parse_rv parse_rlp_item_to_buffer(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, NUM_ELEMENTS(state->rlpItem_state.buffer));
}
enum parse_rv parse_rlp_item_data(struct EVM_RLP_txn_state *const state, evm_parser_meta_state_t *const meta) {
  return impl_parse_rlp_item(&state->rlpItem_state, meta, state->hasTo ? 0 : MAX_CALLDATA_PREVIEW);
}

//IMPL_FIXED(uint256_t);

#define ASSETCALL_FIXED_DATA_WIDTH (20 + 32 + 32)

void init_assetCall_data(struct EVM_assetCall_state *const state, uint64_t length) {
    state->state = 0;
    PRINTF("Initing assetCall Data\n");
    if(length < ASSETCALL_FIXED_DATA_WIDTH)
      REJECT("Calldata too small for assetCall");
    state->data_length = length - ASSETCALL_FIXED_DATA_WIDTH;
    initFixed(fs(&state->address_state), sizeof(state->address_state));
    PRINTF("Initing assetCall Data\n");
}

_Static_assert(
  (
    offsetof(union EVM_endpoint_argument_states, uint256_state.buf)
    ==
    offsetof(union EVM_endpoint_argument_states, fixed_state.buffer_)
  ),
  "buffers do not line up in EVM_endpoint_argument_states");

void init_abi_call_data(struct EVM_ABI_state *const state, uint64_t length) {
  state->state = ABISTATE_SELECTOR;
  state->argument_index = 0;
  state->data_length = length;
  initFixed(fs(&state->argument_state), sizeof(state->argument_state));
}

enum parse_rv parse_abi_call_data(struct EVM_ABI_state *const state,
                                  parser_input_meta_state_t *const input,
                                  evm_parser_meta_state_t *const meta,
                                  bool hasValue) {
  if(state->data_length < ETHEREUM_SELECTOR_SIZE) REJECT("When present, calldata must have at least %u bytes", ETHEREUM_SELECTOR_SIZE);

  enum parse_rv sub_rv;
rebranch:
  switch(state->state) {
  case ABISTATE_SELECTOR: {
    sub_rv = parseFixed(fs(&state->selector_state), input, ETHEREUM_SELECTOR_SIZE);
    BREAK_IF_NOT_DONE;
    for(size_t i = 0; i < NUM_ELEMENTS(known_endpoints); i++) {
      if(!memcmp(&known_endpoints[i].selector, state->selector_state.buf, ETHEREUM_SELECTOR_SIZE)) {
        meta->known_endpoint = &known_endpoints[i];
        break;
      }
    }

    if(meta->known_endpoint) {
      state->state = ABISTATE_ARGUMENTS;
      initFixed(fs(&state->argument_state), sizeof(state->argument_state));
      if(hasValue) REJECT("No currently supported methods are marked as 'payable'");
      char *method_name = PIC(meta->known_endpoint->method_name);
      ADD_PROMPT("Contract Call", method_name, strlen(method_name), strcpy_prompt);
    } else {
      state->state = ABISTATE_UNRECOGNIZED;
      ADD_ACCUM_PROMPT("Transfer", output_evm_prompt_to_string);
    }

    BREAK_IF_NOT_DONE;
    goto rebranch;
  }

  case ABISTATE_ARGUMENTS: {
    while (state->argument_index < meta->known_endpoint->parameters_count) {
      sub_rv = parseFixed(fs(&state->argument_state), input, ETHEREUM_WORD_SIZE); // TODO: non-word size values
      BREAK_IF_NOT_DONE;
      const struct contract_endpoint_param parameter = meta->known_endpoint->parameters[state->argument_index];
      char *argument_name = PIC(parameter.name);
      setup_prompt_fun_t setup_prompt = PIC(parameter.setup_prompt);
      SET_PROMPT_VALUE(setup_prompt(fs(&state->argument_state)->buffer,
                                    &entry->data.output_prompt));
      initFixed(fs(&state->argument_state), sizeof(state->argument_state));
      ADD_ACCUM_PROMPT_ABI(argument_name, PIC(parameter.output_prompt));
      state->argument_index++;
      BREAK_IF_NOT_DONE;
    }
    BREAK_IF_NOT_DONE;
    state->state = ABISTATE_DONE;
    goto rebranch;
  }

  // Probably we have to allow this, as the metamask constraint means _this_ endpoint will be getting stuff it doesn't understand a lot.
  case ABISTATE_UNRECOGNIZED: {
    sub_rv = skipBytes(fs(&state->argument_state), input, state->data_length);
    BREAK_IF_NOT_DONE;
    state->state = ABISTATE_DONE;
    static char const isPresentLabel[]="Is Present (unsafe)";
    ADD_PROMPT("Contract Data", isPresentLabel, sizeof(isPresentLabel), strcpy_prompt);
    state->state = ABISTATE_DONE;
    BREAK_IF_NOT_DONE;
    goto rebranch;
  }

  case ABISTATE_DONE: {
    sub_rv = PARSE_RV_DONE;
  }

  }
  return sub_rv;
}

enum parse_rv parse_assetCall_data(struct EVM_assetCall_state *const state, parser_input_meta_state_t *const input, evm_parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    bool expectingDeposit = state->data_length > 0;

    PRINTF("AssetCall Data: %.*h\n", input->length, input->src);
    PRINTF("expectingDeposit: %u, input length %u, state->data_length %.*h\n", expectingDeposit, input->length, 8, &state->data_length);
    PRINTF("state: %u\n", state->state);
    switch(state->state) {
    case ASSETCALL_ADDRESS:
      sub_rv = parseFixed(fs(&state->address_state), input, ETHEREUM_ADDRESS_SIZE);
      RET_IF_NOT_DONE;
      SET_PROMPT_VALUE(memcpy(entry->data.output_prompt.address.val, state->address_state.buf, ETHEREUM_ADDRESS_SIZE));
      PRINTF("Address: %.*h\n", ETHEREUM_ADDRESS_SIZE, state->address_state.buf);
      state->state++;
      initFixed(fs(&state->id32_state), sizeof(state->id32_state));
      fallthrough;
    case ASSETCALL_ASSETID:
      sub_rv = parseFixed(fs(&state->id32_state), input, sizeof(Id32));
      RET_IF_NOT_DONE;
      SET_PROMPT_VALUE(memcpy(&entry->data.output_prompt.assetCall.assetID, state->id32_state.buf, sizeof(uint256_t)));
      PRINTF("Asset: %.*h\n", 32, state->id32_state.buf);
      state->state++;
      initFixed(fs(&state->uint256_state), sizeof(state->uint256_state));
      fallthrough;
    case ASSETCALL_AMOUNT:
      sub_rv = parseFixed(fs(&state->uint256_state), input, sizeof(uint256_t));
      RET_IF_NOT_DONE;
      SET_PROMPT_VALUE(readu256BE(state->uint256_state.buf, &entry->data.output_prompt.assetCall.amount));
      PRINTF("Amount: %.*h\n", 32, state->uint256_state.buf);
      state->state++;

      if(state->data_length==0) {
        PRINTF("Plain non-avax transfer\n");
        state->state = ASSETCALL_DONE;
        ADD_ACCUM_PROMPT("Transfer", output_assetCall_prompt_to_string);
        RET_IF_NOT_DONE;
        return PARSE_RV_DONE;
      }
      if (state->data_length != 4) {
        REJECT("unsupported assetCall length");
      }
      initFixed(fs(&state->selector_state), sizeof(state->selector_state));
      fallthrough;
    case ASSETCALL_DATA:
      sub_rv = parseFixed(fs(&state->selector_state), input, 4);
      RET_IF_NOT_DONE;

      static const uint8_t depositSelectorBytes [4] = { 0xd0, 0xe3, 0x0d, 0xb0 };
      if(memcmp(PIC(&depositSelectorBytes), state->selector_state.buf, 4))
        REJECT("unsupported assetCall selector");

      PRINTF("Selector %.*h\n", 4, state->selector_state.buf);

      state->state++;
      if (expectingDeposit) {
        ADD_ACCUM_PROMPT("Deposit", output_assetCall_prompt_to_string);
        RET_IF_NOT_DONE;
      }
      fallthrough;

    case ASSETCALL_DONE:
      return PARSE_RV_DONE;
    }
}
