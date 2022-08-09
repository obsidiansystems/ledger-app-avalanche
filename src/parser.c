#include "exception.h"
#include "globals.h"
#include "parser-impl.h"
#include "protocol.h"
#include "to_string.h"
#include "types.h"
#include "network_info.h"
#include "hash.h"

bool should_flush(const prompt_batch_t *const prompt) {
  bool test = prompt->count > prompt->flushIndex;
  if (test) {
    PRINTF("prompt buffer full; should flush!\n");
  }
  return test;
}
void set_next_batch_size(prompt_batch_t *const prompt, size_t size) {
  if(!size) size = NUM_ELEMENTS(prompt->entries);
  prompt->flushIndex = size-1;
}

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW_(EXC_PARSE_ERROR, "Rejected"); }

#define ADD_PROMPT(label_, data_, size_, to_string_) { \
        if (meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries)) { \
            THROW_(EXC_MEMORY_ERROR, "Tried to add a prompt to full queue"); \
        } \
        meta->prompt.labels[meta->prompt.count] = PROMPT(label_); \
        meta->prompt.entries[meta->prompt.count].to_string = to_string_; \
        memcpy(&meta->prompt.entries[meta->prompt.count].data, data_, size_); \
        meta->prompt.count++; \
        if (should_flush(&meta->prompt)) { \
            sub_rv = PARSE_RV_PROMPT; \
        } \
    }

#define CALL_SUBPARSER(subFieldName, subParser) { \
        sub_rv = parse_ ## subParser(&state->subFieldName, meta); \
        RET_IF_NOT_DONE; \
    }

#define INIT_SUBPARSER(subFieldName, subParser) \
    init_ ## subParser(&state->subFieldName);

#define INIT_SUBPARSER_WITH(subFieldName, subParser, ...) \
    init_ ## subParser(&state->subFieldName, __VA_ARGS__);

static bool is_pchain(blockchain_id_t *blockchain_id);

static void check_asset_id(Id32 const *const asset_id, parser_meta_state_t *const meta) {
    check_null(asset_id);
    check_null(meta);
    network_info_t const *const network_info = network_info_from_network_id(meta->network_id);
    check_null(network_info);
    if (memcmp(asset_id, network_info->avax_asset_id, sizeof(asset_id_t)) != 0) {
      REJECT("Asset ID %.*h is not %.*h and so not supported",
        sizeof(asset_id_t), asset_id,
        sizeof(asset_id_t), network_info->avax_asset_id);
    }
}

void initFixed(struct FixedState *const state, size_t const len) {
    state->filledTo = 0; // should be redudant with the memset, but just in case
    memset(state, 0, len);
}

// Do TRANSACTION_X_CHAIN_TYPE_ID_BASE and TRANSACTION_C_CHAIN_TYPE_ID_IMPORT
// manually because overlap

#define X_TXTS \
    /* case TRANSACTION_X_CHAIN_TYPE_ID_BASE: */ \
    /**/ TRANSACTION_X_CHAIN_TYPE_ID_IMPORT: \
    case TRANSACTION_X_CHAIN_TYPE_ID_EXPORT

#define P_TXTS \
    /**/ TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR: \
    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR: \
    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR: \
    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN: \
    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET: \
    case TRANSACTION_P_CHAIN_TYPE_ID_IMPORT: \
    case TRANSACTION_P_CHAIN_TYPE_ID_EXPORT

#define C_TXTS \
    /* case TRANSACTION_C_CHAIN_TYPE_ID_IMPORT: */ \
    /**/ TRANSACTION_C_CHAIN_TYPE_ID_EXPORT

union transaction_type_id_t convert_type_id_to_type(uint32_t raw_type_id, enum chain_role chain) {
    static const uint32_t c_chain_bit = 24;
    if(raw_type_id & 1<<c_chain_bit) {
        // If this becomes a real type id, just change the 24 for the switch.
      REJECT("Invalid transaction type_id; Must be base, export, or import; found %d", raw_type_id);
    }
    switch (chain) {
    case CHAIN_X:
        switch (raw_type_id) {
        case TRANSACTION_X_CHAIN_TYPE_ID_BASE: // overlaps with C
        case X_TXTS:
          return (union transaction_type_id_t) { .x = raw_type_id };
        case P_TXTS:
        case C_TXTS:
          REJECT("Blockchain ID did not match expected value for network ID");
        default:
          ; // error at end
        }
        break;
    case CHAIN_P:
        switch (raw_type_id) {
        case P_TXTS:
          return (union transaction_type_id_t) { .p = raw_type_id };
        case TRANSACTION_X_CHAIN_TYPE_ID_BASE: // overlaps with C
        case X_TXTS:
        case C_TXTS:
          REJECT("Blockchain ID did not match expected value for network ID");
        default:
          ; // error at end
        }
        break;
    case CHAIN_C:
        switch (raw_type_id) {
        case TRANSACTION_C_CHAIN_TYPE_ID_IMPORT: // overlaps with X
        case C_TXTS:
          return (union transaction_type_id_t) { .c = raw_type_id };
        // case P_TXTS: // nicer error below
        case X_TXTS:
          REJECT("Blockchain ID did not match expected value for network ID");
        case P_TXTS:
          // Redundant check just for nicer error. TODO: be more systematic?
          REJECT("Transaction ID indicates P-chain but blockchain ID is is not 0");
        default:
          ; // error at end
        }
        break;
    }
    REJECT("Invalid transaction type_id; Must be base, export, or import; found %d", raw_type_id);
}

enum parse_rv parseFixed(struct FixedState *const state, parser_input_meta_state_t *const input, size_t const len) {
    size_t const available = input->length - input->consumed;
    size_t const needed = len - state->filledTo;
    size_t const to_copy = MIN(needed, available);
    memcpy(&state->buffer[state->filledTo], &input->src[input->consumed], to_copy);
    state->filledTo += to_copy;
    input->consumed += to_copy;
    return state->filledTo == len ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
}

enum parse_rv skipBytes(struct FixedState *const state, parser_input_meta_state_t *const input, size_t const len) {
  size_t const available = input->length - input->consumed;
  size_t const needed = len - state->filledTo;
  size_t const to_copy = MIN(needed, available);
  state->filledTo += to_copy;
  input->consumed += to_copy;
  return state->filledTo == len ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
}

IMPL_FIXED_BE(uint16_t);
IMPL_FIXED_BE(uint32_t);
IMPL_FIXED_BE(uint64_t);
IMPL_FIXED(Id32);
IMPL_FIXED(blockchain_id_t);
IMPL_FIXED(Address);

void init_SECP256K1TransferOutput(struct SECP256K1TransferOutput_state *const state) {
    state->state = 0;
    state->address_n = 0;
    state->address_i = 0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

static void output_prompt_to_string(char *const out, size_t const out_size, output_prompt_t const *const in) {
    network_info_t const *const network_info = network_info_from_network_id(in->network_id);
    if (network_info == NULL) REJECT("Can't determine network HRP for addresses");
    char const *const hrp = network_info->hrp;

    size_t ix = nano_avax_to_string(out, out_size, in->amount);

    static char const to[] = " to ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' to ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    pkh_to_string(&out[ix], out_size - ix, hrp, strlen(hrp), &in->address.val);
}

static void output_address_to_string(char *const out, size_t const out_size, address_prompt_t const *const in) {
    char const *const hrp = network_info_from_network_id_not_null(in->network_id)->hrp;
    size_t ix = 0;
    pkh_to_string(&out[ix], out_size - ix, hrp, strlen(hrp), &in->address.val);
}

static void validator_to_string(char *const out, size_t const out_size, address_prompt_t const *const in) {
    size_t ix = 0;
    nodeid_to_string(&out[ix], out_size - ix, &in->address.val);
}

static void ids_to_string(char *const out, size_t const out_size, Id32 const *const in) {
    size_t ix = 0;
    id_to_string(&out[ix], out_size - ix, in);
}

static void chainname_to_string(char *const out, size_t const out_size, chainname_prompt_t const *const in) {

    size_t ix = 0;
    chain_name_to_string(&out[ix], out_size - ix, in->buffer, in->buffer_size);
}

static void gendata_to_hex(char *const out, size_t const out_size, gendata_prompt_t const *const in) {
    size_t ix = 0;
    bin_to_hex(&out[ix], out_size - ix, in->buffer, sizeof(in->buffer));
}

enum parse_rv parse_SECP256K1TransferOutput(struct SECP256K1TransferOutput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0: {
            // Amount; Type is already handled in init_Output
            CALL_SUBPARSER(uint64State, uint64_t);
            PRINTF("OUTPUT AMOUNT: %.*h\n", sizeof(state->uint64State.buf), state->uint64State.buf); // we don't seem to have longs in printf specfiers.
            if (__builtin_uaddll_overflow(state->uint64State.val, meta->sum_of_outputs, &meta->sum_of_outputs)) THROW_(EXC_MEMORY_ERROR, "Sum of outputs overflowed");
            meta->last_output_amount = state->uint64State.val;
            state->state++;
            INIT_SUBPARSER(uint64State, uint64_t);
        } fallthrough;
        case 1:
            // Locktime
            CALL_SUBPARSER(uint64State, uint64_t);
            PRINTF("LOCK TIME: %.*h\n", sizeof(state->uint64State.buf), state->uint64State.buf); // we don't seem to have longs in printf specfiers.
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 2:
            // Threshold
            CALL_SUBPARSER(uint32State, uint32_t);
            PRINTF("Threshold: %d\n", state->uint32State.val);
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 3: // Address Count
            CALL_SUBPARSER(uint32State, uint32_t);
            state->state++;
            state->address_n = state->uint32State.val;
            if (state->address_n != 1) REJECT("Multi-address outputs are not supported");
            INIT_SUBPARSER(addressState, Address);
            fallthrough;
        case 4: {
            if (state->address_i == state->address_n) {
                state->state++;
                break;
            }
            do {
                // loop invariant
                if (state->address_i == state->address_n) {
                   THROW(EXC_MEMORY_ERROR);
                }

                CALL_SUBPARSER(addressState, Address);
                PRINTF("Output address %d: %.*h\n",
                    state->address_i + 1,
                    sizeof(state->addressState.buf), state->addressState.buf);

                output_prompt_t output_prompt;
                memset(&output_prompt, 0, sizeof(output_prompt));
                if (!(meta->last_output_amount > 0)) REJECT("Assertion failed: last_output_amount > 0");
                output_prompt.amount = meta->last_output_amount;
                output_prompt.network_id = meta->network_id;
                memcpy(&output_prompt.address, &state->addressState.val, sizeof(output_prompt.address));
                // TODO: We can get rid of this if we add back the P/X- in front of an address
                if (memcmp(state->addressState.buf, global.apdu.u.sign.change_address, sizeof(public_key_hash_t)) == 0) {
                  // skip change address
                } else if(meta->swap_output) {
                  switch (meta->chain) {
                  case CHAIN_X:
                    switch (meta->type_id.x) {
                    case TRANSACTION_X_CHAIN_TYPE_ID_EXPORT:
                        if (meta->swapCounterpartChain == CHAIN_P) {
                            ADD_PROMPT("X to P chain", &output_prompt, sizeof(output_prompt), output_prompt_to_string)
                        } else {
                            ADD_PROMPT("X to C chain", &output_prompt, sizeof(output_prompt), output_prompt_to_string);
                        }
                        break;
                    default:
                        // If we throw here, we set swap_output somewhere _wrong_.
                        THROW(EXC_PARSE_ERROR);
                    };
                    break;
                  case CHAIN_P:
                    switch (meta->type_id.p) {
                    case TRANSACTION_P_CHAIN_TYPE_ID_EXPORT:
                        ADD_PROMPT(
                            "P chain export",
                            &output_prompt, sizeof(output_prompt),
                            output_prompt_to_string
                            );
                        break;
                    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR:
                    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR:

                        if (__builtin_uaddll_overflow(meta->staked, meta->last_output_amount, &meta->staked)) THROW_(EXC_MEMORY_ERROR, "Stake total overflowed.");
                        ADD_PROMPT(
                            "Stake",
                            &output_prompt, sizeof(output_prompt),
                            output_prompt_to_string
                            );
                        break;
                    default:
                        // If we throw here, we set swap_output somewhere _wrong_.
                        THROW(EXC_PARSE_ERROR);
                    };
                    break;
                  case CHAIN_C:
                    // If we throw here, we set swap_output somewhere _wrong_.
                    THROW(EXC_PARSE_ERROR);
                  }
                } else {
                  switch (meta->chain) {
                  case CHAIN_X:
                    switch (meta->type_id.x) {
                    case TRANSACTION_X_CHAIN_TYPE_ID_IMPORT:
                      ADD_PROMPT(
                          "Sending",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                      break;
                    default:
                      ADD_PROMPT(
                          "Transfer",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                    }
                    break;
                  case CHAIN_P:
                    switch (meta->type_id.p) {
                    case TRANSACTION_P_CHAIN_TYPE_ID_IMPORT:
                      ADD_PROMPT(
                          "P chain import",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                      break;
                    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR:
                      PRINTF("This transaction does not conduct a transfer of funds\n");
                      break;
                    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN:
                      PRINTF("This transaction does not conduct a transfer of funds\n");
                      break;
                    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET:
                      PRINTF("This transaction does not conduct a transfer of funds\n");
                      break;
                    default:
                      ADD_PROMPT(
                          "Transfer",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                    }
                    break;
                  case CHAIN_C:
                    switch (meta->type_id.c) {
                    case TRANSACTION_C_CHAIN_TYPE_ID_EXPORT:
                      ADD_PROMPT(
                          "C chain export",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                      break;
                    default:
                      ADD_PROMPT(
                          "Transfer",
                          &output_prompt, sizeof(output_prompt),
                          output_prompt_to_string
                          );
                    }
                    break;
                  }
                }

                state->address_i++;
                if (state->address_i < state->address_n) {
                    INIT_SUBPARSER(addressState, Address);
                    RET_IF_PROMPT_FLUSH;
                    continue;
                } else {
                    state->state++;
                    RET_IF_PROMPT_FLUSH;
                    break;
                }
            } while (false);
        }
        fallthrough; // NOTE
        case 5:
            sub_rv = PARSE_RV_DONE;
            break;
    }
    return sub_rv;
}

void init_SECP256K1OutputOwners(struct SECP256K1OutputOwners_state *const state) {
  state->state=0;
  state->address_i=0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_SECP256K1OutputOwners(struct SECP256K1OutputOwners_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0: {
            // Type ID
            CALL_SUBPARSER(uint32State, uint32_t);
            PRINTF("OUPTUT OWNERS\n");
            state->state++;
            INIT_SUBPARSER(uint64State, uint64_t);
        } fallthrough;
        case 1:
            // Locktime
            CALL_SUBPARSER(uint64State, uint64_t);
            PRINTF("LOCK TIME: %.*h\n", sizeof(state->uint64State.buf), state->uint64State.buf); // we don't seem to have longs in printf specfiers.
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 2:
            // Threshold
            CALL_SUBPARSER(uint32State, uint32_t);
            PRINTF("Threshold: %d\n", state->uint32State.val);
            if(meta->type_id.p == TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET)
            {
              ADD_PROMPT("Threshold", &state->uint32State.val, sizeof(state->uint32State.val), number_to_string_indirect32);
            }
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            RET_IF_PROMPT_FLUSH;
            fallthrough;
        case 3: // Address Count
            CALL_SUBPARSER(uint32State, uint32_t);
            state->state++;
            state->address_n = state->uint32State.val;
            PRINTF("Addr Count\n");
            if (state->address_n != 1) REJECT("Multi-address outputs are not supported");
            INIT_SUBPARSER(addressState, Address);
            fallthrough;
        case 4: {
            if (state->address_i == state->address_n) {
                state->state++;
                break;
            }
            do {
                // loop invariant
                if (state->address_i == state->address_n) {
                   THROW(EXC_MEMORY_ERROR);
                }

                CALL_SUBPARSER(addressState, Address);

                address_prompt_t address_prompt;
                memset(&address_prompt, 0, sizeof(address_prompt));
                address_prompt.network_id = meta->network_id;
                memcpy(&address_prompt.address, &state->addressState.val, sizeof(address_prompt.address));
                // TODO: We can get rid of this if we add back the P/X- in front of an address
                if(meta->type_id.p == TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET)
                {
                    ADD_PROMPT("Address", &address_prompt, sizeof(address_prompt_t), output_address_to_string);
                }
                else
                {
                    ADD_PROMPT("Rewards To", &address_prompt, sizeof(address_prompt_t), output_address_to_string);
                }

                state->address_i++;
                if (state->address_i < state->address_n) {
                    INIT_SUBPARSER(addressState, Address);
                    RET_IF_PROMPT_FLUSH;
                    continue;
                } else {
                    state->state++;
                    RET_IF_PROMPT_FLUSH;
                    break;
                }
            } while (false);
        }
        fallthrough;
        case 5:
            sub_rv = PARSE_RV_DONE;
            break;
    }
    return sub_rv;
}

void init_SubnetAuth(struct SubnetAuth_state *const state)
{
  state->state = 0;
  state->sigindices_i = 0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_SubnetAuth(struct SubnetAuth_state *const state, parser_meta_state_t *const meta) {
  enum parse_rv sub_rv = PARSE_RV_INVALID;
  switch(state->state)
  {
    case 0:
      // Type ID
      CALL_SUBPARSER(uint32State, uint32_t);
      PRINTF("SUBNET AUTH\n");
      state->state++;
      INIT_SUBPARSER(uint32State, uint32_t);
      fallthrough;
    case 1: {
      // Number of Sig Indices
      CALL_SUBPARSER(uint32State, uint32_t);
      state->state++;
      state->sigindices_n = state->uint32State.val;
      PRINTF("Sigind Count\n");
      INIT_SUBPARSER(uint32State, uint32_t);
    } fallthrough;
    case 2: {
      //
      if (state->sigindices_i == state->sigindices_n)
      {
        state->state++;
        break;
      }
      do
      {
        // loop invariant
        if (state->sigindices_i == state->sigindices_n)
        {
          THROW(EXC_MEMORY_ERROR);
        }

        CALL_SUBPARSER(uint32State, uint32_t);

        PRINTF("Address Index: %d\n", state->uint32State.val);

        state->sigindices_i++;
        if (state->sigindices_i < state->sigindices_n)
        {
          INIT_SUBPARSER(uint32State, uint32_t);
          continue;
        }
        else
        {
          state->state++;
          break;
        }
      } while(false);
    } fallthrough;
    case 3:
      sub_rv = PARSE_RV_DONE;
      break;
  }
  return sub_rv;
}

static void lockedFundsPrompt(char *const out, size_t const out_size, locked_prompt_t const *const in) {
    size_t ix = nano_avax_to_string(out, out_size, in->amount);

    static char const to[] = " until ";
    if (ix + sizeof(to) > out_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' until ' into prompt value string");
    memcpy(&out[ix], to, sizeof(to));
    ix += sizeof(to) - 1;

    time_to_string(&out[ix], out_size - ix, &in->until);
}

void init_StakeableLockOutput(struct StakeableLockOutput_state *const state) {
    state->state=0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

enum parse_rv parse_StakeableLockOutput(struct StakeableLockOutput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
      case 0: // Locktime
        CALL_SUBPARSER(uint64State, uint64_t);
        state->locktime=state->uint64State.val;
        PRINTF("StakeableLockOutput locktime: %.*h\n", 8, state->uint64State.buf);
        state->state++;
        INIT_SUBPARSER(uint32State, uint32_t);
        fallthrough;
      case 1: // Parse the type field of the nested output here, rather than dispatching through Output.
        CALL_SUBPARSER(uint32State, uint32_t);
        if(state->uint32State.val != 0x00000007) REJECT("Can only parse SECP256K1TransferableOutput nested in StakeableLockoutput");
        state->state++;
        INIT_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
        fallthrough;
      case 2: // nested TransferrableOutput
        CALL_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
        locked_prompt_t promptData;
        promptData.amount=meta->last_output_amount;
        promptData.until=state->locktime;
        state->state++;
        ADD_PROMPT("Funds locked", &promptData, sizeof(locked_prompt_t), lockedFundsPrompt)
        RET_IF_PROMPT_FLUSH;
        fallthrough;
      case 3:
        sub_rv=PARSE_RV_DONE;
        break;
    }
    return sub_rv;
}

void init_Output(struct Output_state *const state) {
    state->state = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Output(struct Output_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0:
            CALL_SUBPARSER(uint32State, uint32_t);
            state->type = state->uint32State.val;
            PRINTF("Output Type: %d\n", state->type);
            state->state++;
            switch (state->type) {
                default: REJECT("Unrecognized output type");
                case 0x00000007:
                    INIT_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
                    break;
                case 0x00000016:
                    INIT_SUBPARSER(stakeableLockOutput, StakeableLockOutput);
                    break;
            }
            fallthrough;
        case 1:
            switch (state->type) {
                default: REJECT("Unrecognized output type");
                case 0x00000007:
                    PRINTF("SECP256K1TransferOutput\n");
                    CALL_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
                    break;
                case 0x00000016:
                    CALL_SUBPARSER(stakeableLockOutput, StakeableLockOutput);
                    break;
            }
    }
    return sub_rv;
}

void init_TransferableOutput(struct TransferableOutput_state *const state) {
    state->state = 0;
    INIT_SUBPARSER(id32State, Id32);
}

enum parse_rv parse_TransferableOutput(struct TransferableOutput_state *const state, parser_meta_state_t *const meta) {
    PRINTF("***Parse Transferable Output***\n");
    enum parse_rv sub_rv = PARSE_RV_INVALID;

    switch (state->state) {
        case 0: // asset ID
            CALL_SUBPARSER(id32State, Id32);
            PRINTF("Asset ID: %.*h\n", 32, state->id32State.buf);
            check_asset_id(&state->id32State.val, meta);
            state->state++;
            INIT_SUBPARSER(outputState, Output);
            fallthrough;
        case 1:
            CALL_SUBPARSER(outputState, Output);
    }
    return sub_rv;
}

void init_SECP256K1TransferInput(struct SECP256K1TransferInput_state *const state) {
    state->state = 0;
    state->address_index_i = 0;
    state->address_index_n = 0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

enum parse_rv parse_SECP256K1TransferInput(struct SECP256K1TransferInput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;

    switch (state->state) {
        case 0: // Amount
            CALL_SUBPARSER(uint64State, uint64_t);
            state->state++;
            PRINTF("INPUT AMOUNT: %.*h\n", sizeof(uint64_t), state->uint64State.buf);
            if (__builtin_uaddll_overflow(state->uint64State.val, meta->sum_of_inputs, &meta->sum_of_inputs)) THROW_(EXC_MEMORY_ERROR, "Sum of inputs overflowed");
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 1: // Number of address indices
            CALL_SUBPARSER(uint32State, uint32_t);
            state->address_index_n = state->uint32State.val;
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 2: // Address indices
            while (true) {
                CALL_SUBPARSER(uint32State, uint32_t);
                state->address_index_i++;
                PRINTF("Address Index %d: %d\n", state->address_index_i, state->uint32State.val);
                if (state->address_index_i == state->address_index_n) {
                    sub_rv = PARSE_RV_DONE;
                    break;
                }
                INIT_SUBPARSER(addressState, Address);
            }
            break; // Forward the break up.
    }

    return sub_rv;
}

void init_StakeableLockInput(struct StakeableLockInput_state *const state){
    state->state=0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

enum parse_rv parse_StakeableLockInput(struct StakeableLockInput_state *const state, parser_meta_state_t *const meta){
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
      case 0: // Locktime
        CALL_SUBPARSER(uint64State, uint64_t);
        PRINTF("StakeableLockInput locktime: %.*h\n", 8, state->uint64State.buf);
        state->state++;
        INIT_SUBPARSER(uint32State, uint32_t);
        fallthrough;
      case 1: // Parse the type field of the nested input here, rather than dispatching through Output.
        CALL_SUBPARSER(uint32State, uint32_t);
        if(state->uint32State.val != 0x00000005) REJECT("Can only parse SECP256K1TransferableInput nested in StakeableLockInput");
        state->state++;
        INIT_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
        fallthrough;
      case 2: // nested Input
        CALL_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
    }
    return sub_rv;
}

void init_Input(struct Input_state *const state) {
    state->state = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Input(struct Input_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;

    switch (state->state) {
        case 0:
            CALL_SUBPARSER(uint32State, uint32_t);
            state->type = state->uint32State.val;
            PRINTF("INPUT TYPE: %d\n", state->type);
            state->state++;
            switch (state->type) {
                default: REJECT("Unrecognized input type");
                case 0x00000005: // SECP256K1 transfer input
                    INIT_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
                    break;
                case 0x00000015: // SECP256K1 transfer input
                    INIT_SUBPARSER(stakeableLockInput, StakeableLockInput);
                    break;
            }
            fallthrough;
        case 1:
            switch (state->type) {
                default: REJECT("Unrecognized input type");
                case 0x00000005: // SECP256K1 transfer input
                    PRINTF("SECP256K1 Input\n");
                    CALL_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
                    break;
                case 0x00000015: // SECP256K1 transfer input
                    CALL_SUBPARSER(stakeableLockInput, StakeableLockInput);
                    break;
            }
    }

    return sub_rv;
}

void init_TransferableInput(struct TransferableInput_state *const state) {
    state->state = 0;
    INIT_SUBPARSER(id32State, Id32);
}

enum parse_rv parse_TransferableInput(struct TransferableInput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0: // tx_id
            CALL_SUBPARSER(id32State, Id32);
            state->state++;
            PRINTF("TX_ID: %.*h\n", 32, state->id32State.buf);
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 1: // utxo_index
            CALL_SUBPARSER(uint32State, uint32_t);
            PRINTF("UTXO_INDEX: %u\n", state->uint32State.val);
            state->state++;
            INIT_SUBPARSER(id32State, Id32);
            fallthrough;
        case 2: // asset_id
            CALL_SUBPARSER(id32State, Id32);
            PRINTF("ASSET ID: %.*h\n", 32, state->id32State.buf);
            check_asset_id(&state->id32State.val, meta);
            state->state++;
            INIT_SUBPARSER(inputState, Input);
            fallthrough;
        case 3: // Input
            CALL_SUBPARSER(inputState, Input);
    }
    return sub_rv;
}

IMPL_ARRAY(TransferableOutput);
IMPL_ARRAY(TransferableInput);

void init_Memo(struct Memo_state *const state) {
    state->state = 0;
    state->n = 0;
    state->i = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Memo(struct Memo_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;

    switch (state->state) {
        case 0:
            CALL_SUBPARSER(uint32State, uint32_t);
            state->n = state->uint32State.val;
            state->state++;
            fallthrough;
        case 1: {
            size_t available = meta->input.length - meta->input.consumed;
            size_t needed = state->n - state->i;
            size_t to_consume = available > needed ? needed : available;
            state->i += to_consume;
            PRINTF("Memo bytes: %.*h\n", to_consume, &meta->input.src[meta->input.consumed]);
            meta->input.consumed += to_consume;
            sub_rv = state->i == state->n ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
        }
    }

    return sub_rv;
}

void initTransaction(struct TransactionState *const state) {
    state->state = 0;
    init_uint32_t(&state->uint32State);
    cx_sha256_init(&state->hash_state);
    INIT_SUBPARSER(uint16State, uint16_t);
}

void strcpy_prompt(char *const out, size_t const out_size, char const *const in) {
    strncpy(out, in, out_size);
}

static bool prompt_fee(parser_meta_state_t *const meta) {
    uint64_t fee = -1; // if this is unset this should be obviously wrong
    PRINTF("inputs: %.*h outputs: %.*h\n", 8, &meta->sum_of_inputs, 8, &meta->sum_of_outputs);
    if (__builtin_usubll_overflow(meta->sum_of_inputs, meta->sum_of_outputs, &fee)) THROW_(EXC_MEMORY_ERROR, "Difference of outputs from inputs overflowed");
    if (meta->prompt.count >= NUM_ELEMENTS(meta->prompt.entries)) THROW_(EXC_MEMORY_ERROR, "Tried to add a prompt to full queue");
    meta->prompt.labels[meta->prompt.count] = PROMPT("Fee");
    meta->prompt.entries[meta->prompt.count].to_string = nano_avax_to_string_indirect64;
    memcpy(&meta->prompt.entries[meta->prompt.count].data, &fee, sizeof(fee));
    meta->prompt.count++;
    return should_flush(&meta->prompt);
}

void init_BaseTransactionHeader(struct BaseTransactionHeaderState *const state) {
  state->state = BTSH_NetworkId; // We start on Network ID
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum opt_chain_role {
  OPT_CHAIN_X = CHAIN_X,
  OPT_CHAIN_P = CHAIN_P,
  OPT_CHAIN_C = CHAIN_C,
  OPT_CHAIN_INVAL = -1
};

static enum opt_chain_role decode_chain_id(network_id_t const network_id, blockchain_id_t *blockchain_id) {
  const network_info_t *const net_info = network_info_from_network_id_not_null(network_id);
  const blockchain_id_t *const x_blockchain_id = &net_info->x_blockchain_id;
  const blockchain_id_t *const c_blockchain_id = &net_info->c_blockchain_id;
  if (is_pchain(blockchain_id)) {
    return OPT_CHAIN_P;
  } else if (!memcmp(x_blockchain_id, blockchain_id, sizeof(*blockchain_id))) {
    return OPT_CHAIN_X;
  } else if (!memcmp(c_blockchain_id, blockchain_id, sizeof(*blockchain_id))) {
    return OPT_CHAIN_C;
  } else {
    return OPT_CHAIN_INVAL;
  }
}

enum parse_rv parse_BaseTransactionHeader(struct BaseTransactionHeaderState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch(state->state) {
      case BTSH_NetworkId: {
            CALL_SUBPARSER(uint32State, uint32_t);
            state->state++;
            PRINTF("Network ID: %.*h\n", sizeof(state->uint32State.buf), state->uint32State.buf);
            meta->network_id = parse_network_id(state->uint32State.val);
            INIT_SUBPARSER(bidState, blockchain_id_t);
      }
      fallthrough;
      case BTSH_BlockchainId: {
            CALL_SUBPARSER(bidState, blockchain_id_t);
            PRINTF("Blockchain ID: %.*h\n", 32, state->bidState.val.bytes);
            enum opt_chain_role chain = decode_chain_id(meta->network_id, &state->bidState.val);
            if (chain == OPT_CHAIN_INVAL) {
                REJECT("Blockchain ID did not match expected value for network ID");
            }
            meta->chain = chain;
            state->state++;
      } fallthrough;
      case BTSH_Done:
        PRINTF("Done\n");
        sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_BaseTransaction(struct BaseTransactionState *const state) {
  state->state = BTS_Outputs; // We start on Outputs
  INIT_SUBPARSER(outputsState, TransferableOutputs);
}

enum parse_rv parse_BaseTransaction(struct BaseTransactionState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case BTS_Outputs: // outputs
            PRINTF("Parsing outputs\n");
            CALL_SUBPARSER(outputsState, TransferableOutputs);
            PRINTF("Done with outputs\n");
            state->state++;
            INIT_SUBPARSER(inputsState, TransferableInputs);
            fallthrough;
        case BTS_Inputs: { // inputs
            CALL_SUBPARSER(inputsState, TransferableInputs);
            PRINTF("Done with inputs\n");
            state->state++;
            INIT_SUBPARSER(memoState, Memo);
        } fallthrough;
        case BTS_Memo: // memo
            CALL_SUBPARSER(memoState, Memo);
            PRINTF("Done with memo;\n");
            state->state++;
            fallthrough;
        case BTS_Done:
            PRINTF("Done\n");
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

static bool is_pchain(blockchain_id_t *blockchain_id) {
  for (unsigned int i = 0; i < sizeof(*blockchain_id); i++)
    if (blockchain_id->bytes[i] != 0)
      return false;
  return true;
}

void init_ImportTransaction(struct ImportTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_ImportTransaction(struct ImportTransactionState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    bool showChainPrompt = false;
      switch (state->state) {
        case 0: // ChainID
            CALL_SUBPARSER(bidState, blockchain_id_t);
            enum opt_chain_role counterpart_chain = decode_chain_id(meta->network_id, &state->bidState.val);
            if (counterpart_chain == OPT_CHAIN_INVAL) {
                REJECT("Invalid counterpart Chain ID");
            }
            switch (meta->chain) {
            case CHAIN_C:
              REJECT("internal error: C Chain not handled here");
            case CHAIN_P:
              if (counterpart_chain != CHAIN_X)
                REJECT("Invalid XChain ID");
              break;
            case CHAIN_X:
              showChainPrompt = true;
              switch (counterpart_chain) {
              case CHAIN_P:
              case CHAIN_C:
                meta->swapCounterpartChain = counterpart_chain;
                break;
              default:
                REJECT("Invalid Chain ID - must be P or C");
              }
              break;
            }
            state->state++;
            INIT_SUBPARSER(inputsState, TransferableInputs);
            PRINTF("Done with ChainID;\n");

            static char const cChainLabel[]="C-chain";
            static char const pChainLabel[]="P-chain";
            if (showChainPrompt) {
              ADD_PROMPT("From",
                            meta->swapCounterpartChain == CHAIN_C ? cChainLabel : pChainLabel,
                            meta->swapCounterpartChain == CHAIN_C ? sizeof(cChainLabel) : sizeof(pChainLabel),
                            strcpy_prompt);
              RET_IF_PROMPT_FLUSH;
            }
            fallthrough;

        case 1: {
            meta->swap_output = true;
            CALL_SUBPARSER(inputsState, TransferableInputs);
            state->state++;
            PRINTF("Done with source chain Address\n");
            break;
        }
        case 2:
             // This is bc we call the parser recursively, and, at the end, it gets called with
             // nothing to parse...But it exits without unwinding the stack, so if we are here,
             // we need to set this in order to exit properly
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_ExportTransaction(struct ExportTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_ExportTransaction(struct ExportTransactionState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0: // ChainID
            CALL_SUBPARSER(bidState, blockchain_id_t);
            enum opt_chain_role counterpart_chain = decode_chain_id(meta->network_id, &state->bidState.val);
            if (counterpart_chain == OPT_CHAIN_INVAL) {
                REJECT("Invalid counterpart Chain ID");
            }
            switch (meta->chain) {
            case CHAIN_C:
              REJECT("internal error: C Chain not handled here");
            case CHAIN_P:
              switch (counterpart_chain) {
              case CHAIN_X:
              case CHAIN_C:
                meta->swapCounterpartChain = counterpart_chain;
                break;
              default:
                REJECT("Invalid Chain ID - must be X or C");
              }
              break;
            case CHAIN_X:
              switch (counterpart_chain) {
              case CHAIN_P:
              case CHAIN_C:
                meta->swapCounterpartChain = counterpart_chain;
                break;
              default:
                REJECT("Invalid Chain ID - must be P or C");
              }
            }
            state->state++;
            INIT_SUBPARSER(outputsState, TransferableOutputs);
            PRINTF("Done with ChainID;\n");
            fallthrough;

        case 1: {// PChain Dst
            meta->swap_output = true;
            CALL_SUBPARSER(outputsState, TransferableOutputs);
            state->state++;
            PRINTF("Done with destination chain Address\n");
            break;
        }
        case 2:
             // This is bc we call the parser recursively, and, at the end, it gets called with
             // nothing to parse...But it exits without unwinding the stack, so if we are here,
             // we need to set this in order to exit properly
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_EVMOutput(struct EVMOutput_state *const state) {
  state->state = 0;
  INIT_SUBPARSER(addressState, Address);
}

enum parse_rv parse_EVMOutput(struct EVMOutput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
      case 0: { // Address
          CALL_SUBPARSER(addressState, Address);
          state->state++;
          PRINTF("ADDRESS: %.*h\n", 20, state->addressState.buf);
          INIT_SUBPARSER(uint32State, uint32_t);
      } fallthrough;
      case 1: { // Amount
          CALL_SUBPARSER(uint64State, uint64_t);
          PRINTF("AMOUNT: %x\n", state->uint64State.val);
          if (__builtin_uaddll_overflow(state->uint64State.val, meta->sum_of_outputs, &meta->sum_of_outputs)) THROW_(EXC_MEMORY_ERROR, "Sum of outputs overflowed");
          meta->last_output_amount = state->uint64State.val;
          state->state++;
          INIT_SUBPARSER(id32State, Id32);
      } fallthrough;
      case 2: { // AssetID
          CALL_SUBPARSER(id32State, Id32);
          PRINTF("ASSET: %.*h\n", 32, state->id32State.buf);
          state->state++;
      } fallthrough;
      case 3: {
          state->state++;
          output_prompt_t output_prompt;
          memset(&output_prompt, 0, sizeof(output_prompt));
          if (!(meta->last_output_amount > 0)) REJECT("Assertion failed: last_output_amount > 0");
          output_prompt.amount = meta->last_output_amount;
          output_prompt.network_id = meta->network_id;
          // addressState explicitly is not part of the ephemeral sub-states of
          // EVMOutput_state so that this value is still available here.
          memcpy(&output_prompt.address, &state->addressState.val,
              sizeof(output_prompt.address));

          ADD_PROMPT(
                "Importing",
                &output_prompt, sizeof(output_prompt),
                output_prompt_to_string
                );
          BREAK_IF_PROMPT_FLUSH;
      } fallthrough;
      case 4:
        sub_rv=PARSE_RV_DONE;
    }
    return sub_rv;
}

IMPL_ARRAY(EVMOutput);

void init_EVMInput(struct EVMInput_state *const state) {
  state->state = 0;
  INIT_SUBPARSER(addressState, Address);
}

enum parse_rv parse_EVMInput(struct EVMInput_state *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
      case 0: { // Address
          CALL_SUBPARSER(addressState, Address);
          state->state++;
          PRINTF("ADDRESS: %.*h\n", 20, state->addressState.buf);
          INIT_SUBPARSER(uint64State, uint64_t);
      } fallthrough;
      case 1: { // Amount
          CALL_SUBPARSER(uint64State, uint64_t);
          PRINTF("AMOUNT: %.*h\n", 8, &state->uint64State.val);
            if (__builtin_uaddll_overflow(state->uint64State.val, meta->sum_of_inputs, &meta->sum_of_inputs)) THROW_(EXC_MEMORY_ERROR, "Sum of inputs overflowed");
          state->state++;
          INIT_SUBPARSER(id32State, Id32);
      } fallthrough;
      case 2: { // AssetID
          CALL_SUBPARSER(id32State, Id32);
          PRINTF("ASSET: %.*h\n", 32, state->id32State.buf);
          INIT_SUBPARSER(uint64State, uint64_t);
      } fallthrough;
      case 3: { // nonce
          CALL_SUBPARSER(uint64State, uint64_t);
          PRINTF("NONCE: %.*h\n", 8, &state->uint64State.val);
      }
    }
    return sub_rv;
}

IMPL_ARRAY(EVMInput);

void init_CChainImportTransaction(struct CChainImportTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_CChainImportTransaction(struct CChainImportTransactionState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
      switch (state->state) {
        case 0: // sourceChain
            CALL_SUBPARSER(bidState, blockchain_id_t);
            enum opt_chain_role chain = decode_chain_id(meta->network_id, &state->bidState.val);
            if (chain == OPT_CHAIN_INVAL) {
                REJECT("Source Blockchain ID did not match expected value for network ID");
            }
            state->state++;
            INIT_SUBPARSER(inputsState, TransferableInputs);
            PRINTF("Done with ChainID;\n");
            fallthrough;
        case 1: {
            CALL_SUBPARSER(inputsState, TransferableInputs);
            state->state++;
            INIT_SUBPARSER(evmOutputsState, EVMOutputs);
            PRINTF("Done with TransferableInputs\n");
        } fallthrough;
        case 2: { // EVMOutputs
            CALL_SUBPARSER(evmOutputsState, EVMOutputs);
            PRINTF("Done with EVMOutputs\n");
            state->state++;
        } fallthrough;
        case 3:
             // This is bc we call the parser recursively, and, at the end, it gets called with
             // nothing to parse...But it exits without unwinding the stack, so if we are here,
             // we need to set this in order to exit properly
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_CChainExportTransaction(struct CChainExportTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_CChainExportTransaction(struct CChainExportTransactionState *const state, parser_meta_state_t *const meta) {
    enum parse_rv sub_rv = PARSE_RV_INVALID;
      switch (state->state) {
        case 0: // destinationChain
            CALL_SUBPARSER(bidState, blockchain_id_t);
            enum opt_chain_role chain = decode_chain_id(meta->network_id, &state->bidState.val);
            if (chain == OPT_CHAIN_INVAL) {
                REJECT("Destination Blockchain ID did not match expected value for network ID");
            }
            state->state++;
            INIT_SUBPARSER(inputsState, EVMInputs);
            PRINTF("Done with ChainID;\n");
            fallthrough;
        case 1: { // Inputs
            CALL_SUBPARSER(inputsState, EVMInputs);
            state->state++;
            INIT_SUBPARSER(outputsState, TransferableOutputs);
            PRINTF("Done with EVMInputs\n");
        } fallthrough;
        case 2: { // TransferableOutputs
            CALL_SUBPARSER(outputsState, TransferableOutputs);
            PRINTF("Done with TransferableOutputs\n");
            state->state++;
        } fallthrough;
        case 3:
             // This is bc we call the parser recursively, and, at the end, it gets called with
             // nothing to parse...But it exits without unwinding the stack, so if we are here,
             // we need to set this in order to exit properly
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_Validator(struct Validator_state *const state) {
  state->state=0;
  INIT_SUBPARSER(addressState, Address);
}

enum parse_rv parse_Validator(struct Validator_state *const state, parser_meta_state_t *const meta) {
  enum parse_rv sub_rv = PARSE_RV_INVALID;
  switch(state->state) {
    case 0:
      CALL_SUBPARSER(addressState, Address);
      state->state++;

      address_prompt_t pkh_prompt;
      pkh_prompt.network_id = meta->network_id;
      memcpy(&pkh_prompt.address, &state->addressState.val, sizeof(pkh_prompt.address));
      ADD_PROMPT("Validator", &pkh_prompt, sizeof(address_prompt_t), validator_to_string);
      INIT_SUBPARSER(uint64State, uint64_t);
      RET_IF_PROMPT_FLUSH;
      fallthrough; // NOTE
    case 1:
      CALL_SUBPARSER(uint64State, uint64_t);
      state->state++;
      ADD_PROMPT("Start time", &state->uint64State.val, sizeof(uint64_t), time_to_string_void_ret);
      INIT_SUBPARSER(uint64State, uint64_t);
      RET_IF_PROMPT_FLUSH;
      fallthrough; // NOTE
    case 2:
      CALL_SUBPARSER(uint64State, uint64_t);
      state->state++;
      ADD_PROMPT("End time", &state->uint64State.val, sizeof(uint64_t), time_to_string_void_ret);
      INIT_SUBPARSER(uint64State, uint64_t);
      RET_IF_PROMPT_FLUSH;
      fallthrough; // NOTE
    case 3:
      CALL_SUBPARSER(uint64State, uint64_t);
      state->state++;
      meta->staking_weight = state->uint64State.val;
      if(meta->type_id.p == TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR)
      {
        ADD_PROMPT("Weight", &state->uint64State.val, sizeof(uint64_t), number_to_string_indirect64);
      }
      else
      {
        ADD_PROMPT("Total Stake", &state->uint64State.val, sizeof(uint64_t), nano_avax_to_string_indirect64);
      }
      RET_IF_PROMPT_FLUSH;
      fallthrough; // NOTE
    case 4:
      return PARSE_RV_DONE;
  }
  return sub_rv;
}

void init_AddValidatorTransaction(struct AddValidatorTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(validatorState, Validator);
}

// Also covers AddDelegator transactions; the structure is identical but
// thresholds and result are different. We've already notified the user of
// which we are doing before we reach this stage.
enum parse_rv parse_AddValidatorTransaction(
  struct AddValidatorTransactionState *const state,
  parser_meta_state_t *const meta)
{
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    switch (state->state) {
        case 0: // ChainID
          CALL_SUBPARSER(validatorState, Validator);
          state->state++;
          INIT_SUBPARSER(outputsState, TransferableOutputs);
          fallthrough;
        case 1: {// Value
            meta->swap_output = true;
            CALL_SUBPARSER(outputsState, TransferableOutputs);
            state->state++;
            INIT_SUBPARSER(ownersState, SECP256K1OutputOwners);
        } fallthrough;
        case 2: {
            if ( meta->staking_weight != meta->staked ) REJECT("Stake total did not match sum of stake UTXOs: %.*h %.*h", 8, &meta->staking_weight, 8, &meta->staked);
            CALL_SUBPARSER(ownersState, SECP256K1OutputOwners);
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
        } fallthrough;
        case 3: {
            // Add delegator transactions don't include shares.
            if(meta->type_id.p == TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR) {
              sub_rv = PARSE_RV_DONE;
              state->state++;
              break;
            }
            CALL_SUBPARSER(uint32State, uint32_t);
            state->state++;
            ADD_PROMPT("Delegation Fee", &state->uint32State.val, sizeof(uint32_t), delegation_fee_to_string);
            BREAK_IF_PROMPT_FLUSH;
        } fallthrough;
        case 4:
             // This is bc we call the parser recursively, and, at the end, it gets called with
             // nothing to parse...But it exits without unwinding the stack, so if we are here,
             // we need to set this in order to exit properly
            sub_rv = PARSE_RV_DONE;
    }
    return sub_rv;
}

void init_AddSNValidatorTransaction(struct AddSNValidatorTransactionState *const state) {
  state->state = 0;
  INIT_SUBPARSER(validatorState, Validator);
}

enum parse_rv parse_AddSNValidatorTransaction(
  struct AddSNValidatorTransactionState *const state,
  parser_meta_state_t *const meta)
{
  enum parse_rv sub_rv = PARSE_RV_INVALID;
  switch(state->state)
  {
    case 0: //ChainID
      CALL_SUBPARSER(validatorState, Validator);
      state->state++;
      INIT_SUBPARSER(id32State, Id32);
      fallthrough;
    case 1: {//Subnet ID
      CALL_SUBPARSER(id32State, Id32);
      ADD_PROMPT("Subnet", &state->id32State.val, sizeof(Id32), ids_to_string);
      state->state++;
      INIT_SUBPARSER(subnetauthState, SubnetAuth);
      RET_IF_PROMPT_FLUSH;
    } fallthrough;
    case 2: {
      CALL_SUBPARSER(subnetauthState, SubnetAuth);
      state->state++;
    } fallthrough;
    case 3:
      sub_rv = PARSE_RV_DONE;
  }
  return sub_rv;
}

void init_Genesis(struct Genesis_state *const state)
{
  state->state = 0;
  INIT_SUBPARSER(gen_n_state, uint32_t);
}

enum parse_rv parse_Genesis(struct Genesis_state *const state, parser_meta_state_t *const meta)
{
  enum parse_rv sub_rv = PARSE_RV_INVALID;
rebranch:
  switch(state->state)
  {
    case 0: {
      // Number of bytes of Genesis Data
      CALL_SUBPARSER(gen_n_state, uint32_t);
      uint32_t temp = state->gen_n_state.val;
      state->gen_n = temp;
      state->gen_i = 0;
      cx_sha256_init(&state->genhash_state);
      state->state++;
      PRINTF("Gen Data Count\n");
    } fallthrough;
    case 1: {
      // loop invariant
      if (state->gen_i >= state->gen_n)
      {
        THROW(EXC_MEMORY_ERROR);
      }

      if (state->gen_i == state->gen_n)
      {
        state->state++;
        goto rebranch;
      }

      parser_input_meta_state_t * input = &meta->input;

      size_t const available = input->length - input->consumed;
      size_t const needed = state->gen_n - state->gen_i;
      size_t const to_hash = MIN(needed, available);
      update_hash(&state->genhash_state, &meta->input.src[input->consumed], to_hash);
      state->gen_i += to_hash;
      input->consumed += to_hash;
      sub_rv = state->gen_i == state->gen_n ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
      RET_IF_NOT_DONE;

      state->state++;
    } fallthrough;
    case 2: {
      if (state->gen_i <  state->gen_n)
      {
        PRINTF("Should not have gotten here yet\n");
        THROW(EXC_MEMORY_ERROR);
      }

      state->state++;
      genhash_t temp_final_hash;
      finish_hash((cx_hash_t *const)&state->genhash_state, &temp_final_hash);
      ADD_PROMPT("Genesis Data", &temp_final_hash, sizeof(temp_final_hash), gendata_to_hex);
      RET_IF_PROMPT_FLUSH;
    } fallthrough;
    case 3:
      sub_rv = PARSE_RV_DONE;
      break;
  }
  return sub_rv;
}



void init_CreateSubnetTransaction(struct CreateSubnetTransactionState *const state)
{
  state->state = 0;
  INIT_SUBPARSER(ownersState, SECP256K1OutputOwners);
}

enum parse_rv parse_CreateSubnetTransaction(
     struct CreateSubnetTransactionState *const state,
     parser_meta_state_t *const meta)

{
  enum parse_rv sub_rv = PARSE_RV_INVALID;
  switch(state->state)
  {
    case 0:
      CALL_SUBPARSER(ownersState, SECP256K1OutputOwners);
      state->state++;
      fallthrough;
    case 1:
      sub_rv = PARSE_RV_DONE;
      break;
  }
  return sub_rv;
}

void init_ChainName(struct ChainName_state *const state)
{
  state->state = 0;
  INIT_SUBPARSER(uint16State, uint16_t);
}

enum parse_rv parse_ChainName(struct ChainName_state *const state, parser_meta_state_t *const meta)
{
  enum parse_rv sub_rv = PARSE_RV_INVALID;
rebranch:
  switch(state->state)
  {
    case 0:
      // Number of bytes in Chain Name
      CALL_SUBPARSER(uint16State, uint16_t);
      state->state++;
      state->name.buffer_size = state->uint16State.val;
      state->chainN_i = 0;
      memset(state->name.buffer, 0, sizeof(state->name.buffer));
      if (state->name.buffer_size > sizeof(state->name.buffer)) {
        PRINTF("Chain Name is too long");
        THROW(EXC_MEMORY_ERROR);
      }
      PRINTF("Chain Name Length: %d\n", state->name.buffer_size);
      fallthrough;
    case 1: {
      // loop invariant
      if (state->chainN_i == state->name.buffer_size)
      {
        THROW(EXC_MEMORY_ERROR);
      }

      if (state->chainN_i == state->name.buffer_size)
      {
        state->state++;
        goto rebranch;
      }

      parser_input_meta_state_t * input = &meta->input;

      size_t const available = input->length - input->consumed;
      size_t const needed = state->name.buffer_size - state->chainN_i;
      size_t const to_copy = MIN(needed, available);
      memcpy(&state->name.buffer, &meta->input.src[input->consumed], to_copy);
      state->chainN_i += to_copy;
      input->consumed += to_copy;
      sub_rv = state->chainN_i == state->name.buffer_size ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
      RET_IF_NOT_DONE;

      state->state++;
    } fallthrough;
    case 2: {
      if (state->chainN_i <  state->name.buffer_size)
      {
        PRINTF("Should not have gotten here yet\n");
        THROW(EXC_MEMORY_ERROR);
      }
      state->state++;
      ADD_PROMPT("Chain Name", &state->name, sizeof(state->name), chainname_to_string);
      RET_IF_PROMPT_FLUSH;
    } fallthrough;
    case 3:
      sub_rv = PARSE_RV_DONE;
      break;
  }
  return sub_rv;
}

void init_CreateChainTransaction(struct CreateChainTransactionState *const state) {
  state->state = 0;
  state->fxid_i = 0;
  INIT_SUBPARSER(id32State, Id32);
}

enum parse_rv parse_CreateChainTransaction(
  struct CreateChainTransactionState *const state,
  parser_meta_state_t *const meta)
{
  enum parse_rv sub_rv = PARSE_RV_INVALID;
  switch(state->state)
  {
    case 0: // Subnet ID
      CALL_SUBPARSER(id32State, Id32);
      ADD_PROMPT("Subnet", &state->id32State.val, sizeof(Id32), ids_to_string);
      state->state++;
      INIT_SUBPARSER(chainnameState, ChainName);
      fallthrough;
    case 1: { // chain name
      CALL_SUBPARSER(chainnameState, ChainName);
      PRINTF("Done with Chain Name\n");
      state->state++;
      INIT_SUBPARSER(id32State, Id32);
    } fallthrough;
    case 2: {
      CALL_SUBPARSER(id32State, Id32);
      //PRINTF("VM ID: %.*h\n", 32, state->id32State.buf);
      ADD_PROMPT("VM ID", &state->id32State.val, sizeof(Id32), ids_to_string);
      state->state++;
      INIT_SUBPARSER(uint32State, uint32_t);
      RET_IF_PROMPT_FLUSH;
    } fallthrough;
    case 3: {
      CALL_SUBPARSER(uint32State, uint32_t);
      PRINTF("Num of fxids\n");
      state->fxid_n = state->uint32State.val;
      state->state++;
      INIT_SUBPARSER(id32State, Id32);
    } fallthrough;
    case 4: {
      if(state->fxid_i == state->fxid_n)
      {
        state->state++;
        INIT_SUBPARSER(genesisState, Genesis);
        break;
      }
      do
      {
        // loop invariant
        if(state->fxid_i == state->fxid_n)
        {
          THROW(EXC_MEMORY_ERROR);
        }

        CALL_SUBPARSER(id32State, Id32);

        PRINTF("FX ID: %.*h\n", 32, state->id32State.buf);

        state->fxid_i++;
        if(state->fxid_i < state->fxid_n)
        {
          INIT_SUBPARSER(id32State, Id32);
          continue;
        }
        else
        {
          state->state++;
          INIT_SUBPARSER(genesisState, Genesis);
          break;
        }
      } while(false);
    } fallthrough;
    case 5: {
      CALL_SUBPARSER(genesisState, Genesis);
      state->state++;
      INIT_SUBPARSER(subnetauthState, SubnetAuth);
    } fallthrough;
    case 6: {
      CALL_SUBPARSER(subnetauthState, SubnetAuth);
      state->state++;
    } fallthrough;
    case 7:
      sub_rv = PARSE_RV_DONE;
  }
  return sub_rv;
}


static char const transactionLabel[] = "Transaction";
static char const importLabel[] = "Import";
static char const exportLabel[] = "Export";
static char const validateLabel[] = "Add Validator";
static char const validatesnLabel[] = "Add Subnet Validator";
static char const createchainLabel[] = "Create Chain";
static char const delegateLabel[] = "Add Delegator";
static char const createsubnetLabel[] = "Create Subnet";

typedef struct { char const* label; size_t label_size; } label_t;

#define LABEL(l) (label_t) { .label = l ## Label, .label_size = sizeof(l ## Label) }

static label_t type_id_to_label(union transaction_type_id_t type_id, enum chain_role chain) {
  switch (chain) {
  case CHAIN_X:
    switch (type_id.x) {
    case TRANSACTION_X_CHAIN_TYPE_ID_BASE: return LABEL(transaction);
    case TRANSACTION_X_CHAIN_TYPE_ID_IMPORT: return LABEL(import);
    case TRANSACTION_X_CHAIN_TYPE_ID_EXPORT: return LABEL(export);
    default:; // throws below
    };
    break;
  case CHAIN_P:
    switch (type_id.p) {
    case TRANSACTION_P_CHAIN_TYPE_ID_IMPORT: return LABEL(import);
    case TRANSACTION_P_CHAIN_TYPE_ID_EXPORT: return LABEL(export);
    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR: return LABEL(validate);
    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR: return LABEL(validatesn);
    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN: return LABEL(createchain);
    case TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR: return LABEL(delegate);
    case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET: return LABEL(createsubnet);
    default:; // throws below
    };
    break;
  case CHAIN_C:
    switch (type_id.c) {
    case TRANSACTION_C_CHAIN_TYPE_ID_IMPORT: return LABEL(import);
    case TRANSACTION_C_CHAIN_TYPE_ID_EXPORT: return LABEL(export);
    default:; // throws below
    };
  };
  THROW(EXC_PARSE_ERROR);
}

#undef LABEL

// Call the subparser and use break on end-of-chunk;
// this allows doing chunkwise computation on the result, e.g. for hashing it.

#define CALL_SUBPARSER_BREAK(subFieldName, subParser) { \
        sub_rv = parse_ ## subParser(&state->subFieldName, meta); \
        PRINTF(#subParser " RV: %d\n", sub_rv); \
        BREAK_IF_NOT_DONE; \
    }

enum parse_rv parseTransaction(struct TransactionState *const state, parser_meta_state_t *const meta) {
    check_null(state);
    check_null(meta);
    check_null(meta->input.src);

    PRINTF("***Parse Transaction***\n");
    enum parse_rv sub_rv = PARSE_RV_INVALID;
    size_t const start_consumed = meta->input.consumed;
    switch (state->state) {
        case 0: // codec ID
            CALL_SUBPARSER_BREAK(uint16State, uint16_t);
            PRINTF("Codec ID: %d\n", state->uint16State.val);
            if (state->uint16State.val != 0) REJECT("Only codec ID 0 is supported");
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
            fallthrough;
        case 1: { // type ID
            CALL_SUBPARSER_BREAK(uint32State, uint32_t);
            state->type = state->uint32State.val;

            // Rejects invalid tx types
            meta->raw_type_id = state->type;
            state->state++;
            PRINTF("Type ID: %.*h\n", sizeof(state->uint32State.buf), state->uint32State.buf);

            INIT_SUBPARSER(baseTxHdrState, BaseTransactionHeader);
        } fallthrough;
        case 2: { // Base transaction header
            CALL_SUBPARSER_BREAK(baseTxHdrState, BaseTransactionHeader);
            PRINTF("Parsed BTH\n");
            meta->type_id = convert_type_id_to_type(meta->raw_type_id, meta->chain);
            state->state++;
            INIT_SUBPARSER(baseTxState, BaseTransaction);
            label_t label = type_id_to_label(meta->type_id, meta->chain);
            ADD_PROMPT("Sign", label.label, label.label_size, strcpy_prompt);
            BREAK_IF_PROMPT_FLUSH;
        } fallthrough;
        case 3: { // Base transaction
            switch (meta->chain) {
              case CHAIN_X:
              case CHAIN_P:
                PRINTF("TRACE pre basic tx subparser break, chain enum: %d\n", meta->chain);
                CALL_SUBPARSER_BREAK(baseTxState, BaseTransaction);
                PRINTF("TRACE post basic tx subparser\n");
                break;
              case CHAIN_C:
                // C-chain atomic transactions have a different format; skip here.
                PRINTF("SKIPPING BASE TRANSACTION\n");
                sub_rv = PARSE_RV_DONE;
                break;
            }
            BREAK_IF_NOT_DONE;

            state->state++;
            switch (meta->chain) {
            case CHAIN_X:
              switch (meta->type_id.x) {
              case TRANSACTION_X_CHAIN_TYPE_ID_BASE:
                break;
              case TRANSACTION_X_CHAIN_TYPE_ID_IMPORT:
                INIT_SUBPARSER(importTxState, ImportTransaction);
                break;
              case TRANSACTION_X_CHAIN_TYPE_ID_EXPORT:
                INIT_SUBPARSER(exportTxState, ExportTransaction);
                break;
              };
              break;
            case CHAIN_P:
              switch (meta->type_id.p) {
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR:
                INIT_SUBPARSER(addSNValidatorTxState, AddSNValidatorTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN:
                INIT_SUBPARSER(createChainTxState, CreateChainTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET:
                INIT_SUBPARSER(createSubnetTxState, CreateSubnetTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR:
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR:
                INIT_SUBPARSER(addValidatorTxState, AddValidatorTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_IMPORT:
                INIT_SUBPARSER(importTxState, ImportTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_EXPORT:
                INIT_SUBPARSER(exportTxState, ExportTransaction);
                break;
              default:
                REJECT("Only base, export, and import transactions are supported");
              };
              break;
            case CHAIN_C:
              switch (meta->type_id.c) {
              case TRANSACTION_C_CHAIN_TYPE_ID_IMPORT:
                INIT_SUBPARSER(cChainImportState, CChainImportTransaction);
                break;
              case TRANSACTION_C_CHAIN_TYPE_ID_EXPORT:
                INIT_SUBPARSER(cChainExportState, CChainExportTransaction);
                break;
              default:
                REJECT("Only base, export, and import transactions are supported");
              };
            };
        } fallthrough;
        case 4: {
            switch (meta->chain) {
            case CHAIN_X:
              switch (meta->type_id.x) {
              case TRANSACTION_X_CHAIN_TYPE_ID_BASE:
                sub_rv = PARSE_RV_DONE;
                break;
              case TRANSACTION_X_CHAIN_TYPE_ID_IMPORT:
                CALL_SUBPARSER_BREAK(importTxState, ImportTransaction);
                break;
              case TRANSACTION_X_CHAIN_TYPE_ID_EXPORT:
                CALL_SUBPARSER_BREAK(exportTxState, ExportTransaction);
                break;
              }
              break;
            case CHAIN_P:
              switch (meta->type_id.p) {
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_SN_VALIDATOR:
                CALL_SUBPARSER_BREAK(addSNValidatorTxState, AddSNValidatorTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_CHAIN:
                CALL_SUBPARSER_BREAK(createChainTxState, CreateChainTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_CREATE_SUBNET:
                CALL_SUBPARSER_BREAK(createSubnetTxState, CreateSubnetTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_VALIDATOR:
              case TRANSACTION_P_CHAIN_TYPE_ID_ADD_DELEGATOR:
                CALL_SUBPARSER_BREAK(addValidatorTxState, AddValidatorTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_IMPORT:
                CALL_SUBPARSER_BREAK(importTxState, ImportTransaction);
                break;
              case TRANSACTION_P_CHAIN_TYPE_ID_EXPORT:
                CALL_SUBPARSER_BREAK(exportTxState, ExportTransaction);
                break;
              default:
                REJECT("Only base, export, and import transactions are supported");
              }
              break;
            case CHAIN_C:
              switch (meta->type_id.c) {
              case TRANSACTION_C_CHAIN_TYPE_ID_IMPORT:
                CALL_SUBPARSER_BREAK(cChainImportState, CChainImportTransaction);
                break;
              case TRANSACTION_C_CHAIN_TYPE_ID_EXPORT:
                CALL_SUBPARSER_BREAK(cChainExportState, CChainExportTransaction);
                break;
              default:
                REJECT("Only base, export, and import transactions are supported");
              }
            }
            BREAK_IF_NOT_DONE;
            state->state++;
        } fallthrough;
        case 5: {
                  PRINTF("Prompting for fee\n");
                  if (prompt_fee(meta))
                      sub_rv = PARSE_RV_PROMPT;
                  state->state++;
                  PRINTF("Prompted for fee\n");
                  BREAK_IF_PROMPT_FLUSH;
        } fallthrough;
        case 6:
                sub_rv = PARSE_RV_DONE;
                break;
    }
    if (meta->input.consumed > start_consumed) {
        size_t consume_next = meta->input.consumed - start_consumed;
        PRINTF("Hash %d bytes of input\n", consume_next);
        update_hash(&state->hash_state, &meta->input.src[start_consumed], consume_next);
    }
    PRINTF("Consumed %d bytes of input so far\n", meta->input.consumed);
    return sub_rv;
}
