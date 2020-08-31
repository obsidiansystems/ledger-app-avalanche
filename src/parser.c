#include "types.h"
#include "globals.h"
#include "parser.h"
#include "protocol.h"

#define REJECT(msg, ...) { PRINTF("Rejecting: " msg "\n", ##__VA_ARGS__); THROW(EXC_REJECT); }

#define CALL_SUBPARSER(subFieldName, subParser) { \
  sub_rv = parse_ ## subParser(&state->subFieldName, buf); \
    if (sub_rv != PARSE_RV_DONE) break; \
  }

#define INIT_SUBPARSER(subFieldName, subParser) \
  init_ ## subParser(&state->subFieldName);

void initFixed(struct FixedState* state, size_t len) {
    state->filledTo = 0;
    memset(&state->buffer, 0, len);
}

enum parse_rv parseFixed(struct FixedState* state, struct buf* buf, size_t len) {
    size_t available = buf->length - buf->consumed;
    size_t needed = len - state->filledTo;
    size_t to_copy = available > needed ? needed : available;
    memcpy(state->buffer + state->filledTo, buf->src + buf->consumed, to_copy);
    state->filledTo += to_copy;
    buf->consumed += to_copy;
    return state->filledTo == len ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
}

#define IMPL_FIXED(name) \
    inline enum parse_rv parse_ ## name (struct name ## _state *state, struct buf* buf) { \
        return parseFixed((struct FixedState*) state, buf, sizeof(name));\
    } \
    inline void init_ ## name (struct name ## _state *state) { \
        return initFixed((struct FixedState*) state, sizeof(state)); \
    }

#define IMPL_FIXED_BE(name) \
    inline enum parse_rv parse_ ## name (struct name ## _state *state, struct buf* buf) { \
        enum parse_rv sub_rv; \
        sub_rv = parseFixed((struct FixedState*) state, buf, sizeof(name)); \
        if (sub_rv == PARSE_RV_DONE) { \
            state->val = READ_UNALIGNED_BIG_ENDIAN(name, state->buf); \
        } \
        return sub_rv; \
    } \
    inline void init_ ## name (struct name ## _state *state) { \
        return initFixed((struct FixedState*) state, sizeof(state)); \
    }

IMPL_FIXED_BE(uint32_t);
IMPL_FIXED_BE(uint64_t);
IMPL_FIXED(Id32);
IMPL_FIXED(Address);

void init_SECP256K1TransferOutput(struct SECP256K1TransferOutput_state *state) {
    state->state = 0;
    state->address_n = 0;
    state->address_i = 0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

enum parse_rv parse_SECP256K1TransferOutput(struct SECP256K1TransferOutput_state *state, struct buf* buf) {
  enum parse_rv sub_rv;
  switch (state->state) {
      case 0:
          // Amount; Type is already handled in init_Output
          CALL_SUBPARSER(uint64State, uint64_t);
          state->state++;
          PRINTF("OUTPUT AMOUNT: %.*h\n", 8, state->uint64State.buf); // we don't seem to have longs in printf specfiers.
          INIT_SUBPARSER(uint64State, uint64_t);
      case 1:
          // Locktime
          CALL_SUBPARSER(uint64State, uint64_t);
          PRINTF("LOCK TIME: %.*h\n", 8, state->uint64State.buf); // we don't seem to have longs in printf specfiers.
          state->state++;
          INIT_SUBPARSER(uint32State, uint32_t);
      case 2:
          // Threshold
          CALL_SUBPARSER(uint32State, uint32_t);
          PRINTF("Threshold: %d\n", state->uint32State.val);
          state->state++;
          INIT_SUBPARSER(uint32State, uint32_t);
      case 3: // Address Count
          CALL_SUBPARSER(uint32State, uint32_t);
          state->state++;
          state->address_n = state->uint32State.val;
          INIT_SUBPARSER(addressState, Address);
      case 4:
        while (1) {
            CALL_SUBPARSER(addressState, Address);
            state->address_i++;
            PRINTF("Output address %d: %.*h\n", state->address_i, 20, state->addressState.buf);
            if (state->address_i == state->address_n) return PARSE_RV_DONE;
            INIT_SUBPARSER(addressState, Address);
        }
  }
  return sub_rv;
}

void init_Output(struct Output_state *state) {
    state->state = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Output(struct Output_state *state, struct buf *buf) {
    enum parse_rv sub_rv;
    switch (state->state) {
      case 0:
          CALL_SUBPARSER(uint32State, uint32_t);
          state->type = state->uint32State.val;
          state->state++;
          switch (state->type) {
              case 0x00000007:
                INIT_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
                state->state++;
          }
      case 1:
          switch (state->type) {
              case 0x00000007:
                  PRINTF("SECP256K1TransferOutput\n");
                  CALL_SUBPARSER(secp256k1TransferOutput, SECP256K1TransferOutput);
          }
    }
    return sub_rv;
}

void init_TransferableOutput(struct TransferableOutput_state *state) {
    state->state = 0;
    INIT_SUBPARSER(id32State, Id32);
}

enum parse_rv parse_TransferableOutput(struct TransferableOutput_state *state, struct buf *buf) {
    PRINTF("***Parse Transferable Output***\n");
    enum parse_rv sub_rv;

    switch (state->state) {
      case 0: // asset ID
          CALL_SUBPARSER(id32State, Id32);
          state->state++;
          PRINTF("Asset ID: %.*h\n", 32, state->id32State.buf);
          INIT_SUBPARSER(outputState, Output);
      case 1:
          CALL_SUBPARSER(outputState, Output);
    }
    return sub_rv;
}

void init_SECP256K1TransferInput(struct SECP256K1TransferInput_state *state) {
    state->state = 0;
    state->address_index_i = 0;
    state->address_index_n = 0;
    INIT_SUBPARSER(uint64State, uint64_t);
}

enum parse_rv parse_SECP256K1TransferInput(struct SECP256K1TransferInput_state *state, struct buf *buf) {
    enum parse_rv sub_rv;

    switch (state->state) {
        case 0: // Amount
            CALL_SUBPARSER(uint64State, uint64_t);
            state->state++;
            PRINTF("Amount: %.*h\n", sizeof(uint64_t), state->uint64State.buf);
            INIT_SUBPARSER(uint32State, uint32_t);
        case 1: // Number of address indices
            CALL_SUBPARSER(uint32State, uint32_t);
            state->address_index_n = state->uint32State.val;
            state->state++;
            INIT_SUBPARSER(uint32State, uint32_t);
        case 2: // Address indices
            while(1) {
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



void init_Input(struct Input_state *state) {
    state->state = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Input(struct Input_state *state, struct buf *buf) {
    enum parse_rv sub_rv;

    switch (state->state) {
        case 0:
            CALL_SUBPARSER(uint32State, uint32_t);
            state->type = state->uint32State.val;
            state->state++;
            switch (state->type) {
                case 0x00000005: // SECP256K1 transfer input
                  INIT_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
            }
        case 1:
            switch (state->type) {
                case 0x00000005: // SECP256K1 transfer input
                    PRINTF("SECP256K1 Input\n");
                    CALL_SUBPARSER(secp256k1TransferInput, SECP256K1TransferInput);
            }
    }

    return sub_rv;
}

void init_TransferableInput(struct TransferableInput_state *state) {
    state->state = 0;
    INIT_SUBPARSER(id32State, Id32);
}

enum parse_rv parse_TransferableInput(struct TransferableInput_state *state, struct buf *buf) {
    enum parse_rv sub_rv;

    switch (state->state) {
        case 0: // tx_id
            CALL_SUBPARSER(id32State, Id32);
            state->state++;
            PRINTF("TX_ID: %.*h\n", 32, state->id32State.buf);
            INIT_SUBPARSER(uint32State, uint32_t);
        case 1: // utxo_index
            CALL_SUBPARSER(uint32State, uint32_t);
            PRINTF("UTXO_INDEX: %u\n", state->uint32State.val);
            state->state++;
            INIT_SUBPARSER(id32State, Id32);
        case 2: // asset_id
            CALL_SUBPARSER(id32State, Id32);
            PRINTF("ASSET ID: %u\n", state->uint32State.val);
            state->state++;
            INIT_SUBPARSER(inputState, Input);
        case 3: // Input
            CALL_SUBPARSER(inputState, Input);
    }

    return sub_rv;
}

#define IMPL_ARRAY(name) \
    void init_ ## name ## s (struct name ## s_state *state) { \
        state->state = 0; \
        state->i = 0; \
        init_uint32_t(&state->len_state); \
    } \
    enum parse_rv parse_ ## name ## s (struct name ## s_state *state, struct buf* buf) { \
        enum parse_rv sub_rv; \
        switch (state->state) { \
            case 0: \
                CALL_SUBPARSER(len_state, uint32_t); \
                state->len = READ_UNALIGNED_BIG_ENDIAN(uint32_t, state->len_state.buf); \
                state->state++; \
                init_ ## name(&state->item); \
            case 1: \
                while (1) { \
                    PRINTF(#name " %d\n", state->i + 1); \
                    CALL_SUBPARSER(item, name); \
                    state->i++; \
                    if (state->i == state->len) return PARSE_RV_DONE; \
                    init_ ## name(&state->item); \
                } \
                break; \
        } \
        return sub_rv; \
    }

IMPL_ARRAY(TransferableOutput);
IMPL_ARRAY(TransferableInput);

void init_Memo(struct Memo_state *state) {
    state->state = 0;
    state->n = 0;
    state->i = 0;
    INIT_SUBPARSER(uint32State, uint32_t);
}

enum parse_rv parse_Memo(struct Memo_state *state, struct buf* buf) {
    enum parse_rv sub_rv;

    switch (state->state) {
        case 0:
            CALL_SUBPARSER(uint32State, uint32_t);
            state->n = state->uint32State.val;
            state->state++;
        case 1: {
            size_t available = buf->length - buf->consumed;
            size_t needed = state->n - state->i;
            size_t to_consume = available > needed ? needed : available;
            state->i += to_consume;
            PRINTF("Memo bytes: %.*h\n", to_consume, buf->src + buf->consumed);
            buf->consumed += to_consume;
            sub_rv = state->i == state->n ? PARSE_RV_DONE : PARSE_RV_NEED_MORE;
        }
    }

    return sub_rv;
}

void initTransaction(struct TransactionState* state) {
    state->state = 0;
    init_uint32_t(&state->uint32State);
    cx_sha256_init(&state->hash_state);
}

void update_transaction_hash(cx_sha256_t *const state, uint8_t const *const src, size_t const length) {
    PRINTF("HASH DATA: %.*h\n", length, src);
    cx_hash((cx_hash_t *const)state, 0, src, length, NULL, 0);
}

enum parse_rv parseTransaction(struct TransactionState *const state, struct buf *const buf) {
    PRINTF("***Parse Transaction***\n");
    enum parse_rv sub_rv;

    uint8_t *start = buf->src + buf->consumed;

    switch (state->state) {
        case 0: // type ID
            CALL_SUBPARSER(uint32State, uint32_t);
            // Keep this so we can switch on it for supporting more than BaseTx
            state->type = state->uint32State.val;
            if (state->type != 0) REJECT("Only Base Tx is supported");
            state->state++;
            PRINTF("Type ID: %.*h\n", 4, state->uint32State.buf);
            INIT_SUBPARSER(uint32State, uint32_t);
        case 1: // Network ID
            CALL_SUBPARSER(uint32State, uint32_t);
            state->state++;
            PRINTF("Network ID: %.*h\n", 4, state->uint32State.buf);
            INIT_SUBPARSER(id32State, Id32);
        case 2: // blockchain ID
            CALL_SUBPARSER(id32State, Id32);
            PRINTF("Blockchain ID: %.*h\n", 32, state->id32State.buf);
            state->state++;
            INIT_SUBPARSER(outputsState, TransferableOutputs);
        case 3: // outputs
            CALL_SUBPARSER(outputsState, TransferableOutputs);
            PRINTF("Done with outputs\n");
            state->state++;
            INIT_SUBPARSER(inputsState, TransferableInputs);
        case 4: // inputs
            CALL_SUBPARSER(inputsState, TransferableInputs);
            PRINTF("Done with inputs\n");
            state->state++;
            INIT_SUBPARSER(memoState, Memo);
        case 5: // memo
            CALL_SUBPARSER(memoState, Memo);
            PRINTF("Done with memo; done.\n");
    }

    update_transaction_hash(&state->hash_state, start, buf->consumed);

    return sub_rv;
}

/*
parse_rv parseSomeObject(struct SomeObjectState *state, struct buf *buffer) {
    parse_rv sub_rv;

    // If we need to operate chunk-wise on this object, save the starting point of the buffer:
    size_t chunkStart = buffer->consumed;

    // Almost the whole function is embedded in a switch on the state:
    switch (state->stateIndex) {
      case 0:
        sub_rv = parseUint32(&(state->firstIntElement), buffer);
        if (sub_rv != PARSE_RV_DONE) break;

        // Here we can do something based on parseUint32 being done; we know we
        // have a whole int in state->firstIntElement->val to read.

        // Don't allow 4s:
        if (state->firstIntElement->val == 4) {
            PRINTF("Rejected: I arbitrarily hate 4\n");
            THROW(EXC_REJECT);
        }

        // and then before the next case statement we increment our state and initialize the next child:
        state->stateIndex++; // Not necessarily linear, but good practice in general.
        initSomeChildObject(&state->someChildName);

      case 1:
          sub_rv = parseSomeChild(&(state->someOtherChildName), buffer);
          ... // much the same as above, but for the next member of the structure, etc, etc.


      case last:
          sub_rv = someLastParser(...);
          ...
          sub_rv = PARSE_RV_DONE;
          break;
    }


    // As we saved our start point above, we can now operate on this object as a
    // stream of unstructured chunks at this point (e.g. to hash it);
    update_some_hash_func(buffer->src + chunkStart, buffer->consumed - chunkStart);

    return sub_rv;
}
*/
