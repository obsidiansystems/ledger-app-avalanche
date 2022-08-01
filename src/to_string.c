#include "to_string.h"

#include "apdu.h"
#include "keys.h"
#include "key_macros.h"
#include "globals.h"
#include "bech32encode.h"
#include "cb58.h"

#include <string.h>
#include <limits.h>

static const char nodeid_prefix[] = "NodeID-";
size_t nodeid_to_string(
    char out[const], size_t const out_size, public_key_hash_t const *const payload)
{
    if (out_size < sizeof(nodeid_prefix) - 1)
        THROW(EXC_MEMORY_ERROR);

    size_t ix = 0;
    memcpy(&out[ix], nodeid_prefix, sizeof(nodeid_prefix) - 1);
    ix += sizeof(nodeid_prefix) - 1;

    size_t b58sz = out_size - ix;
    if (!cb58enc(&out[ix], &b58sz, (const void*)payload, sizeof(*payload)))
        THROW(EXC_MEMORY_ERROR);

    return b58sz;
}

size_t chain_name_to_string(
    char out[const], size_t const out_size, uint8_t const *const payload, size_t const buf_size)
{
  if (buf_size > out_size)
      THROW(EXC_MEMORY_ERROR);
  
  size_t chain_name_size;
  size_t ix = 0;
  char terminate = '\0';

  memcpy(&out[ix], (const char*)payload, buf_size);
  ix += buf_size;
  
  memcpy(&out[ix], &terminate, sizeof(char));
  
  chain_name_size = out_size - ix;
  
  return chain_name_size;
}

size_t id_to_string(
    char out[const], size_t const out_size, Id32 const *const payload)
{
    if (out_size == 0)
        THROW(EXC_MEMORY_ERROR);

    size_t b58sz = out_size;
    if (!cb58enc(out, &b58sz, (const void*)payload, sizeof(*payload)))
        THROW(EXC_MEMORY_ERROR);
    return b58sz;
}

size_t buf_to_string(
    char out[const], size_t const out_size, uint8_t const *const payload, size_t const buf_size)
{
    size_t b58sz = out_size;
    if (!cb58enc(out, &b58sz, (const void*)payload, buf_size))
        THROW(EXC_MEMORY_ERROR);
    return b58sz;
}

size_t pkh_to_string(
    char out[const], size_t const out_size,
    char const *const hrp, size_t const hrp_size,
    public_key_hash_t const *const payload)
{
    uint8_t base32_enc[32];

    size_t base32_size = sizeof(base32_enc);
    if (!base32_encode(base32_enc, &base32_size, (uint8_t const *const)payload, sizeof(*payload))) {
        THROW(EXC_MEMORY_ERROR);
    }

    size_t bech32_out_size = out_size;
    if (!bech32_encode(out, &bech32_out_size, hrp, hrp_size, base32_enc, base32_size)) {
        THROW(EXC_MEMORY_ERROR);
    }
    return bech32_out_size;
}

static inline void bound_check_buffer(size_t const counter, size_t const size) {
    if (counter >= size) {
        THROW(EXC_MEMORY_ERROR);
    }
}

void bip32_path_to_string(
    char out[const], size_t const out_size, bip32_path_t const *const path)
{
    check_null(out);
    check_null(path);
    size_t out_current_offset = 0;
    for (int i = 0; i < MAX_BIP32_PATH && i < path->length; i++) {
        bool const is_hardened = path->components[i] & BIP32_HARDENED_PATH_BIT;
        uint32_t const component = path->components[i] & ~BIP32_HARDENED_PATH_BIT;
        number_to_string_indirect32(out + out_current_offset, out_size - out_current_offset, &component);
        out_current_offset = strlen(out);
        if (is_hardened) {
            bound_check_buffer(out_current_offset, out_size);
            out[out_current_offset++] = '\'';
        }
        if (i < path->length - 1) {
            bound_check_buffer(out_current_offset, out_size);
            out[out_current_offset++] = '/';
        }
        bound_check_buffer(out_current_offset, out_size);
        out[out_current_offset] = '\0';
    }
}

// These functions do not output terminating null bytes.

// This function fills digits, potentially with all leading zeroes, from the end of the buffer backwards
// This is intended to be used with a temporary buffer of length MAX_INT_DIGITS
// Returns offset of where it stopped filling in
static inline size_t convert_number(
    char dest[MAX_INT_DIGITS], uint64_t number, bool leading_zeroes)
{
    check_null(dest);
    char *const end = dest + MAX_INT_DIGITS;
    for (char *ptr = end - 1; ptr >= dest; ptr--) {
        *ptr = '0' + number % 10;
        number /= 10;
        if (!leading_zeroes && number == 0) { // TODO: This is ugly
            return ptr - dest;
        }
    }
    return 0;
}

// add a fixed number of zeros with padding
static inline size_t convert_number_fixed(
    char dest[MAX_INT_DIGITS], uint64_t number, size_t padding)
{
    check_null(dest);
    char *const end = dest + padding;
    for (char *ptr = end - 1; ptr >= dest; ptr--) {
        *ptr = '0' + number % 10;
        number /= 10;
    }
    if (number != 0) THROW(EXC_PARSE_ERROR);
    return padding;
}

void number_to_string_indirect64(
    char dest[const], size_t const buff_size,
    uint64_t const *const number)
{
  check_null(dest);
  check_null(number);
  if (buff_size < MAX_INT_DIGITS + 1)
    THROW(EXC_WRONG_LENGTH); // terminating null
  number_to_string(dest, *number);
}

void number_to_string_indirect32(
    char dest[const], size_t const buff_size,
    uint32_t const *const number)
{
    check_null(dest);
    check_null(number);
    if (buff_size < MAX_INT_DIGITS + 1)
        THROW(EXC_WRONG_LENGTH); // terminating null
    number_to_string(dest, *number);
}

#define DELEGATION_FEE_DIGITS 4
#define DELEGATION_FEE_SCALE 10000

void delegation_fee_to_string(
    char dest[const], size_t const buff_size,
    uint32_t const *const delegation_fee)
{
    check_null(dest);
    check_null(delegation_fee);

    if (buff_size < 13) // 429496.7295%
      THROW(EXC_WRONG_LENGTH);

    uint32_t whole_percent = *delegation_fee / DELEGATION_FEE_SCALE;
    uint32_t fractional_percent = *delegation_fee % DELEGATION_FEE_SCALE;
    size_t off = number_to_string(dest, whole_percent);
    if (fractional_percent == 0) {
        dest[off++] = '%';
        dest[off++] = '\0';
        return;
    }
    dest[off++] = '.';

    char tmp[MAX_INT_DIGITS];
    convert_number(tmp, fractional_percent, true);

    // Eliminate trailing 0s
    char *start = tmp + MAX_INT_DIGITS - DELEGATION_FEE_DIGITS;
    char *end;
    for (end = tmp + MAX_INT_DIGITS - 1; end >= start; end--) {
        if (*end != '0') {
            end++;
            break;
        }
    }

    size_t length = end - start;
    memcpy(dest + off, start, length);
    off += length;

    dest[off++] = '%';
    dest[off++] = '\0';
}

size_t number_to_string(
    char dest[const], uint64_t number) {
    check_null(dest);
    char tmp[MAX_INT_DIGITS];
    size_t off = convert_number(tmp, number, false);

    // Copy without leading 0s
    size_t length = sizeof(tmp) - off;
    memcpy(dest, tmp + off, length);
    dest[length] = '\0';
    return length;
}

#define DECIMAL_DIGITS 9
#define NANO_AVAX_SCALE 1000000000
#define WEI_GWEI_SCALE 1000000000
#define WEI_NAVAX_DIGITS 9
#define WEI_AVAX_DIGITS 18

// Display avax in human readable form
size_t subunit_to_unit_string(
    char dest[const], size_t const buff_size,
    uint64_t subunits, uint64_t scale)
{
    check_null(dest);

    if (buff_size < MAX_INT_DIGITS + 2)
      THROW(EXC_WRONG_LENGTH); // terminating null

    uint64_t whole_avax = subunits / scale;
    uint64_t fractional_avax = subunits % scale;
    size_t off = number_to_string(dest, whole_avax);
    if (fractional_avax == 0) {
        return off;
    }
    dest[off++] = '.';

    char tmp[MAX_INT_DIGITS];
    convert_number(tmp, fractional_avax, true);

    // Eliminate trailing 0s
    char *start = tmp + MAX_INT_DIGITS - DECIMAL_DIGITS;
    char *end;
    for (end = tmp + MAX_INT_DIGITS - 1; end >= start; end--) {
        if (*end != '0') {
            end++;
            break;
        }
    }

    size_t length = end - start;
    memcpy(dest + off, start, length);
    off += length;
    dest[off] = '\0';
    return off;
}

// Display avax in human readable form
size_t subunit_to_unit_string_256(
    char dest[const], size_t const buff_size,
    const uint256_t *const subunits, uint8_t digits)
{
    check_null(dest);
    size_t off = tostring256_fixed_point(subunits, 10, digits, dest, buff_size);

    if (off == (size_t)-1)
      THROW(EXC_WRONG_LENGTH); // terminating null

    return off;
}

size_t nano_avax_to_string(
    char dest[const], size_t const buff_size,
    uint64_t const nano_avax)
{
  static char const unit[] = " AVAX";
  size_t ix = subunit_to_unit_string(dest, buff_size, nano_avax, NANO_AVAX_SCALE);
  if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' AVAX' into prompt value string");
  memcpy(&dest[ix], unit, sizeof(unit));
  ix += sizeof(unit) - 1;
  return ix;
}

size_t wei_to_gwei_string(
    char dest[const], size_t const buff_size,
    uint64_t const wei)
{
  static char const unit[] = " GWEI";
  size_t ix = subunit_to_unit_string(dest, buff_size, wei, WEI_GWEI_SCALE);
  if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' GWEI' into prompt value string");
  memcpy(&dest[ix], unit, sizeof(unit));
  ix += sizeof(unit) - 1;
  return ix;
}
size_t wei_to_gwei_string_256(
    char dest[const], size_t const buff_size,
    uint256_t const* wei)
{
  static char const unit[] = " GWEI";
  size_t ix = subunit_to_unit_string_256(dest, buff_size, wei, 9);
  if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' GWEI' into prompt value string");
  memcpy(&dest[ix], unit, sizeof(unit));
  ix += sizeof(unit) - 1;
  return ix;
}
size_t wei_to_navax_string(
    char dest[const], size_t const buff_size,
    uint64_t const wei)
{
  static char const unit[] = " nAVAX";
  size_t ix = subunit_to_unit_string(dest, buff_size, wei, WEI_GWEI_SCALE);
  if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' nAVAX' into prompt value string");
  memcpy(&dest[ix], unit, sizeof(unit));
  ix += sizeof(unit) - 1;
  return ix;
}

size_t wei_to_avax_or_navax_string_256(
    char dest[const], size_t const buff_size,
    uint256_t const *const wei)
{
  const uint8_t AVAX_NAVAX_DISPLAY_THRESHOLD_BE[] = {
      0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0, 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
      0x0, 0x03, 0x8D, 0x7E, 0xA4, 0xC6, 0x80, 0x00}; // 38D7EA4C68000 = 1000000000000000dec
  uint256_t AVAX_NAVAX_DISPLAY_THRESHOLD_256;
  readu256BE(AVAX_NAVAX_DISPLAY_THRESHOLD_BE, &AVAX_NAVAX_DISPLAY_THRESHOLD_256);

  if (gte256(wei, &AVAX_NAVAX_DISPLAY_THRESHOLD_256)) {
    static char const unit[] = " AVAX";
    size_t ix = subunit_to_unit_string_256(dest, buff_size, wei, WEI_AVAX_DIGITS);
    if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' AVAX' into prompt value string");
    memcpy(&dest[ix], unit, sizeof(unit));
    ix += sizeof(unit) - 1;
    return ix;
  } else {
    static char const unit[] = " nAVAX";
    size_t ix = subunit_to_unit_string_256(dest, buff_size, wei, WEI_NAVAX_DIGITS);
    if (ix + sizeof(unit) > buff_size) THROW_(EXC_MEMORY_ERROR, "Can't fit ' nAVAX' into prompt value string");
    memcpy(&dest[ix], unit, sizeof(unit));
    ix += sizeof(unit) - 1;
    return ix;
  }
}

void nano_avax_to_string_indirect64(
    char dest[const], size_t const buff_size,
    uint64_t const *const number)
{
    check_null(number);
    nano_avax_to_string(dest, buff_size, *number);
}

void copy_string(
    char dest[const], size_t const buff_size,
    char const *const src)
{
    check_null(dest);
    check_null(src);
    char const *const src_in = (char const *)PIC(src);
    // I don't care that we will loop through the string twice, latency is not an issue
    if (strlen(src_in) >= buff_size)
        THROW(EXC_WRONG_LENGTH);
    strncpy(dest, src_in, buff_size);
}

void bin_to_hex(
    char out[const], size_t const out_size,
    uint8_t const *const in, size_t const in_size)
{
    check_null(out);
    check_null(in);

    size_t const out_len = in_size * 2;
    if (out_size < out_len + 1)
        THROW(EXC_MEMORY_ERROR);

    char const *const src = (char const *)PIC(in);
    for (size_t i = 0; i < in_size; i++) {
        out[i * 2] = "0123456789ABCDEF"[src[i] >> 4];
        out[i * 2 + 1] = "0123456789ABCDEF"[src[i] & 0x0F];
    }
    out[out_len] = '\0';
}

void bin_to_hex_lc(
    char out[], size_t const out_size,
    uint8_t const in[], size_t const in_size)
{
    check_null(out);
    check_null(in);

    size_t const out_len = in_size * 2;
    if (out_size < out_len + 1)
    {
        THROW(EXC_MEMORY_ERROR);
    }

    uint8_t const *const src = (uint8_t const *)PIC(in);

    for (size_t i = 0; i < in_size; i++) {
        out[i * 2] = "0123456789abcdef"[src[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[src[i] & 0x0F];
    }
    out[out_len] = '\0';
}

void buffer_to_hex(
    char out[const], size_t const out_size, buffer_t const *const in) {
    check_null(out);
    check_null(in);
    buffer_t const *const src = (buffer_t const *)PIC(in);
    bin_to_hex(out, out_size, src->bytes, src->length);
}

// Time format implementation based on musl’s __secs_to_tm
// https://git.musl-libc.org/cgit/musl/tree/src/time/__secs_to_tm.c

/* 2000-03-01 (mod 400 year, immediately after feb29 */
#define LEAPOCH (946684800LL + 86400*(31+29))

#define DAYS_PER_400Y (365*400 + 97)
#define DAYS_PER_100Y (365*100 + 24)
#define DAYS_PER_4Y   (365*4   + 1)

 // YYYY-MM-DD HH:MM:SS UTC
#define TIME_FORMAT_SIZE 23

size_t time_to_string(
    char dest[const], size_t const buff_size,
    uint64_t const *const time)
{
    check_null(dest);
    check_null(time);

    if (buff_size + 1 < TIME_FORMAT_SIZE)
        THROW(EXC_WRONG_LENGTH);

    int64_t days, secs;
    int remdays, remsecs, remyears;
    int qc_cycles, c_cycles, q_cycles;
    int years, months;
    static const char days_in_month[] = {31,30,31,30,31,31,30,31,30,31,31,29};

    secs = *time - LEAPOCH;
    days = secs / 86400;
    remsecs = secs % 86400;
    if (remsecs < 0) {
        remsecs += 86400;
        days--;
    }

    qc_cycles = days / DAYS_PER_400Y;
    remdays = days % DAYS_PER_400Y;
    if (remdays < 0) {
        remdays += DAYS_PER_400Y;
        qc_cycles--;
    }

    c_cycles = remdays / DAYS_PER_100Y;
    if (c_cycles == 4) c_cycles--;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = remdays / DAYS_PER_4Y;
    if (q_cycles == 25) q_cycles--;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = remdays / 365;
    if (remyears == 4) remyears--;
    remdays -= remyears * 365;

    years = remyears + 4*q_cycles + 100*c_cycles + 400LL*qc_cycles;

    for (months=0; days_in_month[months] <= remdays; months++)
        remdays -= days_in_month[months];

    if (months >= 10) {
        months -= 12;
        years++;
    }

    if (years < 20) THROW(EXC_PARSE_ERROR);

    size_t ix = 0;

    // format is YYYY-MM-DD HH:MM:SS UTC
    ix += convert_number_fixed(&dest[ix], years + 2000, 4);
    dest[ix++] = '-';
    ix += convert_number_fixed(&dest[ix], months + 3, 2);
    dest[ix++] = '-';
    ix += convert_number_fixed(&dest[ix], remdays + 1, 2);
    dest[ix++] = ' ';
    ix += convert_number_fixed(&dest[ix], remsecs / 3600, 2);
    dest[ix++] = ':';
    ix += convert_number_fixed(&dest[ix], remsecs / 60 % 60, 2);
    dest[ix++] = ':';
    ix += convert_number_fixed(&dest[ix], remsecs % 60, 2);
    dest[ix++] = ' ';
    dest[ix++] = 'U';
    dest[ix++] = 'T';
    dest[ix++] = 'C';
    dest[ix++] = '\0';

    return ix;
}


void time_to_string_void_ret(
    char dest[const], size_t const buff_size,
    uint64_t const *const time)
{
    return (void)time_to_string(dest, buff_size, time);
}
