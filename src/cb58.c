/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.
 *
 * Modified to work with Avalanche CB58.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "os_cx.h"

#include "cb58.h"

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool cb58enc(/* out */ char *cb58, /* in/out */ size_t *cb58sz, const void *data, size_t binsz)
{
    // append 4-byte checksum
    const size_t checked_binsz = binsz + 4;
    uint8_t checked_bin[checked_binsz];
    memcpy(&checked_bin, data, binsz);

    cx_sha256_t hash_state;
    cx_sha256_init(&hash_state);
    uint8_t temp_sha256_hash[CX_SHA256_SIZE];
    cx_hash((cx_hash_t *)&hash_state, CX_LAST, (uint8_t const *const) data, binsz, temp_sha256_hash, CX_SHA256_SIZE);
    memcpy(&checked_bin[binsz], &temp_sha256_hash[CX_SHA256_SIZE - 4], 4);

    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < checked_binsz && !checked_bin[zcount])
        ++zcount;

    size = (checked_binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < checked_binsz; ++i, high = j)
    {
        for (carry = checked_bin[i], j = size - 1; ((int)j >= 0) && ((j > high) || carry); --j)
        {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*cb58sz <= zcount + size - j)
    {
        *cb58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount)
        memset(cb58, '1', zcount);
    for (i = zcount; j < size; ++i, ++j)
        cb58[i] = b58digits_ordered[buf[j]];

    cb58[i] = '\0';
    *cb58sz = i + 1;

    return true;
}
