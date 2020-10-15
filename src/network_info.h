#pragma once

#include "exception.h"
#include <stdint.h>
#include <string.h>

typedef enum {
  NETWORK_ID_MAINNET  = 1,
  NETWORK_ID_FUJI     = 5,
  NETWORK_ID_LOCAL    = 12345,
} network_id_t;

static inline network_id_t parse_network_id(uint32_t const val) {
  switch ((network_id_t)val) {
  case NETWORK_ID_MAINNET:
  case NETWORK_ID_FUJI:
  case NETWORK_ID_LOCAL:
    return (network_id_t)val;
  default: THROW(EXC_PARSE_ERROR);
  }
}

#define MAX_HRP_SIZE 6
#define MAX_NETWORK_NAME_SIZE 8
#define BLOCKCHAIN_ID_SIZE 32
#define ASSET_ID_SIZE 32

typedef uint8_t blockchain_id_t[BLOCKCHAIN_ID_SIZE] ;
typedef uint8_t asset_id_t[ASSET_ID_SIZE];
typedef char hrp_t[MAX_HRP_SIZE];
typedef char network_name_t[MAX_NETWORK_NAME_SIZE];

typedef struct {
  network_id_t network_id;
  blockchain_id_t blockchain_id;
  asset_id_t avax_asset_id;
  hrp_t hrp;
  network_name_t network_name;
} network_info_t;

#define NETWORK_INFO_SIZE 3

extern const network_info_t const network_info[NETWORK_INFO_SIZE];

static inline network_info_t const *network_info_from_network_id(network_id_t const network_id) {
  for (int i = 0; i < NETWORK_INFO_SIZE; i++)
    if (network_id == network_info[i].network_id)
      return &network_info[i];
  return NULL;
}

static inline network_info_t const *network_info_from_network_id_not_null(network_id_t const network_id) {
  network_info_t const *res = network_info_from_network_id(network_id);
  if (res == NULL) {
    THROW(EXC_PARSE_ERROR);
  } else {
    return res;
  }
}

static inline network_info_t const *network_info_from_blockchain_id(const blockchain_id_t const blockchain_id) {
  if (blockchain_id == NULL) return NULL;
  for (int i = 0; i < NETWORK_INFO_SIZE; i++)
    if (memcmp(blockchain_id, network_info[i].blockchain_id, sizeof(*blockchain_id)) == 0)
      return &network_info[i];
  return NULL;
}

static inline network_info_t const *network_info_from_blockchain_id_not_null(const blockchain_id_t const blockchain_id) {
  network_info_t const *res = network_info_from_blockchain_id(blockchain_id);
  if (res == NULL) {
    THROW(EXC_PARSE_ERROR);
  } else {
    return res;
  }
}
