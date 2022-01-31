#include "network_info.h"

const network_info_t network_info[NETWORK_INFO_SIZE] =
{
  { .network_id = NETWORK_ID_MAINNET,
    // 2oYMBNV4eNHyqk2fjjV5nVQLDbtmNJzq5s3qs3Lo6ftnC6FByM
    .x_blockchain_id = { 0xed, 0x5f, 0x38, 0x34, 0x1e, 0x43, 0x6e, 0x5d, 0x46, 0xe2, 0xbb, 0x00, 0xb4, 0x5d, 0x62, 0xae, 0x97, 0xd1, 0xb0, 0x50, 0xc6, 0x4b, 0xc6, 0x34, 0xae, 0x10, 0x62, 0x67, 0x39, 0xe3, 0x5c, 0x4b },
    // 2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5
    .c_blockchain_id = { 0x04, 0x27, 0xd4, 0xb2, 0x2a, 0x2a, 0x78, 0xbc, 0xdd, 0xd4, 0x56, 0x74, 0x2c, 0xaf, 0x91, 0xb5, 0x6b, 0xad, 0xbf, 0xf9, 0x85, 0xee, 0x19, 0xae, 0xf1, 0x45, 0x73, 0xe7, 0x34, 0x3f, 0xd6, 0x52 },
    // FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z
    .avax_asset_id = { 0x21, 0xe6, 0x73, 0x17, 0xcb, 0xc4, 0xbe, 0x2a, 0xeb, 0x00, 0x67, 0x7a, 0xd6, 0x46, 0x27, 0x78, 0xa8, 0xf5, 0x22, 0x74, 0xb9, 0xd6, 0x05, 0xdf, 0x25, 0x91, 0xb2, 0x30, 0x27, 0xa8, 0x7d, 0xff },
    .hrp = "avax",
    .network_name = "mainnet",
  },
  { .network_id = NETWORK_ID_FUJI,
    // 2JVSBoinj9C2J33VntvzYtVJNZdN2NKiwwKjcumHUWEb5DbBrm
    .x_blockchain_id = { 0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59, 0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7 },
    // yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp
    .c_blockchain_id = { 0x7f, 0xc9, 0x3d, 0x85, 0xc6, 0xd6, 0x2c, 0x5b, 0x2a, 0xc0, 0xb5, 0x19, 0xc8, 0x70, 0x10, 0xea, 0x52, 0x94, 0x01, 0x2d, 0x1e, 0x40, 0x70, 0x30, 0xd6, 0xac, 0xd0, 0x02, 0x1c, 0xac, 0x10, 0xd5 },
    // U8iRqJoiJm8xZHAacmvYyZVwqQx6uDNtQeP3CQ6fcgQk3JqnK
    .avax_asset_id = { 0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42, 0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa },
    .hrp = "fuji",
    .network_name = "fuji",
  },
  { .network_id = NETWORK_ID_LOCAL,
    // 2eNy1mUFdmaxXNj1eQHUe7Np4gju9sJsEtWQ4MX3ToiNKuADed
    .x_blockchain_id = { 0xd8, 0x91, 0xad, 0x56, 0x05, 0x6d, 0x9c, 0x01, 0xf1, 0x8f, 0x43, 0xf5, 0x8b, 0x5c, 0x78, 0x4a, 0xd0, 0x7a, 0x4a, 0x49, 0xcf, 0x3d, 0x1f, 0x11, 0x62, 0x38, 0x04, 0xb5, 0xcb, 0xa2, 0xc6, 0xbf },
    // BZycCYv295rhtyykDkJHaGe7foSadXawXT4XTZPqXBrg
    .c_blockchain_id = {0x9d, 0x07, 0x75, 0xf4, 0x50, 0x60, 0x4b, 0xd2, 0xfb, 0xc4, 0x9c, 0xe0, 0xc5, 0xc1, 0xc6, 0xdf, 0xeb, 0x2d, 0xc2, 0xac, 0xb8, 0xc9, 0x2c, 0x26, 0xee, 0xae, 0x6e, 0x6d, 0xf4, 0x50, 0x2b, 0x19},
    // .c_blockchain_id = { 0x91, 0x06, 0x0e, 0xab, 0xfb, 0x5a, 0x57, 0x17, 0x20, 0x10, 0x9b, 0x58, 0x96, 0xe5, 0xff, 0x00, 0x01, 0x0a, 0x1c, 0xfe, 0x6b, 0x10, 0x3d, 0x58, 0x5e, 0x6e, 0xbf, 0x27, 0xb9, 0x7a, 0x17, 0x35 },
    // 2fombhL7aGPwj3KH4bfrmJwW6PVnMobf9Y2fn9GwxiAAJyFDbe
    .avax_asset_id = { 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb },
    .hrp = "local",
    .network_name = "local",
  },

};
