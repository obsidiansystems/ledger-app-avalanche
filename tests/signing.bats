
. ./tests/lib.sh

#@test "Signing APDU returns something when given something to sign and clickthrough happens." {
#  run apdu_fixed "8003000011048000002c800001358000000080000000"
#  [ "$status" -eq 0 ]
#  grep -q "<= b''9000" <(echo "$output")
#  run apdu_with_clicks "800381000400001111" "rR"
#  [ "$status" -eq 0 ]
#  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
#  # 142 characters of hexadecimal der-encoded signature, one newline.
#  # TODO: use openssl to verify the signature.
#  run check_signature "" "00001111" "$rv"
#  diff <(echo $output) - <<<"Signature Verified Successfully"
# }

@test "Signing APDU rejects when given garbage to sign and strict checking is enabled." {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  run apdu_with_clicks "8003c1000400001111" "rR"
  [ "$status" -eq 0 ]
  grep -q "<= b''9405" <(echo "$output")
 }

#@test "Signing with strict checking and a valid but nonuseful transaction passes" {
#  TRANSACTION="a10000001c0000002000000024000000280000002c00000095000000000000000000000000000000000000006900000008000000610000001000000018000000610000000040787d01000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab90c0000000800000000000000"
#  doSign "$TRANSACTION"
#  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
#  run check_signature "" "$TRANSACTION" "$rv"
#  diff <(echo $output) - <<<"Signature Verified Successfully"
#}
#
#@test "Signing with strict checking and a valid useful transaction passes" {
#  run apdu_fixed "8003400011048000002c800001358000000080000000"
#  [ "$status" -eq 0 ]
#  grep -q "<= b''9000" <(echo "$output")
#  sendTransaction "840100001c000000200000006e00000072000000a200000070010000000000000200000015fb8111fc78fa36da6af96c45ac4714cc9a33974fdae13cc524b29e1a488c7f030000000007a824df0419adf4c92ca563085525e7224b014ecc97cf3de684dd7b57c05856000000000000000000010000000000000000000000071fd1d33723cfcb7d280824c90cfd6bd4042fb1f30fb6218af80d31a3c7f67701000000ce0000000c0000006d0000006100000010000000180000006100000000e8764817000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab96100000010000000180000006100000024c714130400000049000000100000003000000031000000ac8a4bc0656aeee68d4414681f4b2611341c4f0edd4c022f2d250ef8bb58682f0114000000931ca32ee12a6a79d58b9d25a9e75b6929b1b0aa140000000c000000100000000000000000000000" --isCtxd
#  TRANSACTION="5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
#  sendTransaction "$TRANSACTION"
#  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
#  run check_signature "8002000011048000002c800001358000000080000000" "$TRANSACTION" "$rv"
#  diff <(echo $output) - <<<"Signature Verified Successfully"
#}

@test "Signing with strict checking and an incorrect context fails" {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  sendTransaction "5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000" --isCtxd
  run sendTransaction "5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
  grep -q "<= b''9405" <(echo "$output")
}

@test "Signing with strict checking of a transaction having a type script fails" {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  sendTransaction "840100001c000000200000006e00000072000000a200000070010000000000000200000015fb8111fc78fa36da6af96c45ac4714cc9a33974fdae13cc524b29e1a488c7f030000000007a824df0419adf4c92ca563085525e7224b014ecc97cf3de684dd7b57c05856000000000000000000010000000000000000000000071fd1d33723cfcb7d280824c90cfd6bd4042fb1f30fb6218af80d31a3c7f67701000000ce0000000c0000006d0000006100000010000000180000006100000000e8764817000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab96100000010000000180000006100000024c714130400000049000000100000003000000031000000ac8a4bc0656aeee68d4414681f4b2611341c4f0edd4c022f2d250ef8bb58682f0114000000931ca32ee12a6a79d58b9d25a9e75b6929b1b0aa140000000c000000100000000000000000000000" --isCtxd
  run sendTransaction "a80100001c00000020000000490000004d0000007d00000094010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000170100000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9aa000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
  grep -q "<= b''9405" <(echo "$output")
  rejectionMessageCheck "Cannot parse transactions with non-DAO type scripts"
}

#@test "Signing with strict checking and a different change address passes." {
#  run apdu_fixed "8003400011048000002c800001358000000080000000"
#  run apdu_fixed "8003510011048000002c800001358000000180000001"
#  [ "$status" -eq 0 ]
#  grep -q "<= b''9000" <(echo "$output")
#  echo STRICTCEHCK >> speculos.log
#  sendTransaction "840100001c000000200000006e00000072000000a200000070010000000000000200000015fb8111fc78fa36da6af96c45ac4714cc9a33974fdae13cc524b29e1a488c7f030000000007a824df0419adf4c92ca563085525e7224b014ecc97cf3de684dd7b57c05856000000000000000000010000000000000000000000071fd1d33723cfcb7d280824c90cfd6bd4042fb1f30fb6218af80d31a3c7f67701000000ce0000000c0000006d0000006100000010000000180000006100000000e8764817000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab96100000010000000180000006100000024c714130400000049000000100000003000000031000000ac8a4bc0656aeee68d4414681f4b2611341c4f0edd4c022f2d250ef8bb58682f0114000000931ca32ee12a6a79d58b9d25a9e75b6929b1b0aa140000000c000000100000000000000000000000" --isCtxd
#  TRANSACTION="5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000a70cc7f490647d8c060dc308a0779542981dba1a61000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b690f63b6fca7abff77c558bffa7401ec40dcb52140000000c000000100000000000000000000000"
#  sendTransaction "$TRANSACTION"
#  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
#  run check_signature "" "$TRANSACTION" "$rv"
#  diff <(echo $output) - <<<"Signature Verified Successfully"
#  promptsCheck 5 tests/sign-with-change-path.txt
#}

@test "Signing with strict checking and more than one destination fails" {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  sendTransaction "840100001c000000200000006e00000072000000a200000070010000000000000200000015fb8111fc78fa36da6af96c45ac4714cc9a33974fdae13cc524b29e1a488c7f030000000007a824df0419adf4c92ca563085525e7224b014ecc97cf3de684dd7b57c05856000000000000000000010000000000000000000000071fd1d33723cfcb7d280824c90cfd6bd4042fb1f30fb6218af80d31a3c7f67701000000ce0000000c0000006d0000006100000010000000180000006100000000e8764817000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab96100000010000000180000006100000024c714130400000049000000100000003000000031000000ac8a4bc0656aeee68d4414681f4b2611341c4f0edd4c022f2d250ef8bb58682f0114000000931ca32ee12a6a79d58b9d25a9e75b6929b1b0aa140000000c000000100000000000000000000000" --isCtxd
  TRANSACTION="5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b67dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b58dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
  run sendTransaction "$TRANSACTION"
  [ "$status" -eq 0 ]
  grep -q "<= b''9405" <(echo "$output")
}
