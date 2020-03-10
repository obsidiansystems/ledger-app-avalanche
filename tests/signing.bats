
. ./tests/lib.sh

blake2b_p () {
  blake2 --length 32 --personal 636b622d64656661756c742d68617368 | tee txhashdump
}

blake2b_lock_hash () {
  (blake2b_p | tee dumpfile1 ; echo -n "5500000000000000 55000000100000005500000055000000410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") | tee dumpfile | xxd -p -r | blake2b_p
}

check_signature () {
  r_val=$(head -c64 <<<"$2")
  s_val=$(tail -c+65 <<<"$2" | head -c64)

  # Check the high bit, add a zero byte if needed.
  if [ "$(xxd -r -ps <<<"$r_val" | xxd -b | cut -d' ' -f2 | head -c1 )" == "1" ] ; then r_val="00$r_val"; fi;
  if [ "$(xxd -r -ps <<<"$s_val" | xxd -b | cut -d' ' -f2 | head -c1 )" == "1" ] ; then s_val="00$s_val"; fi;

  rlen=$((${#r_val}/2))
  slen=$((${#s_val}/2))

  rfmt="02$(printf "%x" $rlen)${r_val}"
  sfmt="02$(printf "%x" $slen)${s_val}"

  SIG="30$(printf "%x" $(($rlen+$slen+4)))$rfmt$sfmt"

  xxd -r -ps <<<"$1" | blake2b_lock_hash | xxd -p -r | openssl pkeyutl -verify -pubin -inkey tests/public_key_0_0.pem -sigfile <(xxd -r -ps <<<"$SIG")
}

@test "Signing APDU returns something when given something to sign and clickthrough happens." {
  run apdu_fixed "8003000011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  run apdu_with_clicks "800381000400001111" "rR"
  [ "$status" -eq 0 ]
  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
  echo $rv
  # 142 characters of hexadecimal der-encoded signature, one newline.
  # TODO: use openssl to verify the signature.
  run check_signature "00001111" "$rv"
  diff <(echo $output) - <<<"Signature Verified Successfully"
 } 

@test "Signing APDU rejects when given garbage to sign and strict checking is enabled." {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  run apdu_with_clicks "8003c1000400001111" "rR"
  [ "$status" -eq 0 ]
  grep -q "<= b''9405" <(echo "$output")
 }

sendTransaction() {
  bytesToSign=$(($(wc -c <<<"$1")/2))
  toSend=$1
  while [ "$bytesToSign" -gt 230 ] ;
  do 
    run apdu_fixed "80034100e6$(head -c 460 <<<"$toSend")"
    [ "$status" -eq 0 ]
    grep -q "<= b''9000" <(echo "$output")
    toSend="$(tail -c+461 <<<"$toSend")";
    bytesToSign=$(($(wc -c <<<"$toSend")/2))
  done
  bytes=$(printf "%x" $(($(wc -c <<<"$toSend")/2)))
  if [ -z "$2" ]; then
    run apdu_with_clicks "8003c100$bytes$toSend" "rR"
  else
    run apdu_fixed "8003e100$bytes$toSend"
  fi
}

doSign() {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  bytesToSign=$(($(wc -c <<<"$1")/2))
  toSend=$1
  while [ "$bytesToSign" -gt 230 ] ;
  do 
    run apdu_fixed "80034100e6$(head -c 460 <<<"$toSend")"
    [ "$status" -eq 0 ]
    grep -q "<= b''9000" <(echo "$output")
    toSend="$(tail -c+461 <<<"$toSend")";
    bytesToSign=$(($(wc -c <<<"$toSend")/2))
  done
  bytes=$(printf "%x" $(($(wc -c <<<"$toSend")/2)))
  run apdu_with_clicks "8003c100$bytes$toSend" "rR"
}

@test "Signing with strict checking and a valid but nonuseful transaction passes" {
  TRANSACTION="a10000001c0000002000000024000000280000002c00000095000000000000000000000000000000000000006900000008000000610000001000000018000000610000000040787d01000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab90c0000000800000000000000"
  doSign "$TRANSACTION"
  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
  run check_signature "$TRANSACTION" "$rv"
  diff <(echo $output) - <<<"Signature Verified Successfully"
}

@test "Signing with strict checking and a valid useful transaction passes" {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  sendTransaction "840100001c000000200000006e00000072000000a200000070010000000000000200000015fb8111fc78fa36da6af96c45ac4714cc9a33974fdae13cc524b29e1a488c7f030000000007a824df0419adf4c92ca563085525e7224b014ecc97cf3de684dd7b57c05856000000000000000000010000000000000000000000071fd1d33723cfcb7d280824c90cfd6bd4042fb1f30fb6218af80d31a3c7f67701000000ce0000000c0000006d0000006100000010000000180000006100000000e8764817000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab96100000010000000180000006100000024c714130400000049000000100000003000000031000000ac8a4bc0656aeee68d4414681f4b2611341c4f0edd4c022f2d250ef8bb58682f0114000000931ca32ee12a6a79d58b9d25a9e75b6929b1b0aa140000000c000000100000000000000000000000" --isCtxd
  TRANSACTION="5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
  sendTransaction "$TRANSACTION"
  rv="$(egrep "<= b'.*'9000" <(echo "$output")|cut -d"'" -f2)"
  run check_signature "$TRANSACTION" "$rv"
  diff <(echo $output) - <<<"Signature Verified Successfully"
}

@test "Signing with strict checking and an incorrect context fails" {
  run apdu_fixed "8003400011048000002c800001358000000080000000"
  [ "$status" -eq 0 ]
  grep -q "<= b''9000" <(echo "$output")
  sendTransaction "5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000" --isCtxd
  sendTransaction "5f0100001c00000020000000490000004d0000007d0000004b010000000000000100000084dcb061adebff4ef93d57c975ba9058a9be939d79ea12ee68003f6492448890000000000100000000010000000000000000000000ddca231a524bfa522d65ed751829d757c361b6203493503027d877f7e76a18e800000000ce0000000c0000006d0000006100000010000000180000006100000000863ba101000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab961000000100000001800000061000000c01f2ca715000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b57dd485a1b0c0a57c377e896a1a924d7ed02ab9140000000c000000100000000000000000000000"
  grep -q "<= b''9405" <(echo "$output")
}