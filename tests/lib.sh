
apdu() {
  python -m ledgerblue.runScript --apdu
}

apdu_fixed () {
  echo "$*" | apdu | sed 's/HID //'
}

# l/r represent pushing button down, L/R represent releasing
clicks() {
  echo "$1" > /dev/tcp/localhost/5667
}

apdu_with_clicks () {
  echo "$1" | apdu &
  sleep 2;
  while read -n1 click; do
    clicks $click
    sleep 0.1
  done <<<"$2"
}

ACCEPT_CLICKS="rRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrRrlRL"

COMMIT="$(echo "$GIT_DESCRIBE" | sed 's/-dirty/*/')"
HEXCOMMIT="$(echo -n ${COMMIT}|xxd -ps -g0)"

blake2b_p () {
  blake2 --length 32 --personal 636b622d64656661756c742d68617368
}

blake2b_lock_hash () {
  (blake2b_p ; echo -n "5500000000000000 55000000100000005500000055000000410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") | xxd -p -r | blake2b_p
}

check_signature () {
  sig=$(tr -d -c '[:xdigit:]' <<<"$3")
  r_val=$(head -c64 <<<"$sig")
  s_val=$(tail -c+65 <<<"$sig" | head -c64)

  # Check the high bit, add a zero byte if needed.
  if [ "$(xxd -r -ps <<<"$r_val" | xxd -b | cut -d' ' -f2 | head -c1 )" == "1" ] ; then r_val="00$r_val"; fi;
  if [ "$(xxd -r -ps <<<"$s_val" | xxd -b | cut -d' ' -f2 | head -c1 )" == "1" ] ; then s_val="00$s_val"; fi;

  rlen=$((${#r_val}/2))
  slen=$((${#s_val}/2))

  rfmt="02 $(printf "%02x" $rlen) ${r_val}"
  sfmt="02 $(printf "%02x" $slen) ${s_val}"

  SIG="30 $(printf "%02x" $((rlen+slen+4))) $rfmt $sfmt"

  xxd -r -ps <<<"$2" | openssl pkeyutl -verify -pubin -inkey <(get_key_in_pem "$1") -sigfile <(xxd -r -ps <<<"$SIG")
}

get_key_in_pem() {
  bip_path="$1"
  bip_path_len=$((${#bip_path}/2))
  bip_fmt="$(printf "%02x" $bip_path_len)$bip_path"
  derivation="80020000${bip_fmt}"
  result="$(apdu_with_clicks "$derivation" "$ACCEPT_CLICKS" |& egrep "b'41.*'9000" | sed "s/^<= b'41//;s/'9000$//")"
  echo "-----BEGIN PUBLIC KEY-----"
  cat tests/public_key_der_prefix.der <(xxd -ps -r <<<"$result") | base64
  echo "-----END PUBLIC KEY-----"
}

promptsCheck() {
  if [ "$DEBUG" != "1" ]; then return 0; fi;
  egrep -A2 'Prompt [0-9]:' speculos.log | tail -n $(($1*3))
  diff $2 <(egrep -A2 'Prompt [0-9]:' speculos.log | tail -n $(($1*3)))
}

rejectionMessageCheck() {
  if [ "$DEBUG" != "1" ]; then return 0; fi;
  test "$(egrep '^Rejecting: ' speculos.log | tail -n${2:-1} | head -n1)" = "Rejecting: $1"
}
hardRejectionMessageCheck() {
  if [ "$DEBUG" != "1" ]; then return 0; fi;
  test "$(egrep "^Can't sign: " speculos.log | tail -n1)" = "Can't sign: $1"
}

APP_VM=$(cat Makefile | sed -n -e 's/^.*APPVERSION_M=//p' | head -n 1)
APP_VN=$(cat Makefile | sed -n -e 's/^.*APPVERSION_N=//p' | head -n 1)
APP_VP=$(cat Makefile | sed -n -e 's/^.*APPVERSION_P=//p' | head -n 1)

formatVersion() {
  printf "%02x" "$1"
}

getCurrentVersion() {
  printf "%02x%02x%02x" "$APP_VM" "$APP_VN" "$APP_VP"
}