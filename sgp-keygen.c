#include <stdio.h>
#include <pb_encode.h>
#include <sodium.h>
#include <assert.h>
#include "publickey.pb.h"

int main() {
    PublicKeyData pkd = {1, {1}, 1, {1}, 1, {crypto_sign_PUBLICKEYBYTES, ""}, 1, {crypto_box_PUBLICKEYBYTES, ""}, 0, 0};
    uint8_t sk[crypto_box_SECRETKEYBYTES+crypto_sign_SECRETKEYBYTES];
    crypto_box_keypair(pkd.enc_keys[0].bytes, sk);
    crypto_sign_keypair(pkd.sig_keys[0].bytes, &sk[crypto_box_SECRETKEYBYTES]);

    PublicKey pk;
    pb_ostream_t stream = pb_ostream_from_buffer(pk.publickey_msg.bytes,
            sizeof(pk.publickey_msg.bytes));
    pb_encode(&stream, PublicKeyData_fields, &pkd);
    pk.publickey_msg.size = stream.bytes_written;

    pk.sigs_count = 1;
    unsigned long long smlen;
    crypto_sign(pk.sigs[0].bytes, &smlen,
            pk.publickey_msg.bytes, pk.publickey_msg.size,
            &sk[crypto_box_SECRETKEYBYTES]);
    assert(smlen < sizeof(pk.sigs[0].bytes));
    pk.sigs[0].size = crypto_sign_BYTES;

    // output and erase the secret keys
    fwrite(sk, 1, sizeof(sk), stderr);
    for (int i=0; i<sizeof(sk); i++) sk[i] = 0;

    uint8_t buffer[256];
    stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
    pb_encode(&stream, PublicKey_fields, &pk);
    fwrite(buffer, 1, stream.bytes_written, stdout);
}

