#include <stdio.h>
#include <pb_decode.h>
#include <sodium.h>
#include <assert.h>
#include "publickey.pb.h"
#include "box.pb.h"

#define min(a,b) ((a>b)?b:a)

int main(int argc, char** argv) {
	if (argc != 2) {fprintf(stderr, "%s our_sk", argv[0]); return 1;}
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    {
        FILE* f = fopen(argv[1], "r");
        if (f == NULL) {fprintf(stderr, "Cannot open our secret key file"); return 1;}
        int len = fread(sk, 1, crypto_box_SECRETKEYBYTES, f);
        fclose(f);
        if (len != crypto_box_SECRETKEYBYTES) {fprintf(stderr, "Bad secret key file"); return 1;}
    }

    uint8_t buf[1<<16];
    int len = fread(buf, 1, 1<<16, stdin);
    pb_istream_t stream = pb_istream_from_buffer(buf, len);
    Box box;
    if (!pb_decode(&stream, Box_fields, &box)) return 1;
    if (box.enc_algo != 1) return 1;

    uint8_t n[crypto_box_NONCEBYTES];
    for (int i=0; i<crypto_box_NONCEBYTES; ++i) n[i] = box.data.bytes[i];
    for (int i=0; i<crypto_box_BOXZEROBYTES; ++i) box.data.bytes[i] = 0;

    stream = pb_istream_from_buffer(box.sender.bytes, box.sender.size);
    PublicKey pk;
    if (!pb_decode(&stream, PublicKey_fields, &pk)) return 1;
    PublicKeyData pkd;
    stream = pb_istream_from_buffer(pk.publickey_msg.bytes,
            pk.publickey_msg.size);
    if (!pb_decode(&stream, PublicKeyData_fields, &pkd)) return 1;
    int decrypted = 0;
    for (int i=0; i<min(pkd.enc_keys_count,pkd.enc_algos_count); i++) {
        if (pkd.enc_keys[i].size == crypto_box_PUBLICKEYBYTES
                && pkd.sig_algos[i] == 1) {
            uint8_t* encpk = &pkd.enc_keys[i].bytes[0];
            if (crypto_box_open(buf,box.data.bytes+8,box.data.size-8,n,encpk,sk)
                 == 0) {
                decrypted = 1;
                break;
            }
        }
    }
    for (int i=0; i<crypto_box_SECRETKEYBYTES; i++) sk[i] = 0;


    if (decrypted) {
        int got = fwrite(buf+crypto_box_ZEROBYTES, 1, box.data.size-8-crypto_box_ZEROBYTES, stdout);
        assert(got == box.data.size-8-crypto_box_ZEROBYTES);
        got = fwrite(box.sender.bytes, 1, box.sender.size, stderr);
        assert(got == box.sender.size);
    }

    return !decrypted;
}
