#include <stdio.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <sodium.h>
#include "publickey.pb.h"
#include "box.pb.h"

#define min(a,b) ((a>b)?b:a)

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "%s their_pk our_pk our_sk", argv[0]);
        return 2;
    }
    uint8_t* encpk;
    {
        FILE* f = fopen(argv[1], "r");
        if (f == NULL) {fprintf(stderr, "Cannot open their public key file"); return 1;}
        uint8_t buffer[256];
        int len = fread(buffer, 1, sizeof(buffer), f);
        fclose(f);
        pb_istream_t stream = pb_istream_from_buffer(buffer, len);
        PublicKey pk;
        if (!pb_decode(&stream, PublicKey_fields, &pk)) return 1;
        PublicKeyData pkd;
        stream = pb_istream_from_buffer(pk.publickey_msg.bytes,
                pk.publickey_msg.size);
        if (!pb_decode(&stream, PublicKeyData_fields, &pkd)) return 1;
        for (int i=0; i<min(pkd.enc_keys_count,pkd.enc_algos_count); i++) {
            if (pkd.enc_keys[i].size == crypto_box_PUBLICKEYBYTES
                    && pkd.sig_algos[i] == 1) {
                encpk = &pkd.enc_keys[i].bytes[0];
                break;
            }
        }
    }

    Box box;
    box.enc_algo = 1;
    {
        FILE* f = fopen(argv[2], "r");
        if (f == NULL) {fprintf(stderr, "Cannot open our public key file"); return 1;}
        box.sender.size = fread(box.sender.bytes, 1, sizeof(box.sender.bytes), f);
        fclose(f);
    }

    unsigned char sk[crypto_box_SECRETKEYBYTES];
    {
        FILE* f = fopen(argv[3], "r");
        if (f == NULL) {fprintf(stderr, "Cannot open our secret key file"); return 1;}
        int len = fread(sk, 1, crypto_box_SECRETKEYBYTES, f);
        fclose(f);
        if (len != crypto_box_SECRETKEYBYTES) {fprintf(stderr, "Bad secret key file"); return 1;}
    }

    uint8_t m[1<<16];
    for (int i=0; i<crypto_box_ZEROBYTES; ++i) m[i] = 0; 
    int mlen = crypto_box_ZEROBYTES;
    mlen += fread(m + crypto_box_ZEROBYTES, 1, 64900 - crypto_box_ZEROBYTES, stdin);
    randombytes_buf(box.data.bytes, crypto_box_NONCEBYTES);
    crypto_box(box.data.bytes + crypto_box_NONCEBYTES,m,mlen,box.data.bytes,encpk,sk);
    box.data.size = crypto_box_NONCEBYTES + mlen - crypto_box_BOXZEROBYTES;
    for(int i=crypto_box_NONCEBYTES; i<box.data.size; ++i) {
        box.data.bytes[i] = box.data.bytes[i+crypto_box_BOXZEROBYTES];
    }

    pb_ostream_t stream = pb_ostream_from_buffer(m, sizeof(m));
    pb_encode(&stream, Box_fields, &box);
    fwrite(m, 1, stream.bytes_written, stdout);
    return 0;
}
