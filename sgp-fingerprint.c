#include <stdio.h>
#include <pb_decode.h>
#include <sodium.h>
#include <assert.h>
#include <malloc.h>
#include "sha3.h"
#include "publickey.pb.h"

typedef unsigned long long llu;
bool crypto_sign_detach_open(const uint8_t *m, llu mlen,const uint8_t* sig,
        const uint8_t* pk) {
    uint8_t* sm = malloc(mlen+crypto_sign_BYTES);
    if (sm == NULL) return -1;
    uint8_t* m_ = malloc(mlen+crypto_sign_BYTES);
    if (m == NULL) {free(sm); return -1;}
    for (llu i=0; i<crypto_sign_BYTES; ++i) sm[i] = sig[i];
    for (llu i=0; i<mlen; ++i) sm[crypto_sign_BYTES+i] = m[i];
    llu _;
    int ret =
        crypto_sign_open(m_,&_,sm,mlen+crypto_sign_BYTES,pk);
    free(sm);
    free(m_);
    return ret;
}

int main(int argc, char** argv) {
    int human = argc == 2 && argv[1][0] == '-' && argv[1][1] == 'h';
    uint8_t buffer[256];
    int len = fread(buffer, 1, sizeof(buffer), stdin);
    pb_istream_t stream = pb_istream_from_buffer(buffer, len);
    PublicKey pk;
    if (!pb_decode(&stream, PublicKey_fields, &pk)) return 1;
    PublicKeyData pkd;
    stream = pb_istream_from_buffer(pk.publickey_msg.bytes,
            pk.publickey_msg.size);
    if (!pb_decode(&stream, PublicKeyData_fields, &pkd)) return 1;
    for (int i=0; i<pkd.sig_keys_count; i++) {
        if (  pk.sigs_count < i
           || pk.sigs[i].size < crypto_sign_BYTES
           || pkd.sig_keys[i].size < crypto_sign_PUBLICKEYBYTES
           || crypto_sign_detach_open(pk.publickey_msg.bytes,
               pk.publickey_msg.size, pk.sigs[i].bytes, pkd.sig_keys[i].bytes)
           != 0) {
            fprintf(stderr, "Invalid key\n");
            return 2;
        } else {
            initialise(1344, 256, 128);
            char* dgst = digest((char*)pkd.sig_keys[i].bytes,
                    pkd.sig_keys[i].size, 1);
            for (int i=0; i<128/8; i+=2) {
                if (i > 0 && human) {
                    fprintf(stdout, " ");
                    if (i == 8) fprintf(stdout, " ");
                }
                fprintf(stdout, "%X", (dgst[i]&0xF0)>>4);
                fprintf(stdout, "%X", dgst[i]&0x0F);
                fprintf(stdout, "%X", (dgst[i+1]&0xF0)>>4);
                fprintf(stdout, "%X", dgst[i+1]&0x0F);
            }
            if (human) printf("\n");
            else return 1;
            dispose();
        }
    }
}
