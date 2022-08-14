#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// XOR two strings
void XOR(unsigned char * payload, unsigned int payload_len, const char * xor_key, unsigned int xor_key_len){
    int j;

    j = 0;
    for (int i = 0; i < payload_len; i++) {
        if (j == xor_key_len) j = 0;

        payload[i] = payload[i] ^ xor_key[j];
        j++;
    }
}
