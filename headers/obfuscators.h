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



// Print the contents of an address in hex
// Used for debugging purposes only
//
// void print_hex(unsigned char *payload, unsigned int payload_len){
//     int i;
//    
//     printf("{");
//     for (i=0; i<payload_len; i++){
//         printf("0x%02x, ", payload[i]);
//
//     }
//     printf("}\n");
//    
// }