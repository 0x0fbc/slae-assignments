//
// Custom libsodium decrypter sample.
// Author: fbcsec
// This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
// http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
// Student ID: SLAE - 1187
//

#include <sodium.h>


const unsigned char ciphertext[51] = "\xB0\x79\x37\xDD\x26\x22\x51\xD5\xA7\x54\x34\x6E\xD4\x3F\xCF\x00\xB8\xD5\x4C\xE4\xE9\x43\xF1\xB6\x48\xB3\xEA\x42\xA9\x84\x6C\x07\x41\xA8\xE0\xB3\xAC\xDD\x73\x44\x9B\x52\x21\xF5\x68\x15\x87\x3E\xAD\x4A";
unsigned long long ciphertext_len = 50;

const unsigned char key[crypto_secretbox_KEYBYTES+1] = "\xD8\xA7\x97\x77\x9D\xCE\x60\x9C\xFD\x5C\x43\x17\x54\xAC\xED\xA4\xC7\x8F\x9F\xFE\x0D\xAA\xF3\x5B\x02\x7F\xB6\xB9\xDD\xD2\xC0\xB5";
const unsigned char nonce[crypto_secretbox_NONCEBYTES+1] = "\x52\x08\x3A\x39\xA4\x16\x5F\xB7\x63\x59\xE6\x13\x15\xB6\xF7\xFD\xF5\xE2\x1C\x91\xD0\x68\x3F\x53";

unsigned char output[34];


int main(void) {

    int (*call_output)() = (int(*)())output;

    int sodium_init();
    if (crypto_secretbox_open_easy(output, ciphertext, ciphertext_len, nonce, key) != 0) {
        return 1;
    }

    call_output();

    return 0;
}
