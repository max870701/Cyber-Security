#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

// Function to convert an ASCII string to a hex string
char *ascii_to_hex(const char *ascii_str) {
    if (ascii_str == NULL) {
        return NULL;
    }

    size_t len = strlen(ascii_str);
    char *hex_str = malloc(len * 2 + 1);
    if (hex_str == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02X", (unsigned char)ascii_str[i]);
    }
    hex_str[len * 2] = '\0';

    return hex_str;
}

int main() {
    const char *ascii_str = "A top secret!";
    char *hex_str = ascii_to_hex(ascii_str);
    if (hex_str == NULL) {
        printf("Error converting ASCII to hex\n");
        return 1;
    }
    printf("Hex string: %s\n", hex_str);

    BIGNUM *bn = BN_new();
    if (!BN_hex2bn(&bn, hex_str)) {
        printf("Error converting hex to BIGNUM\n");
        free(hex_str);
        return 1;
    }
    printf("BIGNUM: %s\n", BN_bn2dec(bn));

    // Cleanup
    free(hex_str);
    BN_free(bn);

    return 0;
}
