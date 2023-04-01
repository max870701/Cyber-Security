#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *calculate_d(BIGNUM *e, BIGNUM *phi_n, BN_CTX *ctx) {
    BIGNUM *d = BN_new();
    if (!BN_mod_inverse(d, e, phi_n, ctx)) {
        printf("Error: Unable to compute d.\n");
        return NULL;
    }
    return d;
}

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

// Function to convert a hex string to an ASCII string
void hex_to_ascii(const char *hex_str, char *ascii_str) {
    size_t len = strlen(hex_str);
    for (size_t i = 0; i < len; i += 2) {
        char hex_byte[3];
        hex_byte[0] = hex_str[i];
        hex_byte[1] = hex_str[i + 1];
        hex_byte[2] = '\0';

        int byte_value;
        sscanf(hex_byte, "%2x", &byte_value);
        ascii_str[i / 2] = (char) byte_value;
    }
    ascii_str[len / 2] = '\0';
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *M_decrypted = BN_new();

    // Initialize p, q, e (you can replace these with your own values)
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decrypt the encrypted message using the private key (n, d)
    BN_mod_exp(M_decrypted, C, d, n, ctx);

    // Convert M_decrypted Big Number to the hex string
    char *hex_str = BN_bn2hex(M_decrypted);
    size_t len = strlen(hex_str) / 2;
    char ascii_str[len + 1];

    // Convert M_decrypted hex string to the original ASCII string
    hex_to_ascii(hex_str, ascii_str);

    // Print the results
    printBN("n: ", n);
    printBN("d: ", d);
    printBN("Encrypted message (C): ", C);
    printBN("Decrypted message (M_decrypted): ", M_decrypted);
    printf("Decrypted message (ASCII): %s\n", ascii_str);

    // Cleanup
    BN_free(n);
    BN_free(d);
    BN_free(C);
    BN_free(M_decrypted);
    BN_CTX_free(ctx);

    return 0;
}

