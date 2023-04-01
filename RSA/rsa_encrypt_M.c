#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
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

int main() {
    const char *ascii_str = "A top secret!";
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *M_decrypted = BN_new();

    // Convert an ASCII string to a hex string
    char *hex_str = ascii_to_hex(ascii_str);
    if (hex_str == NULL) {
        printf("Error converting ASCII to hex\n");
        return 1;
    }

    // Initialize p, q, e (you can replace these with your own values)
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");

    // Initialize M with the given message
    BN_hex2bn(&M, hex_str);

    // Encrypt the message using the public key (n, e)
    BN_mod_exp(C, M, e, n, ctx);

    // Decrypt the encrypted message using the private key (n, d)
    BN_mod_exp(M_decrypted, C, d, n, ctx);

    // Print the results
    printBN("n: ", n);
    printBN("e: ", e);
    printBN("d: ", d);
    printf("Message (ASCII): %s\n", ascii_str);
    printBN("Message (M): ", M);
    printBN("Encrypted message (C): ", C);
    printBN("Decrypted message (M_decrypted): ", M_decrypted);

    // Cleanup
    BN_free(e);
    BN_free(n);
    BN_free(d);
    BN_free(M);
    BN_free(C);
    BN_free(M_decrypted);
    BN_CTX_free(ctx);

    return 0;
}

