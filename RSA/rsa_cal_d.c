#include <stdio.h>
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

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi_n = BN_new();
    BIGNUM *d = BN_new();

    // Initialize p, q, e (you can replace these with your own values)
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // Calculate n = p * q
    BN_mul(n, p, q, ctx);

    // Calculate phi_n = (p-1) * (q-1)
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi_n, p_minus_1, q_minus_1, ctx);

    // Calculate d
    d = calculate_d(e, phi_n, ctx);
    if (d == NULL) {
        return 1;
    }

    // Print the results
    printBN("p: ", p);
    printBN("q: ", q);
    printBN("e: ", e);
    printBN("n: ", n);
    printBN("phi_n: ", phi_n);
    printBN("d: ", d);

    // Cleanup
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(phi_n);
    BN_free(d);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);

    return 0;
}

