#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    const char *hex_str = "4120746F702073656372657421";
    size_t len = strlen(hex_str) / 2;

    char ascii_str[len + 1];
    hex_to_ascii(hex_str, ascii_str);

    printf("Hex string: %s\n", hex_str);
    printf("ASCII string: %s\n", ascii_str);

    return 0;
}
