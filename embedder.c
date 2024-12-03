#include <stdio.h>
#include <stdlib.h>

void embed_binary_payload(const char *host_file_path, const unsigned char *binary_payload, size_t binary_payload_size, const char *output_file_path) {
    FILE *host_file = fopen(host_file_path, "rb");
    if (!host_file) {
        perror("Error opening host file");
        exit(EXIT_FAILURE);
    }

    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(host_file);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), host_file)) > 0) {
        fwrite(buffer, 1, bytes_read, output_file);
    }

    fwrite(binary_payload, 1, binary_payload_size, output_file);

    fclose(host_file);
    fclose(output_file);

    printf("Binary payload embedded into %s\n", output_file_path);
}

int main() {
    unsigned char new_payload[] = {};
    size_t new_payload_size = sizeof(new_payload);

    const char *host_file_path = "path/to/host_file.pdf"; 
    const char *output_file_path = "path/to/output_file.pdf"; 

    embed_binary_payload(host_file_path, new_payload, new_payload_size, output_file_path);

    return 0;
}
