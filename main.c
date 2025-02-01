#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

void add_image_header(const uint8_t **data, size_t *size, const uint8_t *header, size_t header_size) {
    uint8_t *new_data = malloc(header_size + *size);
    if (new_data) {
        memcpy(new_data, header, header_size);
        memcpy(new_data + header_size, *data, *size);

        *data = new_data;
        *size += header_size;
    }
}

int fuzz_target(const uint8_t *data, size_t size) {
    int x, y, comp;
    const uint8_t *m = stbi_load_from_memory(data, size, &x, &y, &comp, 0);
    if (m) {
        stbi_image_free(m);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int64_t seed = 0;
    for(int i = 0; i < size; i++) {
        seed *= 33;
        seed += data[i];
        seed %= 1000000007;
    } 
    srand(seed);

    static const uint8_t jpeg_header[] = {0xFF, 0xD8};
    static const uint8_t png_header[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    static const uint8_t bmp_header[] = {0x42, 0x4D};
    static const uint8_t psd_header[] = {0x38, 0x42, 0x50, 0x53};
    static const uint8_t tga_header[] = {0x00, 0x00, 0x02};
    static const uint8_t gif_header[] = {0x47, 0x49, 0x46, 0x38};
    static const uint8_t hdr_header[] = {'#', '?'};
    static const uint8_t pic_header[] = {0x53, 0x50, 0x43};
    static const uint8_t pnm_header[] = {'P', '5'};

    int format_choice = rand() % 9;

    switch (format_choice) {
        case 0: add_image_header(&data, &size, jpeg_header, sizeof(jpeg_header)); break;
        case 1: add_image_header(&data, &size, png_header, sizeof(png_header)); break;
        case 2: add_image_header(&data, &size, bmp_header, sizeof(bmp_header)); break;
        case 3: add_image_header(&data, &size, psd_header, sizeof(psd_header)); break;
        case 4: add_image_header(&data, &size, tga_header, sizeof(tga_header)); break;
        case 5: add_image_header(&data, &size, gif_header, sizeof(gif_header)); break;
        case 6: add_image_header(&data, &size, hdr_header, sizeof(hdr_header)); break;
        case 7: add_image_header(&data, &size, pic_header, sizeof(pic_header)); break;
        case 8: add_image_header(&data, &size, pnm_header, sizeof(pnm_header)); break;
    }

    const int result = fuzz_target(data, size);
    free(data);
    return result;
}
