#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

uint8_t *add_image_header(const uint8_t *data, size_t size, const uint8_t *header, size_t header_size) {
    uint8_t *new_data = malloc(header_size + size);
    if (new_data) {
        memcpy(new_data, header, header_size);
        memcpy(new_data + header_size, *data, size);
    }
    return new_data;
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
    static const uint8_t jpeg_header[] = {0xFF, 0xD8};
    static const uint8_t png_header[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    static const uint8_t bmp_header[] = {0x42, 0x4D};
    static const uint8_t psd_header[] = {0x38, 0x42, 0x50, 0x53};
    static const uint8_t tga_header[] = {0x00, 0x00, 0x02};
    static const uint8_t gif_header[] = {0x47, 0x49, 0x46, 0x38};
    static const uint8_t hdr_header[] = {'#', '?'};
    static const uint8_t pic_header[] = {0x53, 0x50, 0x43};
    static const uint8_t pnm_header[] = {'P', '5'};

    // Array of headers and their sizes
    const struct {
        const uint8_t *header;
        size_t size;
    } headers[] = {
        {jpeg_header, sizeof(jpeg_header)},
        {png_header, sizeof(png_header)},
        {bmp_header, sizeof(bmp_header)},
        {psd_header, sizeof(psd_header)},
        {tga_header, sizeof(tga_header)},
        {gif_header, sizeof(gif_header)},
        {hdr_header, sizeof(hdr_header)},
        {pic_header, sizeof(pic_header)},
        {pnm_header, sizeof(pnm_header)}
    };

    // Iterate over each format
    for (int i = 0; i < 9; ++i) {
        uint8_t *buf = add_image_header(data, size, headers[i].header, headers[i].size);
        if (buf) {
            fuzz_target(buf, headers[i].size + size);
            free(buf);
        }
    }

    return 0;
}
