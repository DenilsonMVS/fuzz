#include <stdint.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int fuzz_target(const uint8_t *data, size_t size) {
    int x, y, comp;
    const uint8_t *m = stbi_load_from_memory(data, size, &x, &y, &comp, 0);
    if(m) {
        stbi_image_free(m);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fuzz_target(data, size);
}

