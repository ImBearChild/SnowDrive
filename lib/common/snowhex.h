#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void snowhex_format(const uint8_t *data, size_t len, char *out,
                    size_t out_size);

#ifdef __cplusplus
}
#endif
