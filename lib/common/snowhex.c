#include "snowhex.h"

void snowhex_format(const uint8_t *data, size_t len, char *out,
                    size_t out_size) {
  size_t pos = 0;
  for (size_t i = 0; i < len; i++) {
    if (pos + 3 > out_size - 1)
      break;
    out[pos++] = "0123456789abcdef"[data[i] >> 4];
    out[pos++] = "0123456789abcdef"[data[i] & 0xF];
    if (i + 1 < len)
      out[pos++] = ' ';
  }
  out[pos] = '\0';
}
