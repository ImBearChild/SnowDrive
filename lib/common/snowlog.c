#include "snowlog.h"

#if !defined(ESP_PLATFORM)

#include <stdlib.h>

static int snowlog_level = SNOWLOG_INFO;

int snowlog_get_level(void) { return snowlog_level; }

void snowlog_set_level(int level) {
  if (level >= SNOWLOG_NONE && level <= SNOWLOG_VERBOSE)
    snowlog_level = level;
}

__attribute__((constructor)) static void snowlog_init(void) {
  const char *env = getenv("SNOWLOG_LEVEL");
  if (env) {
    int level = atoi(env);
    if (level >= SNOWLOG_NONE && level <= SNOWLOG_VERBOSE)
      snowlog_level = level;
  }
}

#endif
