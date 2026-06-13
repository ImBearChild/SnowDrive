#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  SNOWLOG_NONE = 0,
  SNOWLOG_ERROR = 1,
  SNOWLOG_WARN = 2,
  SNOWLOG_INFO = 3,
  SNOWLOG_DEBUG = 4,
  SNOWLOG_VERBOSE = 5,
};

#if defined(ESP_PLATFORM)
#include <esp_log.h>

#ifndef SNOWLOG_TAG
#define SNOWLOG_TAG "snow"
#endif

#define SNOW_LOGE(...) ESP_LOGE(SNOWLOG_TAG, __VA_ARGS__)
#define SNOW_LOGW(...) ESP_LOGW(SNOWLOG_TAG, __VA_ARGS__)
#define SNOW_LOGI(...) ESP_LOGI(SNOWLOG_TAG, __VA_ARGS__)
#define SNOW_LOGD(...) ESP_LOGD(SNOWLOG_TAG, __VA_ARGS__)
#define SNOW_LOGV(...) ESP_LOGV(SNOWLOG_TAG, __VA_ARGS__)

#else
#include <stdio.h>

int snowlog_get_level(void);
void snowlog_set_level(int level);

#define SNOW_LOGE(fmt, ...)                                                    \
  do {                                                                         \
    if (snowlog_get_level() >= 1)                                              \
      fprintf(stderr, "[E][" SNOWLOG_TAG "] " fmt "\n", ##__VA_ARGS__);        \
  } while (0)
#define SNOW_LOGW(fmt, ...)                                                    \
  do {                                                                         \
    if (snowlog_get_level() >= 2)                                              \
      fprintf(stderr, "[W][" SNOWLOG_TAG "] " fmt "\n", ##__VA_ARGS__);        \
  } while (0)
#define SNOW_LOGI(fmt, ...)                                                    \
  do {                                                                         \
    if (snowlog_get_level() >= 3)                                              \
      fprintf(stderr, "[I][" SNOWLOG_TAG "] " fmt "\n", ##__VA_ARGS__);        \
  } while (0)
#define SNOW_LOGD(fmt, ...)                                                    \
  do {                                                                         \
    if (snowlog_get_level() >= 4)                                              \
      fprintf(stderr, "[D][" SNOWLOG_TAG "] " fmt "\n", ##__VA_ARGS__);        \
  } while (0)
#define SNOW_LOGV(fmt, ...)                                                    \
  do {                                                                         \
    if (snowlog_get_level() >= 5)                                              \
      fprintf(stderr, "[V][" SNOWLOG_TAG "] " fmt "\n", ##__VA_ARGS__);        \
  } while (0)

#endif

#ifdef __cplusplus
}
#endif
