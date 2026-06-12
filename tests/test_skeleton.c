#include "unity.h"
#include <snow9660/snow9660.h>
#include <snowscsi/snowscsi.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_snowscsi_version_not_null(void) {
  TEST_ASSERT_NOT_NULL(snowscsi_version());
}

void test_snowscsi_version_format(void) {
  const char *ver = snowscsi_version();
  TEST_ASSERT_NOT_NULL(strchr(ver, '.'));
}

void test_snow9660_version_not_null(void) {
  TEST_ASSERT_NOT_NULL(snow9660_version());
}

void test_snow9660_version_format(void) {
  const char *ver = snow9660_version();
  TEST_ASSERT_NOT_NULL(strchr(ver, '.'));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_snowscsi_version_not_null);
  RUN_TEST(test_snowscsi_version_format);
  RUN_TEST(test_snow9660_version_not_null);
  RUN_TEST(test_snow9660_version_format);
  return UNITY_END();
}
