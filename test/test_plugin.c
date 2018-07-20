#include <glib.h>


void test_sample_plugin(void) {
  g_assert_cmpint(1 + 1, ==, 2);
}
