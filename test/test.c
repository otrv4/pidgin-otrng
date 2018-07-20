#include <glib.h>

#include "test_plugin.c"

int main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/plugin/sample", test_sample_plugin);

  return g_test_run();
}
