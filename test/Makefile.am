#TODO include license

check_PROGRAMS = test

test_SOURCES = 	test.c \
			    $(pidgin_otrng_la_SOURCES)

test_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS)
test_LDFLAGS = $(pidgin_otrng_la_LDFLAGS) @TEST_LIBS@
