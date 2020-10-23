XTBL := $(shell pkg-config --variable=xtlibdir xtables)

CFLAGS = -fPIC -I../kernel -g -Wall -I.

all:  libipt_SNATMAP.so
install:  libipt_SNATMAP.so
	if [ -d $(DESTDIR)$(XTBL) ]; then install libipt_SNATMAP.so $(DESTDIR)$(XTBL); \
		ln -fs libipt_SNATMAP.so $(DESTDIR)$(XTBL)/libipt_DNATMAP.so; \
		else echo "No pkg-config --variable=xtlibdir xtables"; fi

lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: lib%.c libxt_set.h xshared.h
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libipt_SNATMAP.so

