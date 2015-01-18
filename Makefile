CC=gcc
LD=gcc
CFLAGS=-O2
LDFLAGS=
COMP_CFLAGS=$(CFLAGS) -std=c99 -Wall
LINK_LDFLAGS=$(LDFLAGS)
SPAWND_LDFLAGS=-lrt
SPAWNDCTL_LDFLAGS=-lrt
COMP=$(CC) $(COMP_CFLAGS) -c -o
LINK=$(LD) $(LINK_LDFLAGS) -o
LOGWTMP_LDFALGS=-lutil
NAME=spawnd
VERSION?=git
TARGET=$(NAME)
TARBALL=$(NAME)-$(VERSION).tar.gz
DESTDIR?=

SBINS=spawnd spawnd-helper-killall spawnd-helper-logwtmp spawnd-helper-utmplogout
BINS=spawndctl
SCRIPTS=spawnd-start spawnd-stop spawnd-restart spawnd-status spawnd-save spawnd-reboot spawnd-halt spawnd-poweroff spawnd-domain spawnd-domain-show spawnd-domain-add spawnd-domain-delete

.PHONY : all

all : $(SBINS) $(BINS)

spawnd : spawnd.o misc.o
	$(LINK) $@ $(SPAWND_LDFLAGS) $^

spawndctl : spawndctl.o misc.o
	$(LINK) $@ $(SPAWNDCTL_LDFLAGS) $^

spawnd-helper-killall : killthemall.o
	$(LINK) $@ $^

spawnd-helper-logwtmp : logwtmp.o
	$(LINK) $@ $(LOGWTMP_LDFALGS) $^

spawnd-helper-utmplogout : utmplogout.o
	$(LINK) $@ $(LOGWTMP_LDFALGS) $^

killthemall.o : killthemall.c Makefile
	$(COMP) $@ $<

utmplogout.o : utmplogout.c Makefile
	$(COMP) $@ $<

spawnd.o : spawnd.c misc.h config.h common.h ipc.h Makefile
	$(COMP) $@ $<

spawndctl.o : spawndctl.c config.h common.h ipc.h Makefile
	$(COMP) $@ $<

misc.o : misc.c misc.h Makefile
	$(COMP) $@ $<

logwtmp.o : logwtmp.c Makefile
	$(COMP) $@ $<

.PHONY : clean tarball install

clean:
	rm -f *.o $(TARBALL) $(SBINS) $(BINS)

tarball: $(TARBALL)

$(TARBALL) : $(SCRIPTS) common.h ipc.h config.h spawnd.c spawndctl.c misc.h misc.c killthemall.c logwtmp.c utmplogout.c Makefile AUTHORS COPYING
	rm -rf $(NAME)-$(VERSION)
	mkdir -m 755 $(NAME)-$(VERSION)
	cp $^ $(NAME)-$(VERSION)/
	tar cz $(NAME)-$(VERSION) > $@
	rm -rf $(NAME)-$(VERSION)

install : $(SBINS) $(BINS)
	mkdir -m 755 -p $(DESTDIR)/sbin
	install -m 755 $(SBINS) $(DESTDIR)/sbin/
	mkdir -m 755 -p $(DESTDIR)/bin
	install -m 755 $(BINS) $(SCRIPTS) $(DESTDIR)/bin/
