#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for file format modules
#
# Copyright (C) 1999, Adtran Inc. and Linux Support Services, LLC
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

FORMAT_LIBS=format_g723.so format_wav.so format_mp3.so # format_wav_gsm.so

GSMLIB=../codecs/gsm/lib/libgsm.a

CFLAGS+=

all: $(FORMAT_LIBS)

clean:
	rm -f *.so *.o

%.so : %.o
	$(CC) -shared -Xlinker -x -o $@ $<

format_wav.so : format_wav.o
	$(CC) -shared -Xlinker -x -o $@ $< -laudiofile

format_wav_gsm.so : format_wav_gsm.o
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBGSM)

install: all
	for x in $(FORMAT_LIBS); do $(INSTALL) -m 755 $$x $(MODULES_DIR) ; done
#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for file format modules
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# Mark Spencer <markster@digium.com>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

.PHONY: clean clean-depend all depend uninstall

ifneq ($(wildcard ../menuselect.makeopts),)
  include ../menuselect.makeopts
endif

SELECTED_MODS:=$(filter-out $(MENUSELECT_FORMATS),$(patsubst %.c,%,$(wildcard format_*.c)))

GSMLIB=../codecs/gsm/lib/libgsm.a

MODS:=$(patsubst %,%.so,$(SELECTED_MODS))

all: $(MODS)

clean-depend:
	rm -f .depend

clean: clean-depend
	rm -f *.so *.o

%.so : %.o
	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
  include .depend
endif

format_ogg_vorbis.so : format_ogg_vorbis.o
	$(CC) $(SOLINK) -o $@ $< $(OGG_LIB) $(VORBIS_LIB)

format_ogg_vorbis.o: format_ogg_vorbis.c
	$(CC) -c -o $@ $(CFLAGS) $(OGG_INCLUDE) $(VORBIS_INCLUDE) $<

install: all
	for x in $(MODS); do $(INSTALL) -m 755 $$x $(DESTDIR)$(MODULES_DIR) ; done

uninstall:

depend: .depend

.depend:
	../build_tools/mkdep $(CFLAGS) `ls *.c`
