#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for PBX frontends (dynamically loaded)
#
# Copyright (C) 1999, Adtran Inc. and Linux Support Services, LLC
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

#
# Uncomment if you have g723.1 code (with the same API as the Annex-A code
# and have placed it in the g723.1 directory and/or the Annex-B code in 
# g723.1b)
#
#MODG723=codec_g723_1.so codec_g723_1b.so
MODG723=$(shell [ -f g723.1/coder.c ] && echo "codec_g723_1.so")
MODG723+=$(shell [ -f g723.1b/coder2.c ] && echo "codec_g723_1b.so")

CFLAGS+=

LIBG723=g723.1/libg723.a
LIBG723B=g723.1b/libg723b.a
LIBGSM=gsm/lib/libgsm.a
LIBMP3=mp3/libmp3.a

CODECS+=$(MODG723) codec_gsm.so #codec_mp3_d.so

all: $(CODECS)

clean:
	rm -f *.so *.o
	make -C g723.1 clean
	make -C g723.1b clean
	make -C gsm clean
	make -C mp3 clean

$(LIBG723):
	make -C g723.1 all

$(LIBGSM):
	make -C gsm lib/libgsm.a

$(LIBG723B):
	make -C g723.1b all

$(LIBMP3):
	make -C mp3 all

codec_g723_1.so : codec_g723_1.o $(LIBG723)
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBG723)

codec_g723_1b.o : codec_g723_1.c
	$(CC) -c -o $@ $(CFLAGS) -DANNEX_B $<

codec_g723_1b.so : codec_g723_1b.o $(LIBG723B)
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBG723B) -lm

codec_gsm.so: codec_gsm.o $(LIBGSM)
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBGSM)

codec_mp3_d.so: codec_mp3_d.o $(LIBMP3)
	$(CC) -shared -Xlinker -x -o $@ $< $(LIBMP3)

%.so : %.o
	$(CC) -shared -Xlinker -x -o $@ $<

install: all
	for x in $(CODECS); do $(INSTALL) -m 755 $$x $(MODULES_DIR) ; done
#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for codec modules
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

SELECTED_MODS:=$(filter-out $(MENUSELECT_CODECS),$(patsubst %.c,%,$(wildcard codec_*.c)))

ifeq ($(wildcard ilbc/iLBC_decode.h),)
  MODS:=$(filter-out codec_ilbc,$(MODS))
else
  LIBILBC=ilbc/libilbc.a
endif

LIBLPC10=lpc10/liblpc10.a

MODS:=$(patsubst %,%.so,$(SELECTED_MODS))

all: $(MODS)

clean-depend:
	rm -f .depend

clean: clean-depend
	rm -f *.so *.o
	[ ! -d g723.1 ] || $(MAKE) -C g723.1 clean
	[ ! -d g723.1b ] || $(MAKE) -C g723.1b clean
	$(MAKE) -C gsm clean
	$(MAKE) -C lpc10 clean
	$(MAKE) -C ilbc clean

$(LIBG723):
	CFLAGS="$(ASTCFLAGS)" $(MAKE) -C g723.1 all

gsm/lib/libgsm.a:
	CFLAGS="$(ASTCFLAGS) -I." $(MAKE) -C gsm lib/libgsm.a

$(LIBG723B):
	CFLAGS="$(ASTCFLAGS)" $(MAKE) -C g723.1b all

$(LIBLPC10):
	CFLAGS="$(ASTCFLAGS)" $(MAKE) -C lpc10 all

$(LIBILBC):
	CFLAGS="$(ASTCFLAGS)" $(MAKE) -C ilbc all

codec_ilbc.so: codec_ilbc.o $(LIBILBC)
	$(CC) $(SOLINK) -o $@ $< $(LIBILBC)

codec_g723_1.so : codec_g723_1.o $(LIBG723)
	$(CC) $(SOLINK) -o $@ $< $(LIBG723)

codec_g723_1b.o : codec_g723_1.c
	$(CC) -c -o $@ $(CFLAGS) -DANNEX_B -Dsingle $<

codec_g723_1b.so : codec_g723_1b.o $(LIBG723B)
	$(CC) $(SOLINK) -o $@ $< $(LIBG723B) -lm

ifeq ($(GSM_LIB),internal)
codec_gsm.o: codec_gsm.c
	$(CC) -c -o $@ $(CFLAGS) -Igsm/inc $<

codec_gsm.so: codec_gsm.o gsm/lib/libgsm.a
	$(CC) $(SOLINK) -o $@ $< gsm/lib/libgsm.a
else
codec_gsm.o: codec_gsm.c
	$(CC) -c -o $@ $(CFLAGS) $(GSM_INCLUDE) $<

codec_gsm.so: codec_gsm.o
	$(CC) $(SOLINK) -o $@ $< $(GSM_LIB)
endif

codec_speex.o: codec_speex.c
	$(CC) -c -o $@ $(CFLAGS) $(SPEEX_INCLUDE) $<

codec_speex.so: codec_speex.o
	$(CC) $(SOLINK) -o $@ $< $(SPEEX_LIB)

codec_lpc10.so: codec_lpc10.o $(LIBLPC10)
	$(CC) $(SOLINK) -o $@ $< $(LIBLPC10) -lm

%.so : %.o
	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
  include .depend
endif

install: all
	for x in $(MODS); do $(INSTALL) -m 755 $$x $(DESTDIR)$(MODULES_DIR) ; done

uninstall:

depend: .depend

.depend:
	../build_tools/mkdep $(CFLAGS) `ls *.c`
