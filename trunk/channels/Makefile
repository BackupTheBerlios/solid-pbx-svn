#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for channel drivers
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

SELECTED_MODS:=$(filter-out $(MENUSELECT_CHANNELS),$(patsubst %.c,%,$(wildcard chan_*.c)))

ifeq ($(PROC),sparc64)
  PROC=ultrasparc
  CFLAGS += -mtune=$(PROC) -pipe -fomit-frame-pointer -mcpu=v8
endif

ifeq ($(OSARCH),SunOS)
  SOLINK+=-lrt
endif

ifeq ($(wildcard $(CROSS_COMPILE_TARGET)/usr/include/mISDNuser/mISDNlib.h),)
  SELECTED_MODS:=$(filter-out chan_misdn.so,$(SELECTED_MODS))
else
  CFLAGS+=-Imisdn 
endif

MODS:=$(patsubst %,%.so,$(SELECTED_MODS))

all: $(MODS) 

clean-depend:
	rm -f .depend

clean: clean-depend
	rm -f *.so *.o
	rm -f busy.h ringtone.h gentone gentone-ulaw

%.so : %.o
	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
  include .depend
endif

ifneq ($(wildcard misdn/Makefile.ast),)
  include misdn/Makefile.ast
endif

gentone: gentone.c
	$(HOST_CC) -o gentone gentone.c -lm

gentone-ulaw: gentone-ulaw.c
	$(HOST_CC) -o gentone-ulaw gentone-ulaw.c -lm

busy.h: gentone
	./gentone busy 480 620

ringtone.h: gentone
	./gentone ringtone 440 480

chan_oss.o: chan_oss.c busy.h ringtone.h
	$(CC) -c -o $@ $(CFLAGS) $(OSSAUDIO_INCLUDE) $<

chan_oss.so: chan_oss.o
	$(CC) $(SOLINK) -o $@ chan_oss.o $(OSSAUDIO_LIB)

chan_iax2.so: chan_iax2.o iax2-parser.o iax2-provision.o
	$(CC) $(SOLINK) -o $@ $< iax2-parser.o iax2-provision.o

chan_zap.so: chan_zap.o
	$(CC) $(SOLINK) -o $@ $< $(PRI_LIB) $(ZAPTEL_LIB)

chan_zap.o: chan_zap.c
	$(CC) -c -o $@ $(CFLAGS) $(ZAPTEL_INCLUDE) $<

chan_alsa.so: chan_alsa.o
	$(CC) $(SOLINK) -o $@ $< $(ASOUND_LIB)

chan_alsa.o: chan_alsa.c busy.h ringtone.h
	$(CC) -c -o $@ $(CFLAGS) $(ASOUND_INCLUDE) $<

chan_nbs.so: chan_nbs.o
	$(CC) $(SOLINK) -o $@ $< $(NBS_LIB)

chan_nbs.o: chan_nbs.c
	$(CC) -c -o $@ $(CFLAGS) $(NBS_INCLUDE) $<

chan_vpb.o: chan_vpb.c
	$(CXX) -c $(CFLAGS:-Werror=) -o $@ chan_vpb.c

chan_vpb.so: chan_vpb.o
	 $(CXX) $(SOLINK) -o $@ $< -lvpb -lpthread -lm -ldl

chan_jingle.o: chan_jingle.c
	$(CC) -c -o $@ $(CFLAGS) $(IKSEMEL_INCLUDE) $<

chan_jingle.so: chan_jingle.o
	$(CC) $(SOLINK) -o $@ $< $(IKSEMEL_LIB)

misdn/chan_misdn_lib.a:
	make -C misdn

chan_misdn.so: chan_misdn.o misdn_config.o misdn/chan_misdn_lib.a
	$(CC) -shared -Xlinker -x -L/usr/lib -o $@ $^ -lisdnnet -lmISDN

chan_misdn.o: chan_misdn.c
	$(CC) $(CFLAGS) -DCHAN_MISDN_VERSION=\"0.3.0\" -c $< -o $@

misdn_config.o: misdn_config.c misdn/chan_misdn_config.h
	$(CC) $(CFLAGS) -DCHAN_MISDN_VERSION=\"0.3.0\" -c $< -o $@

install: all
	for x in $(MODS); do $(INSTALL) -m 755 $$x $(DESTDIR)$(MODULES_DIR) ; done

uninstall:

depend: .depend

.depend:
	../build_tools/mkdep $(CFLAGS) `ls *.c`

env:
	env
