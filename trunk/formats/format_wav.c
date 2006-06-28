/*
 * Asterisk -- A telephony toolkit for Linux.
 *
 * Microsoft WAV File Format using libaudiofile 
 * 
 * Copyright (C) 1999, Adtran Inc. and Linux Support Services, LLC
 *
 * Mark Spencer <markster@linux-support.net>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */
 
#include <asterisk/channel.h>
#include <asterisk/file.h>
#include <asterisk/logger.h>
#include <asterisk/sched.h>
#include <asterisk/module.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <audiofile.h>


/* Read 320 samples at a time, max */ 
#define WAV_MAX_SIZE 320

/* Fudge in milliseconds */
#define WAV_FUDGE 2

struct ast_filestream {
	/* First entry MUST be reserved for the channel type */
	void *reserved[AST_RESERVED_POINTERS];
	/* This is what a filestream means to us */
	int fd; /* Descriptor */
	/* Audio File */
	AFfilesetup afs;
	AFfilehandle af;
	int lasttimeout;
	struct ast_channel *owner;
	struct ast_filestream *next;
	struct ast_frame fr;				/* Frame information */
	char waste[AST_FRIENDLY_OFFSET];	/* Buffer for sending frames, etc */
	short samples[WAV_MAX_SIZE];
};


static struct ast_filestream *glist = NULL;
static pthread_mutex_t wav_lock = PTHREAD_MUTEX_INITIALIZER;
static int glistcnt = 0;

static char *name = "wav";
static char *desc = "Microsoft WAV format (PCM/16, 8000Hz mono)";
static char *exts = "wav";

static struct ast_filestream *wav_open(int fd)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */
	struct ast_filestream *tmp;
	int notok = 0;
	int fmt, width;
	double rate;
	if ((tmp = malloc(sizeof(struct ast_filestream)))) {
		tmp->afs = afNewFileSetup();
		if (!tmp->afs) {
			ast_log(LOG_WARNING, "Unable to create file setup\n");
			free(tmp);
			return NULL;
		}
		afInitFileFormat(tmp->afs, AF_FILE_WAVE);
		tmp->af = afOpenFD(fd, "r", tmp->afs);
		if (!tmp->af) {
			afFreeFileSetup(tmp->afs);
			ast_log(LOG_WARNING, "Unable to open file descriptor\n");
			free(tmp);
			return NULL;
		}
#if 0
		afGetFileFormat(tmp->af, &version);
		if (version != AF_FILE_WAVE) {
			ast_log(LOG_WARNING, "This is not a wave file (%d)\n", version);
			notok++;
		}
#endif
		/* Read the format and make sure it's exactly what we seek. */
		if (afGetChannels(tmp->af, AF_DEFAULT_TRACK) != 1) {
			ast_log(LOG_WARNING, "Invalid number of channels %d.  Should be mono (1)\n", afGetChannels(tmp->af, AF_DEFAULT_TRACK));
			notok++;
		}
		afGetSampleFormat(tmp->af, AF_DEFAULT_TRACK, &fmt, &width);
		if (fmt != AF_SAMPFMT_TWOSCOMP) {
			ast_log(LOG_WARNING, "Input file is not signed\n");
			notok++;
		}
		rate = afGetRate(tmp->af, AF_DEFAULT_TRACK);
		if ((rate < 7900) || (rate > 8100)) {
			ast_log(LOG_WARNING, "Rate %f is not close enough to 8000 Hz\n", rate);
			notok++;
		}
		if (width != 16) {
			ast_log(LOG_WARNING, "Input file is not 16-bit\n");
			notok++;
		}
		if (notok) {
			afCloseFile(tmp->af);
			afFreeFileSetup(tmp->afs);
			free(tmp);
			return NULL;
		}
		if (pthread_mutex_lock(&wav_lock)) {
			afCloseFile(tmp->af);
			afFreeFileSetup(tmp->afs);
			ast_log(LOG_WARNING, "Unable to lock wav list\n");
			free(tmp);
			return NULL;
		}
		tmp->next = glist;
		glist = tmp;
		tmp->fd = fd;
		tmp->owner = NULL;
		tmp->fr.data = tmp->samples;
		tmp->fr.frametype = AST_FRAME_VOICE;
		tmp->fr.subclass = AST_FORMAT_SLINEAR;
		/* datalen will vary for each frame */
		tmp->fr.src = name;
		tmp->fr.mallocd = 0;
		tmp->lasttimeout = -1;
		glistcnt++;
		pthread_mutex_unlock(&wav_lock);
		ast_update_use_count();
	}
	return tmp;
}

static struct ast_filestream *wav_rewrite(int fd, char *comment)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */
	struct ast_filestream *tmp;
	if ((tmp = malloc(sizeof(struct ast_filestream)))) {
		tmp->afs = afNewFileSetup();
		if (!tmp->afs) {
			ast_log(LOG_WARNING, "Unable to create file setup\n");
			free(tmp);
			return NULL;
		}
		/* WAV format */
		afInitFileFormat(tmp->afs, AF_FILE_WAVE);
		/* Mono */
		afInitChannels(tmp->afs, AF_DEFAULT_TRACK, 1);
		/* Signed linear, 16-bit */
		afInitSampleFormat(tmp->afs, AF_DEFAULT_TRACK, AF_SAMPFMT_TWOSCOMP, 16);
		/* 8000 Hz */
		afInitRate(tmp->afs, AF_DEFAULT_TRACK, (double)8000.0);
		tmp->af = afOpenFD(fd, "w", tmp->afs);
		if (!tmp->af) {
			afFreeFileSetup(tmp->afs);
			ast_log(LOG_WARNING, "Unable to open file descriptor\n");
			free(tmp);
			return NULL;
		}
		if (pthread_mutex_lock(&wav_lock)) {
			ast_log(LOG_WARNING, "Unable to lock wav list\n");
			free(tmp);
			return NULL;
		}
		tmp->next = glist;
		glist = tmp;
		tmp->fd = fd;
		tmp->owner = NULL;
		tmp->lasttimeout = -1;
		glistcnt++;
		pthread_mutex_unlock(&wav_lock);
		ast_update_use_count();
	} else
		ast_log(LOG_WARNING, "Out of memory\n");
	return tmp;
}

static struct ast_frame *wav_read(struct ast_filestream *s)
{
	return NULL;
}

static void wav_close(struct ast_filestream *s)
{
	struct ast_filestream *tmp, *tmpl = NULL;
	if (pthread_mutex_lock(&wav_lock)) {
		ast_log(LOG_WARNING, "Unable to lock wav list\n");
		return;
	}
	tmp = glist;
	while(tmp) {
		if (tmp == s) {
			if (tmpl)
				tmpl->next = tmp->next;
			else
				glist = tmp->next;
			break;
		}
		tmpl = tmp;
		tmp = tmp->next;
	}
	glistcnt--;
	if (s->owner) {
		s->owner->stream = NULL;
		if (s->owner->streamid > -1)
			ast_sched_del(s->owner->sched, s->owner->streamid);
		s->owner->streamid = -1;
	}
	pthread_mutex_unlock(&wav_lock);
	ast_update_use_count();
	if (!tmp) 
		ast_log(LOG_WARNING, "Freeing a filestream we don't seem to own\n");
	afCloseFile(tmp->af);
	afFreeFileSetup(tmp->afs);
	close(s->fd);
	free(s);
}

static int ast_read_callback(void *data)
{
	u_int32_t delay = -1;
	int retval = 0;
	int res;
	struct ast_filestream *s = data;
	/* Send a frame from the file to the appropriate channel */

	if ((res = afReadFrames(s->af, AF_DEFAULT_TRACK, s->samples, sizeof(s->samples)/2)) < 1) {
		if (res)
			ast_log(LOG_WARNING, "Short read (%d) (%s)!\n", res, strerror(errno));
		s->owner->streamid = -1;
		return 0;
	}
	/* Per 8 samples, one milisecond */
	delay = res / 8;
	s->fr.frametype = AST_FRAME_VOICE;
	s->fr.subclass = AST_FORMAT_SLINEAR;
	s->fr.offset = AST_FRIENDLY_OFFSET;
	s->fr.datalen = res * 2;
	s->fr.data = s->samples;
	s->fr.mallocd = 0;
	s->fr.timelen = delay;
	/* Unless there is no delay, we're going to exit out as soon as we
	   have processed the current frame. */
	/* If there is a delay, lets schedule the next event */
	if (delay != s->lasttimeout) {
		/* We'll install the next timeout now. */
		s->owner->streamid = ast_sched_add(s->owner->sched, 
											  delay, 
											  ast_read_callback, s);
		
		s->lasttimeout = delay;
	} else {
		/* Just come back again at the same time */
		retval = -1;
	}
	/* Lastly, process the frame */
	if (ast_write(s->owner, &s->fr)) {
		ast_log(LOG_WARNING, "Failed to write frame\n");
		s->owner->streamid = -1;
		return 0;
	}
	
	return retval;
}

static int wav_apply(struct ast_channel *c, struct ast_filestream *s)
{
	/* Select our owner for this stream, and get the ball rolling. */
	s->owner = c;
	ast_read_callback(s);
	return 0;
}

static int wav_write(struct ast_filestream *fs, struct ast_frame *f)
{
	int res;
	if (f->frametype != AST_FRAME_VOICE) {
		ast_log(LOG_WARNING, "Asked to write non-voice frame!\n");
		return -1;
	}
	if (f->subclass != AST_FORMAT_SLINEAR) {
		ast_log(LOG_WARNING, "Asked to write non-signed linear frame (%d)!\n", f->subclass);
		return -1;
	}
	if ((res = afWriteFrames(fs->af, AF_DEFAULT_TRACK, f->data, f->datalen/2)) != f->datalen/2) {
		ast_log(LOG_WARNING, "Unable to write frame: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}	
	return 0;
}

char *wav_getcomment(struct ast_filestream *s)
{
	return NULL;
}

int load_module()
{
	return ast_format_register(name, exts, AST_FORMAT_SLINEAR,
								wav_open,
								wav_rewrite,
								wav_apply,
								wav_write,
								wav_read,
								wav_close,
								wav_getcomment);								
								
								
}

int unload_module()
{
	struct ast_filestream *tmp, *tmpl;
	if (pthread_mutex_lock(&wav_lock)) {
		ast_log(LOG_WARNING, "Unable to lock wav list\n");
		return -1;
	}
	tmp = glist;
	while(tmp) {
		if (tmp->owner)
			ast_softhangup(tmp->owner);
		tmpl = tmp;
		tmp = tmp->next;
		free(tmpl);
	}
	pthread_mutex_unlock(&wav_lock);
	return ast_format_unregister(name);
}	

int usecount()
{
	int res;
	if (pthread_mutex_lock(&wav_lock)) {
		ast_log(LOG_WARNING, "Unable to lock wav list\n");
		return -1;
	}
	res = glistcnt;
	pthread_mutex_unlock(&wav_lock);
	return res;
}

char *description()
{
	return desc;
}

/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Work with WAV in the proprietary Microsoft format.
 * Microsoft WAV format (8000hz Signed Linear)
 * \arg File name extension: wav (lower case)
 * \ingroup formats
 */
 
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/sched.h"
#include "asterisk/module.h"
#include "asterisk/endian.h"

/* Some Ideas for this code came from makewave.c by Jeffrey Chilton */

/* Portions of the conversion code are by guido@sienanet.it */

#define	WAV_BUF_SIZE	320

struct wav_desc {	/* format-specific parameters */
	int bytes;
	int needsgain;
	int lasttimeout;
	int maxlen;
	struct timeval last;
};

#define BLOCKSIZE 160

#define GAIN 2		/* 2^GAIN is the multiple to increase the volume by */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htoll(b) (b)
#define htols(b) (b)
#define ltohl(b) (b)
#define ltohs(b) (b)
#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define htoll(b)  \
          (((((b)      ) & 0xFF) << 24) | \
	       ((((b) >>  8) & 0xFF) << 16) | \
		   ((((b) >> 16) & 0xFF) <<  8) | \
		   ((((b) >> 24) & 0xFF)      ))
#define htols(b) \
          (((((b)      ) & 0xFF) << 8) | \
		   ((((b) >> 8) & 0xFF)      ))
#define ltohl(b) htoll(b)
#define ltohs(b) htols(b)
#else
#error "Endianess not defined"
#endif
#endif


static int check_header(FILE *f)
{
	int type, size, formtype;
	int fmt, hsize;
	short format, chans, bysam, bisam;
	int bysec;
	int freq;
	int data;
	if (fread(&type, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (type)\n");
		return -1;
	}
	if (fread(&size, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (size)\n");
		return -1;
	}
	size = ltohl(size);
	if (fread(&formtype, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (formtype)\n");
		return -1;
	}
	if (memcmp(&type, "RIFF", 4)) {
		ast_log(LOG_WARNING, "Does not begin with RIFF\n");
		return -1;
	}
	if (memcmp(&formtype, "WAVE", 4)) {
		ast_log(LOG_WARNING, "Does not contain WAVE\n");
		return -1;
	}
	if (fread(&fmt, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (fmt)\n");
		return -1;
	}
	if (memcmp(&fmt, "fmt ", 4)) {
		ast_log(LOG_WARNING, "Does not say fmt\n");
		return -1;
	}
	if (fread(&hsize, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (formtype)\n");
		return -1;
	}
	if (ltohl(hsize) < 16) {
		ast_log(LOG_WARNING, "Unexpected header size %d\n", ltohl(hsize));
		return -1;
	}
	if (fread(&format, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Read failed (format)\n");
		return -1;
	}
	if (ltohs(format) != 1) {
		ast_log(LOG_WARNING, "Not a wav file %d\n", ltohs(format));
		return -1;
	}
	if (fread(&chans, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Read failed (format)\n");
		return -1;
	}
	if (ltohs(chans) != 1) {
		ast_log(LOG_WARNING, "Not in mono %d\n", ltohs(chans));
		return -1;
	}
	if (fread(&freq, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (freq)\n");
		return -1;
	}
	if (ltohl(freq) != DEFAULT_SAMPLE_RATE) {
		ast_log(LOG_WARNING, "Unexpected freqency %d\n", ltohl(freq));
		return -1;
	}
	/* Ignore the byte frequency */
	if (fread(&bysec, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Read failed (BYTES_PER_SECOND)\n");
		return -1;
	}
	/* Check bytes per sample */
	if (fread(&bysam, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Read failed (BYTES_PER_SAMPLE)\n");
		return -1;
	}
	if (ltohs(bysam) != 2) {
		ast_log(LOG_WARNING, "Can only handle 16bits per sample: %d\n", ltohs(bysam));
		return -1;
	}
	if (fread(&bisam, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Read failed (Bits Per Sample): %d\n", ltohs(bisam));
		return -1;
	}
	/* Skip any additional header */
	if (fseek(f,ltohl(hsize)-16,SEEK_CUR) == -1 ) {
		ast_log(LOG_WARNING, "Failed to skip remaining header bytes: %d\n", ltohl(hsize)-16 );
		return -1;
	}
	/* Skip any facts and get the first data block */
	for(;;)
	{ 
		char buf[4];
	    
	    /* Begin data chunk */
	    if (fread(&buf, 1, 4, f) != 4) {
			ast_log(LOG_WARNING, "Read failed (data)\n");
			return -1;
	    }
	    /* Data has the actual length of data in it */
	    if (fread(&data, 1, 4, f) != 4) {
			ast_log(LOG_WARNING, "Read failed (data)\n");
			return -1;
	    }
	    data = ltohl(data);
	    if(memcmp(buf, "data", 4) == 0 ) 
			break;
	    if(memcmp(buf, "fact", 4) != 0 ) {
			ast_log(LOG_WARNING, "Unknown block - not fact or data\n");
			return -1;
	    }
	    if (fseek(f,data,SEEK_CUR) == -1 ) {
			ast_log(LOG_WARNING, "Failed to skip fact block: %d\n", data );
			return -1;
	    }
	}
#if 0
	curpos = lseek(fd, 0, SEEK_CUR);
	truelength = lseek(fd, 0, SEEK_END);
	lseek(fd, curpos, SEEK_SET);
	truelength -= curpos;
#endif	
	return data;
}

static int update_header(FILE *f)
{
	off_t cur,end;
	int datalen,filelen,bytes;
	
	cur = ftello(f);
	fseek(f, 0, SEEK_END);
	end = ftello(f);
	/* data starts 44 bytes in */
	bytes = end - 44;
	datalen = htoll(bytes);
	/* chunk size is bytes of data plus 36 bytes of header */
	filelen = htoll(36 + bytes);
	
	if (cur < 0) {
		ast_log(LOG_WARNING, "Unable to find our position\n");
		return -1;
	}
	if (fseek(f, 4, SEEK_SET)) {
		ast_log(LOG_WARNING, "Unable to set our position\n");
		return -1;
	}
	if (fwrite(&filelen, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to set write file size\n");
		return -1;
	}
	if (fseek(f, 40, SEEK_SET)) {
		ast_log(LOG_WARNING, "Unable to set our position\n");
		return -1;
	}
	if (fwrite(&datalen, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to set write datalen\n");
		return -1;
	}
	if (fseeko(f, cur, SEEK_SET)) {
		ast_log(LOG_WARNING, "Unable to return to position\n");
		return -1;
	}
	return 0;
}

static int write_header(FILE *f)
{
	unsigned int hz=htoll(8000);
	unsigned int bhz = htoll(16000);
	unsigned int hs = htoll(16);
	unsigned short fmt = htols(1);
	unsigned short chans = htols(1);
	unsigned short bysam = htols(2);
	unsigned short bisam = htols(16);
	unsigned int size = htoll(0);
	/* Write a wav header, ignoring sizes which will be filled in later */
	fseek(f,0,SEEK_SET);
	if (fwrite("RIFF", 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&size, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite("WAVEfmt ", 1, 8, f) != 8) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&hs, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&fmt, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&chans, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&hz, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bhz, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bysam, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&bisam, 1, 2, f) != 2) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite("data", 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	if (fwrite(&size, 1, 4, f) != 4) {
		ast_log(LOG_WARNING, "Unable to write header\n");
		return -1;
	}
	return 0;
}

static int wav_open(struct ast_filestream *s)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */
	struct wav_desc *tmp = (struct wav_desc *)s->private;
	if ((tmp->maxlen = check_header(s->f)) < 0)
		return -1;
	return 0;
}

static int wav_rewrite(struct ast_filestream *s, const char *comment)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */

	if (write_header(s->f))
		return -1;
	return 0;
}

static void wav_close(struct ast_filestream *s)
{
	char zero = 0;
	struct wav_desc *fs = (struct wav_desc *)s->private;
	/* Pad to even length */
	if (fs->bytes & 0x1)
		fwrite(&zero, 1, 1, s->f);
}

static struct ast_frame *wav_read(struct ast_filestream *s, int *whennext)
{
	int res;
	int samples;	/* actual samples read */
	int x;
	short *tmp;
	int bytes = WAV_BUF_SIZE;	/* in bytes */
	off_t here;
	/* Send a frame from the file to the appropriate channel */
	struct wav_desc *fs = (struct wav_desc *)s->private;

	here = ftello(s->f);
	if (fs->maxlen - here < bytes)		/* truncate if necessary */
		bytes = fs->maxlen - here;
	if (bytes < 0)
		bytes = 0;
/* 	ast_log(LOG_DEBUG, "here: %d, maxlen: %d, bytes: %d\n", here, s->maxlen, bytes); */
	s->fr.frametype = AST_FRAME_VOICE;
	s->fr.subclass = AST_FORMAT_SLINEAR;
	s->fr.mallocd = 0;
	AST_FRAME_SET_BUFFER(&s->fr, s->buf, AST_FRIENDLY_OFFSET, bytes);
	
	if ( (res = fread(s->fr.data, 1, s->fr.datalen, s->f)) <= 0 ) {
		if (res)
			ast_log(LOG_WARNING, "Short read (%d) (%s)!\n", res, strerror(errno));
		return NULL;
	}
	s->fr.datalen = res;
	s->fr.samples = samples = res / 2;

	tmp = (short *)(s->fr.data);
#if __BYTE_ORDER == __BIG_ENDIAN
	/* file format is little endian so we need to swap */
	for( x = 0; x < samples; x++)
		tmp[x] = (tmp[x] << 8) | ((tmp[x] & 0xff00) >> 8);
#endif

	if (fs->needsgain) {
		for (x=0; x < samples; x++) {
			if (tmp[x] & ((1 << GAIN) - 1)) {
				/* If it has data down low, then it's not something we've artificially increased gain
				   on, so we don't need to gain adjust it */
				fs->needsgain = 0;
				break;
			}
		}
		if (fs->needsgain) {
			for (x=0; x < samples; x++)
				tmp[x] = tmp[x] >> GAIN;
		}
	}
			
	*whennext = samples;
	return &s->fr;
}

static int wav_write(struct ast_filestream *fs, struct ast_frame *f)
{
	int x;
	short tmp[8000], *tmpi;
	float tmpf;
	struct wav_desc *s = (struct wav_desc *)fs->private;
	int res;

	if (f->frametype != AST_FRAME_VOICE) {
		ast_log(LOG_WARNING, "Asked to write non-voice frame!\n");
		return -1;
	}
	if (f->subclass != AST_FORMAT_SLINEAR) {
		ast_log(LOG_WARNING, "Asked to write non-SLINEAR frame (%d)!\n", f->subclass);
		return -1;
	}
	if (f->datalen > sizeof(tmp)) {
		ast_log(LOG_WARNING, "Data length is too long\n");
		return -1;
	}
	if (!f->datalen)
		return -1;

#if 0
	printf("Data Length: %d\n", f->datalen);
#endif	

	tmpi = f->data;
	/* Volume adjust here to accomodate */
	for (x=0;x<f->datalen/2;x++) {
		tmpf = ((float)tmpi[x]) * ((float)(1 << GAIN));
		if (tmpf > 32767.0)
			tmpf = 32767.0;
		if (tmpf < -32768.0)
			tmpf = -32768.0;
		tmp[x] = tmpf;
		tmp[x] &= ~((1 << GAIN) - 1);

#if __BYTE_ORDER == __BIG_ENDIAN
		tmp[x] = (tmp[x] << 8) | ((tmp[x] & 0xff00) >> 8);
#endif

	}
	if ((res = fwrite(tmp, 1, f->datalen, fs->f)) != f->datalen ) {
		ast_log(LOG_WARNING, "Bad write (%d): %s\n", res, strerror(errno));
		return -1;
	}

	s->bytes += f->datalen;
	update_header(fs->f);
		
	return 0;

}

static int wav_seek(struct ast_filestream *fs, off_t sample_offset, int whence)
{
	off_t min, max, cur, offset = 0, samples;

	samples = sample_offset * 2; /* SLINEAR is 16 bits mono, so sample_offset * 2 = bytes */
	min = 44; /* wav header is 44 bytes */
	cur = ftello(fs->f);
	fseeko(fs->f, 0, SEEK_END);
	max = ftello(fs->f);
	if (whence == SEEK_SET)
		offset = samples + min;
	else if (whence == SEEK_CUR || whence == SEEK_FORCECUR)
		offset = samples + cur;
	else if (whence == SEEK_END)
		offset = max - samples;
        if (whence != SEEK_FORCECUR) {
		offset = (offset > max)?max:offset;
	}
	/* always protect the header space. */
	offset = (offset < min)?min:offset;
	return fseeko(fs->f, offset, SEEK_SET);
}

static int wav_trunc(struct ast_filestream *fs)
{
	if (ftruncate(fileno(fs->f), ftello(fs->f)))
		return -1;
	return update_header(fs->f);
}

static off_t wav_tell(struct ast_filestream *fs)
{
	off_t offset;
	offset = ftello(fs->f);
	/* subtract header size to get samples, then divide by 2 for 16 bit samples */
	return (offset - 44)/2;
}

static const struct ast_format wav_f = {
	.name = "wav",
	.exts = "wav",
	.format = AST_FORMAT_SLINEAR,
	.open =	wav_open,
	.rewrite = wav_rewrite,
	.write = wav_write,
	.seek = wav_seek,
	.trunc = wav_trunc,
	.tell =	wav_tell,
	.read = wav_read,
	.close = wav_close,
	.buf_size = WAV_BUF_SIZE + AST_FRIENDLY_OFFSET,
	.desc_size = sizeof(struct wav_desc),
	.module = &mod_data, /* XXX */
};

static int load_module(void *mod)
{
	return ast_format_register(&wav_f);
}

static int unload_module(void *mod)
{
	return ast_format_unregister(wav_f.name);
}	

static const char *description(void)
{
	return "Microsoft WAV format (8000hz Signed Linear)";
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD1;
