/*
 * Asterisk -- A telephony toolkit for Linux.
 *
 * Old-style G.723 frame/timestamp format.
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
#include <sys/time.h>
#include "../channels/adtranvofr.h"


#define G723_MAX_SIZE 1024

struct ast_filestream {
	/* First entry MUST be reserved for the channel type */
	void *reserved[AST_RESERVED_POINTERS];
	/* This is what a filestream means to us */
	int fd; /* Descriptor */
	u_int32_t lasttimeout;	/* Last amount of timeout */
	struct ast_channel *owner;
	struct ast_filestream *next;
	struct ast_frame *fr;	/* Frame representation of buf */
	struct timeval orig;	/* Original frame time */
	char buf[G723_MAX_SIZE + AST_FRIENDLY_OFFSET];	/* Buffer for sending frames, etc */
};


static struct ast_filestream *glist = NULL;
static pthread_mutex_t g723_lock = PTHREAD_MUTEX_INITIALIZER;
static int glistcnt = 0;

static char *name = "g723sf";
static char *desc = "G.723.1 Simple Timestamp File Format";
static char *exts = "g723";

static struct ast_filestream *g723_open(int fd)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */
	struct ast_filestream *tmp;
	if ((tmp = malloc(sizeof(struct ast_filestream)))) {
		if (pthread_mutex_lock(&g723_lock)) {
			ast_log(LOG_WARNING, "Unable to lock g723 list\n");
			free(tmp);
			return NULL;
		}
		tmp->next = glist;
		glist = tmp;
		tmp->fd = fd;
		tmp->owner = NULL;
		tmp->fr = (struct ast_frame *)tmp->buf;
		tmp->fr->data = tmp->buf + sizeof(struct ast_frame);
		tmp->fr->frametype = AST_FRAME_VOICE;
		tmp->fr->subclass = AST_FORMAT_G723_1;
		/* datalen will vary for each frame */
		tmp->fr->src = name;
		tmp->fr->mallocd = 0;
		tmp->lasttimeout = -1;
		tmp->orig.tv_usec = 0;
		tmp->orig.tv_sec = 0;
		glistcnt++;
		pthread_mutex_unlock(&g723_lock);
		ast_update_use_count();
	}
	return tmp;
}

static struct ast_filestream *g723_rewrite(int fd, char *comment)
{
	/* We don't have any header to read or anything really, but
	   if we did, it would go here.  We also might want to check
	   and be sure it's a valid file.  */
	struct ast_filestream *tmp;
	if ((tmp = malloc(sizeof(struct ast_filestream)))) {
		if (pthread_mutex_lock(&g723_lock)) {
			ast_log(LOG_WARNING, "Unable to lock g723 list\n");
			free(tmp);
			return NULL;
		}
		tmp->next = glist;
		glist = tmp;
		tmp->fd = fd;
		tmp->owner = NULL;
		tmp->fr = NULL;
		tmp->lasttimeout = -1;
		glistcnt++;
		pthread_mutex_unlock(&g723_lock);
		ast_update_use_count();
	} else
		ast_log(LOG_WARNING, "Out of memory\n");
	return tmp;
}

static struct ast_frame *g723_read(struct ast_filestream *s)
{
	return NULL;
}

static void g723_close(struct ast_filestream *s)
{
	struct ast_filestream *tmp, *tmpl = NULL;
	if (pthread_mutex_lock(&g723_lock)) {
		ast_log(LOG_WARNING, "Unable to lock g723 list\n");
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
	pthread_mutex_unlock(&g723_lock);
	ast_update_use_count();
	if (!tmp) 
		ast_log(LOG_WARNING, "Freeing a filestream we don't seem to own\n");
	close(s->fd);
	free(s);
}

static int ast_read_callback(void *data)
{
	u_int16_t size;
	u_int32_t delay = -1;
	int looper = 1;
	int retval = 0;
	int res;
	struct ast_filestream *s = data;
	/* Send a frame from the file to the appropriate channel */
	while(looper) {
		if (read(s->fd, &size, 2) != 2) {
			/* Out of data, or the file is no longer valid.  In any case
			   go ahead and stop the stream */
			s->owner->streamid = -1;
			return 0;
		}
		/* Looks like we have a frame to read from here */
		size = ntohs(size);
		if (size > G723_MAX_SIZE - sizeof(struct ast_frame)) {
			ast_log(LOG_WARNING, "Size %d is invalid\n", size);
			/* The file is apparently no longer any good, as we
			   shouldn't ever get frames even close to this 
			   size.  */
			s->owner->streamid = -1;
			return 0;
		}
		/* Read the data into the buffer */
		s->fr->offset = AST_FRIENDLY_OFFSET;
		s->fr->datalen = size;
		s->fr->data = s->buf + sizeof(struct ast_frame) + AST_FRIENDLY_OFFSET;
		if ((res = read(s->fd, s->fr->data , size)) != size) {
			ast_log(LOG_WARNING, "Short read (%d of %d bytes) (%s)!\n", res, size, strerror(errno));
			s->owner->streamid = -1;
			return 0;
		}
		/* Read the delay for the next packet, and schedule again if necessary */
		if (read(s->fd, &delay, 4) == 4) 
			delay = ntohl(delay);
		else
			delay = -1;
		/* Average out frames <= 40 ms */
		if (delay < 41)
			s->fr->timelen = 30;
		else
			s->fr->timelen = delay;
		/* Unless there is no delay, we're going to exit out as soon as we
		   have processed the current frame. */
		if (delay > VOFR_FUDGE) {
			looper = 0;
			/* If there is a delay, lets schedule the next event */
			if (delay != s->lasttimeout) {
				/* We'll install the next timeout now. */
				s->owner->streamid = ast_sched_add(s->owner->sched, 
													  delay - VOFR_FUDGE, 
													  ast_read_callback, s);
				
				s->lasttimeout = delay;
			} else
				/* Just come back again at the same time */
				retval = -1;
		}
		/* Lastly, process the frame */
		if (ast_write(s->owner, s->fr)) {
			ast_log(LOG_WARNING, "Failed to write frame\n");
			s->owner->streamid = -1;
			return 0;
		}
	}
	return retval;
}

static int g723_apply(struct ast_channel *c, struct ast_filestream *s)
{
	u_int32_t delay;
	/* Select our owner for this stream, and get the ball rolling. */
	s->owner = c;
	/* Read and ignore the first delay */
	if (read(s->fd, &delay, 4) != 4) {
		ast_log(LOG_WARNING, "Bad stream?\n");
		return -1;
	}
	ast_read_callback(s);
	return 0;
}

static int g723_write(struct ast_filestream *fs, struct ast_frame *f)
{
	struct timeval now;
	u_int32_t delay;
	u_int16_t size;
	int res;
	if (fs->fr) {
		ast_log(LOG_WARNING, "Asked to write on a read stream??\n");
		return -1;
	}
	if (f->frametype != AST_FRAME_VOICE) {
		ast_log(LOG_WARNING, "Asked to write non-voice frame!\n");
		return -1;
	}
	if (f->subclass != AST_FORMAT_G723_1) {
		ast_log(LOG_WARNING, "Asked to write non-g723 frame!\n");
		return -1;
	}
	if (!(fs->orig.tv_usec || fs->orig.tv_sec)) {
		/* First frame should have zeros for delay */
		delay = 0;
		if (gettimeofday(&fs->orig, NULL)) {
			ast_log(LOG_WARNING, "gettimeofday() failed??  What is this?  Y2k?\n");
			return -1;
		}
	} else {
		if (gettimeofday(&now, NULL)) {
			ast_log(LOG_WARNING, "gettimeofday() failed??  What is this?  Y2k?\n");
			return -1;
		}
		delay = (now.tv_sec - fs->orig.tv_sec) * 1000 + (now.tv_usec - fs->orig.tv_usec) / 1000;
		delay = htonl(delay);
		fs->orig.tv_sec = now.tv_sec;
		fs->orig.tv_usec = now.tv_usec;
	}
	if ((res = write(fs->fd, &delay, 4)) != 4) {
		ast_log(LOG_WARNING, "Unable to write delay: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}
	size = htons(f->datalen);
	if ((res =write(fs->fd, &size, 2)) != 2) {
		ast_log(LOG_WARNING, "Unable to write size: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}
	if ((res = write(fs->fd, f->data, f->datalen)) != f->datalen) {
		ast_log(LOG_WARNING, "Unable to write frame: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}	
	return 0;
}

char *g723_getcomment(struct ast_filestream *s)
{
	return NULL;
}

int load_module()
{
	return ast_format_register(name, exts, AST_FORMAT_G723_1,
								g723_open,
								g723_rewrite,
								g723_apply,
								g723_write,
								g723_read,
								g723_close,
								g723_getcomment);
								
								
}

int unload_module()
{
	struct ast_filestream *tmp, *tmpl;
	if (pthread_mutex_lock(&g723_lock)) {
		ast_log(LOG_WARNING, "Unable to lock g723 list\n");
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
	pthread_mutex_unlock(&g723_lock);
	return ast_format_unregister(name);
}	

int usecount()
{
	int res;
	if (pthread_mutex_lock(&g723_lock)) {
		ast_log(LOG_WARNING, "Unable to lock g723 list\n");
		return -1;
	}
	res = glistcnt;
	pthread_mutex_unlock(&g723_lock);
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

/*! 
 * \file
 *
 * \brief Old-style G.723.1 frame/timestamp format.
 * 
 * \arg Extensions: g723, g723sf
 * \ingroup formats
 */
 
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/sched.h"
#include "asterisk/module.h"

#define G723_MAX_SIZE 1024

static struct ast_frame *g723_read(struct ast_filestream *s, int *whennext)
{
	unsigned short size;
	int res;
	int delay;
	/* Read the delay for the next packet, and schedule again if necessary */
	/* XXX is this ignored ? */
	if (fread(&delay, 1, 4, s->f) == 4) 
		delay = ntohl(delay);
	else
		delay = -1;
	if (fread(&size, 1, 2, s->f) != 2) {
		/* Out of data, or the file is no longer valid.  In any case
		   go ahead and stop the stream */
		return NULL;
	}
	/* Looks like we have a frame to read from here */
	size = ntohs(size);
	if (size > G723_MAX_SIZE) {
		ast_log(LOG_WARNING, "Size %d is invalid\n", size);
		/* The file is apparently no longer any good, as we
		   shouldn't ever get frames even close to this 
		   size.  */
		return NULL;
	}
	/* Read the data into the buffer */
	s->fr.frametype = AST_FRAME_VOICE;
	s->fr.subclass = AST_FORMAT_G723_1;
	s->fr.mallocd = 0;
	AST_FRAME_SET_BUFFER(&s->fr, s->buf, AST_FRIENDLY_OFFSET, size);
	if ((res = fread(s->fr.data, 1, s->fr.datalen, s->f)) != size) {
		ast_log(LOG_WARNING, "Short read (%d of %d bytes) (%s)!\n", res, size, strerror(errno));
		return NULL;
	}
	*whennext = s->fr.samples = 240;
	return &s->fr;
}

static int g723_write(struct ast_filestream *s, struct ast_frame *f)
{
	u_int32_t delay;
	u_int16_t size;
	int res;
	/* XXX there used to be a check s->fr means a read stream */
	if (f->frametype != AST_FRAME_VOICE) {
		ast_log(LOG_WARNING, "Asked to write non-voice frame!\n");
		return -1;
	}
	if (f->subclass != AST_FORMAT_G723_1) {
		ast_log(LOG_WARNING, "Asked to write non-g723 frame!\n");
		return -1;
	}
	delay = 0;
	if (f->datalen <= 0) {
		ast_log(LOG_WARNING, "Short frame ignored (%d bytes long?)\n", f->datalen);
		return 0;
	}
	if ((res = fwrite(&delay, 1, 4, s->f)) != 4) {
		ast_log(LOG_WARNING, "Unable to write delay: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}
	size = htons(f->datalen);
	if ((res = fwrite(&size, 1, 2, s->f)) != 2) {
		ast_log(LOG_WARNING, "Unable to write size: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}
	if ((res = fwrite(f->data, 1, f->datalen, s->f)) != f->datalen) {
		ast_log(LOG_WARNING, "Unable to write frame: res=%d (%s)\n", res, strerror(errno));
		return -1;
	}	
	return 0;
}

static int g723_seek(struct ast_filestream *fs, off_t sample_offset, int whence)
{
	return -1;
}

static int g723_trunc(struct ast_filestream *fs)
{
	/* Truncate file to current length */
	if (ftruncate(fileno(fs->f), ftello(fs->f)) < 0)
		return -1;
	return 0;
}

static off_t g723_tell(struct ast_filestream *fs)
{
	return -1;
}

static const struct ast_format g723_1_f = {
	.name = "g723sf",
	.exts = "g723|g723sf",
	.format = AST_FORMAT_G723_1,
	.write = g723_write,
	.seek =	g723_seek,
	.trunc = g723_trunc,
	.tell =	g723_tell,
	.read =	g723_read,
	.buf_size = G723_MAX_SIZE + AST_FRIENDLY_OFFSET,
	.module = &mod_data, /* XXX */
};

static int load_module(void *mod)
{
	return ast_format_register(&g723_1_f);
}

static int unload_module(void *mod)
{
	return ast_format_unregister(g723_1_f.name);
}	

static const char *description(void)
{
	return "G.723.1 Simple Timestamp File Format";
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD1;
