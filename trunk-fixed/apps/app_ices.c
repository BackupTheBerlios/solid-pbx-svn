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
 * \brief Stream to an icecast server via ICES (see contrib/asterisk-ices.xml)
 *
 * \author Mark Spencer <markster@digium.com>
 * 
 * \ingroup applications
 */
 
#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 33516 $")

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>

#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/frame.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/translate.h"
#include "asterisk/options.h"

#define ICES "/usr/bin/ices"
#define LOCAL_ICES "/usr/local/bin/ices"

static char *app = "ICES";

static char *synopsis = "Encode and stream using 'ices'";

static char *descrip = 
"  ICES(config.xml) Streams to an icecast server using ices\n"
"(available separately).  A configuration file must be supplied\n"
"for ices (see examples/asterisk-ices.conf). \n";

LOCAL_USER_DECL;

static int icesencode(char *filename, int fd)
{
	int res;
	int x;
	res = fork();
	if (res < 0) 
		ast_log(LOG_WARNING, "Fork failed\n");
	if (res)
		return res;
	if (ast_opt_high_priority)
		ast_set_priority(0);
	dup2(fd, STDIN_FILENO);
	for (x=STDERR_FILENO + 1;x<256;x++) {
		if ((x != STDIN_FILENO) && (x != STDOUT_FILENO))
			close(x);
	}
	/* Most commonly installed in /usr/local/bin */
	execl(ICES, "ices", filename, (char *)NULL);
	/* But many places has it in /usr/bin */
	execl(LOCAL_ICES, "ices", filename, (char *)NULL);
	/* As a last-ditch effort, try to use PATH */
	execlp("ices", "ices", filename, (char *)NULL);
	ast_log(LOG_WARNING, "Execute of ices failed\n");
	return -1;
}

static int ices_exec(struct ast_channel *chan, void *data)
{
	int res=0;
	struct localuser *u;
	int fds[2];
	int ms = -1;
	int pid = -1;
	int flags;
	int oreadformat;
	struct timeval last;
	struct ast_frame *f;
	char filename[256]="";
	char *c;

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "ICES requires an argument (configfile.xml)\n");
		return -1;
	}

	LOCAL_USER_ADD(u);
	
	last = ast_tv(0, 0);
	
	if (pipe(fds)) {
		ast_log(LOG_WARNING, "Unable to create pipe\n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	flags = fcntl(fds[1], F_GETFL);
	fcntl(fds[1], F_SETFL, flags | O_NONBLOCK);
	
	ast_stopstream(chan);

	if (chan->_state != AST_STATE_UP)
		res = ast_answer(chan);
		
	if (res) {
		close(fds[0]);
		close(fds[1]);
		ast_log(LOG_WARNING, "Answer failed!\n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}

	oreadformat = chan->readformat;
	res = ast_set_read_format(chan, AST_FORMAT_SLINEAR);
	if (res < 0) {
		close(fds[0]);
		close(fds[1]);
		ast_log(LOG_WARNING, "Unable to set write format to signed linear\n");
		LOCAL_USER_REMOVE(u);
		return -1;
	}
	if (((char *)data)[0] == '/')
		strncpy(filename, (char *)data, sizeof(filename) - 1);
	else
		snprintf(filename, sizeof(filename), "%s/%s", (char *)ast_config_AST_CONFIG_DIR, (char *)data);
	/* Placeholder for options */		
	c = strchr(filename, '|');
	if (c)
		*c = '\0';	
	res = icesencode(filename, fds[0]);
	close(fds[0]);
	if (res >= 0) {
		pid = res;
		for (;;) {
			/* Wait for audio, and stream */
			ms = ast_waitfor(chan, -1);
			if (ms < 0) {
				ast_log(LOG_DEBUG, "Hangup detected\n");
				res = -1;
				break;
			}
			f = ast_read(chan);
			if (!f) {
				ast_log(LOG_DEBUG, "Null frame == hangup() detected\n");
				res = -1;
				break;
			}
			if (f->frametype == AST_FRAME_VOICE) {
				res = write(fds[1], f->data, f->datalen);
				if (res < 0) {
					if (errno != EAGAIN) {
						ast_log(LOG_WARNING, "Write failed to pipe: %s\n", strerror(errno));
						res = -1;
						ast_frfree(f);
						break;
					}
				}
			}
			ast_frfree(f);
		}
	}
	close(fds[1]);
	
	if (pid > -1)
		kill(pid, SIGKILL);
	if (!res && oreadformat)
		ast_set_read_format(chan, oreadformat);

	LOCAL_USER_REMOVE(u);

	return res;
}

static int unload_module(void *mod)
{
	int res;

	res = ast_unregister_application(app);

	STANDARD_HANGUP_LOCALUSERS;

	return res;
}

static int load_module(void *mod)
{
	return ast_register_application(app, ices_exec, synopsis, descrip);
}

static const char *description(void)
{
	return "Encode and Stream via icecast and ices";
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD1;
