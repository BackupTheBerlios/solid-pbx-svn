/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Anthony Minessale anthmct@yahoo.com
 * Development of this app Sponsered/Funded  by TAAN Softworks Corp
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
 * \brief Fork CDR application
 *
 * \author Anthony Minessale anthmct@yahoo.com
 *
 * \note Development of this app Sponsered/Funded  by TAAN Softworks Corp
 * 
 * \ingroup applications
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 32846 $")

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/cdr.h"
#include "asterisk/module.h"

static char *app = "ForkCDR";
static char *synopsis = 
"Forks the Call Data Record";
static char *descrip = 
"  ForkCDR([options]):  Causes the Call Data Record to fork an additional\n"
	"cdr record starting from the time of the fork call\n"
"If the option 'v' is passed all cdr variables will be passed along also.\n"
"";

LOCAL_USER_DECL;

static void ast_cdr_fork(struct ast_channel *chan) 
{
	struct ast_cdr *cdr;
	struct ast_cdr *newcdr;
	struct ast_flags flags = { AST_CDR_FLAG_KEEP_VARS };

	cdr = chan->cdr;

	while (cdr->next)
		cdr = cdr->next;
	
	if (!(newcdr = ast_cdr_dup(cdr)))
		return;
	
	ast_cdr_append(cdr, newcdr);
	ast_cdr_reset(newcdr, &flags);
	
	if (!ast_test_flag(cdr, AST_CDR_FLAG_KEEP_VARS))
		ast_cdr_free_vars(cdr, 0);
	
	ast_set_flag(cdr, AST_CDR_FLAG_CHILD | AST_CDR_FLAG_LOCKED);
}

static int forkcdr_exec(struct ast_channel *chan, void *data)
{
	int res = 0;
	struct localuser *u;

	if (!chan->cdr) {
		ast_log(LOG_WARNING, "Channel does not have a CDR\n");
		return 0;
	}

	LOCAL_USER_ADD(u);

	if (!ast_strlen_zero(data))
		ast_set2_flag(chan->cdr, strchr(data, 'v'), AST_CDR_FLAG_KEEP_VARS);
	
	ast_cdr_fork(chan);

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
	return ast_register_application(app, forkcdr_exec, synopsis, descrip);
}

static const char *description(void)
{
	return "Fork The CDR into 2 separate entities.";
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD1;