/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Justin Huff <jjhuff@mspin.net>
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
 * \brief Applictions connected with CDR engine
 *
 * \author Justin Huff <jjhuff@mspin.net>
 *  
 * \ingroup applications
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 32846 $")

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "asterisk/channel.h"
#include "asterisk/cdr.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/logger.h"
#include "asterisk/config.h"
#include "asterisk/manager.h"
#include "asterisk/utils.h"


static char *tdesc = "CDR user field apps";

static char *setcdruserfield_descrip = 
               "[Synopsis]\n"
               "SetCDRUserField(value)\n\n"
               "[Description]\n"
               "SetCDRUserField(value): Set the CDR 'user field' to value\n"
               "       The Call Data Record (CDR) user field is an extra field you\n"
               "       can use for data not stored anywhere else in the record.\n"
               "       CDR records can be used for billing or storing other arbitrary data\n"
               "       (I.E. telephone survey responses)\n"
               "       Also see AppendCDRUserField().\n";

		
static char *setcdruserfield_app = "SetCDRUserField";
static char *setcdruserfield_synopsis = "Set the CDR user field";

static char *appendcdruserfield_descrip = 
               "[Synopsis]\n"
               "AppendCDRUserField(value)\n\n"
               "[Description]\n"
               "AppendCDRUserField(value): Append value to the CDR user field\n"
               "       The Call Data Record (CDR) user field is an extra field you\n"
               "       can use for data not stored anywhere else in the record.\n"
               "       CDR records can be used for billing or storing other arbitrary data\n"
               "       (I.E. telephone survey responses)\n"
               "       Also see SetCDRUserField().\n";
		
static char *appendcdruserfield_app = "AppendCDRUserField";
static char *appendcdruserfield_synopsis = "Append to the CDR user field";

LOCAL_USER_DECL;

static int action_setcdruserfield(struct mansession *s, struct message *m)
{
	struct ast_channel *c = NULL;
	char *userfield = astman_get_header(m, "UserField");
	char *channel = astman_get_header(m, "Channel");
	char *append = astman_get_header(m, "Append");

	if (ast_strlen_zero(channel)) {
		astman_send_error(s, m, "No Channel specified");
		return 0;
	}
	if (ast_strlen_zero(userfield)) {
		astman_send_error(s, m, "No UserField specified");
		return 0;
	}
	c = ast_get_channel_by_name_locked(channel);
	if (!c) {
		astman_send_error(s, m, "No such channel");
		return 0;
	}
	if (ast_true(append))
		ast_cdr_appenduserfield(c, userfield);
	else
		ast_cdr_setuserfield(c, userfield);
	ast_mutex_unlock(&c->lock);
	astman_send_ack(s, m, "CDR Userfield Set");
	return 0;
}

static int setcdruserfield_exec(struct ast_channel *chan, void *data)
{
	struct localuser *u;
	int res = 0;
	static int dep_warning = 0;
	
	LOCAL_USER_ADD(u);

	if (chan->cdr && data) {
		ast_cdr_setuserfield(chan, (char*)data);
	}

	if (!dep_warning) {
		dep_warning = 1;
		ast_log(LOG_WARNING, "SetCDRUserField is deprecated.  Please use CDR(userfield) instead.\n");
	}

	LOCAL_USER_REMOVE(u);
	
	return res;
}

static int appendcdruserfield_exec(struct ast_channel *chan, void *data)
{
	struct localuser *u;
	int res = 0;
	static int dep_warning = 0;
	
	LOCAL_USER_ADD(u);

	if (chan->cdr && data) {
		ast_cdr_appenduserfield(chan, (char*)data);
	}

	if (!dep_warning) {
		dep_warning = 1;
		ast_log(LOG_WARNING, "AppendCDRUserField is deprecated.  Please use CDR(userfield) instead.\n");
	}

	LOCAL_USER_REMOVE(u);
	
	return res;
}

static int unload_module(void *mod)
{
	int res;
	
	res = ast_unregister_application(setcdruserfield_app);
	res |= ast_unregister_application(appendcdruserfield_app);
	res |= ast_manager_unregister("SetCDRUserField");

	STANDARD_HANGUP_LOCALUSERS;

	return res;
}

static int load_module(void *mod)
{
	int res;

	res = ast_register_application(setcdruserfield_app, setcdruserfield_exec, setcdruserfield_synopsis, setcdruserfield_descrip);
	res |= ast_register_application(appendcdruserfield_app, appendcdruserfield_exec, appendcdruserfield_synopsis, appendcdruserfield_descrip);
	res |= ast_manager_register("SetCDRUserField", EVENT_FLAG_CALL, action_setcdruserfield, "Set the CDR UserField");
	
	return res;
}

static const char *description(void)
{
	return tdesc;
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD1;
