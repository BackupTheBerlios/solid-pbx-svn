/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Russell Bryant <russelb@clemson.edu> 
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
 * \brief Functions for reading or setting the MusicOnHold class
 *
 * \author Russell Bryant <russelb@clemson.edu> 
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 32846 $")

#include <stdlib.h>

#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/stringfields.h"

static int depwarning = 0;

static int moh_read(struct ast_channel *chan, char *cmd, char *data,
		    char *buf, size_t len)
{
	if (!depwarning) {
		depwarning = 1;
		ast_log(LOG_WARNING, "MUSICCLASS() is deprecated; use CHANNEL(musicclass) instead.\n");
	}

	ast_copy_string(buf, chan->musicclass, len);

	return 0;
}

static int moh_write(struct ast_channel *chan, char *cmd, char *data,
		     const char *value)
{
	if (!depwarning) {
		depwarning = 1;
		ast_log(LOG_WARNING, "MUSICCLASS() is deprecated; use CHANNEL(musicclass) instead.\n");
	}

	ast_string_field_set(chan, musicclass, value);

	return 0;
}

static struct ast_custom_function moh_function = {
	.name = "MUSICCLASS",
	.synopsis = "Read or Set the MusicOnHold class",
	.syntax = "MUSICCLASS()",
	.desc = "Deprecated. Use CHANNEL(musicclass) instead.\n",
	.read = moh_read,
	.write = moh_write,
};

static char *tdesc = "Music-on-hold dialplan function";

static int unload_module(void *mod)
{
	return ast_custom_function_unregister(&moh_function);
}

static int load_module(void *mod)
{
	return ast_custom_function_register(&moh_function);
}

static const char *description(void)
{
	return tdesc;
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD(MOD_1 | NO_USECOUNT, NULL, NULL, NULL);
