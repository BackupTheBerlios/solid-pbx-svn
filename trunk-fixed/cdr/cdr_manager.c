/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2004 - 2005
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
 * \brief Asterisk Call Manager CDR records.
 * 
 * See also
 * \arg \ref AstCDR
 * \arg \ref AstAMI
 * \arg \ref Config_ami
 * \ingroup cdr_drivers
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 32846 $")

#include <sys/types.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>

#include "asterisk/channel.h"
#include "asterisk/cdr.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/utils.h"
#include "asterisk/manager.h"
#include "asterisk/config.h"

#define DATE_FORMAT 	"%Y-%m-%d %T"
#define CONF_FILE	"cdr_manager.conf"

static char *desc = "Asterisk Call Manager CDR Backend";
static char *name = "cdr_manager";

static int enablecdr = 0;

static void loadconfigurationfile(void)
{
	char *cat;
	struct ast_config *cfg;
	struct ast_variable *v;
	
	cfg = ast_config_load(CONF_FILE);
	if (!cfg) {
		/* Standard configuration */
		enablecdr = 0;
		return;
	}
	
	cat = ast_category_browse(cfg, NULL);
	while (cat) {
		if (!strcasecmp(cat, "general")) {
			v = ast_variable_browse(cfg, cat);
			while (v) {
				if (!strcasecmp(v->name, "enabled")) {
					enablecdr = ast_true(v->value);
				}
				
				v = v->next;
			}
		}
	
		/* Next category */
		cat = ast_category_browse(cfg, cat);
	}
	
	ast_config_destroy(cfg);
}

static int manager_log(struct ast_cdr *cdr)
{
	time_t t;
	struct tm timeresult;
	char strStartTime[80] = "";
	char strAnswerTime[80] = "";
	char strEndTime[80] = "";
	
	if (!enablecdr)
		return 0;

	t = cdr->start.tv_sec;
	localtime_r(&t, &timeresult);
	strftime(strStartTime, sizeof(strStartTime), DATE_FORMAT, &timeresult);
	
	if (cdr->answer.tv_sec)	{
    		t = cdr->answer.tv_sec;
    		localtime_r(&t, &timeresult);
		strftime(strAnswerTime, sizeof(strAnswerTime), DATE_FORMAT, &timeresult);
	}

	t = cdr->end.tv_sec;
	localtime_r(&t, &timeresult);
	strftime(strEndTime, sizeof(strEndTime), DATE_FORMAT, &timeresult);

	manager_event(EVENT_FLAG_CALL, "Cdr",
	    "AccountCode: %s\r\n"
	    "Source: %s\r\n"
	    "Destination: %s\r\n"
	    "DestinationContext: %s\r\n"
	    "CallerID: %s\r\n"
	    "Channel: %s\r\n"
	    "DestinationChannel: %s\r\n"
	    "LastApplication: %s\r\n"
	    "LastData: %s\r\n"
	    "StartTime: %s\r\n"
	    "AnswerTime: %s\r\n"
	    "EndTime: %s\r\n"
	    "Duration: %ld\r\n"
	    "BillableSeconds: %ld\r\n"
	    "Disposition: %s\r\n"
	    "AMAFlags: %s\r\n"
	    "UniqueID: %s\r\n"
	    "UserField: %s\r\n",
	    cdr->accountcode, cdr->src, cdr->dst, cdr->dcontext, cdr->clid, cdr->channel,
	    cdr->dstchannel, cdr->lastapp, cdr->lastdata, strStartTime, strAnswerTime, strEndTime,
	    cdr->duration, cdr->billsec, ast_cdr_disp2str(cdr->disposition), 
	    ast_cdr_flags2str(cdr->amaflags), cdr->uniqueid, cdr->userfield);
	    	
	return 0;
}

static const char *description(void)
{
	return desc;
}

static int unload_module(void *mod)
{
	ast_cdr_unregister(name);
	return 0;
}

static int load_module(void *mod)
{
	int res;

	/* Configuration file */
	loadconfigurationfile();
	
	res = ast_cdr_register(name, desc, manager_log);
	if (res) {
		ast_log(LOG_ERROR, "Unable to register Asterisk Call Manager CDR handling\n");
	}
	
	return res;
}

static int reload(void *mod)
{
	loadconfigurationfile();
	return 0;
}

static const char *key(void)
{
	return ASTERISK_GPL_KEY;
}

STD_MOD(MOD_1 | NO_USECOUNT, reload, NULL, NULL);
