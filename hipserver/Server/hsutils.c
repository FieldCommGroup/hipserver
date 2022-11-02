/*************************************************************************************************
 * Copyright 2019-2021 FieldComm Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************/

/**********************************************************
 *
 * File Name:
 *   hsutils.c
 * File Description:
 *   Misc. utility functions for HServer.
 *
 **********************************************************/
#include <debug.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <toolqueues.h>
#include <toolutils.h>
#include "common.h"
#include "errval.h"
#include "tooldef.h"
#include "hsudp.h"
#include "hsutils.h"

/************
 *  Globals
 ************/
FILE *p_hsLogPtr = NULL;

/************************************
 *  Private Variables for this file
 ************************************/
//static char HSLOG_NAME[FILENAME_LEN] = HS_NAME;

/**********************************************
 *  Private function prototypes for this file
 **********************************************/

/*****************************
 *  Function Implementations
 *****************************/

uint8_t open_hsLog(void)
{
	uint8_t errval = NO_ERROR;
	p_hsLogPtr = p_toolLogPtr;
//	const char *funcName = "open_hsLog";
//	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);
//
//	/* p_hsLogPtr is the global log file pointer for HS */
//	if (p_hsLogPtr == NULL)
//	{
//		/* Log does not exist yet */
//		strcat(HSLOG_NAME, "_log.txt");
//		errval = open_logfile(&p_hsLogPtr, HSLOG_NAME);
//	} /* if (p_hsLogPtr == NULL) */
//	else
//	{
//		fprintf(stderr, "Log is already open\n");
//	}

	return (errval);
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
void close_hsLog(void)
{
//	const char *funcName = "close_hsLog";
//	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);
//
//	close_logfile(p_hsLogPtr);
//	dbgp_init("%s closed\n", HSLOG_NAME);
}

