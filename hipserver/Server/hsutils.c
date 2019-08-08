/*****************************************************************
 * Copyright (C) 2015-2017 FieldComm Group
 *
 * All Rights Reserved.
 * This software is CONFIDENTIAL and PROPRIETARY INFORMATION of
 * FieldComm Group, Austin, Texas USA, and may not be used either
 * directly or by reference without permission of FieldComm Group.
 *
 * THIS SOFTWARE FILE AND ITS CONTENTS ARE PROVIDED AS IS WITHOUT
 * WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION, WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND BEING FREE OF DEFECT.
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

