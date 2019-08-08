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
 *   hssems.c
 * File Description:
 *   Functions to create, delete and use semaphores, and
 *   access data protected by semaphores in HServer.
 *
 **********************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "errno.h"
#include "hssems.h"
#include "hsutils.h"
#include "tooldef.h"

/************
 *  Globals
 ************/
sem_t semServerTables, *p_semServerTables;    // tabular data retained in server
sem_t semStopMainThr, *p_semStopMainThr; /* terminate Main Thread */

/************************************
 *  Private variables for this file
 ************************************/
/* --- None --- */

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
/* --- None --- */

/*****************************
 *  Function Implementations
 *****************************/

errVal_t create_hs_semaphores(uint8_t createFlag)
{
	errVal_t errVal = SEM_ERROR;

	const char *funcName = "create_hs_semaphores";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_init("----------------------------------\n");
	dbgp_init("  Creating %s Semaphores...\n", TOOL_NAME);

	/* Create/open all synchronization semaphores */
	uint8_t initVal = (createFlag ? SEMTAKEN : SEMIGN);

	do
	{
		if (create_semaphores(createFlag) != NO_ERROR)
		{
			break;
		}

		p_semStopMainThr = open_a_semaphore("semStopMainThr", createFlag,
				initVal);
		if (p_semStopMainThr == NULL)
		{
			break;
		}

		p_semServerTables = open_a_semaphore("semServerTables", createFlag,
				initVal);
		if (p_semServerTables == NULL)
		{
			break;
		}

		errVal = NO_ERROR;
	} while (FALSE);

	if ((createFlag) && (errVal == NO_ERROR))
	{
		dbgp_init("  %d %s Semaphores Created\n", get_sem_count(), TOOL_NAME);
		sem_post(p_semServerTables);	// access to Server Tables is enabled
	}
	else
	{
		fprintf(p_hsLogPtr, "  Failed to Create %s Semaphores\n",
		TOOL_NAME);
	}
	dbgp_init("----------------------------------\n");

	return errVal;
}
