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
		// #191
		char semStop[SEM_NAME_SIZE] = "semStopMainThr";
		char semServ[SEM_NAME_SIZE] = "semServerTables";
		createUniqueName(semStop);

		p_semStopMainThr = open_a_semaphore(semStop, createFlag,
				initVal);
		if (p_semStopMainThr == NULL)
		{
			break;
		}

		createUniqueName(semServ);
		p_semServerTables = open_a_semaphore(semServ, createFlag,
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
