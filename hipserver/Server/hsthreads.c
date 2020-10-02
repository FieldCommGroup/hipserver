/*************************************************************************************************
 * Copyright 2019 FieldComm Group, Inc.
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
 *   hsthreads.c
 * File Description:
 *   Functions to create and delete the threads used in 
 *   HServer and do the necessary initializations and
 *   setups for HServer.
 *
 **********************************************************/
#include <appmsg.h>
#include <debug.h>
#include <hsqueues.h>
#include <toolsems.h>
#include <toolsigs.h>
#include <toolthreads.h>
#include <toolutils.h>
#include "errval.h"
#include "tooldef.h"
#include "tppdu.h"
#include "hsthreads.h"
#include "hsudp.h"
#include "hsutils.h"
#include "serverstate.h"
#include "hsrequest.h"

/************
 *  Globals
 ************/
pthread_t popRxThrID;  // used by Server to read msg from APP
pthread_t popTxThrID;  // used by APP to read msg from Server
pthread_t socketThrID; // used by Server to read socket
pthread_t appThrID = 0; // used by Server to launch the APP program

extern char AppCommandLine[];

/************************************
 *  Private variables for this file  
 ************************************/

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static errVal_t create_hs_threads(void);

/*****************************
 *  Private Function Implementations
 *****************************/

/*
 * this thread launches the APP command line and waits for it to terminate
 */
void *appThrFunc(void *thrName)
{
	const char *funcName = "appThrFunc";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_intfc("\nStarting %s...\n", (char *)thrName);

	//launch HART-IP APP program
	int rtn = system(AppCommandLine); // returns when APP exits
	if (rtn != 0)
	{
		dbgp_logdbg("APP termination.  Command line was: %s\n", AppCommandLine);
	}
}


static errVal_t initialize_hs(void)
{
	errVal_t errval;

	const char *funcName = "initialize_hs";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_init("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");
	dbgp_init("Initializing %s...\n", TOOL_NAME);

	do
	{
		/* Create HServer sockets */
		errval = create_socket();

		if (errval != NO_ERROR)
		{
			fprintf(p_hsLogPtr, "Socket could not be created\n");
			break;
		}

		/* Create HServer-APP queues */
		errval = create_mqueues(MQUSAGE_SERVER);	// server owns queues
		if (errval != NO_ERROR)
		{
			dbgp_logdbg("Msg Queues could not be initialized\n");
			break;
		}
	} while (FALSE);

	if (errval == NO_ERROR)
	{
		dbgp_logdbg("%s Initialized\n", TOOL_NAME);
	}
	else
	{
		dbgp_log("Failed to Initialize %s\n", TOOL_NAME);
	}
	dbgp_init("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n");

	return (errval);
}


/*****************************
 *  Function Implementations
 *****************************/

errVal_t do_hs_setup(void)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "do_hs_setup";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_init("\n==================================\n");
	dbgp_init("Starting %s Setup...\n", TOOL_NAME);

	do
	{
		clear_request_table();

		errval = (errVal_t) open_hsLog();
		if (errval != NO_ERROR)
		{
			dbgp_logdbg("%s log could not be opened\n", TOOL_NAME);
		}

		/* Initialize HServer */
		errval = initialize_hs(); // creates MQs and sockets
		if (errval != NO_ERROR)
		{
			fprintf(p_hsLogPtr, "HServer could not be initialized\n");
			break;
		}

		// MQs are initialized and APP thread is operating, now send INIT message to APP
		// Must accomplish this communication before other HS threads are launched

		// APP has finished initialization before this response is received

		/* Create the various threads used for HServer */
		errval = create_hs_threads();
		if (errval != NO_ERROR)
		{
			fprintf(p_hsLogPtr, "Error Creating Threads\n");
			break;
		}

		// initialize the APP
		// APP is launched already: either by user or by create_hs_threads() > appThrFunc()
		errVal_t errval;
		struct AppMsg msg;
		msg.command = INIT_APP_CMD;
		msg.transaction = 0;
		memset_s(msg.pdu, TPPDU_MAX_FRAMELEN, 0);
		errval = snd_msg_to_app(&msg);

		eServerState = SRVR_READY;	// open for business!

	} while (FALSE);

	if (errval == NO_ERROR)
	{
		dbgp_init("Done %s Setup\n", TOOL_NAME);
	}
	else
	{
		dbgp_init("%s Setup Failed\n", TOOL_NAME);
	}
	dbgp_init("==================================\n");

	return (errval);
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
static errVal_t create_hs_threads(void)
{
	errVal_t errval = NO_ERROR;
	uint8_t hsThrCountBeg = get_thread_count();
	uint8_t hsThrCounter = 0;
	uint8_t totalThrCount = hsThrCountBeg;
	const char *popRxThrName = "popRxMsg Thread";
	const char *popTxThrName = "popTxMsg Thread";
	const char *socketThrName = "Socket Thread";
	const char *appThrName = "APP Thread";

	const char *funcName = "create_hs_threads";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	do
	{
		/* Create all the threads required for HServer. The main
		 * thread is already created and does not need to be
		 * tracked and managed like the rest.
		 */
		dbgp_logdbg("----------------------------------\n");
		dbgp_logdbg("  Creating %s threads...\n", TOOL_NAME);

		/* Thread for Server to receive msg from APP */
		errval = start_a_thread(&popRxThrID, popRxThrFunc, popRxThrName);
		if (errval != NO_ERROR)
		{
			fprintf(p_hsLogPtr, "Error Creating %s\n", popRxThrName);
			break;
		}
		hsThrCounter++;
		dbgp_thr("   Created (#%d) %s\n", hsThrCounter, popRxThrName);

		/* Thread to process HServer socket communication */
		errval = start_a_thread(&socketThrID, socketThrFunc, socketThrName);
		if (errval != NO_ERROR)
		{
			fprintf(p_hsLogPtr, "Error Creating %s\n", socketThrName);
			break;
		}
		hsThrCounter++;
		dbgp_thr("   Created (#%d) %s\n", hsThrCounter, socketThrName);

		/* Thread to run APP program */
		if (eAppLaunch == LNCH_AUTO)
		{
			usleep(1000); // wait 1ms to allow other threads to spin up
			errval = start_a_thread(&appThrID, appThrFunc, appThrName);
			if (errval != NO_ERROR)
			{
				fprintf(p_hsLogPtr, "Error Creating %s\n", appThrName);
				break;
			}
			hsThrCounter++;
			dbgp_thr("   Created (#%d) %s\n", hsThrCounter, appThrName);
		}

		totalThrCount = get_thread_count();

		dbgp_thr("    Started with %d threads\n", hsThrCountBeg); dbgp_thr("    Created %d additional threads\n", hsThrCounter); dbgp_thr("    Expected %d total threads\n",
				(hsThrCountBeg + hsThrCounter)); dbgp_thr("    Current thread total = %d\n", totalThrCount);

		if ((hsThrCountBeg + hsThrCounter) != totalThrCount)
		{
			fprintf(p_hsLogPtr, "Incorrect total thread counter!!!\n");
		}
	} while (FALSE);

	if (errval == NO_ERROR)
	{
		dbgp_logdbg("  %d %s Threads Created\n", hsThrCounter, TOOL_NAME);
	}
	else
	{
		fprintf(p_hsLogPtr, "  Failed to Create %s Threads\n", TOOL_NAME);
	}
	dbgp_logdbg("----------------------------------\n");

	return (errval);
}

