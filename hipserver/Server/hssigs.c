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
 *   hssigs.c
 * File Description:
 *   Functions to initialize and set up signal handlers 
 *   and other signal related operations for HServer.
 *
 **********************************************************/
#include  <errno.h>
#include  <stdio.h>

#include "debug.h"
#include "hssems.h"
#include "toolutils.h"
#include "hssigs.h"
#include "hsudp.h"
#include "hsqueues.h"

static void sighandler_hs_endall(int32_t sigNum);

errVal_t assign_hs_sig_handlers(sigaction_t *p_newAction,
		sigaction_t *p_oldAction);

errVal_t initialize_hs_signals(void)
{
	errVal_t errval;

	do
	{
		errval = initialize_signals(sighandler_hs_endall); // sets newAction, oldAction
		if (errval == LINUX_ERROR)
		{
			break;
		}

		errval = assign_hs_sig_handlers(&newAction, &oldAction);

	} while (FALSE); /* Run the loop at most once */

	return errval;
}

errVal_t setup_rtsig(int32_t sigNum,
		void (*p_sighandler)(int32_t, siginfo_t*, void*),
		sigaction_t *p_newAction, sigaction_t *p_oldAction)
{
	errVal_t errval;

	const char *funcName = "setup_rtsig";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	/* Use sa_sigaction field to set up handler when sa_flags is SIGINFO */
	p_newAction->sa_flags = SA_SIGINFO;
	p_newAction->sa_sigaction = p_sighandler;

	/* Query old action for the signal and set up specified handler */
	errval = (errVal_t) sigaction(sigNum, NULL, p_oldAction);
	do
	{
		/* Proceed only if no errors */
		if (errval == LINUX_ERROR)
		{
			fprintf(p_toolLogPtr,
					"System error %d in old sigaction() for signal %d\n",
					errno, sigNum);
			errval = SIGSET_ERROR;
			break;
		}

		if (p_oldAction->sa_handler == SIG_IGN)
		{
			dbgp_sig("Signal %d was being ignored!!!\n", sigNum);
		}
		else
		{
			if (p_oldAction->sa_handler == SIG_DFL)
			{
				dbgp_sig("Signal %d had default action set!!!\n", sigNum);
			}

			dbgp_sig("Setting new action for Signal %d!!!\n", sigNum);
			errval = (errVal_t) sigaddset(&p_newAction->sa_mask, sigNum);
			if (errval == LINUX_ERROR)
			{
				fprintf(p_toolLogPtr,
						"System error %d in sigaddset() for signal %d\n",
						errno, sigNum);
				errval = SIGSET_ERROR;
				break;
			}
			errval = (errVal_t) sigaction(sigNum, p_newAction, NULL);
			if (errval == LINUX_ERROR)
			{
				fprintf(p_toolLogPtr,
						"void sighandler_gensigs(int32_t sigNum)System error %d in new sigaction() for signal %d\n",
						errno, sigNum);
				errval = SIGSET_ERROR;
				break;
			}
		}
	} while (FALSE); /* Run the loop at most once */

	return (errval);
}

void sighandler_socketInactivity(int32_t sigNum, siginfo_t *p_sigInfo,
		void *p_context)
{
	const char *funcName = "sighandler_socketInactivity";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_sig("Got RT Signal %d\n", sigNum);
	if (sigNum >= SIGRTMIN)
	{
		uint8_t thisSess = sigNum - SIGRTMIN;
		print_to_both(p_toolLogPtr, "HART-IP Session Timeout...  ");
		clear_session_info(thisSess);
	}
}

static void sighandler_hs_endall(int32_t sigNum)
{
	/* Signal handler for signals that, if received, should
	 * terminate the application cleanly.
	 */

	const char *funcName = "sighandler_endall";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	switch (sigNum)
	{
	case SIGHUP:
		dbgp_logdbg("Got SIGHUP\n");
		break;
	case SIGINT:
		dbgp_logdbg("Got SIGINT (Ctrl-C)\n");
		break;
	case SIGQUIT:
		dbgp_logdbg("Got SIGQUIT (Ctrl-\\)\n");
		break;
	case SIGSEGV:
		dbgp_logdbg("Got SIGSEGV (Segmentation Fault!)\n");
		break;
	case SIGTSTP:
		dbgp_logdbg("Got SIGTSTP (Ctrl-Z)\n");
		break;
	default:
		dbgp_logdbg("Inappropriate signal %d!!\n", sigNum);
		return;
	} // switch

	ifEndApp = TRUE;

	if (GetAppRecdMsgCount() > 0)
	{
		// caught signal while APP is running, send it TERM command
		dbgp_logdbg("Sending TERM_APP_CMD to the APP...\n");
		struct AppMsg msg;
		msg.command = TERM_APP_CMD;
		msg.transaction = 0;
		memset(msg.pdu, 0, TPPDU_MAX_FRAMELEN);
		snd_msg_to_app(&msg);
		dbgp_logdbg("TERM_APP_CMD sent, not awaiting response...\n");
	}

	// tjohnston 6/20/2019 - always go thru this code to begin the shutdown
	//                     - following was an else clause
	dbgp_sem("Posting StopMainThr semaphore from sighandler_hs_endall()\n");
	int errval = sem_post(p_semStopMainThr);
	if (errval == LINUX_ERROR)
	{
		print_to_both(p_toolLogPtr,
				"System error %d in sem_post() for signal %d\n", errno,
				sigNum);
	}
	sleep(1);
}

errVal_t assign_hs_sig_handlers(sigaction_t *p_newAction,
		sigaction_t *p_oldAction)
{
	int32_t sigNum;
	errVal_t errval;

	const char *funcName = "assign_hs_sig_handlers";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_sig("\n\nSignal Value Range: %d - %d\n", MINSIG, MAXSIG);dbgp_sig("SIGRTMIN = %d, SIGRTMAX = %d\n", SIGRTMIN, SIGRTMAX);

	for (sigNum = SIGRTMIN; sigNum < SIGRTMAX; sigNum++)
	{
		dbgp_sig(" Setting signal %d\n", sigNum);

		/* HART-IP Server specific signal handling
		 * - Real Time signals for socket handling
		 */

		/* Handle Real Time signals differently for future scalability
		 * and information gathering via use of SA_SIGINFO value for
		 * sa_flag with signal numbers between SIGRTMIN and SIGRTMAX
		 * with different handlers to be used as needed. Currently,
		 * only one signal (SIGRTMIN) is used for one socket client */
		errval = setup_rtsig(sigNum, sighandler_socketInactivity, p_newAction,
				p_oldAction);

		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "\n!!!!Failed to set up signal %d!!!\n",
					sigNum);
			break;
		}
	}

	return (errval);
}

void shutdown_server(void)
{
	// Send the signal for Ctrl+C to the thread.
	// #6004
	sighandler_hs_endall(SIGINT);
}
