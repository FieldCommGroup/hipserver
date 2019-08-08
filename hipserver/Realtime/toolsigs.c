/*****************************************************************
 * Copyright (C) 2015-2018 FieldComm Group
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
 *   toolsigs.c
 * File Description:
 *   Functions to initialize and set up signal handlers 
 *   and other signal related operations for the tool.
 *
 **********************************************************/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "toolsems.h"
#include "toolsigs.h"
#include "toolutils.h"
#include "tooldef.h"

/************
 *  Globals
 ************/
bool_t ifEndApp = FALSE; /* For terminating application on interrupt */

/************************************
 *  Private variables for this file  
 ************************************/
sigaction_t newAction, oldAction;
sigset_t newSet, oldSet;

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static errVal_t assign_sig_handlers(void (*p_sighandler)(int32_t), sigaction_t *p_newAction,
		sigaction_t *p_oldAction);
//static errVal_t setup_sig(int32_t sigNum, void (*p_sighandler)(int32_t),
//		sigaction_t *p_newAction, sigaction_t *p_oldAction);
static void sighandler_endall(int32_t sigNum);
static void sighandler_gensigs(int32_t sigNum);

/*****************************
 *  Function Implementations
 *****************************/
errVal_t initialize_signals(void (*p_endAll)(int32_t))
{
	errVal_t errval;

	const char *funcName = "initialize_signals";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_init("\n==================================\n");
	dbgp_init("Initializing %s Signals...\n", TOOL_NAME);

	/* Do signal related settings */
	errval = (errVal_t) sigemptyset(&newAction.sa_mask);

	do
	{
		if (errval == LINUX_ERROR)
		{
			print_to_both(p_toolLogPtr, "Error %d in sigemptyset()\n", errno);
			break;
		}

		/* Keep SIGINT mask ready, in case SIGINT is received */
		errval = (errVal_t) sigemptyset(&newSet);
		if (errval == LINUX_ERROR)
		{
			print_to_both(p_toolLogPtr,
					"System error %d in sigemptyset() for SIGINT\n",
					errno);
			break;
		}

		errval = (errVal_t) sigaddset(&newSet, SIGHUP);
		if (errval == LINUX_ERROR)
		{
			print_to_both(p_toolLogPtr,
					"System error %d in sigaddset() for SIGHUP\n",
					errno);
			break;
		}

		errval = (errVal_t) sigaddset(&newSet, SIGINT);
		if (errval == LINUX_ERROR)
		{
			print_to_both(p_toolLogPtr,
					"System error %d in sigaddset() for SIGINT\n",
					errno);
			break;
		}

		errval = assign_sig_handlers(p_endAll, &newAction, &oldAction);
		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "Error assigning signal handlers!!\n");
			break;
		}
		dbgp_init("Signals Initialized\n");
		dbgp_init("==================================\n");
	} while (FALSE); /* Run the loop at most once */

	return (errval);
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
static errVal_t assign_sig_handlers(void (*p_endAll)(int32_t), sigaction_t *p_newAction,
		sigaction_t *p_oldAction)
{
	int32_t sigNum;
	errVal_t errval;

	const char *funcName = "assign_sig_handlers";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_sig("\n\nSignal Value Range: %d - %d\n", MINSIG, MAXSIG); dbgp_sig("SIGRTMIN = %d, SIGRTMAX = %d\n", SIGRTMIN, SIGRTMAX);

	for (sigNum = MINSIG; sigNum < MAXSIG; sigNum++)
	{
		if ((sigNum == SIGKILL) || (sigNum == SIGSTOP)
				|| ((sigNum > SIGSYS) && (sigNum < SIGRTMIN)))
		{
			/* Skip certain signals that should not be touched.
			 * SIGKILL and SIGSTOP cannot be intercepted by user processes.
			 * SIGRTMIN is determined at runtime and its value cannot
			 * be assumed to be a constant. A sigNum value where
			 * SIGUNUSED < sigNum < SIGRTMIN is probably used by the
			 * pthread library for its internal use, so it should be
			 * skipped.
			 */
			dbgp_sig(" Skipping signal %d\n", sigNum);
			continue;
		}

		dbgp_sig(" Setting signal %d\n", sigNum);

		if ((sigNum >= SIGRTMIN) && (sigNum < SIGRTMAX))
		{
			continue;	// handled elsewhere
		}

		bool_t ifEndAll = FALSE;

		/* Other specific signal handling */
		switch (sigNum)
		{
		case SIGCHLD:
			/* Ignore the signal raised by a child's termination */
			errval = setup_sig(sigNum, SIG_IGN, p_newAction, p_oldAction);
			break;
		case SIGINT:
			ifEndAll = TRUE;
			break;
		case SIGHUP:
			ifEndAll = TRUE;
			break;
		case SIGQUIT:
			ifEndAll = TRUE;
			break;
		case SIGSEGV:
			ifEndAll = TRUE;
			break;
		case SIGTSTP:
			ifEndAll = TRUE;
			break;
		case SIGWINCH:
			/* Ignore the signal generated by resizing window */
			errval = setup_sig(sigNum, SIG_IGN, p_newAction, p_oldAction);
			break;
		default:
			/* Set up a generic handler for other signals so we
			 * know if some unexpected signal comes
			 */
			errval = setup_sig(sigNum, sighandler_gensigs, p_newAction,
					p_oldAction);
			break;
		} /* switch */

		if (ifEndAll)
		{
			/* Set up signal handler for signals that should cause the
			 * tool to terminate cleanly.
			 */
			errval = setup_sig(sigNum, p_endAll, p_newAction,
					p_oldAction);
		}

		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "\n!!!!Failed to set up signal %d!!!\n",
					sigNum);
			break;
		}
	} // for (sigNum = MINSIG; sigNum < MAXSIG; sigNum++)

	return (errval);
}

errVal_t setup_sig(int32_t sigNum, void (*p_sighandler)(int32_t),
		sigaction_t *p_newAction, sigaction_t *p_oldAction)
{
	errVal_t errval;

	const char *funcName = "setup_sig";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	/* Use sa_handler field to set up handler when sa_flags is not SIGINFO */
	p_newAction->sa_handler = p_sighandler;

	if ((sigNum == SIGALRM) || (sigNum == SIGIO))
	{
		p_newAction->sa_flags = SA_RESTART | SA_NODEFER;
	}
	else
	{
		p_newAction->sa_flags = 0;
	}

	/* Query old action for the signal and set up specified handler */
	errval = (errVal_t) sigaction(sigNum, NULL, p_oldAction);
	do
	{
		if (errval == LINUX_ERROR)
		{
			print_to_both(p_toolLogPtr,
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
			} dbgp_sig("Setting new action for Signal %d!!!\n", sigNum);
			errval = (errVal_t) sigaddset(&p_newAction->sa_mask, sigNum);
			if (errval == LINUX_ERROR)
			{
				print_to_both(p_toolLogPtr,
						"System error %d in sigaddset() for signal %d\n",
						errno, sigNum);
				errval = SIGSET_ERROR;
				break;
			}

			errval = (errVal_t) sigaction(sigNum, p_newAction, NULL);
			if (errval == LINUX_ERROR)
			{
				print_to_both(p_toolLogPtr,
						"System error %d in new sigaction() for signal %d\n",
						errno, sigNum);
				errval = SIGSET_ERROR;
				break;
			}
		}
	} while (FALSE); /* Run the loop at most once */

	return (errval);
}

static void sighandler_endall(int32_t sigNum)
{
	/* Signal handler for signals that, if received, should
	 * terminate the application cleanly.
	 */

	const char *funcName = "sighandler_endall";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	switch (sigNum)
	{
	case SIGINT:
		dbgp_logdbg("Got SIGINT (Ctrl-C)\n");
		break;
	case SIGHUP:
		dbgp_logdbg("Got SIGHUP (Ctrl-C)\n");
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
		break;
	} // switch

	ifEndApp = TRUE;
}

static void sighandler_gensigs(int32_t sigNum)
{
	const char *funcName = "sighandler_gensigs";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	/* Generic handler for unexpected signals */
	print_to_both(p_toolLogPtr, "Got signal %d\n", sigNum);

	if (sigNum > MAXSIG)
	{
		print_to_both(p_toolLogPtr, "Illegal signal!!\n");
	}
}

