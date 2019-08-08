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
 *   debug.h
 * File Description:
 *   Header file to define the values of various constants
 *   used to enable/disable print statements in specific
 *   code areas.
 *
 **********************************************************/
#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>

#include "toolutils.h"     /* for p_toolLogPtr */

/* Direct all stdout to stderr for unbuffered printing */
#define printf(format, a...)     fprintf(stderr, format, ## a)

// define DEBUG_MODE to enable extra output to console
//#define DEBUG_MODE

/****************
 *  Definitions
 ****************/
/* Set values of the following to 1 to turn on debug printing
 * for the desired code areas.
 */
#define DEBUG_HS      0     /* HART-IP Server debug */
#define DEBUG_INIT    0     /* Initial debug (logged on screen) */
#define DEBUG_INTFC   0     /* Interface debug */
#define DEBUG_NOOP    0     /* Replace tested dbgp_* w/ dbgp_noop */
#define DEBUG_SEM     0     /* semaphore debug */
#define DEBUG_SIG     0     /* signal debug */
#define DEBUG_THR     0     /* thread debug */
#define DEBUG_TMR     0     /* timer debug */
#define DEBUG_TRC     0     /* trace calls */
#define DEBUG_SUB     0     /* subscriptions */

#if (DEBUG_HS)
#define dbgp_hs(format, a...)     print_to_both(p_toolLogPtr, format, ## a)
#else
#define dbgp_hs(format, a...)
#endif

#if (DEBUG_INIT)
#define dbgp_init(format, a...)    print_to_both(p_toolLogPtr, format, ## a)
#else
#define dbgp_init(format, a...)
#endif

#if (DEBUG_INTFC)
#define dbgp_intfc(format, a...)    print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_intfc(format, a...)
#endif

#if (DEBUG_NOOP)
#define dbgp_noop(format, a...)    print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_noop(format, a...)
#endif

#if (DEBUG_SEM)
#define dbgp_sem(format, a...)     print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_sem(format, a...)
#endif

#if (DEBUG_SIG)
#define dbgp_sig(format, a...)     print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_sig(format, a...)
#endif

#if (DEBUG_THR)
#define dbgp_thr(format, a...)     print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_thr(format, a...)
#endif

#if (DEBUG_TMR)
#define dbgp_tmr(format, a...)     print_to_log(p_toolLogPtr, format, ## a)
#else
#define dbgp_tmr(format, a...)
#endif

#if (DEBUG_TRC)
#define dbgp_trace(format, a...)   fprintf(stderr, format, ## a)
#else
#define dbgp_trace(format, a...)
#endif

/* Always print this information to screen and log file. */
#define dbgp_log(format, a...)     print_to_both(p_toolLogPtr, format, ## a)

#ifdef DEBUG_MODE
#define dbgp_logdbg(format, a...)     print_to_both(p_toolLogPtr, format, ## a)
#else
#define dbgp_logdbg(format, a...)     (p_toolLogPtr && fprintf(p_toolLogPtr, format, ## a))
#endif

#endif /* _DEBUG_H */

