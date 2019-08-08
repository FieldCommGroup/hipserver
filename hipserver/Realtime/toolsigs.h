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
 *   toolsigs.h
 * File Description:
 *   Header file for toolsigs.c
 *
 **********************************************************/
#ifndef _TOOLSIGS_H
#define _TOOLSIGS_H

#include <signal.h>

#include "datatypes.h"
#include "errval.h"

/*************
 *  Typedefs
 *************/
typedef struct sigaction sigaction_t;

/****************
 *  Definitions
 ****************/
#define MAXSIG     (NSIG-1) /* NSIG = largest system signal number + 1 */
#define MINSIG     SIGHUP

/************
 *  Globals
 ************/
extern bool_t ifEndApp;
extern sigaction_t newAction, oldAction;
extern sigset_t newSet, oldSet;

/************************
 *  Function Prototypes
 ************************/
#ifdef __cplusplus  /* when included in a C++ file, tell compiler these are C functions */
extern "C" {
#endif
errVal_t initialize_signals(void (*p_endAll)(int32_t));
errVal_t setup_sig(int32_t sigNum, void (*p_sighandler)(int32_t),
		sigaction_t *p_newAction, sigaction_t *p_oldAction);
#ifdef __cplusplus
}
#endif
#endif /* _TOOLSIGS_H */

