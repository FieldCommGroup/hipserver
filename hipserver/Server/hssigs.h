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
 *   hssigs.h
 * File Description:
 *   Header file for hssigs.c
 *
 **********************************************************/
#ifndef _HSSIGS_H
#define _HSSIGS_H


#include <signal.h>
#include <pthread.h>

#include "toolsigs.h"
#include "datatypes.h"
#include "errval.h"


/*************
 *  Typedefs
 *************/


/****************
 *  Definitions
 ****************/


/************
 *  Globals
 ************/

/************************
 *  Function Prototypes
 ************************/

errVal_t initialize_hs_signals(void);

errVal_t  setup_rtsig(int32_t sigNum,
                      void (*p_sighandler)(int32_t,
                      siginfo_t*, void*),
                      sigaction_t *p_newAction,
                      sigaction_t *p_oldAction);

void sighandler_socketInactivity(int32_t sigNum,
                      siginfo_t *p_sigInfo,
                      void *p_context);

void shutdown_server();

#endif /* _HSSIGS_H */

