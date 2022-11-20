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

void sighandler_timer(int32_t sigNum,
                      siginfo_t *p_sigInfo,
                      void *p_context);

void shutdown_server();

#endif /* _HSSIGS_H */

