/*************************************************************************************************
 * Copyright 2020 FieldComm Group, Inc.
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

