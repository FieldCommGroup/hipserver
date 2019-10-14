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
 *   hsthreads.h
 * File Description:
 *   Header file for hsthreads.c
 *
 **********************************************************/
#ifndef _HSTHREADS_H
#define _HSTHREADS_H

#include <pthread.h>
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
extern pthread_t popRxThrID;
extern pthread_t popTxThrID;
extern pthread_t socketThrID;
extern pthread_t appThrID;

/************************
 *  Function Prototypes
 ************************/
errVal_t do_hs_setup(void);

#endif  /* _HSTHREADS_H */

