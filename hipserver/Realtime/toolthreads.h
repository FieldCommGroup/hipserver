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
 *   toolthreads.h
 * File Description:
 *   Header file for toolthreads.c
 *
 **********************************************************/
#ifndef _TOOLTHREADS_H
#define _TOOLTHREADS_H

#include <pthread.h>

#include "datatypes.h"
#include "errval.h"

/*************
 *  Typedefs
 *************/
typedef struct thr_info_struct
{
	pthread_t thrID;
	const char *thrName;
} thr_info_t;

/****************
 *  Definitions
 ****************/
#define MAX_THRS     15   /* Should suffice for now */

/************
 *  Globals
 ************/
extern pthread_t mainThrID;

/************************
 *  Function Prototypes
 ************************/
#ifdef __cplusplus  /* when included in a C++ file, tell compiler these are C functions */
extern "C" {
#endif
void delete_threads(void);
uint8_t get_thread_count(void);
errVal_t start_a_thread(pthread_t *p_thrID, void *(*p_thrFunc)(void *),	const char *thrName);
#ifdef __cplusplus
}
#endif
#endif  /* _TOOLTHREADS_H */

