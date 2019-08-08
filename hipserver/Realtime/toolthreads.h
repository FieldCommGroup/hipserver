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

