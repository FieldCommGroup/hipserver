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
 *   toolsems.h
 * File Description:
 *   Header file for toolsems.c
 *
 **********************************************************/
#ifndef _TOOLSEMS_H
#define _TOOLSEMS_H

#include <semaphore.h>

#include "errval.h"
#include "datatypes.h"

/*************
 *  Typedefs
 *************/
typedef struct sem_info_struct
{
	sem_t *p_sem;
	const char *semName;
} sem_info_t;

/****************
 *  Definitions
 ****************/
#define SEMPERMS      0666   /* access perms (octal) for semaphores */

#define SEMFREE       1    /* Initial value for an available semaphore */
#define SEMIGN        2    /* Ignore value */
#define SEMTAKEN      0    /* Initial value for a locked semaphore */

#define MAX_SEMS      50   /* Should suffice for now */
#define SEM_NAME_SIZE 100

/************
 *  Globals
 ************/
extern sem_t *p_semEndAll;

/************************
 *  Function Prototypes
 ************************/
#ifdef __cplusplus  /* when included in a C++ file, tell compiler these are C functions */
extern "C" {
#endif
errVal_t create_semaphores(uint8_t createFlag);
void delete_semaphores(void);
uint8_t get_sem_count(void);
uint8_t get_sem_name(sem_t *p_sem, char *semName);
sem_t *open_a_semaphore(const char *semName, uint8_t createFlag,
		uint8_t initVal);
int sem_wait_nointr(sem_t *sem);
void *createUniqueName(char*);
#ifdef __cplusplus
}
#endif

#endif /* _TOOLSEMS_H */

