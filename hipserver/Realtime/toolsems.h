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
#ifdef __cplusplus
}
#endif

#endif /* _TOOLSEMS_H */

