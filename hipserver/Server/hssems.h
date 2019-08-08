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
 *   hssems.h
 * File Description:
 *   Header file for hssems.c
 *
 **********************************************************/
#ifndef _HSSEMS_H
#define _HSSEMS_H

#include <semaphore.h>

#include "toolsems.h"
#include "errval.h"


/*************
 *  Typedefs
 *************/
/* --- None --- */

/****************
 *  Definitions
 ****************/
/* --- None --- */

/************
 *  Globals
 ************/
extern sem_t  *p_semServerTables;  	// request table, subscription table, attached devices table
extern sem_t  *p_semStopMainThr; /* terminate Main Thread */

/************************
 *  Function Prototypes
 ************************/

errVal_t create_hs_semaphores(uint8_t createFlag);

#endif /* _HSSEMS_H */

