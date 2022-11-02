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

