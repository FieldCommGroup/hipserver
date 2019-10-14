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
 *   hsutils.h
 * File Description:
 *   Header file for hsutils.c
 *
 **********************************************************/
#ifndef _HSUTILS_H
#define _HSUTILS_H

#include <unistd.h>
#include "datatypes.h"

/*************
 *  Typedefs
 *************/

/****************************
 *  Global extern variables
 ****************************/
extern FILE *p_hsLogPtr;

/************************
 *  Function Prototypes
 ************************/
void shutdown_hs(void);
uint8_t open_hsLog(void);
void close_hsLog(void);

#endif /* _HSUTILS_H */

