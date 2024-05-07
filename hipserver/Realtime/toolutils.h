/**************************************************************************
 * Copyright 2019-2024 FieldComm Group, Inc.
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
 **************************************************************************/

/**********************************************************
 *
 * File Name:
 *   toolutils.h
 * File Description:
 *   Header file for toolutils.c
 *
 **********************************************************/
#ifndef _TOOLUTILS_H
#define _TOOLUTILS_H

#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>

#include "datatypes.h"
#include "errval.h"

/*************
 *  Typedefs
 *************/
typedef struct timeval timeval_t;

/****************************
 *  Global extern variables 
 ****************************/
extern FILE *p_toolLogPtr;

/************************
 *  Function Prototypes
 ************************/
#ifdef __cplusplus  /* when included in a C++ file, tell compiler these are C functions */
extern "C" {
#endif

void     close_logfile(FILE *p_filePtr);
void     close_toolLog(void);
uint32_t GetTickCount(void);
double   get_elapsed_time(); // secs (decimal) since prog began, usec accuracy
errVal_t open_logfile(FILE **pp_filePtr, char *p_fileName);
errVal_t open_toolLog(void);
void     print_hexbytes(uint8_t *bytes, uint8_t numBytes,
                        FILE *p_filePtr = NULL);
void     print_to_both(FILE *p_filePtr, const char *format, ...);
void     print_to_log(FILE *p_filePtr, const char *format, ...);
void     script_sleep(uint32_t sec);
void     script_usleep(uint32_t usec);

#ifdef __cplusplus
}
#endif


#endif /* _TOOLUTILS_H */

