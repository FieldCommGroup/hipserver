/*****************************************************************
 * Copyright (C) 2015-2019 FieldComm Group
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

void close_logfile(FILE *p_filePtr);
void close_toolLog(void);
errVal_t open_logfile(FILE **pp_filePtr, char *p_fileName);
errVal_t open_toolLog(void);
void print_hexbytes(uint8_t *bytes, uint8_t numBytes, FILE *p_filePtr = NULL);
void print_to_both(FILE *p_filePtr, const char *format, ...);
void print_to_log(FILE *p_filePtr, const char *format, ...);
void script_sleep(uint32_t sec);
void script_usleep(uint32_t usec);
double get_elapsed_time();	// decimal seconds since program started, accurate to microsec
uint32_t GetTickCount(void);

#ifdef __cplusplus
}
#endif


#endif /* _TOOLUTILS_H */

