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
 *   common.h
 * File Description:
 *   Header file containing common definitions and 
 *   prototypes used by various files.
 *
 **********************************************************/
#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include "datatypes.h"

/***********************
 * Shortcut Data Types
 ***********************/

#ifndef STR
typedef char STR;
typedef char * PSTR;
typedef const char * CPSTR;
#endif

#ifndef BYTE
typedef unsigned char BYTE;
typedef BYTE * PBYTE;
#endif

#ifndef BOOL
typedef unsigned char BOOL;
typedef BOOL * PBOOL;
#endif

#ifndef WORD
typedef unsigned short WORD;
typedef WORD * PWORD;
#endif

#ifndef DWORD
typedef unsigned long DWORD;
typedef DWORD * PDWORD;
#endif

#ifndef FLOAT
typedef float FLOAT;
typedef float * PFLOAT;
#endif

/*
 * Standard function status return data type
 */
typedef BYTE FSTAT;

/***************
 * Definitions
 ***************/

#ifndef OFF
#define OFF    0
#endif

#ifndef ON
#define ON     1
#endif

/*
 * Return codes for functions that return a status.
 */
#define STATUS_OK        0
#define STATUS_WORKING   1
#define STATUS_BUSY      2

#define STATUS_NEXT      10
#define STATUS_SLEEP     11

#define STATUS_ERROR     255
#define STATUS_BADID     254
#define STATUS_BADCMD    253

/*
 * HART Master Types.
 */
#define HART_PRIMARY     1
#define HART_SECONDARY   0

/*
 * Correct NAN.
 */
#ifndef HART_NAN
#define HART_NAN         0x7FA00000
#endif

/*
 * Misc. conversion definitions
 */
#define BYTES_PER_FLOAT    4        /* bytes in a float type */
#define USEC_PER_MSEC      1000     /* usecs in a millisecond */
#define USEC_PER_SEC       1000000  /* usecs in a second */
#define MSEC_PER_SEC       1000     /* msecs in a second */

#define MS_TO_US(n)        ((n) * USEC_PER_MSEC)
#define S_TO_MS(n)         ((n) * MSEC_PER_SEC)
#define S_TO_US(n)         ((n) * USEC_PER_SEC)

/*
 * Other common definitions
 */
#define FILENAME_LEN     40
#define RESERVED0        0   // Value is Reserved, must be set to 0
#define RESERVED1        1   // Value is Reserved, must be set to 1

/*
 * Misc. macros
 */
#define MAX(a, b)        (((a) > (b)) ? (a) : (b))
#define MIN(a, b)        (((a) < (b)) ? (a) : (b))
#define UMAX(a, b)        (((uint32_t)(a) > (uint32_t)(b)) ? (a) : (b))
#define UMIN(a, b)        (((uint32_t)(a) < (uint32_t)(b)) ? (a) : (b))

#define free_ptr(a)      {if ((a)) {free(a); (a) = NULL;}}

#define LOB(a)           ((uint8_t)((a) & 0xFF))        // LSB
#define HIB(a)           ((uint8_t)(((a) >> 8) & 0xFF)) // MSB

/*******************
 * Data Structures
 *******************/

/***************************
 * Global extern variables
 ***************************/
//extern FILE       *p_toolLogPtr;


/***********************
 * Function Prototypes
 ***********************/

#endif /* _COMMON_H */
