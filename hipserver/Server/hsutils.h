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

