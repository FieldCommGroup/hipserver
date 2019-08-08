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
 *   hsthreads.h
 * File Description:
 *   Header file for hsthreads.c
 *
 **********************************************************/
#ifndef _HSTHREADS_H
#define _HSTHREADS_H

#include <pthread.h>
#include "errval.h"

/*************
 *  Typedefs
 *************/

/****************
 *  Definitions
 ****************/

/************
 *  Globals
 ************/
extern pthread_t popRxThrID;
extern pthread_t popTxThrID;
extern pthread_t socketThrID;
extern pthread_t appThrID;

/************************
 *  Function Prototypes
 ************************/
errVal_t do_hs_setup(void);

#endif  /* _HSTHREADS_H */

