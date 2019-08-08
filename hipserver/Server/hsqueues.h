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
 * File Name:
 *   interface.h
 * File Description:
 *   Header file for interface.c
 *
 **********************************************************/
#ifndef _HSINTERFACE_H_
#define _HSINTERFACE_H_

#include "toolqueues.h"
#include "hstypes.h"
#include "hsmessage.h"

/****************
 *  Definitions
 ****************/

/*************
 *  Typedefs
 *************/

typedef struct interface_hdr_struct
{
	HARTIP_MSG_TYPE msgType;
	uint8_t sessID;
	uint16_t seqNum;
	uint16_t pyldLen;
} interface_hdr_t;

typedef struct interface_msg_struct
{
	interface_hdr_t intfHdr;
	uint8_t tpPDU[SRVRAPP_MAX_PYLD_LEN];
} interface_msg_t;

/************
 *  Globals
 ************/
extern int connectionType;

/************************
 *  Function Prototypes
 ************************/
int GetAppRecdMsgCount();
void *popRxThrFunc(void *thrName);
errVal_t snd_msg_to_app(AppMsg *p_txMsg);
errVal_t rcv_msg_from_app(AppMsg *p_rxMsg);
errVal_t echo_msg_to_srvr(mqd_t mq, void *p_msg);

#endif /* _HSINTERFACE_H_ */

