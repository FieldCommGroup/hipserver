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

