/*****************************************************************
 * Copyright (C) 2017 FieldComm Group
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

/*
 * hsmessage.h
 *
 *  Created on: Nov 13, 2017
 *      Author: user1
 */

#ifndef HIP_SERVER_HSMESSAGE_H_
#define HIP_SERVER_HSMESSAGE_H_

#include "hsudp.h"

/*
 * Session+PDU structure tracks requests and commands executed by server (not APP)
 */
typedef struct _hsmessage_
{
	time_t time;     // time this record was created
	int32_t cmd;      // HART Command #
	hartip_session_t *pSession;  // tracks the client that issued the request
	hartip_msg_t message;  // HART-IP header + TP PDU
} hsmessage_t;

#endif /* HIP_SERVER_HSMESSAGE_H_ */

