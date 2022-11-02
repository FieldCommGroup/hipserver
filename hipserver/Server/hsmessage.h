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

