/*************************************************************************************************
 * Copyright 2020 FieldComm Group, Inc.
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
 */


#ifndef HIP_COMMON_APPMSG_H_
#define HIP_COMMON_APPMSG_H_

/*
 *      All message traffic between the HART-IP server and its companion device APP
 *      is transmitted using AppMsg structs.
 *
 *      For app = HART_APP_CMD
 * 			transaction contains uniquely identifying transaction ID
 * 			message contains HART TP PDU (STX, ACK or BACK) delimiter through check byte
 *
 * 		for app = INIT_APP_CMD
 * 			transaction contains 0
 * 			message contains: 	request - empty,
 * 								reply - null-terminated LATIN-1 string
 * 										describing the APP and its version number
 *
 * 		for app = TERM_APP_CMD
 * 			transaction contains 0
 * 			message contains: request and reply - empty
 *
 */

#include <string.h>
#include "tpdll.h"
#include "safe_lib.h"

#define HART_APP_CMD	0
#define INIT_APP_CMD	1
#define TERM_APP_CMD	2

#define APP_MSG_SIZE	( (2*sizeof(int)) + TPPDU_MAX_FRAMELEN )

struct AppMsg
{
	int command;						// APP COMMAND NUMBER ie Control command, not hart command#
	int transaction;					// Transaction ID
	uint8_t pdu[TPPDU_MAX_FRAMELEN];	// HART TP PDU or APP PDU

	// command and transaction need to stay..void clear() { memset( this, 0, APP_MSG_SIZE); };
	void clear() { memset_s(pdu, TPPDU_MAX_FRAMELEN, 0); };//leave cmd & transaction
	AppMsg& operator=(const AppMsg &SRC) {command = SRC.command;
			transaction = SRC.transaction; memcpy_s(&pdu[0],TPPDU_MAX_FRAMELEN, &(SRC.pdu[0]),TPPDU_MAX_FRAMELEN);
			return *this;   };

	uint8_t *GetPduBuffer()   { return pdu; };
	void     ClearPduBuffer() { memset_s(pdu, sizeof(pdu), 0); };
	void     CopyPduBuffer(uint8_t *to ) { memcpy_s(to, TPPDU_MAX_FRAMELEN, pdu, sizeof(pdu)); };
};


#endif /* HIP_COMMON_APPMSG_H_ */
