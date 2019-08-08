/*
 * appmsg.h
 *
 *  Created on: Mar 26, 2018
 *      Author: user1
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
	void clear() { memset(pdu, 0, TPPDU_MAX_FRAMELEN); };//leave cmd & transaction
	AppMsg& operator=(const AppMsg &SRC) {command = SRC.command;
			transaction = SRC.transaction; memcpy(&pdu[0],&(SRC.pdu[0]),TPPDU_MAX_FRAMELEN);
			return *this;   };

	uint8_t *GetPduBuffer()   { return pdu; };
	void     ClearPduBuffer() { memset(pdu, 0, sizeof(pdu)); };
	void     CopyPduBuffer(uint8_t *to ) { memcpy(to, pdu, sizeof(pdu)); };
};


#endif /* HIP_COMMON_APPMSG_H_ */
