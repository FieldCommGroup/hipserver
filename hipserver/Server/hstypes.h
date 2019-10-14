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
 *
 *****************************************************************/

/**********************************************************
 *
 * File Name:
 *   hstypes.h
 * File Description:
 *   Header file to define the various constants and
 *   typedefs used in HART-IP Server.
 *
 **********************************************************/
#ifndef _HSTYPES_H
#define _HSTYPES_H

#include "appmsg.h"
#include "tpdll.h"

/****************
 *  Definitions
 ****************/

/************************************************ 
 ***** HART-IP PDU constants (From Spec 85) ***** 
 ************************************************/

/* Length (in bytes) of the various fields of the HART-IP msg header */
#define HARTIPHDR_BYTECOUNT_LEN    2
#define HARTIPHDR_MSGID_LEN        1
#define HARTIPHDR_MSGTYPE_LEN      1
#define HARTIPHDR_SEQNUM_LEN       2
#define HARTIPHDR_STATUS_LEN       1
#define HARTIPHDR_VERSION_LEN      1

/* Total length (in bytes) of the HART-IP msg header */
#define HARTIP_HEADER_LEN          (HARTIPHDR_VERSION_LEN  +    \
                                    HARTIPHDR_MSGTYPE_LEN  +    \
                                    HARTIPHDR_MSGID_LEN    +    \
                                    HARTIPHDR_STATUS_LEN   +    \
                                    HARTIPHDR_SEQNUM_LEN   +    \
                                    HARTIPHDR_BYTECOUNT_LEN)

/* Max length (in bytes) of the HART-IP pass-through payload */
#define HARTIP_MAX_PYLD_LEN        TPPDU_MAX_FRAMELEN

/* Max length (in bytes) of a HART-IP msg 
 *
 * Msg Length (272 bytes)
 * HART-IP Header (8) + Payload (264)
 * (8 hdr = 1 vers + 1 msgType + 1 msgId + 1 status + 2 seqNum + 2 byteCount)
 * (264 = token-passing msg frame/HART-IP pass-through payload length)
 */
#define HARTIP_MAX_MSG_LEN         (HARTIP_HEADER_LEN  +   \
                                    HARTIP_MAX_PYLD_LEN)

/* Other constants from Spec 85 */
#define HARTIP_MIN_SESS_SUPPORTED  2
#define HARTIP_PRIM_MASTER_TYPE    1
#define HARTIP_SESS_INIT_PYLD_LEN  5

/* Use a safe buffer size to handle misc. messages in HART-IP Server */
#define HS_MAX_BUFFSIZE            (HARTIP_MAX_MSG_LEN * 2)

/*************
 *  Typedefs
 *************/
typedef enum
{
	/* Values per Spec 85, do not alter! */
	HARTIP_MSG_TYPE_REQUEST = 0,
	HARTIP_MSG_TYPE_RESPONSE = 1,
	HARTIP_MSG_TYPE_PUBLISH = 2,
	HARTIP_MSG_TYPE_NAK = 15
} HARTIP_MSG_TYPE;

typedef enum
{
	/* Values per Spec 85, do not alter! */
	HARTIP_MSG_ID_SESS_INIT = 0,
	HARTIP_MSG_ID_SESS_CLOSE = 1,
	HARTIP_MSG_ID_KEEPALIVE = 2,
	HARTIP_MSG_ID_TP_PDU = 3,
	HARTIP_MSG_ID_DISCOVERY = 128
} HARTIP_MSG_ID;

typedef enum
{
	/* Values per Spec 85, do not alter! */
	HARTIP_SESS_ERR_INVALID_MASTER_TYPE = 2,
	HARTIP_SESS_ERR_TOO_FEW_BYTES = 5,
	HARTIP_SESS_ERR_VERSION_NOT_SUPPORTED = 14,
	HARTIP_SESS_ERR_SESSION_NOT_AVLBL = 15,
	HARTIP_SESS_ERR_SESSION_EXISTS = 16
} HARTIP_SESSION_ERROR_TYPE;

/* HART-IP Message Header - From Spec 85 */
typedef struct hartip_hdr_struct
{
	uint8_t version;
	HARTIP_MSG_TYPE msgType;
	HARTIP_MSG_ID msgID;
	uint8_t status;
	uint16_t seqNum;
	uint16_t byteCount;
} hartip_hdr_t;

/* HART-IP Message - From Spec 85 */
typedef struct hartip_msg_struct
{
	hartip_hdr_t hipHdr;
	uint8_t hipTPPDU[TPPDU_MAX_FRAMELEN];	//was HARTIP_MAX_PYLD_LEN
} hartip_msg_t;

#endif /* _HSTYPES_H */

