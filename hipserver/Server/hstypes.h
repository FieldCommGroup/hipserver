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
#include "netinet/in.h"

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

#define HARTIP_MAX_PYLD_DPDU_LEN 258
#define HARTIP_DPDU_STATUS_LEN 2

/* Max length (in bytes) of the HART-IP pass-through payload 
 * DPDU (258Byte max) x 4 +2Byte = 1034 byte
 */
#define HARTIP_MAX_PYLD_LEN ( (HARTIP_MAX_PYLD_DPDU_LEN * 4) + \
                              HARTIP_DPDU_STATUS_LEN )

/* Max length (in bytes) of a HART-IP msg 
 *
 * Msg Length (1042 bytes)
 * HART-IP Header (8) + Payload (1034)
 * (8 hdr = 1 vers + 1 msgType + 1 msgId + 1 status + 2 seqNum + 2 byteCount)
 * (258 = direct-passing msg frame/HART-IP pass-through payload length) * number
 * (2Byte status information)
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
  HARTIP_MSG_ID_DM_PDU = 4,
  HARTIP_MSG_ID_READ_AUDIT = 5,
  HARTIP_MSG_ID_DISCOVERY = 128
} HARTIP_MSG_ID;

typedef enum
{
  /* Values per Spec 85, do not alter! */
  HARTIP_SESS_ERR_INVALID_MASTER_TYPE = 2,
  HARTIP_SESS_ERR_TOO_FEW_BYTES = 5,
  HARTIP_SESS_ERR_TOO_FEW_TIME = 8,
  HARTIP_SESS_ERR_SECURITY_NOT_INITIALIZED = 9,
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
  uint8_t hipTPPDU[HARTIP_MAX_PYLD_LEN];	//was HARTIP_MAX_PYLD_LEN
} hartip_msg_t;

/*************
 *  Typedefs
 *************/
typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_in6 sockaddr_in6_t;

/* Session structure to keep track of clients (for multi-session
 * scalability)
 */
typedef struct _hartip_session_
{
  uint8_t id;
  uint8_t sessNum;         // uniquely identifies a session with a client
  int32_t server_sockfd;   // server's socket handle
  sockaddr_in_t clientAddr;      // client  vv
  uint16_t seqNumber;       // current sequence number
  timer_t idInactTimer;    // the inactivity timer
  uint32_t msInactTimer;    // timer value
} hartip_session_t;

#endif /* _HSTYPES_H */

