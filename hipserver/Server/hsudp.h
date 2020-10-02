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
 *
 *****************************************************************/

/**********************************************************
 *
 * File Name:
 *   hsudp.h
 * File Description:
 *   Header file for hsudp.c
 *
 **********************************************************/
#ifndef _HSUDP_H
#define _HSUDP_H

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "datatypes.h"
#include "errval.h"
#include "hstypes.h"

/****************
 *  Definitions
 ****************/
/* Values from HART-IP Protocol (Spec 85) */
#define HARTIP_PROTOCOL_VERSION      1
#define HARTIP_SERVER_PORT           5094

/* Mask to get the message type */
#define HARTIP_MSG_TYPE_MASK         0x0F

/* Offsets for the fields of a HART-IP message header (derived from
 * header information in Spec 85)
 */
#define HARTIP_OFFSET_VERSION        0
#define HARTIP_OFFSET_MSG_TYPE       1
#define HARTIP_OFFSET_MSG_ID         2
#define HARTIP_OFFSET_STATUS         3
#define HARTIP_OFFSET_SEQ_NUM        4
#define HARTIP_OFFSET_BYTE_COUNT     6

/* Misc. constants */
#if 0 // Test 1 first
#define HARTIP_NUM_SESS_SUPPORTED    HARTIP_MIN_SESS_SUPPORTED - 1
#else
#define HARTIP_NUM_SESS_SUPPORTED    3 /* 2 process data clients and an instrument mgt sys  */
#endif

#define HARTIP_SESSION_ID_INVALID    0xFF         /* arbitrary */
#define HARTIP_SESSION_ID_OK         0xF0         /* arbitrary */
#define HARTIP_SOCKET_FD_INVALID     LINUX_ERROR

/* Inactivity signal - scalable for future multiple sessions by defining
 * the signals as SIGRTMIN+n for session n
 */
#define SIG_INACTIVITY_TIMER(n)      (SIGRTMIN + (n))

/*************
 *  Typedefs
 *************/
typedef struct sockaddr_in sockaddr_in_t;

/* Session structure to keep track of clients (for multi-session
 * scalability)
 */
typedef struct _hartip_session_
{
	uint8_t id;
	uint8_t sessNum;         // uniquely identifies a session with a client
	int32_t server_sockfd;   // server's socket handle
	sockaddr_in_t clientAddr;      // client address
	uint16_t seqNumber;       // current sequence number
	timer_t idInactTimer;    // the inactivity timer
	uint32_t msInactTimer;    // timer value
} hartip_session_t;

/************
 *  Globals
 ************/

// #6003
extern uint16_t portNum;

/************************
 *  Function Prototypes
 ************************/
void clear_session_info(uint8_t sessNum);
void close_socket(void);
errVal_t create_socket(void);
//errVal_t  create_sockets(void);
//void      reset_client_sessions(void);
errVal_t send_burst_to_client(hartip_msg_t *p_response, int sessnum);
errVal_t send_rsp_to_client(hartip_msg_t *p_response,
		hartip_session_t *pSession);
void *socketThrFunc(void *thrName);

#endif /* _HSUDP_H */

