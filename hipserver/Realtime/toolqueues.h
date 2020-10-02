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
 * File Name:
 *   interface.h
 * File Description:
 *   Header file for interface.c
 *
 **********************************************************/
#ifndef _TOOLQUEUES_H_
#define _TOOLQUEUES_H_

using namespace std;

#include <mqueue.h>

#include "datatypes.h"
#include "errval.h"
#include <string>

/****************
 *  Definitions
 ****************/
#define MAX_QUEUE_LEN          5     /* max # of msgs on a queue (arbit) */
#define MAX_QUEUES             5     /* max # of queues in app (arbit) */
#define QMODE_PERMISSION       0644  /* RW for owner, R for grp & others */

#define QNAME_RSP               "/APPREQ"
#define QNAME_REQ               "/APPRSP"
#define QNAME_COM				"/APPCOM"
#define COM_MSGSIZE				20		/* message size to send instance name to APP */

#define QOPEN_FLAG_CREATE      O_CREAT
#define QOPEN_FLAG_RDONLY      O_RDONLY
#define QOPEN_FLAG_WRONLY      O_WRONLY
#define QOPEN_FLAG_RDWR	       O_RDWR

#define QSLEEP                 1	/* queue reading sleep time in ms between reads */

/***** Server-APP Message constants *****/
/* Length (in bytes) of the various fields of the Server-APP msg header */
#define SRVRAPPHDR_MSGTYPE_LEN  HARTIPHDR_MSGTYPE_LEN
#define SRVRAPPHDR_PAYLOAD_LEN  HARTIPHDR_BYTECOUNT_LEN
#define SRVRAPPHDR_SEQNUM_LEN   HARTIPHDR_SEQNUM_LEN
#define SRVRAPPHDR_SESSID_LEN   1

/* Total length (in bytes) of the Server-APP msg header */
#define SRVRAPP_HEADER_LEN      (SRVRAPPHDR_MSGTYPE_LEN   +  \
                                  SRVRAPPHDR_SESSID_LEN    +  \
                                  SRVRAPPHDR_SEQNUM_LEN    +  \
                                  SRVRAPPHDR_PAYLOAD_LEN)

/* Max length (in bytes) of the Server-APP msg payload */
#define SRVRAPP_MAX_PYLD_LEN    HARTIP_MAX_PYLD_LEN

/* Max length (in bytes) of a Server-APP msg
 *
 * Msg Length (270 bytes)
 * Server-APP Header (6) + Payload (264)
 * (6 = 1 msgType + 1 sessId + 2 seqNum + 2 pyldLen)
 * (264 = token-passing msg frame/HART-IP pass-through payload length)
 */
#define SRVRAPP_MAX_MSG_LEN     (SRVRAPP_HEADER_LEN + \
                                  SRVRAPP_MAX_PYLD_LEN)

/*************
 *  Typedefs
 *************/
typedef struct queue_info_struct
{
	mqd_t mqDesc;
	const char *qName;
} queue_info_t;

typedef enum _mqueue_blocking_
{
	MQUEUE_NONBLOCKING = 0, MQUEUE_BLOCKING
} mqueue_blocking_t;

typedef enum _mqueue_usage_
{
	MQUSAGE_SERVER = 0, MQUSAGE_APP
} mqueue_usage_t;

/************
 *  Globals
 ************/

extern mqd_t rspQueue;  // HART response messages received from device
extern mqd_t reqQueue;  // HART request messages routed to device

/************************
 *  Function Prototypes
 ************************/
int highest_instance_number();
string make_mq_name(const char *basename, char *instance);

errVal_t open_mqueue(mqd_t *p_mqDesc, char *mqName, int32_t qFlag,
		int32_t msgsize, int32_t maxmsg);
void close_mqueues(void);
void open_appcom(bool isServer, char *instance /* returned */);
errVal_t create_mqueues(mqueue_usage_t usage = MQUSAGE_APP);// set arg to false if called from device APP
errVal_t snd_msg_to_Q(mqd_t mq, void *p_rxMsg);
errVal_t rcv_msg_from_Q(mqd_t mq, void *p_msg, mqueue_blocking_t blocking);

#endif /* _TOOLQUEUES_H_ */

