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
 *   hsudp.c
 * File Description:
 *   Functions for HART-IP UDP server.
 *
 **********************************************************/
#include "debug.h"
#include "hsqueues.h"
#include "toolsems.h"
#include "toolutils.h"
#include "tooldef.h"
#include "tppdu.h"
#include "hssigs.h"
#include "hsmessage.h"
#include "hssems.h"
#include "hsudp.h"
#include "hsrequest.h"
#include "hssubscribe.h"
#include "app.h"

/************
 *  Globals
 ************/

extern uint16_t portNum;
extern int connectionType;

/************************************
 *  Private variables for this file
 ************************************/
hartip_session_t ClientSessTable[HARTIP_NUM_SESS_SUPPORTED];
hartip_session_t *pCurrentSession = ClientSessTable;

/*
 *  If there is an error in the session initiate request, then the server
 *  must answer the request with an error response, but there will be no
 *  entry into the ClientSessTable.  In this case, we construct an ErrorSession
 *  from the socket_fd (same is used by all sessions) and the client address
 *  returned from the wait_for_client_req().
 */
hartip_session_t ErrorSession;

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static errVal_t create_udpserver_socket(uint16_t serverPortNum,
		int32_t *pSocketFD);
static errVal_t handle_sess_close_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, uint8_t sessNum);
static errVal_t handle_sess_init_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, sockaddr_in_t client_addr);
static errVal_t handle_token_passing_req(hartip_msg_t *p_request, uint8_t sessNum);
static errVal_t handle_keepalive_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, uint8_t sessNum);
static bool_t is_client_sess_valid(sockaddr_in_t *client_sockaddr,
		uint8_t *pSessNum);
static bool_t is_session_avlbl(uint8_t *pSessNum);
static errVal_t parse_client_req(uint8_t *pduHartIp, ssize_t lenPdu,
		hartip_msg_t *p_parsedReq);
static void print_socket_addr(sockaddr_in_t socket_addr);
static errVal_t wait_for_client_req(uint8_t *pduHartIp, ssize_t *lenPdu,
		sockaddr_in_t *client_sockaddr);
static void reset_client_info(void);
static void set_inactivity_timer();
int process_cmd258(hsmessage_t *hsmsg);
int process_cmd257(hsmessage_t *hsmsg);

/*****************************
 *  Function Implementations
 *****************************/
void clear_session_info(uint8_t sessNum)
{
	const char *funcName = "clear_session_info";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	if (sessNum < HARTIP_NUM_SESS_SUPPORTED)
	{
		if (ClientSessTable[sessNum].id != HARTIP_SESSION_ID_INVALID)
		{
			ClientSessTable[sessNum].id = HARTIP_SESSION_ID_INVALID;
			ClientSessTable[sessNum].seqNumber = 0;
			ClientSessTable[sessNum].msInactTimer = 0;

			dbgp_logdbg("Session %d is terminated.\n", sessNum);
		}
	}
	else
	{
		dbgp_logdbg("Invalid session number (%d)\n", sessNum);
		dbgp_logdbg(" Highest session number supported = %d\n",
		HARTIP_NUM_SESS_SUPPORTED - 1);
	}
}

void close_socket(void)
{
	const char *funcName = "close_socket";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	/* There is only one server socket */
	int32_t srvrSocketFD = ClientSessTable[0].server_sockfd;// TODO multiple clients

	if (srvrSocketFD != HARTIP_SOCKET_FD_INVALID)
	{
		dbgp_logdbg("----------------------\n");
		dbgp_logdbg("Closing Server Socket\n");
		if (close(srvrSocketFD) == LINUX_ERROR)
		{
			dbgp_hs("System error (%d) while closing socket\n", errno);
		}
		else
		{
			dbgp_logdbg("Socket closed\n");
			dbgp_logdbg("----------------------\n");
		}
		reset_client_info();
	} // if (srvrSocketFD != HARTIP_SOCKET_FD_INVALID)
}

errVal_t create_socket(void)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "create_socket";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	reset_client_info();

	do
	{
		dbgp_init("  --------------------------------\n");
		dbgp_init("  Creating UDP Socket for %s...\n", TOOL_NAME);

		int32_t serverSocketFD = HARTIP_SOCKET_FD_INVALID;

		// #6003
		errval = create_udpserver_socket(portNum, &serverSocketFD);
		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "  Failed to Create Socket\n");
			break;
		}
		dbgp_init("  Socket Created\n");
		dbgp_init("  --------------------------------\n");

		for (uint8_t i = 0; i < HARTIP_NUM_SESS_SUPPORTED; i++)
		{
			ClientSessTable[i].server_sockfd = serverSocketFD;
		}
	} while (FALSE);

	return (errval);
}

void *socketThrFunc(void *thrName)
{
	const char *funcName = "socketThrFunc";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_init("Starting %s...\n", (char * )thrName);

	uint8_t reqBuff[HS_MAX_BUFFSIZE];
	errVal_t errval;
	ssize_t pduLen = 0;
	hartip_msg_t reqFromClient;
	hartip_msg_t rspToClient;

	/* Start with a clean slate */
	memset_s(reqBuff, sizeof(reqBuff), 0);
	memset_s(&reqFromClient, sizeof(reqFromClient), 0);
	memset_s(&rspToClient, sizeof(rspToClient), 0);

	sockaddr_in_t client_sockaddr;
	uint8_t sessNum = 0;
	pCurrentSession = &ClientSessTable[sessNum];

	dbgp_hs("\n===================\n");

	while (TRUE) // thread runs forever
	{
		int32_t srvrSocketFD = pCurrentSession->server_sockfd;
		if (srvrSocketFD == HARTIP_SOCKET_FD_INVALID)
		{
			dbgp_init("Server Socket does not exist!!\n");
			continue;
		}

		// Clear buffer for receiving next client request
		memset_s(reqBuff, sizeof(reqBuff), 0);

		errval = wait_for_client_req(reqBuff, &pduLen, &client_sockaddr);
		if (errval != NO_ERROR)
		{
			dbgp_logdbg("Receive Error\n");
			continue;
		}
		// Clear struct before usage
		memset_s(&reqFromClient, sizeof(reqFromClient), 0);

		errval = parse_client_req(reqBuff, pduLen, &reqFromClient);
		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "Parsing Error in %s\n", funcName);
			continue;
		}
		dbgp_logdbg("Client request parsed OK.\n");

		HARTIP_MSG_ID thisMsgId = reqFromClient.hipHdr.msgID;

		/* Validate client session if not a request to initiate session */
		if (thisMsgId != HARTIP_MSG_ID_SESS_INIT)
		{
			bool_t isValidSess = is_client_sess_valid(&client_sockaddr,
					&sessNum);
			if (!isValidSess)
			{
				print_to_both(p_toolLogPtr, "Client session invalid!!\n");
				script_sleep(3);
				continue;
			}
			pCurrentSession = &ClientSessTable[sessNum];
			dbgp_hs("Current Session #%d\n", sessNum);
		}

		// Clear struct before usage
		memset_s(&rspToClient, sizeof(rspToClient), 0);

		dbgp_logdbg("#*#*#*# Server recd a ");

		switch (thisMsgId)
		{
		case HARTIP_MSG_ID_SESS_INIT:
			dbgp_logdbg("Session Initiate Request\n");
			errval = handle_sess_init_req(&reqFromClient, &rspToClient,
					client_sockaddr);
			if (errval == NO_ERROR)
			{
				dbgp_logdbg("\nHART-IP Initiate Session...  Session %d is created.\n", pCurrentSession->sessNum);
			}

			// pCurrentSession is set in handle_sess_init_req()

			hsmessage_t hsmsg;
			hsmsg.pSession = pCurrentSession;
			hsmsg.message = rspToClient;
			errval = send_rsp_to_client(&rspToClient, pCurrentSession);
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr, "Error in send_rsp_to_client()\n");
			}
			break;
		case HARTIP_MSG_ID_SESS_CLOSE:
			dbgp_logdbg("HART-IP Close Session...  ");
			errval = handle_sess_close_req(&reqFromClient, &rspToClient,
					sessNum);
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr, "  Failed to close session\n");
			}
			break;
		case HARTIP_MSG_ID_TP_PDU:
			dbgp_logdbg("Token-Passing PDU\n");
			errval = handle_token_passing_req(&reqFromClient, sessNum);
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr,
						"Error in handle_token_passing_req()\n");
			}
			break;
		case HARTIP_MSG_ID_KEEPALIVE:
			dbgp_logdbg("Keep-Alive PDU\n");
			errval = handle_keepalive_req(&reqFromClient, &rspToClient, sessNum);
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr,
						"Error in handle_keepalive_req()\n");
			}
			break;
		case HARTIP_MSG_ID_DISCOVERY:
			dbgp_init("Keep-Alive/Discovery msg\n");
			break;
		default:
			/* Should never come here if parse_client_req() worked */
			print_to_both(p_toolLogPtr,
					"HART-IP Invalid Msg ID (%d) in Client Request.\n", thisMsgId);
			break;
		} /* switch */

		set_inactivity_timer();
	} /* while (TRUE) */

	return NULL;
}

errVal_t send_burst_to_client(hartip_msg_t *p_response, int sessnum)
{
	// add the seq # for the correct client, then increment it
	p_response->hipHdr.seqNum = ClientSessTable[sessnum].seqNumber++;

	return send_rsp_to_client(p_response, &ClientSessTable[sessnum]);
}

/**
 * send_rsp_to_client()
 *         send HART-IP response to the client
 *
 */
errVal_t send_rsp_to_client(hartip_msg_t *p_response,
		hartip_session_t *pSession)
{
	const char *funcName = "send_rsp_to_client";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	errVal_t errval = NO_ERROR;

	do
	{
		if (p_response == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer passed to %s\n",
					funcName);
			break;
		}

		hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

		/* Build Response */
		uint16_t idx;
		uint8_t rspBuff[HS_MAX_BUFFSIZE];

		/* Start with a clean slate */
		memset_s(rspBuff, sizeof(rspBuff), 0);

		/* Fill in the version */
		idx = HARTIP_OFFSET_VERSION;
		rspBuff[idx] = HARTIP_PROTOCOL_VERSION;

		/* Fill in the message type */
		idx = HARTIP_OFFSET_MSG_TYPE;
		rspBuff[idx] = p_rspHdr->msgType;

		/* Fill in the message id */
		idx = HARTIP_OFFSET_MSG_ID;
		rspBuff[idx] = p_rspHdr->msgID;

		/* Fill in the status code */
		idx = HARTIP_OFFSET_STATUS;
		rspBuff[idx] = p_rspHdr->status;

		/* Fill in the sequence number */
		idx = HARTIP_OFFSET_SEQ_NUM;
		rspBuff[idx] = p_rspHdr->seqNum >> 8;
		rspBuff[idx + 1] = p_rspHdr->seqNum & 0xFF;

		/* Fill in the byte count */
		idx = HARTIP_OFFSET_BYTE_COUNT;
		uint16_t byteCount = p_rspHdr->byteCount;

		rspBuff[idx] = byteCount >> 8;
		rspBuff[idx + 1] = byteCount & 0xFF;

		/* Fill in the payload, if not empty */
		uint16_t payloadLen = byteCount - HARTIP_HEADER_LEN;
		if (payloadLen > 0)
		{
			memcpy_s(&rspBuff[HARTIP_HEADER_LEN], (TPPDU_MAX_FRAMELEN - TPPDU_MAX_HDRLEN), 
					p_response->hipTPPDU, payloadLen);
		}

		uint16_t msgLen = HARTIP_HEADER_LEN + payloadLen;

		dbgp_logdbg("\n-------------------\n");
		dbgp_logdbg("Server sending msg to Client:\n");

		dbgp_logdbg("** HART-IP Msg Header:\n");
		uint16_t i;
		for (i = 0; i < HARTIP_HEADER_LEN; i++)
		{
			dbgp_logdbg(" %.2X", rspBuff[i]);
		}
		dbgp_logdbg("\n");

		dbgp_logdbg("** Payload:\n");
		for (i = HARTIP_HEADER_LEN; i < msgLen; i++)
		{
			dbgp_logdbg(" %.2X", rspBuff[i]);
		}
		dbgp_logdbg("\n");
		dbgp_logdbg("-------------------\n");

		socklen_t socklen = sizeof(pSession->clientAddr);

		if (LINUX_ERROR
				== sendto(pSession->server_sockfd, rspBuff, msgLen, 0,
						(struct sockaddr *) &pSession->clientAddr, socklen))
		{
			errval = SOCKET_SENDTO_ERROR;
			print_to_both(p_toolLogPtr, "System Error %d for socket sendto()\n",
			errno);
			break;
		}
		dbgp_logdbg("Msg sent from Server to Client\n");
		dbgp_logdbg("\n<<<<<<<<<<<<<<<<<<<<<<<\n\n");
	} while (FALSE);

	return (errval);
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
/**
 * create_udpserver_socket(): Create HART-IP UDP Server Socket
 */
static errVal_t create_udpserver_socket(uint16_t serverPortNum,
		int32_t *pSocketFD)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "create_udpserver_socket";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	do
	{
		int32_t socketFD = socket(AF_INET, SOCK_DGRAM, 0);

		if (socketFD == LINUX_ERROR)
		{
			errval = SOCKET_CREATION_ERROR;
			print_to_both(p_toolLogPtr, "System Error %d for socket()\n",
			errno);
			break;
		}

		sockaddr_in_t server_addr;
		memset_s(&server_addr, sizeof(server_addr), 0);

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		server_addr.sin_port = htons(serverPortNum);

		dbgp_logdbg("\nServer Socket:\n");
		print_socket_addr(server_addr);

		if (bind(socketFD, (struct sockaddr *) &server_addr,
				sizeof(server_addr)) == LINUX_ERROR)
		{
			if (errno == EINVAL)
			{
				errval = SOCKET_PORT_USED_ERROR;
				print_to_both(p_toolLogPtr,
						"System Error %d for socket bind()\n", errno);
				break;
			}
			else
			{
				errval = SOCKET_BIND_ERROR;
				print_to_both(p_toolLogPtr,
						"System Error %d for socket bind()\n", errno);
				break;
			}
		} // if bind()
		else
		{
			*pSocketFD = socketFD;
		}
	} while (FALSE);

	return (errval);
}

static bool_t is_session_avlbl(uint8_t *pSessNum)
{
	bool_t isSessAvlbl = FALSE;

	for (uint8_t i = 0; i < HARTIP_NUM_SESS_SUPPORTED; i++)
	{
		if (ClientSessTable[i].id == HARTIP_SESSION_ID_INVALID)
		{
			*pSessNum = i;
			isSessAvlbl = TRUE;
			break;
		}
	}

	return (isSessAvlbl);
}

/**
 * handle_sess_close_req(): handle incoming session close request from
 * the client
 */
static errVal_t handle_sess_close_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, uint8_t sessNum)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "handle_sess_close_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	do
	{
		if (p_request == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
					funcName);
			break;
		}
		if (p_response == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer (rsp) passed to %s\n",
					funcName);
			break;
		}

		/* Start with a clean slate */
		memset_s(p_response, sizeof(*p_response), 0);

		hartip_hdr_t *p_reqHdr = &p_request->hipHdr;
		hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

		/* Build response for HART-IP Client */
		p_rspHdr->version = HARTIP_PROTOCOL_VERSION;
		p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
		p_rspHdr->msgID = p_reqHdr->msgID;
		p_rspHdr->status = NO_ERROR;
		p_rspHdr->seqNum = p_reqHdr->seqNum;
		p_rspHdr->byteCount = HARTIP_HEADER_LEN;

		send_rsp_to_client(p_response, &ClientSessTable[sessNum]);
		clear_session_info(sessNum);
	} while (FALSE);

	return (errval);
}

static errVal_t handle_sess_init_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, sockaddr_in_t client_addr)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "handle_sess_init_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);
	sem_wait(p_semServerTables);	// lock server tables when available
	{
		do
		{
			if (p_request == NULL)
			{
				errval = POINTER_ERROR;
				print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
						funcName);
				break;
			}
			if (p_response == NULL)
			{
				errval = POINTER_ERROR;
				print_to_both(p_toolLogPtr, "NULL pointer (rsp) passed to %s\n",
						funcName);
				break;
			}

			/* Start with a clean slate */
			memset_s(p_response, sizeof(*p_response), 0);

			hartip_hdr_t *p_reqHdr = &p_request->hipHdr;
			hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

			/* Build header of response */
			p_rspHdr->version = HARTIP_PROTOCOL_VERSION;
			p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
			p_rspHdr->msgID = p_reqHdr->msgID;
			p_rspHdr->status = NO_ERROR;
			p_rspHdr->seqNum = p_reqHdr->seqNum;
			p_rspHdr->byteCount = HARTIP_HEADER_LEN;

			/* Build payload of response */
			uint16_t byteCount = p_reqHdr->byteCount;
			uint16_t payloadLen = byteCount - HARTIP_HEADER_LEN;

			/* Fill in the payload, if long enough */
			if (payloadLen >= HARTIP_SESS_INIT_PYLD_LEN)
			{
				memcpy_s(p_response->hipTPPDU, HARTIP_MAX_PYLD_LEN, 
					p_request->hipTPPDU, HARTIP_SESS_INIT_PYLD_LEN);
				p_rspHdr->byteCount += HARTIP_SESS_INIT_PYLD_LEN;

				/* First byte of payload should be set to Primary Master */
				p_response->hipTPPDU[0] = HARTIP_PRIM_MASTER_TYPE;
			}

			uint8_t thisSess = 0;
			bool_t isReqErr = FALSE;

			if (p_reqHdr->version != HARTIP_PROTOCOL_VERSION)
			{
				isReqErr = TRUE;
				p_rspHdr->status = HARTIP_SESS_ERR_VERSION_NOT_SUPPORTED;
				print_to_both(p_toolLogPtr,
						"\nHART-IP Initiate Session Refused...  HARTIP Version (%d) not supported\n",
						p_reqHdr->version);
			}
			else if (p_reqHdr->byteCount
					< (HARTIP_HEADER_LEN + HARTIP_SESS_INIT_PYLD_LEN))
			{
				isReqErr = TRUE;
				p_rspHdr->status = HARTIP_SESS_ERR_TOO_FEW_BYTES;
				print_to_both(p_toolLogPtr,
						"\nHART-IP Initiate Session Refused...  Insufficient bytes in pkt\n"
						);
			}
			else if (p_request->hipTPPDU[0] != HARTIP_PRIM_MASTER_TYPE)
			{
				isReqErr = TRUE;
				p_rspHdr->status = HARTIP_SESS_ERR_INVALID_MASTER_TYPE;
				print_to_both(p_toolLogPtr,
						"\nHART-IP Initiate Session Refused...  Invalid Master Type (%d)\n",
						p_request->hipTPPDU[0]);
			}
			else if (!is_session_avlbl(&thisSess))
			{
				isReqErr = TRUE;
				p_rspHdr->status = HARTIP_SESS_ERR_SESSION_NOT_AVLBL;
				print_to_both(p_toolLogPtr,
						"\nHART-IP Initiate Session Refused...  No client sessions are available.  A maximum of %d are supported.\n",
						HARTIP_NUM_SESS_SUPPORTED);
			} // if (!is_session_avlbl(&thisSess))



			if (isReqErr)
			{
				// error session
				// in this case, there is no entry in the ClientSession table
				ErrorSession.server_sockfd = ClientSessTable[0].server_sockfd;
				ErrorSession.clientAddr = client_addr;
				ErrorSession.id = HARTIP_SESSION_ID_INVALID;
				pCurrentSession = &ErrorSession;

				errval = MSG_ERROR;
			}
			else
			{
				/* New session */

				pCurrentSession = &ClientSessTable[thisSess];
				dbgp_hs("Current Session #%d\n", thisSess);


				memcpy_s(&pCurrentSession->clientAddr, sizeof(hartip_session_t::clientAddr), 
						&client_addr, sizeof(client_addr));
				pCurrentSession->id = HARTIP_SESSION_ID_OK;
				int32_t sessSig = SIG_INACTIVITY_TIMER(thisSess);

				dbgp_hs("Inactivity Signal for this session: %d\n", sessSig);

				/* Create the inactivity timer */
				struct sigevent se;
				se.sigev_notify = SIGEV_SIGNAL;
				se.sigev_signo = sessSig;
				se.sigev_value.sival_ptr = &(pCurrentSession->idInactTimer);

				timer_create(CLOCK_REALTIME, &se,
						&pCurrentSession->idInactTimer);
				uint32_t msTimer = (p_request->hipTPPDU[1] << 24)
						| (p_request->hipTPPDU[2] << 16)
						| (p_request->hipTPPDU[3] << 8)
						| (p_request->hipTPPDU[4]);

				dbgp_hs("Inactivity timer interval = %d ms\n", msTimer);
				pCurrentSession->msInactTimer = msTimer;
				pCurrentSession->sessNum = thisSess;
			}


		} while (FALSE);
	}
	sem_post(p_semServerTables);	// unlock server tables when done

	return (errval);
}


/**
 * handle_keepalive_req(): handle incoming keep alive request from
 * the client
 *
 * There is nothing to do but reply success.  The receipt of the message
 * resets the inactivity timer on the server.
 */
static errVal_t handle_keepalive_req(hartip_msg_t *p_request,
		hartip_msg_t *p_response, uint8_t sessNum)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = "handle_keepalive_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	do
	{
		if (p_request == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
					funcName);
			break;
		}
		if (p_response == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer (rsp) passed to %s\n",
					funcName);
			break;
		}

		/* Start with a clean slate */
		memset_s(p_response, sizeof(*p_response), 0);

		hartip_hdr_t *p_reqHdr = &p_request->hipHdr;
		hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

		/* Build response for HART-IP Client */
		p_rspHdr->version = HARTIP_PROTOCOL_VERSION;
		p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
		p_rspHdr->msgID = p_reqHdr->msgID;	// HARTIP_MSG_ID_KEEPALIVE
		p_rspHdr->status = NO_ERROR;
		p_rspHdr->seqNum = p_reqHdr->seqNum;
		p_rspHdr->byteCount = HARTIP_HEADER_LEN;

		send_rsp_to_client(p_response, &ClientSessTable[sessNum]);
//		clear_session_info(sessNum);
	} while (FALSE);

	return (errval);
}

static errVal_t handle_cmd_msg(hsmessage_t &hsmsg)
{
	const char *funcName = "handle_cmd_msg";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	dbgp_hs("\nServer processing msg recd from cmdQueue...\n");
	TpPdu tppdu(hsmsg.message.hipTPPDU);
	errVal_t errval = NO_ERROR;
	do
	{
		hsmsg.message.hipHdr.version = HARTIP_PROTOCOL_VERSION;
		hsmsg.message.hipHdr.status = 0;
		hsmsg.message.hipHdr.msgType = HARTIP_MSG_TYPE_RESPONSE;
		hsmsg.message.hipHdr.msgID = HARTIP_MSG_ID_TP_PDU;
		hsmsg.message.hipHdr.byteCount = HARTIP_HEADER_LEN + tppdu.PduLength();

		errval = send_rsp_to_client(&hsmsg.message, hsmsg.pSession);
	} while (FALSE);
	return (errval);
}

static errVal_t handle_token_passing_req(hartip_msg_t *p_request, uint8_t sessNum)
{
	const char *funcName = "handle_token_passing_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	errVal_t errval = NO_ERROR;

	sem_wait(p_semServerTables);	// lock server tables when available
	{
		do
		{
			if (p_request == NULL)
			{
				errval = POINTER_ERROR;
				print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
						funcName);
				break;
			}

			// create hsmessage
			hsmessage_t hsMsg;
			hsMsg.pSession = pCurrentSession;
			hsMsg.message = *p_request;
			TpPdu tppdu(hsMsg.message.hipTPPDU);
			hsMsg.cmd = tppdu.CmdNum();
			time(&hsMsg.time);  // timestamp


			bool_t isSrvrCommand = (
					hsMsg.cmd == 257 ||
					hsMsg.cmd == 258 ||
					/*
					 *  if APP is an IO system:
					 *  	pass subscription commands on
					 *  else
					 *  	hipserver handles the subscriptions
					 */
					(hsMsg.cmd == 532 && connectionType != hipiosys) ||
					(hsMsg.cmd == 533 && connectionType != hipiosys)
					) ? TRUE : FALSE;

			/* Start with a clean slate */
			AppMsg txMsg;
			memset_s(&txMsg, APP_MSG_SIZE, 0);
			memcpy_s(txMsg.pdu, TPPDU_MAX_FRAMELEN, p_request->hipTPPDU, sizeof(p_request->hipTPPDU));
			txMsg.transaction = (sessNum << 16);
			txMsg.transaction += hsMsg.message.hipHdr.seqNum; // client # + HART-IP sequence number

			if (isSrvrCommand)
			{ // these msgs processed by server

				dbgp_intfc("Server received msg from cmdQueue\n");

				TpPdu pdu(hsMsg.message.hipTPPDU);
				
				if (pdu.CmdNum() == 257)
				{ // #6005
					process_cmd257(&hsMsg);
					handle_cmd_msg(hsMsg);
				}

				else if (pdu.CmdNum() == 258)
				{
					process_cmd258(&hsMsg);
					handle_cmd_msg(hsMsg);
					shutdown_server();
				}

				else if (pdu.CmdNum() == 532)
				{
					process_cmd532(&hsMsg);
					handle_cmd_msg(hsMsg);
				}
				else if (pdu.CmdNum() == 533)
				{
					process_cmd533(&hsMsg);
					handle_cmd_msg(hsMsg);
				}
				else
				{
					print_to_both(p_toolLogPtr,
							"Server received unknown command msg from cmdQueue\n");
				}
			}
			else
			{
				// add message to request table, used to match responses from a device
				add_request_to_table(txMsg.transaction, &hsMsg);
				snd_msg_to_app(&txMsg);
			}

		} while (FALSE);
	}
	sem_post(p_semServerTables);	// unlock server tables when done

	return (errval);
}

/**
 * is_client_sess_valid(): check if the request comes from the correct client
 *
 * RETURN: TRUE if ok to proceed, FALSE otherwise
 */
static bool_t is_client_sess_valid(sockaddr_in_t *pClientAddr,
		uint8_t *pSessNum)
{
	bool_t retval = FALSE;
	uint8_t i;

	for (i = 0; i < HARTIP_NUM_SESS_SUPPORTED; i++)
	{
		dbgp_hs("Checking Client %d Info...\n", i);

		socklen_t socklen = sizeof(*pClientAddr);
		hartip_session_t thisSess = ClientSessTable[i];

		if (thisSess.id == HARTIP_SESSION_ID_INVALID)
		{
			// Session not initiatiated
			continue;
		}

		if (thisSess.server_sockfd == HARTIP_SOCKET_FD_INVALID)
		{
			// Socket for session not initiatiated
			print_to_both(p_toolLogPtr, "Invalid socket ID for session %d\n",
					i);
			continue;
		}

		if (!memcmp(&thisSess.clientAddr, pClientAddr, socklen))
		{
			/* Session exists */
			dbgp_hs("Session %d was initiated for this client\n", i);
			*pSessNum = i;
			retval = TRUE;
			break;
		}
		else
		{
			dbgp_hs("Session %d doesn't match client's session\n", i);
		}
	} // for (i = 0; i < HARTIP_NUM_SESS_SUPPORTED; i++)

	if (!retval)
	{
		print_to_both(p_toolLogPtr, "Client address does not exist!\n");
		print_to_both(p_toolLogPtr, "\nClient Session:\n");
		print_socket_addr(*pClientAddr);

		for (uint8_t j = 0; j < HARTIP_NUM_SESS_SUPPORTED; j++)
		{
			dbgp_init("\nCurrent Session (%d):\n", j);
			print_socket_addr(ClientSessTable[j].clientAddr);
		}
	}

	return (retval);
}

/**
 * parse_client_req()
 *     Parse the HART-IP PDU in p_reqBuff and store the parsed request
 *     "p_parsedReq".  p_parsedReq must be pre-allocated.
 */
static errVal_t parse_client_req(uint8_t *p_reqBuff, ssize_t lenPdu,
		hartip_msg_t *p_parsedReq)
{
	const char *funcName = "parse_client_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	errVal_t errval = NO_ERROR;

	do
	{
		if (p_reqBuff == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
					funcName);
			break;
		}

		if (p_parsedReq == NULL)
		{
			errval = POINTER_ERROR;
			print_to_both(p_toolLogPtr,
					"NULL pointer (parsed req) passed to %s\n", funcName);
			break;
		}

		if (lenPdu < HARTIP_HEADER_LEN)
		{
			print_to_both(p_toolLogPtr, "Incomplete PDU Error!\n");
			errval = PDU_ERROR;
			break;
		}

		/* Start with a clean slate */
		memset_s(p_parsedReq, sizeof(*p_parsedReq), 0);

		hartip_hdr_t *p_clientMsgHdr = &p_parsedReq->hipHdr;

		/* Build Request */
		uint32_t idx;

		/* Version */
		idx = HARTIP_OFFSET_VERSION;
		if (p_reqBuff[idx] != HARTIP_PROTOCOL_VERSION)
		{
			print_to_both(p_toolLogPtr, "HARTIP Version Parse Error!\n");
			errval = VERSION_ERROR;
			break;
		}
		p_clientMsgHdr->version = p_reqBuff[idx];

		/* Message Type */
		idx = HARTIP_OFFSET_MSG_TYPE;
		uint8_t msgType = p_reqBuff[idx] & HARTIP_MSG_TYPE_MASK;

		if ((msgType != HARTIP_MSG_TYPE_REQUEST)
				&& (msgType != HARTIP_MSG_TYPE_RESPONSE)
				&& (msgType != HARTIP_MSG_TYPE_PUBLISH)
				&& (msgType != HARTIP_MSG_TYPE_NAK))
		{
			print_to_both(p_toolLogPtr, "HARTIP Msg Type Parse Error!\n");
			errval = MSG_TYPE_ERROR;
			break;
		}
		p_clientMsgHdr->msgType = (HARTIP_MSG_TYPE) msgType;

		/* Message ID */
		idx = HARTIP_OFFSET_MSG_ID;
		uint8_t msgID = p_reqBuff[idx];

		if ((msgID != HARTIP_MSG_ID_SESS_INIT)
				&& (msgID != HARTIP_MSG_ID_SESS_CLOSE)
				&& (msgID != HARTIP_MSG_ID_KEEPALIVE)
				&& (msgID != HARTIP_MSG_ID_TP_PDU)
				&& (msgID != HARTIP_MSG_ID_DISCOVERY))
		{
			print_to_both(p_toolLogPtr, "HARTIP Msg ID Parse Error!\n");
			errval = MSG_ID_ERROR;
			break;
		}
		p_clientMsgHdr->msgID = (HARTIP_MSG_ID) msgID;

		/* Status Code */
		idx = HARTIP_OFFSET_STATUS;
		p_clientMsgHdr->status = p_reqBuff[idx];

		/* Sequence Number */
		idx = HARTIP_OFFSET_SEQ_NUM;
		p_clientMsgHdr->seqNum = p_reqBuff[idx] << 8 | p_reqBuff[idx + 1];

		/* Byte Count */
		idx = HARTIP_OFFSET_BYTE_COUNT;
		p_clientMsgHdr->byteCount = p_reqBuff[idx] << 8 | p_reqBuff[idx + 1];

		/* Fill in the payload, if not empty */
		uint16_t payloadLen = (p_clientMsgHdr->byteCount) -
		HARTIP_HEADER_LEN;

		if (payloadLen > TPPDU_MAX_FRAMELEN - HARTIP_HEADER_LEN)
		{
			print_to_both(p_toolLogPtr, "HARTIP buffer overflow!\n");
			errval = OVERFLOW_ERROR;
			break;
		}

		if (payloadLen > 0)
		{
			memcpy_s(p_parsedReq->hipTPPDU, TPPDU_MAX_FRAMELEN, &p_reqBuff[HARTIP_HEADER_LEN],
					payloadLen);
		}
	} while (FALSE);

	return (errval);
}

static void print_socket_addr(sockaddr_in_t socket_addr)
{
	dbgp_logdbg("Socket Address:\n");
	dbgp_logdbg(" Family: 0x%.4X, Port: 0x%.4X, Addr: 0x%.8X\n",
			socket_addr.sin_family, socket_addr.sin_port,
			socket_addr.sin_addr.s_addr);
}

/**
 * wait_for_client_req(): wait for client requests on the server sockets.
 *
 * NOTE: this caller will be blocked if there is no client request.
 */
static errVal_t wait_for_client_req(uint8_t *p_reqBuff, ssize_t *p_lenPdu,
		sockaddr_in_t *p_client_sockaddr)
{
	fd_set read_fdset;
	errVal_t errval = NO_ERROR;
	struct timeval timeout =
	{ 0, 2 };

	const char *funcName = "wait_for_client_req";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	do
	{
		FD_ZERO(&read_fdset);
		FD_SET(pCurrentSession->server_sockfd, &read_fdset);

		while (TRUE) /* run forever */
		{
			int retval;
			timeout.tv_sec = 60;
			timeout.tv_usec = 0;	// 2 microseconds
			retval = select(pCurrentSession->server_sockfd + 1, &read_fdset,
			NULL, NULL, NULL/*&timeout*/);
			if (retval == LINUX_ERROR)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				{
					errval = SOCKET_SELECT_ERROR;
					print_to_both(p_toolLogPtr,
							"System Error %d for socket select()\n",
							errno);
					break;
				}
			}
			else if (retval == 0)
			{
				continue; // timeout
			}
			else
			{
				int x = 1;
				// data is available
			}  // select()

			socklen_t socklen = sizeof(*p_client_sockaddr);
			memset_s(p_client_sockaddr, socklen, 0);

			*p_lenPdu = recvfrom(pCurrentSession->server_sockfd, p_reqBuff,
			HARTIP_MAX_PYLD_LEN, 0, (struct sockaddr *) p_client_sockaddr,
					&socklen);

			if (*p_lenPdu == LINUX_ERROR)
			{
				errval = SOCKET_RECVFROM_ERROR;
				print_to_both(p_toolLogPtr,
						"System Error %d for socket recvfrom()\n",
						errno);
				break;
			}

			dbgp_hs("\n>>>>>>>>>>>>>>>>>>>>>>>\n");dbgp_hs("Server got a Client request:\n");
			dbgp_logdbg("\n-------------------\n");
			dbgp_logdbg("Msg recd by Server from Client:\n");

			uint16_t i;
			for (i = 0; i < *p_lenPdu; i++)
			{
				dbgp_logdbg(" %.2X", p_reqBuff[i]);
			}
			dbgp_logdbg("\n");
			dbgp_logdbg("-------------------\n");

			break; // how can this run forever with a break? VG
		} // while (TRUE) /* run forever */
	} while (FALSE);

	return (errval);
}

static void reset_client_info(void)
{
	const char *funcName = "reset_client_info";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	for (uint8_t i = 0; i < HARTIP_NUM_SESS_SUPPORTED; i++)
	{
		clear_session_info(i);
		ClientSessTable[i].server_sockfd = HARTIP_SOCKET_FD_INVALID;
	}
}



static void set_inactivity_timer()
{
	const char *funcName = "set_inactivity_timer";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_nsec = 0;

	if (pCurrentSession->id == HARTIP_SESSION_ID_OK)
	{
		// start timer
		its.it_value.tv_sec = (pCurrentSession->msInactTimer) / 1000;
	}
	else
	{
		// disarm this timer
		its.it_value.tv_sec = 0;
	}

	if (pCurrentSession && pCurrentSession != &ErrorSession)
	{
		timer_settime(pCurrentSession->idInactTimer, 0, &its, NULL);
		dbgp_noop("Server Inactivity Timer Set\n");
	}
}


// #6004
int process_cmd258(hsmessage_t *hsmsg)
{
	TpPdu findme(hsmsg->message.hipTPPDU);

	const uint8_t bc = 4;  // byte count for success response

	if (findme.Validate(0))
	{
		dbgp_log("Received to shutdown server.\n");
		findme.ProcessOkResponse(RC_SUCCESS, bc);
	}

	return STS_OK;          // request is copied into table
}

// #6005
int process_cmd257(hsmessage_t *hsmsg)
{
	TpPdu findme(hsmsg->message.hipTPPDU);

	const uint8_t bc = 5;  // byte count for success response with added data bytes.

	if (findme.Validate(0))
	{
		uint8_t dataSize = 1;
		uint8_t data[dataSize];
		data[0] = connectionType;
		findme.ProcessOkResponse(RC_SUCCESS, bc);
		// look inside *hsmsg
		findme.AddData(data,dataSize);
		// Modify the data based on the byte count.
		//findme.ProcessOkResponseAddData(RC_SUCCESS, bc, connectionType);

	}

	return STS_OK;          // request is copied into table
}
