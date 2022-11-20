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

#include "hshandlermessages.h"
#include "hssecurityconfiguration.h"
#include "debug.h"
#include "hsresponsesender.h"
#include "hsauditlog.h"
#include "hssettings.h"
#include "hsudp.h"
#include <pthread.h>

HandlerMessages::HandlerMessages() : m_commandManager(CommandsManager()), m_noResponse(FALSE) {}
HandlerMessages::~HandlerMessages() {}

void HandlerMessages::Run()
{
	const char *funcName = __func__;
	uint8_t pdustore[HS_MAX_BUFFSIZE];
	ssize_t received = 0;
	hartip_msg_t reqFromClient;
	hartip_msg_t rspToClient;
	errVal_t errval = NO_ERROR;
	bool_t isErrorMsg = FALSE;

	/* Start with a clean slate */
	memset_s(pdustore, sizeof(pdustore), 0);
	memset_s(&reqFromClient, sizeof(reqFromClient), 0);
	memset_s(&rspToClient, sizeof(rspToClient), 0);

	m_connectionsManager = ConnectionsManager::Instance();

	while (IsRunning())
	{
		m_noResponse = FALSE;
		bool_t noMessResponse = FALSE;
		errval = NO_ERROR;
		sockaddr_in_t addr;
		memset_s(pdustore, sizeof(pdustore), 0);
		errval = WaitClient(pdustore, &received, &addr);

		if (errval == NWK_ERROR)
		{
			RemoveCurrentSession();
			break;
		}
		if (errval != NO_ERROR)
		{
			dbgp_logdbg("Receive Error\n");
			continue;
		}

		m_commandManager.RemoveProcessedCommands();
		memset_s(&reqFromClient, sizeof(reqFromClient), 0);
		if (!IsRunning())
		{
			break;
		}

        // Version number is invalid
        bool validVersion = pdustore[HARTIP_OFFSET_VERSION] == HARTIP_PROTOCOL_V1 || pdustore[HARTIP_OFFSET_VERSION] == HARTIP_PROTOCOL_VERSION;
        bool initSession = pdustore[HARTIP_OFFSET_MSG_ID] == HARTIP_MSG_ID_SESS_INIT;
        if (false == validVersion && false == initSession)
        {
            print_to_both(p_toolLogPtr, "Version Error. Version = %u\n ", pdustore[HARTIP_OFFSET_VERSION]);
            HARTIPConnection* pSession = GetCurrentSession();
            if (pSession != NULL)
            {
                AuditLogger->SetStatusSession(pSession, AbortedSession);
            }
            RemoveCurrentSession();
            continue;
        }


		errval = ParseClientRequest(pdustore, received, &reqFromClient);

		/* Cases when session must be silently closed */
		if (errval == NOT_INIT_MSG_ERROR || errval == MSG_TYPE_ERROR || errval == MSG_ID_ERROR || errval == NOT_ZERO_RESERVED_BITS)
		{
			print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);

			/* Check if session is valid before close it */
			bool_t isValid = GetCurrentSession(addr);
			if (!isValid)
			{
				print_to_both(p_toolLogPtr, "Client session invalid!!\n");
				// ProcessInvalidSession();
				// continue;
			}

			/* Silently close the session*/
			dbgp_logdbg("HART-IP Close Session...  ");
			AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
			RemoveCurrentSession();
			continue;
		}

		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);
			break;
		}
		dbgp_logdbg("Client request parsed OK.\n");

		//DUT shall not respond to any message type other than REQ
		if (reqFromClient.hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
		{
			noMessResponse = TRUE;
		}

		HARTIP_MSG_ID thisMsgId = reqFromClient.hipHdr.msgID;

		if (thisMsgId != HARTIP_MSG_ID_SESS_INIT)
		{
			bool_t isValid = GetCurrentSession(addr);

			if (!isValid)
			{
				print_to_both(p_toolLogPtr, "Client session invalid!!\n");
				// ProcessInvalidSession();
				// continue;
			}
			dbgp_hs("Current Session #%d\n", m_currentSession->GetSessionNumber());
		}

		// Clear struct before usage
		memset_s(&rspToClient, sizeof(rspToClient), 0);

		dbgp_logdbg("#*#*#*# Server recd a ");

		switch (thisMsgId)
		{
		case HARTIP_MSG_ID_SESS_INIT:
			dbgp_logdbg("Session Initiate Request\n");

			errval = InitSession(&reqFromClient, &rspToClient, addr);

			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr, "Error in send_rsp_to_client()\n");
			}
			else if (!SecurityConfigurationTable::Instance()->IsConfigured() && m_connectionsManager->GetSessionNumber() == 1 && Settings::Instance()->GetLockedHipVersion() == 0 && !m_connectionsManager->InitiatedSessionIsRunning())
			{
				GetCurrentSession()->SetInitiatedSession();
			}

			break;
		case HARTIP_MSG_ID_DM_PDU:
		case HARTIP_MSG_ID_TP_PDU:
		{
			//MSG should have at least one command
			bool_t isSessionMustBeClosed = FALSE;
			
			ICommand *command = ICommand::ParseMessage(&reqFromClient, GetCurrentResponse(), noMessResponse);
			if(command->IsGood() == TRUE)
			{
				if(pdustore[0] == HARTIP_PROTOCOL_V1 && command->IsSecurityCommand() == TRUE)
				{
					print_to_both(p_toolLogPtr, "Main handler messages -  541/542 execution detected on V1 client. Attempting to close session.\n");

					isSessionMustBeClosed = TRUE;
				}
				else
				{
					//check security commands
					if(command->IsSecurityCommand() == TRUE && GetCurrentSession()->GetSlotNumber() != 0)
					{
						print_to_both(p_toolLogPtr, "Not slot 0 security operation detected: %d, attempting to close session.\n", GetCurrentSession()->GetSlotNumber());

						isSessionMustBeClosed = TRUE;
					}

					else if (command->IsReadOnlyCommand() == TRUE && GetCurrentSession()->IsReadOnly())
					{
						print_to_both(p_toolLogPtr, "Session is in READ ONLY mode, write operation restricted \n");
						isSessionMustBeClosed = TRUE;
					}

					else
					{
						m_commandManager.AddCommand(command);
						errval = command->Execute();

						if (errval == READ_ONLY_ACCESS_ERROR)
						{
						    print_to_both(p_toolLogPtr, "READ_ONLY ERROR MAIN RUN() \n");
							isSessionMustBeClosed = TRUE;
						}
					}					
				}
			}
			else
			{
				isSessionMustBeClosed = TRUE;
			}

			if (isSessionMustBeClosed)
			{
				dbgp_logdbg("HART-IP Close Session...  ");
				AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
				RemoveCurrentSession();
			}
			break;
		}
		case HARTIP_MSG_ID_KEEPALIVE:
			dbgp_logdbg("Keep-Alive PDU\n");
			errval = HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr,
							  "Error in handle_keepalive_req()\n");

				if (errval == TOO_LONG_PAYLOAD_ERROR || errval == KEEP_ALIVE_STATUS_ERROR)
				{
					dbgp_logdbg("HART-IP Close Session...  ");
					AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
					RemoveCurrentSession();
				}
			}
			break;
		case HARTIP_MSG_ID_DISCOVERY:
			dbgp_init("Keep-Alive/Discovery msg\n");
			HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
			break;
		case HARTIP_MSG_ID_READ_AUDIT:
		{
			if(AuditLogger->ProcessMessage5(reqFromClient, GetCurrentResponse()) != NO_ERROR)
			{
				RemoveCurrentSession();
			}
			break;
		}
		case HARTIP_MSG_ID_SESS_CLOSE:
		default:
			dbgp_logdbg("HART-IP Close Session...  ");
			print_to_both(p_toolLogPtr, "Closing session. Session initiated status: %d\n", GetCurrentSession()->IsInitiatedSession());
			if(pdustore[0] == HARTIP_PROTOCOL_V1)
			{
				SecurityConfigurationTable::Instance()->FinishConfigure();
			}
			if (GetCurrentSession()->IsInitiatedSession())
			{
				m_connectionsManager->InitiatedSessionState(FALSE);
				SecurityConfigurationTable::Instance()->FinishConfigure();
			}
			if (reqFromClient.hipHdr.msgID == HARTIP_MSG_ID_SESS_CLOSE && reqFromClient.hipHdr.byteCount - HARTIP_HEADER_LEN == 0)
			{
				errval = CloseSession(&reqFromClient, &rspToClient, isErrorMsg, GetCurrentResponse());
			}
			else
			{
				AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
			}
			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr, "  Failed to close session\n");
			}
			isErrorMsg = FALSE;
			RemoveCurrentSession();
			return;
			break;
		} /* switch */
		RestartTimerCurrentSession();
		//set_inactivity_timer();
	} /* while (TRUE) */
}

void HandlerMessages::RunUdp()
{
	const char *funcName = __func__;
	uint8_t pdustore[HS_MAX_BUFFSIZE];
	ssize_t received = 0;
	// m_semUdp = NULL;
	// m_semUdp = new sem_t();
	// sem_init(m_semUdp, 0, 1);

	memset_s(pdustore, sizeof(pdustore), 0);
	errVal_t errval = NO_ERROR;
	SetMainThread();

	/* Start with a clean slate */
	// memset_s(threadArguments->rawDataBytes, sizeof(threadArguments->rawDataBytes), 0);

	m_connectionsManager = ConnectionsManager::Instance();

	hartip_msg_t reqFromClient;
	memset_s(&reqFromClient, sizeof(reqFromClient), 0);
	hartip_msg_t rspToClient;
	memset_s(&rspToClient, sizeof(rspToClient), 0);

	while (true)
	{
		pthread_t threadIdUdp;
		dbgp_logdbg("########## RunUdp() Started ##########\n");
		m_noResponse = FALSE;
		bool_t noMessResponse = FALSE;
		errval = NO_ERROR;
		received = 0;
		memset_s(pdustore, sizeof(pdustore), 0);

		sockaddr_in_t addr;

		if (IsMainThread())
		{
			errval = WaitClientMainThreadUdp(pdustore, &received, &addr);
		}

		else
		{
			errval = WaitClient(pdustore, &received, &addr);
		}

		if (errval == NWK_ERROR)
		{
			RemoveCurrentSession();
			continue;
		}
		if (errval != NO_ERROR)
		{
			dbgp_logdbg("Receive Error\n");
			continue;
		}

		// Version number is invalid
        // Version number is invalid
        bool validVersion = pdustore[HARTIP_OFFSET_VERSION] == HARTIP_PROTOCOL_V1 || pdustore[HARTIP_OFFSET_VERSION] == HARTIP_PROTOCOL_VERSION;
        bool initSession = pdustore[HARTIP_OFFSET_MSG_ID] == HARTIP_MSG_ID_SESS_INIT;
        if (false == validVersion && false == initSession)
        {
            print_to_both(p_toolLogPtr, "Version Error in %s\n ", funcName);
            HARTIPConnection* pSession = GetCurrentSession();
            if (pSession != NULL)
            {
                AuditLogger->SetStatusSession(pSession, AbortedSession);
            }
            RemoveCurrentSession();
            continue;
        }

		// process raw data received from WaitClient to separate thread and execute actions there
		if (pdustore[0] == HARTIP_PROTOCOL_V1 &&
            (Settings::Instance()->GetLockedHipVersion() == 0 || Settings::Instance()->GetLockedHipVersion() == HARTIP_PROTOCOL_V1))
		{
			// go into this block if PDU is v1 and if V1 is currently being supported by the server
			bool_t isErrorMsg = FALSE;
			memset_s(&reqFromClient, sizeof(reqFromClient), 0);
			memset_s(&rspToClient, sizeof(rspToClient), 0);

			m_commandManager.RemoveProcessedCommands();
			
			errval = ParseClientRequest(pdustore, received, &reqFromClient);

			/* Cases when session must be silently closed */
			if (errval == NOT_INIT_MSG_ERROR || errval == MSG_TYPE_ERROR || errval == MSG_ID_ERROR || errval == NOT_ZERO_RESERVED_BITS)
			{
				print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);

				/* Check if session is valid before close it */
				bool_t isValid = GetCurrentSession(addr);
				if (!isValid)
				{
					print_to_both(p_toolLogPtr, "Client session invalid!!\n");
					ProcessInvalidSession();
					continue;
				}

				/* Silently close the session*/
				dbgp_logdbg("HART-IP Close Session...  ");
				AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
				RemoveCurrentSession();
				continue;
			}

			if (errval != NO_ERROR)
			{
				print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);
				continue;
			}
			dbgp_logdbg("Client request parsed OK.\n");

			//DUT shall not respond to any message type other than REQ
			if (reqFromClient.hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
			{
				noMessResponse = TRUE;
			}

			HARTIP_MSG_ID thisMsgId = reqFromClient.hipHdr.msgID;

			if (thisMsgId != HARTIP_MSG_ID_SESS_INIT)
			{
				bool_t isValid = GetCurrentSession(addr);

				if (!isValid)
				{
					print_to_both(p_toolLogPtr, "Client session invalid!!\n");
					ProcessInvalidSession();
					continue;
				}
				dbgp_hs("Current Session #%d\n", m_currentSession->GetSessionNumber());
			}

			// Clear struct before usage
			memset_s(&rspToClient, sizeof(rspToClient), 0);

			dbgp_logdbg("#*#*#*# Server recd a ");

			switch (thisMsgId)
			{
			case HARTIP_MSG_ID_SESS_INIT:
				dbgp_logdbg("Session Initiate Request\n");

				errval = InitSession(&reqFromClient, &rspToClient, addr);

				if (errval != NO_ERROR)
				{
					print_to_both(p_toolLogPtr, "Error in send_rsp_to_client()\n");
				}
				else if (!SecurityConfigurationTable::Instance()->IsConfigured() && m_connectionsManager->GetSessionNumber() == 1 && Settings::Instance()->GetLockedHipVersion() == 0 && !m_connectionsManager->InitiatedSessionIsRunning())
				{
					GetCurrentSession()->SetInitiatedSession();
				}

				break;
			case HARTIP_MSG_ID_DM_PDU:
			case HARTIP_MSG_ID_TP_PDU:
			{
				//MSG should have at least one command
				bool_t isSessionMustBeClosed = FALSE;
				
				ICommand *command = ICommand::ParseMessage(&reqFromClient, GetCurrentResponse(), noMessResponse);
				if(command->IsGood() == TRUE)
				{
					if(pdustore[0] == HARTIP_PROTOCOL_V1 && command->IsSecurityCommand() == TRUE)
					{
						print_to_both(p_toolLogPtr, "UDP Main thread - 541/542 execution detected on V1 client. Attempting to close session.\n");

						isSessionMustBeClosed = TRUE;
					}

					else if (command->IsReadOnlyCommand() == TRUE && GetCurrentSession()->IsReadOnly())
					{
						print_to_both(p_toolLogPtr, "Session is in READ ONLY mode, write operation restricted \n");
						isSessionMustBeClosed = TRUE;
					}

					else
					{
						m_commandManager.AddCommand(command);
						errval = command->Execute();
						if (errval == READ_ONLY_ACCESS_ERROR)
						{
							isSessionMustBeClosed = TRUE;
						}
					}
				}
				else
				{
					isSessionMustBeClosed = TRUE;
				}
				
				if (isSessionMustBeClosed)
				{
					dbgp_logdbg("HART-IP Close Session...  ");
					AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
					RemoveCurrentSession();
				}
				break;
			}
			case HARTIP_MSG_ID_KEEPALIVE:
				dbgp_logdbg("Keep-Alive PDU\n");
				errval = HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
				if (errval != NO_ERROR)
				{
					print_to_both(p_toolLogPtr,
								  "Error in handle_keepalive_req()\n");

					if (errval == TOO_LONG_PAYLOAD_ERROR || errval == KEEP_ALIVE_STATUS_ERROR)
					{
						dbgp_logdbg("HART-IP Close Session...  ");
						AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
						RemoveCurrentSession();
					}
				}
				break;
			case HARTIP_MSG_ID_DISCOVERY:
				dbgp_init("Keep-Alive/Discovery msg\n");
				HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
				break;
			case HARTIP_MSG_ID_READ_AUDIT:
			{
				if(AuditLogger->ProcessMessage5(reqFromClient, GetCurrentResponse()))
				{
					RemoveCurrentSession();
				}
				break;
			}
			case HARTIP_MSG_ID_SESS_CLOSE:
			default:
				dbgp_logdbg("HART-IP Close Session...  ");
				if(pdustore[0] == HARTIP_PROTOCOL_V1)
				{
					SecurityConfigurationTable::Instance()->FinishConfigure();
				}
				if (GetCurrentSession()->IsInitiatedSession())
				{
					m_connectionsManager->InitiatedSessionState(FALSE);
					SecurityConfigurationTable::Instance()->FinishConfigure();
				}
				if (reqFromClient.hipHdr.msgID == HARTIP_MSG_ID_SESS_CLOSE && reqFromClient.hipHdr.byteCount - HARTIP_HEADER_LEN == 0)
					{
						errval = CloseSession(&reqFromClient, &rspToClient, isErrorMsg, GetCurrentResponse());
					}
				if (errval != NO_ERROR)
				{
					print_to_both(p_toolLogPtr, "  Failed to close session\n");
				}
				isErrorMsg = FALSE;
				RemoveCurrentSession();
				break;
			} /* switch */
			RestartTimerCurrentSession();
			continue;
		}
		else if (pdustore[0] > HARTIP_PROTOCOL_V1 &&
            (Settings::Instance()->GetLockedHipVersion() == HARTIP_PROTOCOL_V1))
		{
			//handle securitynot initialized case
			print_to_both(p_toolLogPtr, "Handle security not initialized.\n");
			if(initSession == true)
			{
				// go into this block if PDU is v1 and if V1 is currently being supported by the server
				bool_t isErrorMsg = FALSE;
				memset_s(&reqFromClient, sizeof(reqFromClient), 0);
				memset_s(&rspToClient, sizeof(rspToClient), 0);

				m_commandManager.RemoveProcessedCommands();
				
				errval = ParseClientRequest(pdustore, received, &reqFromClient);

				/* Cases when session must be silently closed */
				if (errval == NOT_INIT_MSG_ERROR || errval == MSG_TYPE_ERROR || errval == MSG_ID_ERROR || errval == NOT_ZERO_RESERVED_BITS)
				{
					print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);

					/* Check if session is valid before close it */
					bool_t isValid = GetCurrentSession(addr);
					if (!isValid)
					{
						print_to_both(p_toolLogPtr, "Client session invalid!!\n");
						ProcessInvalidSession();
						continue;
					}

					/* Silently close the session*/
					dbgp_logdbg("HART-IP Close Session...  ");
					AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
					RemoveCurrentSession();
					continue;
				}

				if (errval != NO_ERROR)
				{
					print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);
					continue;
				}
				dbgp_logdbg("Client request parsed OK.\n");

				//DUT shall not respond to any message type other than REQ
				if (reqFromClient.hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
				{
					noMessResponse = TRUE;
				}

				HARTIP_MSG_ID thisMsgId = reqFromClient.hipHdr.msgID;

				if (thisMsgId != HARTIP_MSG_ID_SESS_INIT)
				{
					bool_t isValid = GetCurrentSession(addr);

					if (!isValid)
					{
						print_to_both(p_toolLogPtr, "Client session invalid!!\n");
						ProcessInvalidSession();
						continue;
					}
					dbgp_hs("Current Session #%d\n", m_currentSession->GetSessionNumber());
				}

				// Clear struct before usage
				memset_s(&rspToClient, sizeof(rspToClient), 0);

				dbgp_logdbg("Session Initiate Request\n");

				errval = InitSession(&reqFromClient, &rspToClient, addr);

				if (errval != NO_ERROR)
				{
					print_to_both(p_toolLogPtr, "Error in send_rsp_to_client()\n");
				}
				else if (!SecurityConfigurationTable::Instance()->IsConfigured() && m_connectionsManager->GetSessionNumber() == 1 && Settings::Instance()->GetLockedHipVersion() == 0 && !m_connectionsManager->InitiatedSessionIsRunning())
				{
					GetCurrentSession()->SetInitiatedSession();
				}
			}
			continue;
		}
		else if (pdustore[0] >= HARTIP_PROTOCOL_VERSION && (Settings::Instance()->GetLockedHipVersion() == 0 || Settings::Instance()->GetLockedHipVersion() >= HARTIP_PROTOCOL_VERSION) && !m_connectionsManager->InitiatedSessionIsRunning())
		{
			// sem_wait(m_semUdp);
			struct 	ThreadArguments *threadArguments;
			threadArguments = (struct ThreadArguments *)malloc(sizeof(struct ThreadArguments));

			memcpy_s(threadArguments->rawDataBytes, sizeof(threadArguments->rawDataBytes), pdustore, sizeof(pdustore));
			threadArguments->receivedBytes = received;
			threadArguments->clientAddress = addr;
			threadArguments->serverSocket = GetMainSocket();
			sockaddr_in_t *tempServerAddr = GetServerAddress();
			memcpy_s((sockaddr_in_t*)&threadArguments->serverAddress, sizeof(sockaddr_in_t), tempServerAddr, sizeof(sockaddr_in_t)); 
			threadArguments->commandManagerInstance = m_commandManager;

			print_to_both(p_toolLogPtr, "StartUdp: receivedBytes: %d \n", threadArguments->receivedBytes);
			// sem_post(m_semUdp);

			if (pthread_create(&threadIdUdp, NULL, StartUdpProcessThread, (void *)(threadArguments)) != 0)
			{
				perror("pthread_create");
				free(threadArguments);
				exit(-1);
			}
		}
		

		// proceed
	} /* while (TRUE) */
}

void *HandlerMessages::StartUdpProcessThread(void *pTr)
{
	pthread_detach(pthread_self());
	ThreadArguments *threadArgsTemp = static_cast<ThreadArguments *>(pTr);
	print_to_both(p_toolLogPtr, "StartThread: receivedBytes: %d \n", threadArgsTemp->receivedBytes);
	print_to_both(p_toolLogPtr, "StartThread: rawDataSize: %d \n", sizeof(threadArgsTemp->rawDataBytes));
	
	uint16_t portNumber = ntohs(threadArgsTemp->serverAddress.sin_port);
	UdpProcessor* udpThreaded = new UdpProcessor(portNumber);
	udpThreaded->InitThreadedObject();
	udpThreaded->CreateUdpServerSocket(threadArgsTemp->serverSocket, &threadArgsTemp->serverAddress);
	udpThreaded->ProcessUdpSocket(pTr);
	udpThreaded->Stop();
	dbgp_logdbg("Exiting UDP Thread \n");
	free(pTr);
	pthread_exit(pTr);
}

void *HandlerMessages::ProcessUdpSocket(void *threadArgs)
{
	bool_t noMessResponse = FALSE;
	dbgp_logdbg("ProcessUdpSocket: isRunning() %d\n", IsRunning());
	ThreadArguments *threadArgsTemp = static_cast<ThreadArguments *>(threadArgs);
	errVal_t errval = NO_ERROR;
	print_to_both(p_toolLogPtr, "rawDataSize: %d \n", sizeof(threadArgsTemp->rawDataBytes));
	print_to_both(p_toolLogPtr, "receivedBytes: %d \n", threadArgsTemp->receivedBytes);
	const char *funcName = __func__;
	bool_t isErrorMsg = FALSE;
	hartip_msg_t reqFromClient;
	CommandsManager commandManagerUdp = threadArgsTemp->commandManagerInstance;
	commandManagerUdp.RemoveProcessedCommands();
	memset_s(&reqFromClient, sizeof(reqFromClient), 0);
	m_connectionsManager = ConnectionsManager::Instance();

	errval = ParseClientRequest(threadArgsTemp->rawDataBytes, threadArgsTemp->receivedBytes, &reqFromClient);

	/* Cases when session must be silently closed */
	if (errval == NOT_INIT_MSG_ERROR || errval == MSG_TYPE_ERROR || errval == MSG_ID_ERROR || errval == NOT_ZERO_RESERVED_BITS)
	{
		print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);

		/* Check if session is valid before close it */
		bool_t isValid = GetCurrentSession(threadArgsTemp->clientAddress);
		if (!isValid)
		{
			print_to_both(p_toolLogPtr, "Client session invalid!!\n");
			ProcessInvalidSession();
			return this;
		}

		/* Silently close the session*/
		dbgp_logdbg("HART-IP Close Session...  ");
		AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
		RemoveCurrentSession();
		return this;
	}

	if (errval != NO_ERROR)
	{
		print_to_both(p_toolLogPtr, "Parsing Error in %s\n ", funcName);
		return this;
	}
	dbgp_logdbg("Client request parsed OK.\n");

	//DUT shall not respond to any message type other than REQ
	if (reqFromClient.hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
	{
		noMessResponse = TRUE;
	}

	HARTIP_MSG_ID thisMsgId = reqFromClient.hipHdr.msgID;

	if (thisMsgId != HARTIP_MSG_ID_SESS_INIT)
	{
		bool_t isValid = GetCurrentSession(threadArgsTemp->clientAddress);

		if (!isValid)
		{
			print_to_both(p_toolLogPtr, "Client session invalid!!\n");
			ProcessInvalidSession();
			return this;
		}

		dbgp_hs("Current Session #%d\n", m_currentSession->GetSessionNumber());
	}

	// Clear struct before usage

	hartip_msg_t rspToClient;
	memset_s(&rspToClient, sizeof(rspToClient), 0);

	dbgp_logdbg("#*#*#*# UDP - Received Data ");

	switch (thisMsgId)
	{
	case HARTIP_MSG_ID_SESS_INIT:
		dbgp_logdbg("Session Initiate Request\n");

		errval = InitSession(&reqFromClient, &rspToClient, threadArgsTemp->clientAddress);

		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "Error in send_rsp_to_client()\n");
			break;
		}
		else if (!SecurityConfigurationTable::Instance()->IsConfigured() && m_connectionsManager->GetSessionNumber() == 1 && Settings::Instance()->GetLockedHipVersion() == 0 && !m_connectionsManager->InitiatedSessionIsRunning())
		{
			dbgp_logdbg("UDP / DTLS Session initiated\n");
			GetCurrentSession()->SetInitiatedSession();
		}
		
		HandlerMessages::Run();
		break;
	case HARTIP_MSG_ID_DM_PDU:
	case HARTIP_MSG_ID_TP_PDU:
	{
		//MSG should have at least one command
		bool_t isSessionMustBeClosed = FALSE;
		
		ICommand *command = ICommand::ParseMessage(&reqFromClient, GetCurrentResponse(), noMessResponse);
		if(command->IsGood() == TRUE)
		{
			if(command->IsSecurityCommand() == TRUE)
			{
				print_to_both(p_toolLogPtr, "UDP processing - 541/542 execution detected on V1 client. Attempting to close session.\n");

				isSessionMustBeClosed = TRUE;
			}

			else if (command->IsReadOnlyCommand() == TRUE && GetCurrentSession()->IsReadOnly())
			{
				print_to_both(p_toolLogPtr, "Session is in READ ONLY mode, write operation restricted \n");
				isSessionMustBeClosed = TRUE;
			}

			else
			{
				m_commandManager.AddCommand(command);
				errval = command->Execute();
				if (errval == READ_ONLY_ACCESS_ERROR)
				{
					isSessionMustBeClosed = TRUE;
				}
			}
		}
		else
		{
			isSessionMustBeClosed = TRUE;
		}

		if (isSessionMustBeClosed)
		{
			dbgp_logdbg("HART-IP Close Session...  ");
			AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
			RemoveCurrentSession();
		}
		break;
	}
	case HARTIP_MSG_ID_KEEPALIVE:
		dbgp_logdbg("Keep-Alive PDU\n");
		errval = HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "Error in handle_keepalive_req()\n");

			if (errval == TOO_LONG_PAYLOAD_ERROR || errval == KEEP_ALIVE_STATUS_ERROR)
			{
				dbgp_logdbg("HART-IP Close Session...  ");
				AuditLogger->SetStatusSession(GetCurrentSession(), AbortedSession);
				RemoveCurrentSession();
			}
		}
		break;
	case HARTIP_MSG_ID_DISCOVERY:
		dbgp_init("Keep-Alive/Discovery msg\n");
		HandleKeepalive(&reqFromClient, &rspToClient, GetCurrentResponse());
		break;
	case HARTIP_MSG_ID_READ_AUDIT:
	{
		if(AuditLogger->ProcessMessage5(reqFromClient, GetCurrentResponse()))
		{
			RemoveCurrentSession();
		}
		break;
	}
	case HARTIP_MSG_ID_SESS_CLOSE:
	default:
		dbgp_logdbg("HART-IP Close Session...  ");
		if(reqFromClient.hipHdr.version == HARTIP_PROTOCOL_V1)
		{
			SecurityConfigurationTable::Instance()->FinishConfigure();
		}
		if (GetCurrentSession()->IsInitiatedSession())
		{
			m_connectionsManager->InitiatedSessionState(FALSE);
			SecurityConfigurationTable::Instance()->FinishConfigure();
		}
		if (reqFromClient.hipHdr.msgID == HARTIP_MSG_ID_SESS_CLOSE && reqFromClient.hipHdr.byteCount - HARTIP_HEADER_LEN == 0)
		{
			errval = CloseSession(&reqFromClient, &rspToClient, isErrorMsg, GetCurrentResponse());
		}
		if (errval != NO_ERROR)
		{
			print_to_both(p_toolLogPtr, "  Failed to close session\n");
		}
		isErrorMsg = FALSE;
		RemoveCurrentSession();
		return this;
		break;
	} /* switch */

	RestartTimerCurrentSession();
	return this;
}

/**
 * parse_client_req()
 *     Parse the HART-IP PDU in p_reqBuff and store the parsed request
 *     "p_parsedReq".  p_parsedReq must be pre-allocated.
 */

errVal_t HandlerMessages::ParseClientRequest(uint8_t *p_reqBuff, ssize_t lenPdu,
											 hartip_msg_t *p_parsedReq)
{
	m_noResponse = FALSE;
	const char *funcName = __func__;
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
        idx = HARTIP_OFFSET_VERSION;
        uint8_t version = p_reqBuff[idx];

        bool initSession = p_reqBuff[HARTIP_OFFSET_MSG_ID] == HARTIP_MSG_ID_SESS_INIT;
        if (false == initSession)
        {
            /* Version */
            if(version == 0 || SecurityConfigurationTable::Instance()->IsConfigured() == true &&
                               ((Settings::Instance()->GetLockedHipVersion() < MinimalSecureClientVersion && version >= MinimalSecureClientVersion)
                                ||(Settings::Instance()->GetLockedHipVersion() >= MinimalSecureClientVersion && version < MinimalSecureClientVersion)
                               ) || (version > HARTIP_PROTOCOL_VERSION && p_reqBuff[HARTIP_OFFSET_MSG_ID] != 0))
            {
                print_to_both(p_toolLogPtr, "HARTIP Version Parse Error! Version=%d\n", p_reqBuff[idx]);
                errval = VERSION_ERROR;
                break;
            }

        }

		p_clientMsgHdr->version = p_reqBuff[idx];

		/* Message Type */
		idx = HARTIP_OFFSET_MSG_TYPE;
		uint8_t msgType = p_reqBuff[idx] & HARTIP_MSG_TYPE_MASK;

		if((msgType != HARTIP_MSG_TYPE_REQUEST)	&& (msgType != HARTIP_MSG_TYPE_PUBLISH))
		{
			print_to_both(p_toolLogPtr, "HARTIP Msg Type Parse Error!\n");
			errval = MSG_TYPE_ERROR;
			p_clientMsgHdr->msgType = (HARTIP_MSG_TYPE)msgType;
			break;
		}

		uint8_t reservedBits = p_reqBuff[idx] & HARTIP_RESERVED_MASK;

		p_clientMsgHdr->msgType = (HARTIP_MSG_TYPE)msgType;

		/* Message ID */
		idx = HARTIP_OFFSET_MSG_ID;
		uint8_t msgID = p_reqBuff[idx];

		if ((msgID != HARTIP_MSG_ID_SESS_INIT) && (msgID != HARTIP_MSG_ID_SESS_CLOSE) && (msgID != HARTIP_MSG_ID_KEEPALIVE) && (msgID != HARTIP_MSG_ID_TP_PDU) && (msgID != HARTIP_MSG_ID_DM_PDU) && (msgID != HARTIP_MSG_ID_READ_AUDIT) && (msgID != HARTIP_MSG_ID_DISCOVERY))
		{
			print_to_both(p_toolLogPtr, "HARTIP Msg ID Parse Error!\n");
			errval = MSG_ID_ERROR;
			p_clientMsgHdr->msgID = (HARTIP_MSG_ID)msgID;
			break;
		}
		p_clientMsgHdr->msgID = (HARTIP_MSG_ID)msgID;

		if (p_clientMsgHdr->msgID != HARTIP_MSG_ID_SESS_INIT && reservedBits != 0)
		{
			//close session
			print_to_both(p_toolLogPtr, "Filled reserved bits in MessageType.\n");
			errval = NOT_ZERO_RESERVED_BITS;
			break;
		}
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

		// #689
		if (payloadLen > HARTIP_MAX_PYLD_LEN - HARTIP_HEADER_LEN)
		{
			print_to_both(p_toolLogPtr, "HARTIP buffer overflow!\n");
			errval = OVERFLOW_ERROR;
			break;
		}

		if (payloadLen > 0)
		{
			memcpy_s(p_parsedReq->hipTPPDU, HARTIP_MAX_PYLD_LEN, &p_reqBuff[HARTIP_HEADER_LEN],
					 payloadLen);
		}
	} while (FALSE);

	return (errval);
}

errVal_t HandlerMessages::WaitClient(uint8_t *p_reqBuff, ssize_t *p_lenPdu,
									 sockaddr_in_t *p_client_sockaddr)
{
	dbgp_logdbg("\n Wait Client Started");
	const char *funcName = __func__;
	dbgp_logdbg("~~~~~~ %s ~~~~~~\n", funcName);
	errVal_t errval = NO_ERROR;
	std::vector<int32_t> sockets = GetSockets();
	do
	{

		while (IsRunning()) /* run forever */
		{
			dbgp_logdbg("\n Running Start - Wait Client");
			struct timeval timeout =
				{0, 1000}; // changing timeout to 1000 microseconds because this is causing slowdown on UDP
			int retval;
			fd_set read_fdset, write_fdset, error_fdset;

			FD_ZERO(&read_fdset);
			FD_ZERO(&write_fdset);
			FD_ZERO(&error_fdset);
			int max = 0;

			for (std::vector<int32_t>::iterator it = sockets.begin(); it != sockets.end(); ++it)
			{
				if (max < *it)
					max = *it;
				FD_SET(*it, &read_fdset);
				FD_SET(*it, &write_fdset);
				FD_SET(*it, &error_fdset);
				print_to_both(p_toolLogPtr,
							  "Socket %d\n",
							  (*it));
			}

			retval = select(max + 1, &read_fdset,
							/*&write_fdset,*/ NULL, &error_fdset, &timeout);
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
			else
			{
				int x = 1;
				// data is available
			} // select()

			int32_t socket = 0;
			for (std::vector<int32_t>::iterator it = sockets.begin(); it != sockets.end(); ++it)
			{
				if (FD_ISSET(*it, &read_fdset))
				{
					socket = (*it);
					break;
				}
			}

			errval = ReadSocket(socket, p_reqBuff, p_lenPdu, p_client_sockaddr);

			if (errval != NO_ERROR)
			{
				Stop();

				break;
			}

			dbgp_hs("\n>>>>>>>>>>>>>>>>>>>>>>>\n");
			dbgp_hs("Server got a Client request:\n");
			dbgp_logdbg("\n-------------------\n");
			// dbgp_logdbg("Msg recd by Server from Client:\n");
			printf("\n");
			uint16_t i;
			for (i = 0; i < *p_lenPdu; i++)
			{
				printf(" %.2X", p_reqBuff[i]);
			}
			printf("\n");
			// dbgp_logdbg("-------------------\n");

			break; // how can this run forever with a break? VG
		}		   // while (TRUE) /* run forever */
	} while (FALSE);

	return (errval);
}

errVal_t HandlerMessages::WaitClientMainThreadUdp(uint8_t *p_reqBuff, ssize_t *p_lenPdu,
												  sockaddr_in_t *p_client_sockaddr)
{
	dbgp_logdbg("\n Wait Client MainThreadUdp \n");
	const char *funcName = __func__;
	dbgp_logdbg("~~~~~~ %s ~~~~~~\n", funcName);
	errVal_t errval = NO_ERROR;

	do
	{

		while (IsRunning()) /* run forever */
		{
			dbgp_logdbg("\n Running Start - Wait Client MainThreadUdp \n ");
			struct timeval timeout =
				{0, 1000}; // changing timeout to 1000 microseconds because this is causing slowdown on UDP
			int retval;
			fd_set read_fdset, write_fdset, error_fdset;

			FD_ZERO(&read_fdset);
			FD_ZERO(&write_fdset);
			FD_ZERO(&error_fdset);
			int max = 0;
			max = GetMainSocket();

			retval = select(max + 1, &read_fdset,
							/*&write_fdset,*/ NULL, &error_fdset, &timeout);
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
			else
			{
				int x = 1;
				// data is available
			} // select()

			errval = ReadSocket(max, p_reqBuff, p_lenPdu, p_client_sockaddr);

			if (errval != NO_ERROR)
			{
				break;
			}

			dbgp_hs("\n>>>>>>>>>>>>>>>>>>>>>>>\n");
			dbgp_hs("Server got a Client request:\n");
			dbgp_logdbg("\n-------------------\n");
			// dbgp_logdbg("Msg recd by Server from Client:\n");
			printf("\n");
			uint16_t i;
			for (i = 0; i < *p_lenPdu; i++)
			{
				printf(" %.2X", p_reqBuff[i]);
			}
			printf("\n");
			// dbgp_logdbg("-------------------\n");

			break; // how can this run forever with a break? VG
		}		   // while (TRUE) /* run forever */
	} while (FALSE);

	return (errval);
}

errVal_t HandlerMessages::CloseSession(hartip_msg_t *p_request,
									   hartip_msg_t *p_response, bool_t isError, IResponseSender *sender)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = __func__;
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
		p_rspHdr->version = ConnectionsManager::Instance()->GetClientsVersion();
		p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
		p_rspHdr->msgID = HARTIP_MSG_ID_SESS_CLOSE;
		p_rspHdr->status = isError == FALSE ? NO_ERROR : MSG_ID_ERROR;
		if (isError)
		{
			AuditLogger->SetStatusSession(sender->GetSession(), AbortedSession);
		}
		p_rspHdr->seqNum = p_reqHdr->seqNum;
		p_rspHdr->byteCount = HARTIP_HEADER_LEN;

		if (p_request->hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
		{
			break;
		}

		sender->SendResponse(p_response);
	} while (FALSE);

	return (errval);
}

/**
 * handle_keepalive_req(): handle incoming keep alive request from
 * the client
 *
 * There is nothing to do but reply success.  The receipt of the message
 * resets the inactivity timer on the server.
 */
errVal_t HandlerMessages::HandleKeepalive(hartip_msg_t *p_request,
										  hartip_msg_t *p_response, IResponseSender *sender)
{
	errVal_t errval = NO_ERROR;

	const char *funcName = __func__;
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
		//Keep Alive has no payload
		if (p_request->hipHdr.byteCount - HARTIP_HEADER_LEN > 0)
		{
			errval = TOO_LONG_PAYLOAD_ERROR;
			m_noResponse = TRUE;
			print_to_both(p_toolLogPtr, "Payload too long (req) passed to %s\n",
						  __func__);
			break;
		}
		//Keep Alive status = 0 - No error occured
		if (p_request->hipHdr.status != 0)
		{
			errval = KEEP_ALIVE_STATUS_ERROR;
			m_noResponse = TRUE;
			print_to_both(p_toolLogPtr, "Status error occured in %s\n",
						  __func__);
			break;
		}
		//Server should answer only on REQ messages
		if (p_request->hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
		{
			break;
		}

		/* Start with a clean slate */
		memset_s(p_response, sizeof(*p_response), 0);

		hartip_hdr_t *p_reqHdr = &p_request->hipHdr;
		hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

		/* Build response for HART-IP Client */
		p_rspHdr->version = m_connectionsManager->GetClientsVersion();
		p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
		p_rspHdr->msgID = p_reqHdr->msgID; // HARTIP_MSG_ID_KEEPALIVE
		p_rspHdr->status = NO_ERROR;
		p_rspHdr->seqNum = p_reqHdr->seqNum;
		p_rspHdr->byteCount = HARTIP_HEADER_LEN;
		sender->SendResponse(p_response);
	} while (FALSE);

	return (errval);
}
