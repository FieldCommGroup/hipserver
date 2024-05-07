/**************************************************************************
 * Copyright 2019-2024 FieldComm Group, Inc.
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
 **************************************************************************/

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
#include "hssettings.h"
#include "app.h"
#include "hscommands.h"
#include "hsauditlog.h"
#include "hssecurityconfiguration.h"
#include <algorithm>
#include "hsnetworkmanager.h"
/************
 *  Globals
 ************/
extern uint16_t portNum;
extern int connectionType;

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static errVal_t create_udpserver_socket(uint16_t serverPortNum, int32_t *pSocketFD);
static bool_t is_client_sess_valid(sockaddr_in_t *client_sockaddr, uint8_t *pSessNum);
static void print_socket_addr(sockaddr_in_t socket_addr);
static void reset_client_info(void);
static void set_inactivity_timer();
/****************************************************
 *          Private functions for this file
 ****************************************************/
/**
 * create_udpserver_socket(): Create HART-IP UDP Server Socket
 */

static errVal_t create_udpserver_socket(uint16_t serverPortNum, int32_t *pSocketFD,
                                        sockaddr_in_t*  pServer_addr)
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

		const int on = 1;
		const int off = 0;

		setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));

		sockaddr_in_t server_addr;
		memset_s(&server_addr, sizeof(server_addr), 0);

		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		server_addr.sin_port = htons(serverPortNum);
        print_to_both(p_toolLogPtr, "UdpSocket: %d\n", socketFD);
		dbgp_logdbg("\nServer Socket using port %d:\n", serverPortNum);
		print_socket_addr(server_addr);

		if (bind(socketFD, (struct sockaddr *) &server_addr, sizeof(server_addr)) == LINUX_ERROR)
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
            memcpy_s(pServer_addr, sizeof(sockaddr_in_t), &server_addr, sizeof(sockaddr_in_t));

			int buffsize = HARTIP_MAX_MSG_LEN;
			//setsockopt(socketFD, SOL_SOCKET, SO_RCVBUF, &buffsize, sizeof(buffsize));
			//setsockopt(socketFD, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize));
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

void UdpProcessor::Run()
{
	m_isRunning = TRUE;
	const char *funcName = __func__;
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	if(create_udpserver_socket(m_port, &m_socket, &m_server_addr) != NO_ERROR)
	{
		Stop();
	}

	dbgp_hs("\n===================\n");

	HandlerMessages::RunUdp();

	close(m_socket);
}

void UdpProcessor::ReconfigureServerSocket()
{
	close(m_socket);
	
   	 dbgp_logdbg("Clearing server socket  \n");
	if(create_udpserver_socket(m_port, &m_socket, &m_server_addr) != NO_ERROR)
	{
		Stop();
	}
	
	
}

errVal_t UdpProcessor::ReadSocket(int32_t socket, uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr)
{
    errVal_t errval = NO_ERROR;
    

    socklen_t socklen = sizeof(sockaddr_in_t);


    dbgp_logdbg("UDP ReadSocket(): MSG_PEEK %d\n", m_socket);
    print_socket_addr(*p_client_sockaddr);
    *p_lenPdu = recvfrom(m_socket, p_reqBuff, HARTIP_MAX_PYLD_LEN, MSG_PEEK, (struct sockaddr *) p_client_sockaddr, &socklen);
    dbgp_logdbg("UDP ReadSocket(): Payload received %d\n", m_socket);

    if (*p_lenPdu == LINUX_ERROR)
	{
		errval = SOCKET_RECVFROM_ERROR;
		print_to_both(p_toolLogPtr,"System Error %d for socket recvfrom()\n", errno);
        return errval;
	}

#ifndef HTS   // # CR 1717 VG
    print_to_both(p_toolLogPtr,"\nSIZE = %d", *p_lenPdu);
#else
    print_to_log(p_toolLogPtr,"\nSIZE = %d", *p_lenPdu);
#endif

    HARTIPConnection *connection;
	bool_t isValidSess = m_connectionsManager->IsSessionExisting(*p_client_sockaddr, &connection);

    if(isValidSess == TRUE)
    {
        OneUdpProcessor *udpSender = dynamic_cast<OneUdpProcessor*>(connection);
        errval = udpSender->ReadSocket(p_reqBuff, p_lenPdu);
    }
    else
    {
        *p_lenPdu = recvfrom(m_socket, p_reqBuff,HARTIP_MAX_PYLD_LEN, 0, (struct sockaddr *) p_client_sockaddr, &socklen);
        print_to_both(p_toolLogPtr,"recv from by udp(%d)", *p_lenPdu);
    }

	if (*p_lenPdu == LINUX_ERROR)
	{
		errval = SOCKET_RECVFROM_ERROR;
		print_to_both(p_toolLogPtr,"System Error %d for socket recvfrom()\n", errno);
	}
    
	return errval;
}

void UdpProcessor::TerminateSocket()
{
	shutdown(m_socket, SHUT_RDWR);
}

void UdpProcessor::DeleteSession(HARTIPConnection* session)
{
	OneUdpProcessor* sender = dynamic_cast<OneUdpProcessor*>(session);
	if(sender!=NULL)
		m_commandManager.RemoveCommandsBySender(sender);

	sender->Wait();
    std::vector<OneUdpProcessor*>::iterator finded = std::find(m_clients.begin(), m_clients.end(), sender);
    if(finded != m_clients.end())
        m_clients.erase(finded);
	SubscribesTable::Instance()->RemoveSubscriber(sender);
	sender->DeleteTimer();
	delete sender;
}

IResponseSender* UdpProcessor::GetCurrentResponse()
{
	if (m_currentSession != NULL)
	{
		m_currentSession->SetNoResponse(m_noResponse);
	}
	return m_currentSession;
}

HARTIPConnection* UdpProcessor::GetCurrentSession()
{
	return m_currentSession;
}

errVal_t UdpProcessor::RestartTimerCurrentSession()
{
	if(m_currentSession != NULL)
	{
		m_currentSession->StartTimer();
	}
}
bool_t UdpProcessor::GetCurrentSession(sockaddr_in_t& address)
{
	HARTIPConnection* connection = NULL;
	bool_t isValidSess = m_connectionsManager->IsSessionExisting(address, &connection);

	if(connection != NULL)
    {
        m_currentSession = dynamic_cast<OneUdpProcessor*>(connection);
    }
	return isValidSess;

}
errVal_t UdpProcessor::InitSession(hartip_msg_t* p_req, hartip_msg_t* p_res, sockaddr_in_t& address)
{
    hartip_hdr_t* p_hartip_hdr = &p_req->hipHdr;
    uint8_t version = p_hartip_hdr->version;
    bool invalidVersion = version > HARTIP_PROTOCOL_VERSION;

	OneUdpProcessor* newSender = new OneUdpProcessor(invalidVersion ? HARTIP_PROTOCOL_VERSION : version);
	newSender->SetSocket(m_socket);

	time_t timeCreate;
	time(&timeCreate);

	errVal_t errval = m_connectionsManager->InitSession(p_req, p_res,
			address, newSender, this, UDP, m_noResponse, m_port);
	if (errval == NO_ERROR)
	{
        // set version per client
        hartip_hdr_t* p_reqHdr = &p_req->hipHdr;

        m_version = invalidVersion ? HARTIP_PROTOCOL_VERSION : p_reqHdr->version;

        if (invalidVersion)
        {
            p_res->hipHdr.version = HARTIP_PROTOCOL_VERSION;
            p_res->hipHdr.status = HARTIP_SESS_ERR_VERSION_NOT_SUPPORTED;
        }

		dbgp_logdbg("\nHART-IP Initiate Session...  Session %d is created.\n", newSender->GetSessionNumber());
		m_currentSession = newSender;
	}
	else
	{
		newSender->SetAddress(address);
		m_currentSession = NULL;
	}

	newSender->SetNoResponse(m_noResponse);

    if (p_req->hipHdr.msgType == HARTIP_MSG_TYPE_REQUEST)
    {
	    errval = newSender->SendResponse(p_res);
    }
	
	if(m_currentSession == NULL)
	{
		delete newSender;      
        newSender = NULL;
		return errval;
	}

	// Evaluate client version here (2 or greater to go secure)
	if (errval == NO_ERROR && m_currentSession != NULL && m_version >= MinimalSecureClientVersion)
	{
        print_to_both(p_toolLogPtr, "Will be accepted DTLS connection\n");

        SSL *ssl = SSL_new(m_ctx);
        BIO* bio = BIO_new_dgram(m_socket, BIO_NOCLOSE);

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        struct sockaddr_in client_addr;
        // block on client connection and cookie exchangep
        // This will set the client_addr
        while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);

        uint32_t client_sockfd = socket(client_addr.sin_family, SOCK_DGRAM, 0);
        if (client_sockfd < 0)
        {
            print_to_both(p_toolLogPtr, "Error in socket(client)\n");
            RemoveCurrentSession();
            errval = SOCKET_CREATION_ERROR;
            return errval;
        }

        int flags = fcntl(client_sockfd, F_GETFL, 0);

        //  blocking socket
        int fcntErr = fcntl(client_sockfd, F_SETFL, flags & ~O_NONBLOCK);
        if (fcntErr < 0)
        {
            print_to_both(p_toolLogPtr, "Error failed to set blocking socket.\n");
            RemoveCurrentSession();
            errval = PARAM_ERROR;
            return errval;
        }

        const int on = 1;
        const int off = 0;

        setsockopt(client_sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));

        int bindErr = bind(client_sockfd, (const struct sockaddr*)&m_server_addr, sizeof(struct sockaddr_in));
        if (bindErr == LINUX_ERROR)
        {
            print_to_both(p_toolLogPtr, "Error bind(client)\n");
            RemoveCurrentSession();
            errval = SOCKET_BIND_ERROR;
            return errval;
        }

        while (connect(client_sockfd, (struct sockaddr*)&client_addr, sizeof(struct sockaddr_in)))
        {
            print_to_both(p_toolLogPtr, "Error connect(client\n");
            RemoveCurrentSession();
            errval = LINUX_ERROR;
            return errval;
        }
        m_socket = client_sockfd;
        /* Set new fd and set BIO to connected - Blocking? */
        BIO_set_fd(SSL_get_rbio(ssl), client_sockfd, BIO_NOCLOSE);
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);

        print_to_both(p_toolLogPtr, "Will be accepted handshake of DTLS connection\n");
        // make handshake
        bool fatalError = false;
        int ret;

        while (!fatalError && ((ret = SSL_accept(ssl)) != 1))
        {
            int error_recv = SSL_get_error(ssl, ret);
            switch (error_recv)
            {
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_WANT_WRITE:
                    continue;

                default:
                {
                    print_to_both(p_toolLogPtr, "SSL Accept failed. Code: %d\n", error_recv);
                    fatalError = true;
                    break;
                }
            }
        }
        if (fatalError)
        {
            close(client_sockfd);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;

            print_to_both(p_toolLogPtr, "SSL Accept failed\n");
            RemoveCurrentSession();
            errval = VALIDATION_ERROR;
            newSender = NULL;
        }
        else
        {
            print_to_both(p_toolLogPtr, "Negotiated Cipher Suite Used:%s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
            
            //AuditLogger->SetStatusSession(newSender, InsecureSession);
            m_currentSession->SetSSL(ssl, client_sockfd);
            newSender->SetSSL(ssl, client_sockfd);
            m_clients.push_back(newSender);
        }
    }
    
    
    // rm this else if code block once V1 / non-secure is no longer supported
    else if (m_version < MinimalSecureClientVersion)
    {
    
    	print_to_both(p_toolLogPtr, "Warning - UDP is using non-secure connection \n");
    	

    	if (newSender != NULL)
    	{
    		print_to_both(p_toolLogPtr, "UDP Client Address: %s \n", newSender->GetSessionInfoString());
    		
			m_clients.push_back(newSender);
			Settings::Instance()->SetLockedHipVersion(m_version);
			AuditLogger->SetStatusSession(newSender, InsecureSession);
    	}
    }
	return errval;
}
std::vector<int32_t> UdpProcessor::GetSockets()
{
    std::vector<int32_t> vec;
    for(std::vector<OneUdpProcessor*>::iterator it = m_clients.begin(); it!= m_clients.end(); ++it)
    {
        int32_t socket = (*it)->GetSocket();
        
    	dbgp_logdbg("GetSockets: %d \n", socket);
        if(socket != 0)
            vec.push_back(socket);
    }

	return vec;
}

void UdpProcessor::SetMainThread()
{
	m_is_main_thread = TRUE;
	m_mainsocket = m_socket; 
}
    
bool_t UdpProcessor::IsMainThread()
{
	return m_is_main_thread;
}
    
int32_t UdpProcessor::GetMainSocket()
{
	return m_mainsocket;
}
void UdpProcessor::RemoveCurrentSession()
{
    if (m_currentSession == NULL)
    {
        return;
    }
    SecurityConfigurationTable::Instance()->DeleteConnection(m_currentSession->GetSSL());
	m_connectionsManager->RemoveConnectionFromManager(m_currentSession);
    DeleteSession(m_currentSession);
    NetworkManager::Instance()->RemoveActiveConnection(m_port, UDP);
	m_currentSession = NULL;
}

void UdpProcessor::ProcessInvalidSession()
{
	return;
}

void UdpProcessor::DestroyProcessor()
{
    print_to_both(p_toolLogPtr, "Destroying UDP Processor \n");

	Stop();
	//Join(); commenting out Join as this is making the hipserver freeze when issueing command 539 because of DTLS/UDP threading changes.
}
    
uint32_t UdpProcessor::GetClientCount()
{
	return m_connectionsManager->GetCountClients(this);
}

void UdpProcessor::Start()
{
	HandlerMessages::Start();
}

bool_t UdpProcessor::IsRunning()
{
	dbgp_logdbg("UDP IsRunning(): %s \n", m_isRunning);
	return HandlerMessages::IsRunning();
}

errVal_t OneUdpProcessor::SendBinaryResponse(void* pData, int size)
{
    return VALIDATION_ERROR;
}

errVal_t OneUdpProcessor::SendResponse(hartip_msg_t* p_response)
{
	errVal_t errval = NO_ERROR;
	if (m_noResponse == TRUE)
	{
		dbgp_logdbg("Session init called \n");
		return errval;
	}

	const char* funcName = "OneUdpProcessor";
	sem_wait(&m_sem);
	do
	{
		if (p_response == NULL)
		{
			errval = POINTER_ERROR;
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
		rspBuff[idx] = m_version;

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
			memcpy_s(&rspBuff[HARTIP_HEADER_LEN], HARTIP_MAX_PYLD_LEN, 
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

		socklen_t socklen = sizeof(m_clientAddr);
		int sended;
		if (m_ssl != NULL)
        {
            bool need_io = true;
            while (need_io && ((sended = SSL_write(m_ssl, rspBuff, msgLen)) != msgLen))
            {
                // flag to exit SSL_write loop unless WANT_WRITE or WANT_READ
                need_io = false;
                int error_recv = SSL_get_error(m_ssl, sended);
                switch (error_recv)
                {
                    case SSL_ERROR_ZERO_RETURN:
                    case SSL_ERROR_SYSCALL:
                        errval = SOCKET_SENDTO_ERROR;
                        break;

                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_READ:
                        need_io = true;
                        break;
                        // otherwise fatal and break out
                    default:
                    {
                        errval = SOCKET_SENDTO_ERROR;
                        print_to_both(p_toolLogPtr, "System Error %d for SSL_write()\n", errno);
                        break;
                    }
                }
            }
        }
		else
        {
            sended = sendto(m_server_sockfd, rspBuff, msgLen, 0, (struct sockaddr *) &m_clientAddr, socklen);
        }

		if (sended== LINUX_ERROR)
		{
			AuditLogger->SetStatusSession(this, WritesOccured);
			errval = SOCKET_SENDTO_ERROR;
			print_to_both(p_toolLogPtr, "System Error %d for socket sendto()\n",
			errno);
			break;
		}
		AuditLogger->SetStatusSession(this, WritesOccured, FALSE);
		dbgp_logdbg("Msg sent from Server to Client\n");
		dbgp_logdbg("\n<<<<<<<<<<<<<<<<<<<<<<<\n\n");
	} while (FALSE);
	sem_post(&m_sem);
	return (errval);
}

OneUdpProcessor::~OneUdpProcessor()
{
    if(m_ssl != NULL)
    {

        int ret = 0;
        close(m_clientSocket);
        while ((ret = SSL_shutdown(m_ssl)) == 0);
        print_to_both(p_toolLogPtr, "SSL_shutdown_finish: %d\n", ret);
        SSL_free(m_ssl);

        m_ssl = NULL;
    }
}

uint16_t OneUdpProcessor::GetSessionNumber()
{
	return m_sessNum;
}

HARTIPConnection *OneUdpProcessor::GetSession()
{
	return this;
}

void OneUdpProcessor::SetNoResponse(const bool_t& noResponse)
{
	m_noResponse = noResponse;
}

void OneUdpProcessor::SetSSL(SSL* ssl, uint32_t socket)
{
    m_ssl = ssl;
    m_clientSocket = socket;
}

SSL* OneUdpProcessor::GetSSL()
{
    return m_ssl;
}

int32_t OneUdpProcessor::GetSocket()
{
    return m_clientSocket;
}
errVal_t OneUdpProcessor::ReadSocket(uint8_t *p_buffer, ssize_t *p_size)
{
    errVal_t errval = NO_ERROR;
    sockaddr_in_t socketAddr;
	socklen_t socklen = sizeof(socketAddr);
	memset_s(&socketAddr, socklen, 0);
	sem_wait(&m_sem);

	if (m_ssl != NULL)
    {
        int hasP = SSL_has_pending(m_ssl);
        int p = SSL_pending(m_ssl);
        if(p) 
        {
            errval=LINUX_ERROR;
            *p_size = 0;
            return errval;
        }
        while ( (*p_size = SSL_read(m_ssl, p_buffer, HARTIP_MAX_PYLD_LEN)) < 0)
        {
            int error_recv = SSL_get_error(m_ssl, *p_size);
            switch (error_recv)
            {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                {
                    int hasP = SSL_has_pending(m_ssl);
                    int p = SSL_pending(m_ssl);
                    continue;
                }

                default:
                {
                    fprintf(stderr, "ERROR: failed to read\n");
                    errval = SOCKET_RECVFROM_ERROR; // is there a better error here?
                    break;
                }
            }
            if (errval != NO_ERROR)
            {
                // exit while loop
                break;
            }
        } // SSL_read

        printf("SSL_read from by udp(%d)", *p_size);
    }
	else
    {
        *p_size = recvfrom(m_server_sockfd, p_buffer,HARTIP_MAX_PYLD_LEN, 0, (struct sockaddr *) &socketAddr, &socklen);

#ifndef HTS   // # CR 1717 VG
        printf("recv from by oneudpprocie(%d)", *p_size);
#endif
    }

	if (*p_size == LINUX_ERROR)
	{
		errval = SOCKET_RECVFROM_ERROR;
		print_to_both(p_toolLogPtr,"System Error %d for socket recvfrom()\n", errno);
	}
	sem_post(&m_sem);

	return errval;
}

int OneUdpProcessor::GetSlotNumber()
{
	return SecurityConfigurationTable::Instance()->GetSlotNumber(GetSSL());
}

bool_t OneUdpProcessor::IsReadOnly()
{
    return SecurityConfigurationTable::Instance()->IsConnectionReadOnly(GetSSL());
}

SSL_CTX* UdpProcessor::m_ctx = NULL;
extern uint8_t clientEncryptionType;
extern unsigned int psk_out_of_bound_serv_cb(SSL *ssl, const char *id, unsigned char *psk, unsigned int max_psk_len);
extern int srp_server_param_cb(SSL *s, int *ad, void *arg);
extern int verify_callback(int ok, X509_STORE_CTX *ctx);
int verify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len);
int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len);

void UdpProcessor::Init()
{
    m_ctx = SSL_CTX_new(DTLS_server_method());

    // Limit min supported protocol ver (per HART-IP Spec. 10.2.1)
    int ret = SSL_CTX_set_min_proto_version(m_ctx, DTLS1_2_VERSION);
    if (ret != 1)
    {
        print_to_both(p_toolLogPtr, "Set min proto version DTSL1_2_VERSION failed.\n");
    }
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_OFF);
	
    if(SSL_CTX_set_cipher_list(m_ctx, CIPHER_SUITES) != 1)
	{
		dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
	}
	
	SSL_CTX_set_psk_server_callback(m_ctx, psk_out_of_bound_serv_cb);
	
	SSL_CTX_set_srp_username_callback(m_ctx, srp_server_param_cb);
	
    SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_cookie_generate_cb(m_ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(m_ctx, verify_cookie);
}

// literally the same as Init()
void UdpProcessor::InitThreadedObject()
{
m_ctx = SSL_CTX_new(DTLS_server_method());

    // Limit min supported protocol ver (per HART-IP Spec. 10.2.1)
    int ret = SSL_CTX_set_min_proto_version(m_ctx, DTLS1_2_VERSION);
    if (ret != 1)
    {
        print_to_both(p_toolLogPtr, "Set min proto version DTSL1_2_VERSION failed.\n");
    }
    SSL_CTX_set_session_cache_mode(m_ctx, SSL_SESS_CACHE_OFF);
	
    if(SSL_CTX_set_cipher_list(m_ctx, CIPHER_SUITES) != 1)
	{
		dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
	}
	
	SSL_CTX_set_psk_server_callback(m_ctx, psk_out_of_bound_serv_cb);
	
	SSL_CTX_set_srp_username_callback(m_ctx, srp_server_param_cb);
	
    SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_cookie_generate_cb(m_ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(m_ctx, verify_cookie);
}

void UdpProcessor::Cleanup()
{
    SSL_CTX_free(m_ctx);
}

void UdpProcessor::CreateUdpServerSocket(int32_t serverSocket, sockaddr_in_t *serverAddress)
{
	m_isRunning = TRUE;
	m_socket = serverSocket;
	memcpy_s(&m_server_addr, sizeof(m_server_addr), serverAddress, sizeof(sockaddr_in_t));
}

unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;

int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    unsigned char *buffer;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    unsigned int resultlength;
    struct sockaddr_in server_addr;

    int retVal = 1;

    /* Initialize a random secret */
    if (!cookie_initialized)
    {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
        {
            print_to_both(p_toolLogPtr, "Random secret creation failed.\n");
            retVal = 0;
        }
        else
        {
            cookie_initialized = 1;
            retVal = 1;
        }
    }

    if (retVal == 1)
    {
        /* Read peer information */
        (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &server_addr);

        /* Create buffer with peer's address and port */
        length = 0;
        length += sizeof(struct in_addr);
        length += sizeof(in_port_t);
        buffer = (unsigned char*)OPENSSL_malloc(length);

        if (buffer == NULL)
        {
            print_to_both(p_toolLogPtr, "random buffer creation failed. OPENSSL allocation error\n");
            retVal = 0;
        }
        else
        {
            memcpy_s(buffer, length, &server_addr.sin_port, sizeof(in_port_t));
            memcpy_s(buffer + sizeof(server_addr.sin_port), length, &server_addr.sin_addr, sizeof(struct in_addr));

            /* Calculate HMAC of buffer using the secret */
            HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
                 (const unsigned char*)buffer, length, result, &resultlength);
            OPENSSL_free(buffer);

            memcpy_s(cookie, *cookie_len, result, resultlength);
            *cookie_len = resultlength;
            retVal = 1;
        }
    }

    return (retVal);
}

/**
 * verify_cookie()
 */
int verify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    unsigned char* buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    struct sockaddr_in server_addr;
    int retVal = 0;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
    {
        print_to_both(p_toolLogPtr, "Cookie not initialized.\n");
        retVal = 0;
    }
    else
    {
        retVal = 1;
        /* Read peer information */
        (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &server_addr);

        /* Create buffer with peer's address and port */
        length = 0;
        length += sizeof(struct in_addr);
        length += sizeof(in_port_t);
        buffer = (unsigned char*)OPENSSL_malloc(length);

        if (buffer == NULL)
        {
            print_to_both(p_toolLogPtr, "random buffer creation failed. OPENSSL allocation error\n");
            retVal = 0;
        }
        else
        {
            retVal = 1;
            memcpy_s(buffer, length, &server_addr.sin_port, sizeof(in_port_t));
            memcpy_s(buffer + sizeof(in_port_t),length, &server_addr.sin_addr, sizeof(struct in_addr));

            /* Calculate HMAC of buffer using the secret */
            HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
                 (const unsigned char*)buffer, length, result, &resultlength);
            OPENSSL_free(buffer);
            
            int diff;
            memcmp_s(result, EVP_MAX_MD_SIZE, cookie, resultlength, &diff);
            int cookieCheck = (cookie_len == resultlength) && diff != 0;
            if (!cookieCheck)
            {
                retVal = 1;
                print_to_both(p_toolLogPtr, "Cookie check OK.\n");
            }
            else
            {
                retVal = 0;
                print_to_both(p_toolLogPtr, "Cookie check fail.\n");
            }
        }
    }

    return retVal;
}
