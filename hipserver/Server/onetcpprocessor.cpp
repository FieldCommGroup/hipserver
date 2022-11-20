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

#include "onetcpprocessor.h"
#include "memory.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "debug.h"
#include "hsudp.h"
#include "hscommands.h"
#include "hsmessage.h"
#include "hssems.h"
#include "hssettings.h"
#include "hssubscribe.h"
#include "hsauditlog.h"
#include "hssecurityconfiguration.h"
#include "hsnetworkmanager.h"

int srp_server_param_cb(SSL *s, int *ad, void *arg);
unsigned int psk_out_of_bound_serv_cb(SSL *ssl, const char *id, unsigned char *psk, unsigned int max_psk_len);

OneTcpProcessor::OneTcpProcessor(uint32_t clientFd, sockaddr_in_t address, IOwnerSession* remover, uint16_t portNumber)
 : HandlerMessages(), m_remover(remover), IResponseSender(), HARTIPConnection(), m_needRemove(FALSE), m_ssl(NULL)
{
	SetAddress(address);
	SetSocket(clientFd);
	m_portNumber = portNumber;
	int buffsize = HARTIP_MAX_MSG_LEN;
}

std::string utf8_to_latin1(const std::string& in)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i)
    {
    	unsigned int shiftUtf8Value = 0xc2;
    	unsigned int byteValueCurrentIndex = static_cast<unsigned int>(static_cast<unsigned char>(in[i]));

    	if (shiftUtf8Value == byteValueCurrentIndex || (shiftUtf8Value + 0x01) == byteValueCurrentIndex)
    	{
    		unsigned int incrementValue = 0x00;
    		if ((shiftUtf8Value + 0x01) == byteValueCurrentIndex)
    		{
    			incrementValue = 0x40;
    		}
    		i++;
    		byteValueCurrentIndex = static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    		byteValueCurrentIndex += incrementValue;
    	}
        ss << static_cast<unsigned char>(byteValueCurrentIndex);
    }
    return ss.str();
}

std::string latin1_to_utf8(const std::string& in)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i)
    {
    	unsigned int shiftUtf8Value = 0xc2;
    	unsigned int utfLatinDiffPoint = 0x7f;
    	unsigned int firstShiftPoint = 0xC0;
    	unsigned int byteValueCurrentIndex = static_cast<unsigned int>(static_cast<unsigned char>(in[i]));

    	if (byteValueCurrentIndex > utfLatinDiffPoint)
    	{
    		if (byteValueCurrentIndex >= firstShiftPoint)
    		{
    			shiftUtf8Value++;
    			byteValueCurrentIndex -= 0x40;
    		}
    		ss << static_cast<unsigned char>(shiftUtf8Value);
    	}
        ss << static_cast<unsigned char>(byteValueCurrentIndex);
    }
    return ss.str();
}

void OneTcpProcessor::Run()
{
	HandlerMessages::Run();

    if (m_ssl)
    {
		SecurityConfigurationTable::Instance()->DeleteConnection(m_ssl);
        SSL_set_shutdown(m_ssl, SSL_SENT_SHUTDOWN);
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = NULL;
		close(m_server_sockfd);
    }

	DeleteTimer();

	if(m_id != HARTIP_SESSION_ID_INVALID)
	{
	 m_connectionsManager->RemoveConnectionFromManager(this);
	 SubscribesTable::Instance()->RemoveSubscriber(this);
	}
	printf("session closed with %s", inet_ntoa(m_clientAddr.sin_addr));
	if(m_needRemove)
    	m_remover->DeleteSession(this);

}

errVal_t OneTcpProcessor::SendBinaryResponse(void* pData, int size)
{
    ssize_t sended = send(m_server_sockfd, pData, size, 0);
    printf("\nSend binary response by tcp(%d:%d)\n", size, sended);
    dbgp_logdbg("Msg sent from Server to Client\n");
	return sended == size? NO_ERROR : LINUX_ERROR;
}

errVal_t OneTcpProcessor::SendResponse(hartip_msg_t *p_response)
{
	errVal_t errval = NO_ERROR;
	if (m_noResponse == TRUE)
	{
		return errval;
	}

    const char *funcName = "OneTcpProcessor::SendResponse";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);
	sem_wait(&m_sem);

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
		rspBuff[idx] = ConnectionsManager::Instance()->GetClientsVersion();

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
		int sended = 0;
		if (m_ssl == NULL)
        {
            sended = send(m_server_sockfd, rspBuff, msgLen, 0);
        }
		else
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
		if (sended == LINUX_ERROR)
		{
			AuditLogger->SetStatusSession(this, WritesOccured);
			errval = SOCKET_SENDTO_ERROR;
			print_to_both(p_toolLogPtr, "System Error %d for socket sendto()\n",
			errno);
			break;
		}
		AuditLogger->SetStatusSession(this, WritesOccured, FALSE);
		printf("\nSend msgId=%d to '%s' by tcp(%d:%d)\n", p_rspHdr->msgID, GetSessionInfoString(), msgLen, sended);
		dbgp_logdbg("Msg sent from Server to Client\n");
		dbgp_logdbg("\n<<<<<<<<<<<<<<<<<<<<<<<\n\n");
	} while (FALSE);
	sem_post(&m_sem);
	return (errval);
}

uint16_t OneTcpProcessor::GetSessionNumber()
{
    return m_sessionNumber;
}

void OneTcpProcessor::SetTimerTime(uint32_t time)
{
	if(time == 0)
	{
		int flag = 1;
		setsockopt(m_server_sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
	}
	else
	{
		HARTIPConnection::SetTimerTime(time);
	}
}

IResponseSender* OneTcpProcessor::GetCurrentResponse()
{
	return this;
}

HARTIPConnection* OneTcpProcessor::GetCurrentSession()
{
	return this;
}

errVal_t OneTcpProcessor::RestartTimerCurrentSession()
{
	if(m_id != HARTIP_SESSION_ID_INVALID)
	{
		StartTimer();
	}
}
bool_t OneTcpProcessor::GetCurrentSession(sockaddr_in_t& address)
{
	HARTIPConnection* connection;
	bool_t isValidSess = m_connectionsManager->IsSessionExisting(address, &connection);

	if(!isValidSess)
	{
		Stop();
	}

	return isValidSess;

}
errVal_t OneTcpProcessor::InitSession(hartip_msg_t *p_req, hartip_msg_t* p_res, sockaddr_in_t& address)
{
	time_t timeCreate;
	time(&timeCreate);
	errVal_t errval = m_connectionsManager->InitSession(p_req, p_res,
					address, GetCurrentSession(), m_remover, TCP, m_noResponse, m_portNumber);

	if (errval == NO_ERROR)
	{
        hartip_hdr_t* p_reqHdr = &p_req->hipHdr;
        m_version = p_reqHdr->version;

        if (m_version > MinimalSecureClientVersion)
        {
            p_res->hipHdr.version = HARTIP_PROTOCOL_VERSION;
            p_res->hipHdr.status = HARTIP_SESS_ERR_VERSION_NOT_SUPPORTED;
        }

		//dbgp_logdbg("\nHART-IP Initiate Session...  Session %d is created.\n", pCurrentSession->sessNum);
	    if (p_req->hipHdr.msgType == HARTIP_MSG_TYPE_REQUEST)
	    {
			errval = SendResponse(p_res);
		}

		// According: Table 22. Client/Server Compatible Operating Mode Summary
		// FieldComm Group Document Number: HCF_SPEC-085, FCG TS20085
		if (m_version >= MinimalSecureClientVersion)
        {
		    // must create TLS Connection
		    m_ssl = SSL_new(m_ctx);
            // Attach SSL to the socket for client
            int ret = SSL_set_fd(m_ssl, m_server_sockfd);
            if (ret == 0)
            {
                print_to_both(p_toolLogPtr, "FATAL: Attaching SSL to socket failed.\n");
                RemoveCurrentSession();
                errval = VALIDATION_ERROR;
            }
            else
            {
                // make handshake
                bool fatalError = false;
                while (!fatalError && ((ret = SSL_accept(m_ssl)) != 1))
                {
                    int error_recv = SSL_get_error(m_ssl, ret);
                    switch (error_recv)
                    {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                            continue;
                        default:
                        {
                            fprintf(stderr, "ERROR: failed to ssl_accept()\n");
                            fatalError = true;
                            break;
                        }
                    }
                }

                if (fatalError)
                {
                    print_to_both(p_toolLogPtr, "SSL Accept failed\n");
                    RemoveCurrentSession();
                    errval = VALIDATION_ERROR;
                }
                else
                {
                    print_to_both(p_toolLogPtr, "Negotiated Cipher Suite Used:%s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(m_ssl)));
                }
            }
        }

        else
        {
			Settings::Instance()->SetLockedHipVersion(m_version);
			AuditLogger->SetStatusSession(this, InsecureSession);
        }
	}
	else
	{
		if (p_req->hipHdr.msgType == HARTIP_MSG_TYPE_REQUEST)
	    {
			errval = SendResponse(p_res);
		}
		if(p_res->hipHdr.status != HARTIP_SESS_ERR_SESSION_EXISTS)
		{
			RemoveCurrentSession();
		}
	}
	return errval;
}
std::vector<int32_t> OneTcpProcessor::GetSockets()
{
	std::vector<int32_t> vec;
	vec.push_back(m_server_sockfd);
	return vec;
	
}
void OneTcpProcessor::RemoveCurrentSession()
{
	m_needRemove = TRUE;
	SecurityConfigurationTable::Instance()->DeleteConnection(m_ssl);
	NetworkManager::Instance()->RemoveActiveConnection(m_portNumber, TCP);
	Stop();
}


errVal_t OneTcpProcessor::ReadSocket(int32_t socket, uint8_t *p_reqBuff, ssize_t *p_lenPdu,
	sockaddr_in_t *p_client_sockaddr)
{
	errVal_t errval = NO_ERROR;
	if (m_ssl == NULL)
    {
        *p_lenPdu = recv(m_server_sockfd, p_reqBuff, HARTIP_MAX_PYLD_LEN, 0);
        printf("recv from '%s' by tcp(%d)", GetSessionInfoString(), *p_lenPdu);
    }
	else
    {
		while ((*p_lenPdu = SSL_read(m_ssl, p_reqBuff, HARTIP_MAX_PYLD_LEN)) < 0)
		{
			int error_recv = SSL_get_error(m_ssl, *p_lenPdu);
			switch (error_recv)
			{
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					continue;

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


		printf("SSL_read from '%s' by tcp(%d)", GetSessionInfoString(), *p_lenPdu);
    }


	if (*p_lenPdu == LINUX_ERROR)
	{
		errval = SOCKET_RECVFROM_ERROR;
		print_to_both(p_toolLogPtr,
				"System Error %d for socket recvfrom()\n",
				errno);
	}
	else if(*p_lenPdu == 0)
	{
		AuditLogger->SetStatusSession(this, AbortedSession);
		errval = NWK_ERROR;
		printf("\n%s disconnected ouside\n", GetSessionInfoString());
	}
	*p_client_sockaddr = m_clientAddr;
	
	return errval;
}

void OneTcpProcessor::ProcessInvalidSession()
{
	m_needRemove = TRUE;
	Stop();
}

HARTIPConnection *OneTcpProcessor::GetSession()
{
	return this;
}

unsigned int psk_out_of_bound_serv_cb(SSL *ssl, const char *id, unsigned char *psk, unsigned int max_psk_len)
{
    unsigned int retVal = 0;
	
    SlotMap& slots = SecurityConfigurationTable::Instance()->Slots();
    SlotMap::iterator itr;

    const ClientCommunication* pSlot = NULL;
    for (itr = slots.begin(); itr != slots.end(); ++itr)
    {
    	if (itr->second.m_clientIdentifier == "")
    	{
    		continue;
    	}
    	print_to_both(p_toolLogPtr, "Server PSK ID: %s || %s\n", itr->second.m_clientIdentifier.c_str(), psk);
    	print_to_both(p_toolLogPtr, "Server Client ID Hex Value: %s\n", utf8_to_latin1(id).c_str());
        if (utf8_to_latin1(id) == itr->second.m_clientIdentifier)
        {
            pSlot = &itr->second;
            print_to_both(p_toolLogPtr, "Now has been accepted SSL`s id : %s\n", id);
            break;
        }
    }
    if (pSlot == NULL)
    {
        print_to_both(p_toolLogPtr, "Unknown Client's ID = %0x\n", id);
        print_to_both(p_toolLogPtr, "SSL CTX PSK Identity Hint: %s \n", SSL_get_psk_identity_hint(ssl));
    }
    else if (pSlot->m_keyVal.size() > max_psk_len)
    {
        printf("Insufficient buffer size to copy PSK_KEY\n");
    }
    else
    {
        memcpy_s(psk, max_psk_len, (unsigned char*)pSlot->m_keyVal.data(), pSlot->m_keyVal.size());
  print_to_both(p_toolLogPtr, "SSL CTX PSK Identity Hint: %s \n", SSL_get_psk_identity_hint(ssl));
        retVal = pSlot->m_keyVal.size();
		SecurityConfigurationTable::Instance()->AddConnection(ssl, itr->first);
    }
    return retVal;
}

int srp_server_param_cb(SSL *s, int *ad, void *arg)
{
    SlotMap& slots = SecurityConfigurationTable::Instance()->Slots();
    SlotMap::iterator itr;
    std::string latinIdentifier = utf8_to_latin1(SSL_get_srp_username(s));

    const ClientCommunication* pSlot = NULL;
    for (itr = slots.begin(); itr != slots.end(); ++itr)
    {
    	    print_to_both(p_toolLogPtr, "Incoming SRP SSL`s id : %s \n", itr->second.m_clientIdentifier.c_str());
        if (itr->second.m_clientIdentifier == latinIdentifier)
        {
            pSlot = &itr->second;
            print_to_both(p_toolLogPtr, "Now has been accepted SSL`s id : %s\n", itr->second.m_clientIdentifier.c_str());
            break;
        }
    }
    if (pSlot == NULL)
    {
        print_to_both(p_toolLogPtr, "Unknown Client's ID = %s\n", latinIdentifier.c_str());
        return SSL3_AL_FATAL;
    }
    
    std::string utf8Password = latin1_to_utf8(pSlot->m_password);
    if (SSL_set_srp_server_param_pw(s, SSL_get_srp_username(s), utf8Password.c_str(), "2048") < 0)
    {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL3_AL_FATAL;
    }
	SecurityConfigurationTable::Instance()->AddConnection(s, itr->first);

    return SSL_ERROR_NONE;
}

int verify_callback(int ok, X509_STORE_CTX* ctx)
{
    return ok;
}

SSL_CTX* OneTcpProcessor::m_ctx = NULL;
extern uint8_t clientEncryptionType;

void OneTcpProcessor::Init()
{
    m_ctx = SSL_CTX_new(TLS_server_method());
    // Limit min supported protocol ver (per HART-IP Spec. 10.2.1)
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

	if (SSL_CTX_set_cipher_list(m_ctx, CIPHER_SUITES) != 1)
	{
		dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
	}
	SSL_CTX_set_psk_server_callback(m_ctx, psk_out_of_bound_serv_cb);

	SSL_CTX_set_srp_username_callback(m_ctx, srp_server_param_cb);
}

void OneTcpProcessor::Cleanup()
{
    SSL_CTX_free(m_ctx);
}

bool_t OneTcpProcessor::IsReadOnly()
{
	return SecurityConfigurationTable::Instance()->IsConnectionReadOnly(m_ssl);
}

int OneTcpProcessor::GetSlotNumber()
{
	return SecurityConfigurationTable::Instance()->GetSlotNumber(m_ssl);
}
