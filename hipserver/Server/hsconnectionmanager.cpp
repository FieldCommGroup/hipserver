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

#include "hsconnectionmanager.h"
#include "fcntl.h"
#include "toolsems.h"
#include "debug.h"
#include <signal.h>
#include "time.h"
#include <arpa/inet.h>
#include "hssyslogger.h"
#include "hsauditlog.h"
#include "hssecurityconfiguration.h"
#include "hssettings.h"
#include "hsnetworkmanager.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define SIG_INACTIVITY_TIMER(n)      (SIGRTMIN + (n))
#define DEFAULT_KEEPALIVE_TIME 90000
#define MIN_KEEPALIVE_TIME 1000


void HARTIPConnection::SetId(uint8_t id)
{
    m_id = id;
}

void HARTIPConnection::SetSessionNumber(uint16_t number)
{
    m_sessNum = number;
}
void HARTIPConnection::SetSocket(uint32_t socket_fd)
{
    m_server_sockfd = socket_fd;
}
void HARTIPConnection::SetAddress(const sockaddr_in_t& address)
{
    memcpy_s(&m_clientAddr, sizeof(m_clientAddr), &address, sizeof(m_clientAddr));
}
void HARTIPConnection::SetAddress6(const sockaddr_in6_t& address)
{
    memcpy_s(&m_clientAddr, sizeof(m_clientAddr6), &address, sizeof(m_clientAddr6));
}

void HARTIPConnection::SetTimerTime(uint32_t time)
{
    m_msInactTimer = time;
}
uint16_t HARTIPConnection::NextSequnce()
{
    return ++m_seqNumber;
}

char* HARTIPConnection::GetSessionInfoString()
{
    static char returnval[32];
    // vulnerability check by inspection is OK:  this method is not accessible by the client  --  tjohnston 11/09/2021
    sprintf(returnval, "%s:%d", inet_ntoa(m_clientAddr.sin_addr), ntohs(m_clientAddr.sin_port));
    return returnval;
}

char* HARTIPConnection::GetSessionIPv4()
{
    static char returnval[24];
    // vulnerability check by inspection is OK:  this method is not accessible by the client  --  tjohnston 11/09/2021
    sprintf(returnval, "%s", inet_ntoa(m_clientAddr.sin_addr));
    return returnval;
}


HARTIPConnection::HARTIPConnection() : m_id(HARTIP_SESSION_ID_INVALID), m_idInactTimer(NULL), m_isInitiatedSession(FALSE)
{
    memset_s(&m_clientAddr, sizeof(m_clientAddr), 0);
    memset_s(&m_clientAddr6, sizeof(m_clientAddr6), 0);
}

bool_t HARTIPConnection::IsSameAddress(sockaddr_in_t& address)
{
    return m_clientAddr.sin_addr.s_addr == address.sin_addr.s_addr ? TRUE : FALSE;
}

void HARTIPConnection::GetAddress(sockaddr_in_t *address)
{
    memcpy_s(address, sizeof(sockaddr_in_t), &m_clientAddr, sizeof(m_clientAddr));
}

void HARTIPConnection::GetAddress6(sockaddr_in6_t *address)
{
    memcpy_s(address, sizeof(sockaddr_in6_t), &m_clientAddr6, sizeof(m_clientAddr6));
}

bool_t HARTIPConnection::IsInitiatedSession()
{
    return m_isInitiatedSession;
}
void HARTIPConnection::SetInitiatedSession()
{
    if (Settings::Instance()->GetLockedHipVersion() == 0)
    {
        print_to_both(p_toolLogPtr, "Setting initiated session to true\n");

        m_isInitiatedSession = TRUE;
        ConnectionsManager::Instance()->InitiatedSessionState(TRUE);
    }
}

void HARTIPConnection::StartTimer()
{
    if(m_msInactTimer == 0)
    {
        return;
    }
    if(m_idInactTimer == NULL)
    {
        m_idInactTimer = new timer_t;
        int32_t sessSig = SIG_INACTIVITY_TIMER(m_sessNum);
        struct sigevent se;
        se.sigev_notify = SIGEV_SIGNAL;
        se.sigev_signo = sessSig;
        se.sigev_value.sival_ptr = m_idInactTimer;
        timer_create(CLOCK_REALTIME, &se,
                            m_idInactTimer);
    }

    struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_nsec = 0;

	if (m_id == HARTIP_SESSION_ID_OK)
	{
		// start timer
		its.it_value.tv_sec = (m_msInactTimer) / 1000;
        its.it_value.tv_nsec = (m_msInactTimer - its.it_value.tv_sec * 1000) * 1000 * 1000;
	}
	else
	{
		// disarm this timer
		its.it_value.tv_sec = 0;
	}

	timer_settime(*m_idInactTimer, 0, &its, NULL);
	dbgp_noop("Server Inactivity Timer Set\n");
}

bool_t HARTIPConnection::IsSession(sockaddr_in_t& addres)
{   
    int diff;
    memcmp_s(&m_clientAddr, sizeof(m_clientAddr), &addres, sizeof(m_clientAddr), &diff);
    return diff == 0 ? TRUE : FALSE;
}

void HARTIPConnection::DeleteTimer()
{
    if(m_idInactTimer == NULL)
        return;
    timer_delete(*m_idInactTimer);
    
    delete m_idInactTimer;
    m_idInactTimer = NULL;
}
void HARTIPConnection::SetSequnce(uint16_t number)
{
    m_seqNumber = number;
}

bool_t HARTIPConnection::IsReadOnly()
{
    return FALSE;
}

int HARTIPConnection::GetSlotNumber()
{
    0;
}

ConnectionsManager* ConnectionsManager::g_manager = NULL;

ConnectionsManager* ConnectionsManager::Instance()
{
    return g_manager;
}

errVal_t ConnectionsManager::CreateManager(int maxCount /* = 5 */)
{
    if(g_manager != NULL)
        return VALIDATION_ERROR;
    g_manager = new ConnectionsManager(maxCount);
    if(g_manager == NULL)
        return LINUX_ERROR;
    errVal_t result = g_manager->CreateSemaphor();
    if(result != NO_ERROR)
    {
        delete g_manager;
    }
    
    return result;
}

void ConnectionsManager::DeleteManager()
{
    if(g_manager != NULL)
    {
        delete g_manager;
    }
}

ConnectionsManager::ConnectionsManager(int maxCount): m_MaxCountClient(maxCount), m_semName("semConnectionsManager"),
    m_countSession(0), m_initSessionRunning(FALSE)
{
	for(int i = 0 ; i < m_MaxCountClient; ++i)
		m_connections.push_back(NULL);
}

void ConnectionsManager::RemoveConnectionFromManager(HARTIPConnection *pConnection)
{
    printf("~~~~~~ %s ~~~~~~\n", __func__);
	dbgp_logdbg("~~~~~~ %s ~~~~~~\n", __func__);
    sem_wait(&m_semaphor);
    {
        for(int i = 0 ; i < m_connections.size(); ++i)
        {
            if(pConnection == m_connections[i] && pConnection != NULL)
            {
                m_countSession = m_countSession == 0 ? m_countSession : --m_countSession;
                dbgp_log("\nClient '%s' disconected\nClient count: %d\n", pConnection->GetSessionInfoString(), m_countSession);
                log2HipSyslogger(118, 1001, 1, pConnection, "Client '%s' disconected", pConnection->GetSessionInfoString());
                AuditLogger->SessionDisconnected(pConnection);
                m_connections[i] = NULL;
                
                m_mapSessionOwner.erase(i);
                break;
            }
        }
    }
    sem_post(&m_semaphor);
}

void ConnectionsManager::RemoveInactivitySession(int sessNumber)
{
    printf("\n~~~~~~ %s ~~~~~~\n", __func__);
    sem_wait(&m_semaphor);
    {
        if (sessNumber >= m_connections.size())
        {
            return;
        }

        if(m_mapSessionOwner[sessNumber] != NULL)
        {
            m_countSession = m_countSession == 0 ? m_countSession : --m_countSession;
            dbgp_log("\nClient '%s' disconected\nClient count: %d\n", m_connections[sessNumber]->GetSessionInfoString(), m_countSession);
            log2HipSyslogger(118, 1003, 1, m_connections[sessNumber], "Session %s inactivity timeout", m_connections[sessNumber]->GetSessionInfoString());
            m_mapSessionOwner[sessNumber]->DeleteSession(m_connections[sessNumber]);
            AuditLogger->SetStatusSession(m_connections[sessNumber], SessionTimeout);
            AuditLogger->SessionDisconnected(m_connections[sessNumber]);
            m_mapSessionOwner.erase(sessNumber);

            if (sessNumber < m_connections.size())
            {
                m_connections[sessNumber] = NULL;
            }
        }
    }
    sem_post(&m_semaphor);
}

errVal_t ConnectionsManager::CreateSemaphor()
{
    dbgp_logdbg("~~~~~~ %s ~~~~~~\n", __func__);
    return (errVal_t)sem_init(&m_semaphor, 0, 1);
}

ConnectionsManager::~ConnectionsManager()
{
    dbgp_logdbg("~~~~~~ %s ~~~~~~\n", __func__);
    sem_destroy(&m_semaphor);
}

bool_t ConnectionsManager::IsAvailableSession(int& session)
{
    printf("\n~~~~~~ %s ~~~~~~\n", __func__);
    bool_t result = FALSE;
    for(int i = 0; i < m_connections.size(); ++i)
    {
        if(m_connections[i] == NULL)
        {
            result = TRUE;
            session = i;
            break;
        }
    }

    if(m_MaxCountClient == 0)
    {
        return FALSE;

        // if max client count is 0 then this should always fail
        m_connections.push_back(NULL);
        session = m_connections.size() - 1;
    }

    return result;
}

errVal_t ConnectionsManager::InitSession(hartip_msg_t *p_request,
		hartip_msg_t *p_response, sockaddr_in_t client_addr, HARTIPConnection* connection, IOwnerSession* owner, TypeConnection type, bool_t& noResponse, uint16_t serverPortNumber)
{
    printf("\n~~~~~~ %s ~~~~~~\n", __func__);


    errVal_t errval = NO_ERROR;
	sem_wait(&m_semaphor);	// lock server tables when available
	{
		do
		{
			connection->SetAddress(client_addr);


			if (p_request == NULL)
			{
				errval = POINTER_ERROR;
				print_to_both(p_toolLogPtr, "NULL pointer (req) passed to %s\n",
						__func__);
				break;
			}
            // Message header and payload should not be more then 5 bytes 
			if (p_request->hipHdr.byteCount - HARTIP_HEADER_LEN > HARTIP_SESS_INIT_PYLD_LEN)
			{
                errval = TOO_LONG_PAYLOAD_ERROR;
                noResponse = TRUE;
				print_to_both(p_toolLogPtr, "Payload too long (req) passed to %s\n",
						__func__);                
                break;
            }           

			if (p_response == NULL)
			{
				errval = POINTER_ERROR;
				print_to_both(p_toolLogPtr, "NULL pointer (rsp) passed to %s\n",
						__func__);
				break;
			}

			/* Start with a clean slate */
			memset_s(p_response, sizeof(*p_response), 0);

			hartip_hdr_t *p_reqHdr = &p_request->hipHdr;
			hartip_hdr_t *p_rspHdr = &p_response->hipHdr;

			/* Build header of response */
			p_rspHdr->msgType = HARTIP_MSG_TYPE_RESPONSE;
			p_rspHdr->msgID = p_reqHdr->msgID;
			p_rspHdr->status = NO_ERROR;
			p_rspHdr->seqNum = p_reqHdr->seqNum;
            p_rspHdr->version = p_reqHdr->version;
			p_rspHdr->byteCount = HARTIP_HEADER_LEN;

			/* Build payload of response */
			uint16_t byteCount = p_reqHdr->byteCount;
			uint16_t payloadLen = byteCount - HARTIP_HEADER_LEN;
			AuditLogger->CreateNewRecordAuditLog(connection, serverPortNumber);
            bool_t isReqErr = FALSE;

            /* Fill in the payload, if long enough */
			if (payloadLen >= HARTIP_SESS_INIT_PYLD_LEN)
			{
				memcpy_s(p_response->hipTPPDU, HARTIP_MAX_PYLD_LEN, 
					p_request->hipTPPDU, HARTIP_SESS_INIT_PYLD_LEN);
				p_rspHdr->byteCount += HARTIP_SESS_INIT_PYLD_LEN;

				/* First byte of payload should be set to Primary Master */
				p_response->hipTPPDU[0] = HARTIP_PRIM_MASTER_TYPE;
			}

			int thisSess = 0;
			
            uint32_t msTimer = (p_request->hipTPPDU[1] << 24)
						| (p_request->hipTPPDU[2] << 16)
						| (p_request->hipTPPDU[3] << 8)
						| (p_request->hipTPPDU[4]);
            
            print_to_both(p_toolLogPtr, "\n Client version: %d \n", p_reqHdr->version);
            print_to_both(p_toolLogPtr, "\n Server version: %d \n", Settings::Instance()->GetLockedHipVersion());
            print_to_both(p_toolLogPtr, "\n Configuration Status: %d \n", SecurityConfigurationTable::Instance()->IsConfigured());
            print_to_both(p_toolLogPtr, "\n Session Count: %d \n", m_countSession);
            print_to_both(p_toolLogPtr, "\n Keep Alive Timer: %d \n", msTimer);

            /* Check that first session is secure session and configuration is finished.*/
            // if initial session was via v2 client but credentials NOT written. then all subsequent v2 session-initiate responses answered with "Security not initialized. Factory reset required". session not opened. v1 session initiates are ignored.
            if (m_initSessionRunning)
            {
                isReqErr = TRUE;
                noResponse = TRUE;
                print_to_both(p_toolLogPtr,
                        "\n Initial Session ongoing. Connection will be refused. Please retry once device has been provisioned. \n");

                log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Initial session ongoing.");
            }
            else if(Settings::Instance()->GetLockedHipVersion() == -255)
            {
                //this means device is bricked so don't respond
                isReqErr = TRUE;
                noResponse = TRUE;
                print_to_both(p_toolLogPtr,
                        "\n Device is in bricked state, run factory reset again. \n");
                log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Device bricked.");
            }
            else
            {
                if(serverPortNumber != portNum)
                {
                    if (type == UDP && serverPortNumber != NetworkManager::Instance()->GetSupplementaryUDPPort())
                    {
                        //Block access to non active UDP supplemental port(ports with active connections)
                        isReqErr = TRUE;
                        noResponse = TRUE;
                        print_to_both(p_toolLogPtr, "\n Supplementary UDP Port does not match server port number provided. \n");
                    }
                    else if (type == TCP && serverPortNumber != NetworkManager::Instance()->GetSupplementaryTCPPort())
                    {
                        //Block access to non active TCP supplemental port(ports with active connections)
                        isReqErr = TRUE;
                        noResponse = TRUE;
                        print_to_both(p_toolLogPtr, "\n Supplementary TCP Port does not match server port number provided. \n");
                    }
                }
                if(isReqErr == FALSE)
                {
                    if(p_reqHdr->version == HARTIP_PROTOCOL_V1)
                    {
                        // if security is provisioned then all v1 session-initiate attempts are ignored. until another factory reset.
                        if(Settings::Instance()->GetLockedHipVersion() >= HARTIP_PROTOCOL_VERSION)
                        {
                            isReqErr = TRUE;
                            noResponse = TRUE;
                            print_to_both(p_toolLogPtr,
                                    "\nSecurity is provisioned, v1 attempt will be ignored Client Version: %d\n",
                                    p_reqHdr->version);
                            log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Security is provisioned. Version (%d) not supported.", p_reqHdr->version);
                        }
                        else if(Settings::Instance()->GetLockedHipVersion() >= 0 && 
                        m_countSession > MinimalParallelConnectionToInitConnection && 
                        !SecurityConfigurationTable::Instance()->IsConfigured())
                        {
                            isReqErr = TRUE;
                            noResponse = TRUE;
                            print_to_both(p_toolLogPtr,
                                    "\n V1 Initial Session ongoing. Connection will be refused. Please retry once device has been provisioned. \n");
                            log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Initial session ongoing.");
                        }
                    }
                    else if(p_reqHdr->version >= HARTIP_PROTOCOL_VERSION)
                    {
                        //m_countSession > MinimalParallelConnectionToInitConnection && 
                        if(Settings::Instance()->GetLockedHipVersion() == HARTIP_PROTOCOL_V1)
                        {
                            errval = SESSION_ERROR;
                            isReqErr = TRUE;
                            p_rspHdr->status = HARTIP_SESS_ERR_SECURITY_NOT_INITIALIZED;
                            print_to_both(p_toolLogPtr,
                                    "\nHART-IP Initiate Session Refused...  Security not initialized\n");
                            log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Security not initialized.");
                        }
                    }
                }
            }            

            if(isReqErr == FALSE)
            {
                //check next non connection related conditions
                if (p_reqHdr->byteCount
                        < (HARTIP_HEADER_LEN + HARTIP_SESS_INIT_PYLD_LEN))
                {
                    isReqErr = TRUE;
                    p_rspHdr->status = HARTIP_SESS_ERR_TOO_FEW_BYTES;
                    print_to_both(p_toolLogPtr,
                            "\nHART-IP Initiate Session Refused...  Insufficient bytes in pkt\n"
                            );
                    log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Insufficient bytes in pkt.");
                }
                else if (p_request->hipTPPDU[0] != HARTIP_PRIM_MASTER_TYPE)
                {
                    isReqErr = TRUE;
                    noResponse = TRUE;
                    p_rspHdr->status = HARTIP_SESS_ERR_INVALID_MASTER_TYPE;
                    print_to_both(p_toolLogPtr,
                            "\nHART-IP Initiate Session Refused...  Invalid Master Type (%d)\n",
                            p_request->hipTPPDU[0]);
                    log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. Invalid Master Type.");
                }
                else if (!IsAvailableSession(thisSess))
                {
                    isReqErr = TRUE;
                    p_rspHdr->status = HARTIP_SESS_ERR_SESSION_NOT_AVLBL;
                    print_to_both(p_toolLogPtr,
                            "\nHART-IP Initiate Session Refused...  No client sessions are available.  A maximum of %d are supported.\n",
                            m_MaxCountClient);
                    printf("\nHART-IP Initiate Session Refused...  No client sessions are available.  A maximum of %d are supported.\n",
                            m_MaxCountClient);
                    log2HipSyslogger(118, 1002, 1, connection, "Session initiate declined - session limit reached");
                } // if (!is_session_avlbl(&thisSess))
                else if(SessionExisting(client_addr) == TRUE)
                {
                    isReqErr = TRUE;
                    p_rspHdr->status = HARTIP_SESS_ERR_SESSION_EXISTS;
                    printf("\nHART-IP Initiate Session Refused...  The client was connected earlier.\n");
                    log2HipSyslogger(36, 1005, 8, connection, "Session Initiate failed. The client was connected earlier.");
                } 
                else if((type == UDP && msTimer < MIN_KEEPALIVE_TIME) || (type == TCP && msTimer < MIN_KEEPALIVE_TIME && msTimer != 0))
                {
                    p_rspHdr->status = HARTIP_SESS_ERR_TOO_FEW_TIME;
                    msTimer = DEFAULT_KEEPALIVE_TIME;
                }
            }

            p_response->hipTPPDU[1]  = (msTimer >> 24) & 0xFF;
            p_response->hipTPPDU[2]  = (msTimer >> 16) & 0xFF;
            p_response->hipTPPDU[3]  = (msTimer >> 8) & 0xFF;
            p_response->hipTPPDU[4]  = msTimer & 0xFF;

			if (isReqErr || thisSess > m_connections.size())
			{
				// error session
				// in this case, there is no entry in the ClientSession table

				errval = MSG_ERROR;
                AuditLogger->SetStatusSession(connection, BadSessionInitialization);
                AuditLogger->SessionDisconnected(connection);
			}
            else
            {
                NetworkManager::Instance()->AddActiveConnection(serverPortNumber, type);

                connection->SetId(HARTIP_SESSION_ID_OK);
                connection->SetSessionNumber(thisSess);
                connection->SetSequnce(p_request->hipHdr.seqNum);
               
                connection->SetTimerTime(msTimer);

                m_mapSessionOwner[thisSess] = owner;
                m_connections[thisSess] = connection;

                m_clientVersion = p_reqHdr->version;
                printf("Client Version: %d\n", m_clientVersion);

                dbgp_logdbg("\nClient '%s' connected(timeout=%d)\nClient count: %d\n", connection->GetSessionInfoString(), msTimer, ++m_countSession);
                log2HipSyslogger(118, 1000, 1, connection, "Session initiated. %s", connection->GetSessionInfoString());
            }


		} while (FALSE);
	}
	sem_post(&m_semaphor);	// unlock server tables when done

	return (errval);
}

bool_t ConnectionsManager::IsSessionExisting(sockaddr_in_t& client_addr, HARTIPConnection** session)
{
    dbgp_logdbg("~~~~~~ %s ~~~~~~\n", __func__);
    bool_t ret = FALSE;
    printf("\nsta");
    sem_wait(&m_semaphor);
    printf("rt\n");
    for(int i = 0; i < m_connections.size(); i++)
    {
        if(m_connections[i]!= NULL && m_connections[i]->IsSession(client_addr))
        {
            if(session != NULL)
            {   
                *session = m_connections[i];
            }
            ret = TRUE;
            break;
        }
    }
    sem_post(&m_semaphor);
    return ret;
}

bool_t ConnectionsManager::SessionExisting(sockaddr_in_t& client_addr)
{
    bool_t ret = FALSE;
    for(int i = 0; i < m_connections.size(); i++)
    {
        if(m_connections[i]!= NULL && m_connections[i]->IsSession(client_addr))
        {
            ret = TRUE;
            break;
        }
    }
    return ret;
}

int ConnectionsManager::GetClientsVersion()
{
    return m_countSession == 0 ?
        HARTIP_PROTOCOL_VERSION :
            m_clientVersion == 1 || m_clientVersion == 2 ?
                m_clientVersion :
                HARTIP_PROTOCOL_VERSION;
}

bool_t ConnectionsManager::IsVersionMatch(uint8_t version)
{
    return ((m_countSession > 0 && version != m_clientVersion) || (m_countSession == 0 && version > HARTIP_PROTOCOL_VERSION)) ? FALSE : TRUE;
}

bool_t ConnectionsManager::InitiatedSessionIsRunning()
{
    return m_initSessionRunning;
}

void ConnectionsManager::InitiatedSessionState(bool_t state)
{
    m_initSessionRunning = state;
}

uint32_t ConnectionsManager::GetCountClients(IOwnerSession* owner)
{
    sem_wait(&m_semaphor);
    int count = 0;
    for(std::map<int, IOwnerSession*>::iterator iter = m_mapSessionOwner.begin(); iter != m_mapSessionOwner.end(); ++iter)
    {
        if(iter->second == owner)
        {
            count++;
        }
    }
    sem_post(&m_semaphor);
    return count;
}

uint32_t ConnectionsManager::GetSessionNumber()
{
    uint32_t count = 0;
    sem_wait(&m_semaphor);
    for(int i = 0; i < m_connections.size(); ++i)
    {
        if(m_connections[i] != NULL)
        {
            ++count;
        }
    }
    sem_post(&m_semaphor);
    return count;
}

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char* file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&mutex_buf[n]);
    }
    else
    {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

static unsigned long id_function(void)
{
    return (unsigned long)pthread_self();
}

void InitSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();

    mutex_buf = (pthread_mutex_t*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

    if (mutex_buf)
    {
        for (int i = 0; i < CRYPTO_num_locks(); i++)
        {
            pthread_mutex_init(&mutex_buf[i], NULL);
        }

        CRYPTO_set_id_callback(id_function);
        CRYPTO_set_locking_callback(locking_function);
    }
    else
    {
        print_to_both(p_toolLogPtr, "mutex buf failed. Allocation error\n");
    }

}

void CleanupSSL()
{
    if (mutex_buf)
    {
        CRYPTO_set_id_callback(NULL);
        CRYPTO_set_locking_callback(NULL);

        for (int i = 0; i < CRYPTO_num_locks(); i++)
        {
            pthread_mutex_destroy(&mutex_buf[i]);
        }

        free(mutex_buf);
        mutex_buf = NULL;
    }

}
