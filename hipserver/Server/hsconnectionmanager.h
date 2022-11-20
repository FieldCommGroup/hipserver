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

#ifndef _HSCONNECTIONS_MANAGER_H_
#define _HSCONNECTIONS_MANAGER_H_
#include "hstypes.h"
#include <semaphore.h>
#include <vector>
#include "errval.h"
#include <map>
#include "hsprocessor.h"
#define HARTIP_SESSION_ID_INVALID    0xFF         /* arbitrary */
#define HARTIP_SESSION_ID_OK         0xF0         /* arbitrary */
#define HARTIP_SOCKET_FD_INVALID     LINUX_ERROR

/* Values from HART-IP Protocol (Spec 85) */
#define HARTIP_PROTOCOL_V1           1  
#define HARTIP_PROTOCOL_VERSION      2
#define HARTIP_SERVER_PORT           5094
#define DEFINE_MAX_COUNT_SESSION     5

/* increase for testing purpose to allow client without secure connection */
#ifdef BasicTest
    #define MinimalSecureClientVersion 3
#else 
    #define MinimalSecureClientVersion 2
#endif


/* for testing purpose it should be increased to two to allow multiple connection per test*/
#ifdef BasicTest
    #define MinimalParallelConnectionToInitConnection 2
#else
    #define MinimalParallelConnectionToInitConnection 0
#endif

#define PSK_CIPHER_SUITES "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CCM"
#define PASSWORD_CIPHER_SUITES "SRP-AES-128-CBC-SHA"
#define CIPHER_SUITES "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CCM:SRP-AES-128-CBC-SHA"
#define COOKIE_SECRET_LENGTH 16

extern uint16_t portNum;

typedef enum
{
	HARTIP_ENCRYPTION_TYPE_PSK = 1,
	HARTIP_ENCRYPTION_TYPE_SRP = 2,
} HARTIP_ENCRYPTION_TYPE;

typedef struct srp_server_arg_st
{
    char szExpected_user[1024];
    char szPass[1024];
} SRP_SERVER_ARG;

void InitSSL();
void CleanupSSL();

class HARTIPConnection
{
public:
    HARTIPConnection();    
    virtual ~HARTIPConnection(){}
    void SetId(uint8_t id);
    void SetSessionNumber(uint16_t number);
    void SetSocket(uint32_t socket_fd);
    void SetAddress(const sockaddr_in_t& address);
    void SetAddress6(const sockaddr_in6_t& address);
    virtual void SetTimerTime(uint32_t time);
    void SetSequnce(uint16_t number);
    uint16_t NextSequnce();

    void StartTimer();
    void DeleteTimer();
    bool_t IsSession(sockaddr_in_t& addres);
    char* GetSessionInfoString();
    char* GetSessionIPv4();
    bool_t IsSameAddress(sockaddr_in_t& address);

    void GetAddress(sockaddr_in_t *address);
    void GetAddress6(sockaddr_in6_t *address);

    virtual bool_t IsReadOnly();
    virtual int GetSlotNumber();

    bool_t IsInitiatedSession();
    void SetInitiatedSession();


protected:
    uint8_t m_id;
	uint16_t m_sessNum;         // uniquely identifies a session with a client
	int32_t m_server_sockfd;   // server's socket handle
	sockaddr_in_t m_clientAddr;      // client  vv
    sockaddr_in6_t m_clientAddr6;
	uint16_t m_seqNumber;       // current sequence number
	timer_t* m_idInactTimer;    // the inactivity timer
	uint32_t m_msInactTimer;    // timer value
    bool_t m_isInitiatedSession;
};

class IOwnerSession
{
public:
    virtual void DeleteSession(HARTIPConnection* session) = 0;
};

class ConnectionsManager
{
public:
    static ConnectionsManager* Instance();
    static errVal_t CreateManager(int maxCount = DEFINE_MAX_COUNT_SESSION);
    static void DeleteManager();

    void RemoveConnectionFromManager(HARTIPConnection *pConnection);
    errVal_t CreateSemaphor();
    void RemoveInactivitySession(int sessNumber);
    bool_t IsAvailableSession(int& session);
    errVal_t InitSession(hartip_msg_t *p_request,
		hartip_msg_t *p_response, sockaddr_in_t client_addr, HARTIPConnection* connection, IOwnerSession* owner, TypeConnection type, bool_t& noResponse, uint16_t serverPortNumber);
    bool_t IsSessionExisting(sockaddr_in_t& client_addr, HARTIPConnection** session);
    bool_t SessionExisting(sockaddr_in_t& client_addr);

    uint32_t GetCountClients(IOwnerSession* owner);

    uint32_t GetSessionNumber();
    int GetClientsVersion();

    bool_t IsVersionMatch(uint8_t version);
    void InitiatedSessionState(bool_t state);
    bool_t InitiatedSessionIsRunning();

private:
    ConnectionsManager(int maxCount);
    ~ConnectionsManager();
    
    const int m_MaxCountClient;
    const char* m_semName;
    std::vector<HARTIPConnection*> m_connections;
    std::map<int, IOwnerSession*> m_mapSessionOwner;
    static ConnectionsManager* g_manager;

    sem_t m_semaphor;
    bool_t m_initSessionRunning;
    int m_countSession;
    int m_clientVersion;
};

#endif

