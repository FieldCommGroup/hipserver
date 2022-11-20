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
#include "threadex.h"
#include "hsresponsesender.h"
#include "hscommandsmanager.h"
#include "hsconnectionmanager.h"
#include "hshandlermessages.h"
#include "hsprocessor.h"


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include "mutex2.h"

/* Misc. constants */
#define HARTIP_NUM_SESS_SUPPORTED    20 /* 2 process data clients and an instrument mgt sys  */


/* Inactivity signal - scalable for future multiple sessions by defining
 * the signals as SIGRTMIN+n for session n
 */
#define SIG_INACTIVITY_TIMER(n)      (SIGRTMIN + (n))

/************
 *  Globals
 ************/

/************************
 *  Function Prototypes
 ************************/
//errVal_t create_udp_socket(void);
//errVal_t  create_sockets(void);
//void      reset_client_sessions(void);

int crypto_THREAD_SETUP(); //InitSSL();

class OneUdpProcessor : public IResponseSender, public HARTIPConnection
{
public:
	OneUdpProcessor(uint8_t v) : IResponseSender(), m_noResponse(FALSE), m_version(v), m_ssl(NULL), m_clientSocket(0) {}
    virtual ~OneUdpProcessor();
	virtual errVal_t SendResponse(hartip_msg_t *p_response);
    virtual errVal_t SendBinaryResponse(void* pData, int size);
	virtual uint16_t GetSessionNumber();
    HARTIPConnection *GetSession();
    void SetNoResponse(const bool_t& noResponse);
    void SetSSL(SSL* ssl, uint32_t socket);
    SSL* GetSSL();
    errVal_t ReadSocket(uint8_t *p_buffer, ssize_t* p_size);
    int32_t GetSocket();

    virtual int GetSlotNumber();
    
    virtual bool_t IsReadOnly();
private: 
    bool_t      m_noResponse;
    uint8_t     m_version;
    SSL*        m_ssl;
    uint32_t    m_clientSocket;
};

class UdpProcessor : public HandlerMessages, public IOwnerSession, public IProcessor
{
public:
    static void Init();
    static void Cleanup();
    void CreateUdpServerSocket(int32_t serverSocket, sockaddr_in_t *serverAddress);
    void InitThreadedObject();
    errVal_t create_context();

    UdpProcessor(uint16_t port): HandlerMessages(), IProcessor(port), m_currentSession(NULL), m_clients(0), m_is_main_thread(FALSE){}
	void TerminateSocket();

protected:
    void Run();
	void DeleteSession(HARTIPConnection* session);

	virtual IResponseSender* GetCurrentResponse() ;

    virtual HARTIPConnection* GetCurrentSession() ;

    virtual errVal_t RestartTimerCurrentSession() ;

    virtual bool_t GetCurrentSession(sockaddr_in_t& address) ;

    virtual errVal_t InitSession(hartip_msg_t *p_req, hartip_msg_t* p_res, sockaddr_in_t& address) ;

    virtual errVal_t ReadSocket(int32_t socket, uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr) ;

    virtual std::vector<int32_t> GetSockets() ;

    virtual void RemoveCurrentSession() ;

    virtual void ProcessInvalidSession() ;
	
    virtual void DestroyProcessor();

    virtual uint32_t GetClientCount();

    virtual void Start();

    virtual bool_t IsRunning();

    virtual void ReconfigureServerSocket();
    
    virtual void SetMainThread();
    
    virtual bool_t IsMainThread();
    
    virtual int32_t GetMainSocket();
    
    virtual sockaddr_in_t* GetServerAddress() { return &m_server_addr; } ;
private:

	OneUdpProcessor* 		m_currentSession;
	int32_t		    m_socket;
    sockaddr_in_t   m_server_addr;
    bool_t m_is_main_thread;
    int32_t m_mainsocket;

    std::vector<OneUdpProcessor*> m_clients;
    static SSL_CTX* m_ctx;
};

#endif /* _HSUDP_H */
