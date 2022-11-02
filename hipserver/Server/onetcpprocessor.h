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

#ifndef ONETCPPROCESSOR_H
#define ONETCPPROCESSOR_H

#include "threadex.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "hstypes.h"
#include "hsresponsesender.h"
#include "hscommandsmanager.h"
#include "hsconnectionmanager.h"
#include "hshandlermessages.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

class OneTcpProcessor : public HandlerMessages, public HARTIPConnection, public IResponseSender
{
public:
    static void Init();
    static void Cleanup();

    OneTcpProcessor(uint32_t clientFd, sockaddr_in_t address, IOwnerSession* remover, uint16_t portNumber);

    virtual errVal_t SendResponse(hartip_msg_t *p_response);
    virtual errVal_t SendBinaryResponse(void* pData, int size);
    virtual uint16_t GetSessionNumber();
protected:

    void Run() ;
    
    virtual void SetTimerTime(uint32_t time);

    virtual IResponseSender* GetCurrentResponse() ;

    virtual HARTIPConnection* GetCurrentSession() ;

    virtual errVal_t RestartTimerCurrentSession() ;

    virtual bool_t GetCurrentSession(sockaddr_in_t& address) ;

    virtual errVal_t InitSession(hartip_msg_t *p_req, hartip_msg_t* p_res, sockaddr_in_t& address) ;

    virtual errVal_t ReadSocket(int32_t socket, uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr) ;

    virtual std::vector<int32_t> GetSockets() ;

    virtual void RemoveCurrentSession() ;

    virtual void ProcessInvalidSession();

    virtual HARTIPConnection *GetSession();

    virtual bool_t IsReadOnly();

    virtual int GetSlotNumber();

    virtual void ReconfigureServerSocket() { return; } ;
    
    virtual void SetMainThread() { return; };
    
    virtual bool_t IsMainThread() { return FALSE; };
    
    virtual int32_t GetMainSocket() { return 0; };
    
    virtual sockaddr_in_t* GetServerAddress() { return NULL; };

private:

    uint8_t                 m_sessionNumber;
    uint16_t                m_portNumber;
    
    IOwnerSession*          m_remover;

    bool_t m_needRemove;

private:
    static SSL_CTX* m_ctx;
    SSL* m_ssl;
};

#endif // ONETCPPROCESSOR_H
