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

#ifndef _HS_HANDLER_MESSAGES_H_
#define _HS_HANDLER_MESSAGES_H_

#include "threadex.h"
#include "hstypes.h"
#include "errval.h"
#include "hscommandsmanager.h"
#include "hsconnectionmanager.h"

/****************
 *  Definitions
 ****************/
/* Values from HART-IP Protocol (Spec 85) */
#define HARTIP_SERVER_PORT           5094

/* Mask to get the message type */
#define HARTIP_MSG_TYPE_MASK         0x0F
#define HARTIP_RESERVED_MASK         0xF0

/* Offsets for the fields of a HART-IP message header (derived from
 * header information in Spec 85)
 */
#define HARTIP_OFFSET_VERSION        0
#define HARTIP_OFFSET_MSG_TYPE       1
#define HARTIP_OFFSET_MSG_ID         2
#define HARTIP_OFFSET_STATUS         3
#define HARTIP_OFFSET_SEQ_NUM        4
#define HARTIP_OFFSET_BYTE_COUNT     6

extern uint16_t portNum;

class IResponseSender;

class HandlerMessages : public ThreadEx
{
public:
    HandlerMessages();
    virtual ~HandlerMessages();

    virtual void Run() ;
    virtual void RunUdp() ;
    
    virtual errVal_t WaitClient(uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr);
        
            virtual errVal_t WaitClientMainThreadUdp(uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr);

	virtual errVal_t CloseSession(hartip_msg_t *p_request,
		hartip_msg_t *p_response, bool_t isError, IResponseSender* sender);
    
    virtual errVal_t ParseClientRequest(uint8_t *p_reqBuff, ssize_t lenPdu,
		hartip_msg_t *p_parsedReq);


    virtual errVal_t HandleKeepalive(hartip_msg_t *p_request,
		hartip_msg_t *p_response, IResponseSender* sender);

public:

    void SetVersion(uint32_t v) { m_version = v; };
    uint32_t GetVersion() const { return m_version; };

private:
    struct ThreadArguments {
        uint8_t rawDataBytes[HS_MAX_BUFFSIZE];
        ssize_t receivedBytes;
        sockaddr_in_t clientAddress;
        CommandsManager commandManagerInstance;
        int32_t serverSocket;
        sockaddr_in_t serverAddress;
    };

    void* ProcessUdpSocket(void* threadArgs);
    void ProcessUdpTrafficSecure();

    // wrap process udp socket in a static function
    static void* StartUdpProcessThread(void* pTr);
    sem_t* m_semUdp;

protected:

    virtual IResponseSender* GetCurrentResponse() = 0;

    virtual HARTIPConnection* GetCurrentSession() = 0;

    virtual errVal_t RestartTimerCurrentSession() = 0;

    virtual bool_t GetCurrentSession(sockaddr_in_t& address) = 0;

    virtual errVal_t InitSession(hartip_msg_t *p_req, hartip_msg_t* p_res, sockaddr_in_t& address) = 0;

    virtual errVal_t ReadSocket(int32_t socket, uint8_t *p_reqBuff, ssize_t *p_lenPdu,
        sockaddr_in_t *p_client_sockaddr) = 0;

    virtual std::vector<int32_t> GetSockets() = 0;

    virtual void RemoveCurrentSession() = 0;

    virtual void ProcessInvalidSession() = 0;
    
    virtual void ReconfigureServerSocket() = 0;
    
    virtual void SetMainThread() = 0 ;
    
    virtual bool_t IsMainThread() = 0 ;
    
    virtual int32_t GetMainSocket() = 0 ;
    
    virtual sockaddr_in_t* GetServerAddress() = 0;
    

    ConnectionsManager*     m_connectionsManager;

    CommandsManager         m_commandManager;

    bool_t                  m_noResponse;

    uint32_t                m_version;
};

#endif
