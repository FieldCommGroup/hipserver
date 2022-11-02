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

#ifndef _HS_NETWORK_MANAGER_
#define _HS_NETWORK_MANAGER_

#include "tcpprocessor.h"
#include "hsudp.h"
#include "mutex2.h"
#include "errval.h"
#include <string>
#include <semaphore.h>

extern uint16_t portNum;

class NetworkManager
{
private:
    static NetworkManager* g_instance;
    MutexEx m_mutex;

    sem_t m_semaphor;
    const uint16_t m_defaultPort;
    uint16_t m_supplementaryUdpPort;
    uint16_t m_supplementaryTcpPort;

    IProcessor *m_defaultUdpProcessor;
    IProcessor *m_defaultTcpProcessor;

    IProcessor *m_additionalUdpProcessor;
    IProcessor *m_additionalTcpProcessor;

    std::vector<uint16_t> m_activeUdpConnections;
    std::vector<uint16_t> m_activeTcpConnections;

    std::vector<IProcessor*> m_additionalUdpProcessors;
    std::vector<IProcessor*> m_additionalTcpProcessors;

    NetworkManager(const uint16_t defPort);
    ~NetworkManager();

    void DestroyProcessor(IProcessor* processor, TypeConnection type);
    errVal_t CreateNewProcessor(uint16_t port, TypeConnection type, IProcessor** processor);

    void AddAdditionalProcessor(IProcessor* processor, TypeConnection type);
    void RemoveAdditionalProcessor(IProcessor* processor, TypeConnection type);

public:
    static NetworkManager* Instance();
    static void Destroy();
    
    errVal_t CreateSemaphor();
    errVal_t CreateDefaultProcessor();
    errVal_t CreateNewProcessor(uint16_t port, TypeConnection type);

    void AddActiveConnection(uint16_t connectedPort, TypeConnection type);
    void RemoveActiveConnection(uint16_t connectedPort, TypeConnection type);

    uint16_t GetAdditionalPort(TypeConnection type);
    uint16_t GetSupplementaryUDPPort() { return m_supplementaryUdpPort; };
    uint16_t GetSupplementaryTCPPort() { return m_supplementaryTcpPort; } ;

    void ProcessCmd538(TpPdu* req);
    void ProcessCmd539(TpPdu* req);
    void ProcessCmd540(TpPdu* req);
    void ConfigureSupplementaryPort(TypeConnection type);

    void RemoveInactiveProcessors();
};

#endif
