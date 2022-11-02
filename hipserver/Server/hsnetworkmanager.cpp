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

#include "hsnetworkmanager.h"
#include "hshostnamesystem.h"
#include "debug.h"
#include "hsprocessor.h"
#include "hssettingshandler.h"
#include <stdexcept>
#include <string>
#include "hssyslogger.h"
#include <spawn.h>

NetworkManager* NetworkManager::g_instance = NULL;

NetworkManager::NetworkManager(const uint16_t defPort) : m_defaultPort(defPort), m_defaultUdpProcessor(NULL), m_defaultTcpProcessor(NULL),
                                                    m_additionalUdpProcessor(NULL), m_additionalTcpProcessor(NULL)
{
    CreateSemaphor();
}

void NetworkManager::DestroyProcessor(IProcessor* processor, TypeConnection type)
{
    sem_wait(&m_semaphor);
    {
        if(processor != NULL)
        {
            processor->DestroyProcessor();
            RemoveAdditionalProcessor(processor, type);
            //delete processor;
            processor = NULL;
        }
    }
    sem_post(&m_semaphor);
}

errVal_t NetworkManager::CreateSemaphor()
{
    dbgp_logdbg("~~~~~~ %s ~~~~~~\n", __func__);
    return (errVal_t)sem_init(&m_semaphor, 0, 1);
}

NetworkManager::~NetworkManager()
{   
    MutexScopeLock lock(m_mutex);
    DestroyProcessor(m_defaultUdpProcessor,UDP);
    DestroyProcessor(m_defaultTcpProcessor,TCP);
    DestroyProcessor(m_additionalUdpProcessor,UDP);
    DestroyProcessor(m_additionalTcpProcessor,TCP);
    sem_destroy(&m_semaphor);
}


NetworkManager* NetworkManager::Instance()
{
    if(g_instance == NULL)
    {
        g_instance = new NetworkManager(portNum);
    }

    return g_instance;
}
    
errVal_t NetworkManager::CreateDefaultProcessor()
{
    m_defaultUdpProcessor = new UdpProcessor(m_defaultPort);
    if(m_defaultUdpProcessor == NULL)
    {
        DestroyProcessor(m_defaultUdpProcessor,UDP);
        dbgp_logdbg("Could not create UdpProcessor with port %d", m_defaultPort);
        return LINUX_ERROR;
    }
    m_defaultUdpProcessor->Start();

    m_defaultTcpProcessor = new TcpProcessor(m_defaultPort);
    if(m_defaultTcpProcessor == NULL)
    {
        DestroyProcessor(m_defaultTcpProcessor,TCP);
        dbgp_logdbg("Could not create TcpProcessor with port %d", m_defaultPort);
        return LINUX_ERROR;
    }
    m_defaultTcpProcessor->Start();

    return NO_ERROR;
}

errVal_t NetworkManager::CreateNewProcessor(uint16_t port, TypeConnection type, IProcessor** processor)
{
    if(m_defaultPort == port)
    {
        (*processor) = NULL;

        dbgp_logdbg("Default %s Processor with '%d' port created earlier", type == UDP ? "Udp": "Tcp", port);
        return NO_ERROR;
    }

    if((*processor) != NULL && (*processor)->GetPort() == port)
    {
        dbgp_logdbg("Additional %s Processor with '%d' port created earlier", type == UDP ? "Udp": "Tcp", port);
        return NO_ERROR;
    }

    // if((*processor) != NULL)
    // {
    //     DestroyProcessor(processor, type);
    // }

    std::string check = "lsof -i:" + std::to_string(port) +" | grep dhclient | awk '{print $2}' | uniq";
    int n1 = check.length();
    char checkArr[n1 + 1];
    strcpy(checkArr, check.c_str());

    std::string runCheck = execCommand(checkArr);
    if (runCheck != "")
    {
        std::string killPort = check + " | xargs kill -9";
        int n2 = killPort.length();
        char killPortArr[n2 + 1];
        strcpy(killPortArr, killPort.c_str());

        int status = 0;
        pid_t pid;
        extern char **environ;
        char *argv[] = {"sh", "-c", killPortArr, NULL};
        status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);

        // system(killPortArr);
		
		script_sleep(1); //putting sleep because the process might not be totally killed before hipserver tries to use the port
    }

    switch(type)
    {
        case UDP:
            (*processor) = new UdpProcessor(port);
            m_supplementaryUdpPort = port;
            break;
        case TCP:
            (*processor) = new TcpProcessor(port);
            m_supplementaryTcpPort = port;
            break;
    }

    AddAdditionalProcessor((*processor), type);
    (*processor)->Start();

    //RemoveInactiveProcessors();

    return NO_ERROR;
}

void NetworkManager::AddAdditionalProcessor(IProcessor* processor, TypeConnection type)
{
    if(type == TCP)
    {
        m_additionalTcpProcessors.push_back(processor);
    }
    else if(type == UDP)
    {
        m_additionalUdpProcessors.push_back(processor);
    }
    print_to_both(p_toolLogPtr,"Port added: %d\n", processor->GetPort());
    print_to_both(p_toolLogPtr,
              "Add - TCP Processor Count: %d, UDP Processor Count: %d\n",
              m_additionalTcpProcessors.size(), m_additionalUdpProcessors.size());
}

void NetworkManager::RemoveAdditionalProcessor(IProcessor* processor, TypeConnection type)
{
    if(type == TCP)
    {
        for(int i = 0 ; i < m_additionalTcpProcessors.size(); i++)
        {
            if(processor == m_additionalTcpProcessors[i] && processor != NULL)
            {
                m_additionalTcpProcessors.erase(m_additionalTcpProcessors.begin() + i);
                break;
            }
        }
    }
    else if(type == UDP)
    {
        for(int i = 0 ; i < m_additionalUdpProcessors.size(); i++)
        {
            if(processor == m_additionalUdpProcessors[i] && processor != NULL)
            {
                m_additionalUdpProcessors.erase(m_additionalUdpProcessors.begin() + i);
                break;
            }
        }
    }

    print_to_both(p_toolLogPtr,
              "Remove - TCP Processor Count: %d, UDP Processor Count: %d\n",
              m_additionalTcpProcessors.size(), m_additionalUdpProcessors.size());
}

errVal_t NetworkManager::CreateNewProcessor(uint16_t port, TypeConnection type)
{
    MutexScopeLock lock(m_mutex);
    
    switch(type)
    {
        case UDP:
        {
            return CreateNewProcessor(port, type, &m_additionalUdpProcessor);
        }
        case TCP:
        {
            return CreateNewProcessor(port, type, &m_additionalTcpProcessor);
        }
    }
}

void NetworkManager::AddActiveConnection(uint16_t connectedPort, TypeConnection type)
{
    if(type == TCP)
    {
        m_activeTcpConnections.push_back(connectedPort);
    }
    else if(type == UDP)
    {
        m_activeUdpConnections.push_back(connectedPort);
    }

    print_to_both(p_toolLogPtr,
              "Add - TCP Connection Count: %d, UDP Connection Count: %d\n",
              m_activeTcpConnections.size(), m_activeUdpConnections.size());
}

void NetworkManager::RemoveActiveConnection(uint16_t connectedPort, TypeConnection type)
{
    if(type == TCP)
    {
        for(int i = 0 ; i < m_activeTcpConnections.size(); i++)
        {
            if(connectedPort == m_activeTcpConnections[i])
            {
                m_activeTcpConnections.erase(m_activeTcpConnections.begin() + i);
                break;
            }
        }
    }
    else if(type == UDP)
    {
        for(int i = 0 ; i < m_activeUdpConnections.size(); i++)
        {
            if(connectedPort == m_activeUdpConnections[i])
            {
                m_activeUdpConnections.erase(m_activeUdpConnections.begin() + i);
                break;
            }
        }
    }

    RemoveInactiveProcessors();

    print_to_both(p_toolLogPtr,
              "Remove - TCP Connection Count: %d, UDP Connection Count: %d\n",
              m_activeTcpConnections.size(), m_activeUdpConnections.size());
}

void NetworkManager::Destroy()
{
    delete g_instance;
    g_instance = NULL;
}

uint16_t NetworkManager::GetAdditionalPort(TypeConnection type)
{
    uint16_t port = portNum;
    IProcessor* processor = NULL;
    switch(type)
    {
        case UDP:
        {
            processor = m_additionalUdpProcessor;
            break;
        }
        case TCP:
        {
            processor = m_additionalTcpProcessor;
            break;
        }
    }

    if(processor != NULL)
    {
        port = processor->GetPort();
    }

    return port;
}

void NetworkManager::ProcessCmd538(TpPdu* req)
{
    uint16_t portUdp = portNum;
    uint16_t portTcp = portNum;

    if(m_supplementaryTcpPort == m_defaultPort)
    {
        portTcp = m_defaultPort;
    }
    else if(m_additionalTcpProcessor != NULL)
    {
        portTcp = m_additionalTcpProcessor->GetPort();
    }
    
    if(m_supplementaryUdpPort == m_defaultPort)
    {
        portUdp = m_defaultPort;
    }
    else if(m_additionalUdpProcessor != NULL)
    {
        portUdp = m_additionalUdpProcessor->GetPort();
    }    
    
    uint8_t portsLen = 4;
	uint8_t statusBytes = 2;
	uint8_t dataSize = portsLen + statusBytes;
    uint8_t resBuffer[dataSize];
    memset(resBuffer, 0, dataSize);

    resBuffer[0] = portUdp >> 8;
    resBuffer[1] = portUdp & 0x0FF;

    resBuffer[2] = portTcp >> 8;
    resBuffer[3] = portTcp & 0x0FF;
    req->SetByteCount(2 /*RC+DC*/);
    req->ProcessOkResponse(RC_SUCCESS, resBuffer, dataSize);
    req->SetRCStatus(RC_SUCCESS, req->getSavedDevStatus()); // #165
    req->SetCheckSum();
}

void NetworkManager::ProcessCmd539(TpPdu* req)
{
    if(req->RequestByteCount() < 2)
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return;
    }

    uint8_t *reqBuffer = req->RequestBytes();

    uint16_t port = 0;
    port = (reqBuffer[0] << 8) + (reqBuffer[1] & 0x0FF);
    
    uint8_t portLen = 2;
	uint8_t statusBytes = 2;
	uint8_t dataSize = portLen + statusBytes;
    uint8_t resBuffer[dataSize];
    memset(resBuffer, 0, dataSize);

    resBuffer[0] = port >> 8;
    resBuffer[1] = port & 0x0FF;

    req->SetByteCount(2 /*RC+DC*/);
    req->ProcessOkResponse(RC_SUCCESS, resBuffer, dataSize);
    log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command 539");
    req->SetRCStatus(RC_SUCCESS, req->getSavedDevStatus()); // #165
    req->SetCheckSum();

    m_supplementaryUdpPort = port;

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("supUDPPort", to_string(port));
}

void NetworkManager::ProcessCmd540(TpPdu* req)
{
        if(req->RequestByteCount() < 2)
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return;
    }

    uint8_t *reqBuffer = req->RequestBytes();

    uint16_t port = 0;
    port = (reqBuffer[0] << 8) + (reqBuffer[1] & 0x0FF);
    
    uint8_t portLen = 2;
	uint8_t statusBytes = 2;
	uint8_t dataSize = portLen + statusBytes;
    uint8_t resBuffer[dataSize];
    memset(resBuffer, 0, dataSize);

    resBuffer[0] = port >> 8;
    resBuffer[1] = port & 0x0FF;

    req->SetByteCount(2 /*RC+DC*/);
    req->ProcessOkResponse(RC_SUCCESS, resBuffer, dataSize);
    log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command 540");
    req->SetRCStatus(RC_SUCCESS, req->getSavedDevStatus()); // #165
    req->SetCheckSum();

    m_supplementaryTcpPort = port;

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("supTCPPort", to_string(port));
}

void NetworkManager::ConfigureSupplementaryPort(TypeConnection type)
{
    if (type == UDP)
    {
        errVal_t res = CreateNewProcessor(m_supplementaryUdpPort, type);
    }

    else if (type == TCP)
    {
        errVal_t res = CreateNewProcessor(m_supplementaryTcpPort, type);
    }
}

void NetworkManager::RemoveInactiveProcessors()
{
    for (int j = 0; j < m_additionalUdpProcessors.size(); j++)
    {
        uint16_t tempPortNumber = m_additionalUdpProcessors[j]->GetPort();

        if (tempPortNumber == m_defaultPort || tempPortNumber == m_supplementaryUdpPort)
        {
            print_to_both(p_toolLogPtr,"Current UDP port %d, skip from cleanup\n", tempPortNumber);
            continue;
        }
        
        bool doCleanup = true;
        for (int i = 0; i < m_activeUdpConnections.size(); i++)
        {
            if (tempPortNumber == m_activeUdpConnections[i])
            {
                print_to_both(p_toolLogPtr,"UDP Port %d still has connections, skip from cleanup\n", tempPortNumber);
                doCleanup = false;
                break;
            }
        }

        if(doCleanup == true)
        {
            print_to_both(p_toolLogPtr,"Try destroy UDP processor %d\n", tempPortNumber);
            DestroyProcessor(m_additionalUdpProcessors[j], UDP);
        }
    }

    for (int j = 0; j < m_additionalTcpProcessors.size(); j++)
    {
        uint16_t tempPortNumber = m_additionalTcpProcessors[j]->GetPort();

        if (tempPortNumber == m_defaultPort || tempPortNumber == m_supplementaryTcpPort)
        {
            print_to_both(p_toolLogPtr,"Current TCP port %d, skip from cleanup\n", tempPortNumber);
            continue;
        }
        
        bool doCleanup = true;
        for (int i = 0; i < m_activeTcpConnections.size(); i++)
        {
            if (tempPortNumber == m_activeTcpConnections[i])
            {
                print_to_both(p_toolLogPtr,"TCP Port %d still has connections, skip from cleanup\n", tempPortNumber);
                doCleanup = false;
                break;
            }
        }

        if(doCleanup == true)
        {
            print_to_both(p_toolLogPtr,"Try destroy TCP processor %d\n", tempPortNumber);
            DestroyProcessor(m_additionalTcpProcessors[j], TCP);
        }
    }
}