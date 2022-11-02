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

#include "tcpprocessor.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include "toolutils.h"

extern uint16_t portNum;

TcpProcessor::TcpProcessor(uint16_t port) : IProcessor(port), m_sem(NULL), m_socket(-1)
{

}

void TcpProcessor::TerminateSocket()
{
    printf("\nClose tcp socket\n");
    shutdown(m_socket, SHUT_RDWR);
    
}

TcpProcessor::~TcpProcessor()
{
    sem_wait(m_sem);
    for(int i = 0; i < m_Clients.size(); ++i)
    {
        if(m_Clients[i] != NULL)
        {
            m_Clients[i]->Stop();
            m_Clients[i]->Join();
            delete m_Clients[i];
        }
    }
    sem_post(m_sem);
    sem_destroy(m_sem);
    delete m_sem;
    m_sem = NULL;
}

void TcpProcessor::Run()
{
    m_isRunning = TRUE;
    int err, len;
    int { -1 };
    if (-1 == (m_socket = socket(AF_INET, SOCK_STREAM, 0)))
    {
        //perror("Socket can not created!\n");
        return;
    }
    m_sem = new sem_t();
    sem_init(m_sem, 0, 1);
    int on = 1;
    int rc = setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

    // set non blocking socket = to be able to use 'select' functions
    int flags = fcntl(m_socket, F_GETFL);
    flags |= O_NONBLOCK;
    int result = fcntl(m_socket, F_SETFL, flags);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (err = bind(m_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        //close(socket_fd);
        //perror("bind error!\n%s ", gai_strerror(err));
        return;
    }

    /*************************************************************/
    /* Set the listen back log                                   */
    /*************************************************************/
    rc = listen(m_socket, 32);
    while (IsRunning())
    {
        fd_set set;
        struct timeval timeout;
        FD_ZERO(&set);
        FD_SET(m_socket, &set);

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        // run
        int max_sd = m_socket;
        int rv = select(max_sd + 1, &set, NULL, NULL, &timeout);
        if (rv == -1)
        {
            //perror("select"); /* an error accured */
            return;
        }
        else if (rv == 0)
        {
            /* a timeout occured */
            //printf("timeout occurred (20 second) \n");
            continue;
        }
        else
        {
            if(!IsRunning())
                break;
            if (FD_ISSET(m_socket, &set))
            {
                if (m_socket != 0)
                {
                    printf("  Listening socket is readable\n");
                    sockaddr_in_t address;
                    memset(&address, 0, sizeof(address));
                    socklen_t len = sizeof(address);
                    int new_sd = accept(m_socket, (struct sockaddr*)&address, &len);
                    if (new_sd < 0)
                    {
                        if (errno != EWOULDBLOCK)
                        {
                            perror("  accept() failed");
                            return;
                        }
                        break;
                    }
                    OneTcpProcessor* newClient;
                    newClient = new OneTcpProcessor(new_sd, address, this, m_port);
                    sem_wait(m_sem);
                    m_Clients.push_back(newClient);
                    sem_post(m_sem);
                    newClient->Start();
                }
            }
        }
    }
    close(m_socket);
} 

void TcpProcessor::DeleteSession(HARTIPConnection* processor)
{
    sem_wait(m_sem);
    for(size_t i = 0; i< m_Clients.size(); ++i)
    {
        if(m_Clients[i] == processor)
        {
            if(m_Clients[i]->IsRunning())
            {   
                m_Clients[i]->Stop();
                //m_Clients[i]->Join();   
            }
            else
            {
                m_Clients.erase(m_Clients.begin() + i);
                delete processor;
            }
            break;
        }
    }
    sem_post(m_sem);
}

void TcpProcessor::DestroyProcessor()
{
    print_to_both(p_toolLogPtr, "Destroying TCP Processor \n");

    Stop();
    Join();
}

uint32_t TcpProcessor::GetClientCount()
{
    sem_wait(m_sem);
    uint32_t count = m_Clients.size();
    sem_post(m_sem);
    return count;
}

void TcpProcessor::Start()
{
    ThreadEx::Start();
}

bool_t TcpProcessor::IsRunning()
{
    return ThreadEx::IsRunning();
}
