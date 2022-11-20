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

#ifndef TCPPROCESSOR_H
#define TCPPROCESSOR_H

#include "threadex.h"
#include "onetcpprocessor.h"
#include "hsprocessor.h"
#include <vector>

class TcpProcessor : public ThreadEx, public IOwnerSession, public IProcessor
{
public:
    TcpProcessor(uint16_t port);
    virtual void DeleteSession(HARTIPConnection* processor);
    void TerminateSocket();
    ~TcpProcessor();
protected:
    virtual void Run();

    // interface IProcessor
    virtual void DestroyProcessor();
    virtual uint32_t GetClientCount();
    virtual void Start();
    virtual bool_t IsRunning();

private:
    std::vector<OneTcpProcessor*> m_Clients;
    int32_t m_socket;
    sem_t* m_sem;
};

#endif // TCPPROCESSOR_H
