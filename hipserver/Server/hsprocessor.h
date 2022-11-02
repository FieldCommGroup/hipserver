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

#ifndef _HS_PROCESSOR_
#define _HS_PROCESSOR_

#include "hstypes.h"


enum TypeConnection
{
    UDP, 
    TCP
};

class IProcessor
{
protected:
    uint16_t m_port;
public:
    IProcessor(uint16_t port) : m_port(port) {};
    virtual ~IProcessor(){};

    virtual void DestroyProcessor() = 0;
    virtual uint32_t GetClientCount() = 0;
    virtual void Start() = 0;
    uint16_t GetPort()
    {
        return m_port;
    }
    
};

#endif
