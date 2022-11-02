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

#ifndef _HS_RESPONSE_SENDER_H_
#define _HS_RESPONSE_SENDER_H_

#include "errval.h"
#include "tppdu.h"
#include "hstypes.h"
#include <semaphore.h>

class HARTIPConnection;

class IResponseSender
{
    protected:
    sem_t m_sem;
public: 
    virtual errVal_t SendResponse(hartip_msg_t *p_response) = 0;
    virtual errVal_t SendBinaryResponse(void* pData, int size) = 0;
    virtual uint16_t GetSessionNumber() = 0;
    virtual HARTIPConnection* GetSession() = 0;

    virtual IResponseSender* GetParentSender()
    {
        return NULL;
    }

    IResponseSender()
    {
        memset(&m_sem, 0, sizeof(m_sem));
        sem_init(&m_sem, 0, 1);
    }

    errVal_t Wait()
    {
        sem_wait(&m_sem);
        return NO_ERROR;
    }

    virtual ~IResponseSender()
    {
        sem_destroy(&m_sem);
    }

};

#endif
