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

#include "errno.h"
#include "stdio.h"
#include <pthread.h>
#include <cstdlib>
#include "threadex.h"

ThreadEx::ThreadEx() : 
m_Tid(0), m_isRunning(FALSE)
{

}

ThreadEx::~ThreadEx()
{

}

void ThreadEx::Start()
{
    m_isRunning = TRUE;
   CreateThread();
   
}

void ThreadEx::ThreadStarted()
{
    m_isRunning = TRUE;
}

void ThreadEx::Join()
{
    int rc = pthread_join(m_Tid, NULL);
    if ( rc != 0 && IsRunning())
    {
        perror("Error in thread join.... (pthread_join())");
    }
}

void ThreadEx::Stop()
{
    m_isRunning = FALSE;
}

bool_t ThreadEx::IsRunning()
{
    return m_isRunning;
}

void* ThreadEx::ThreadFunc(void* pTr)
{
    ThreadEx* pThis = static_cast<ThreadEx*>(pTr);
    pThis->Run();
    pthread_exit(0);
}

void ThreadEx::CreateThread()
{
    int rc = pthread_create (&m_Tid, NULL, ThreadFunc,this);
    if ( rc != 0 )
    {
        perror("Error in thread creation... (pthread_create())");
    }
}
