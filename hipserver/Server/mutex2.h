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

#ifndef MUTEXEX_H
#define MUTEXEX_H

#include <pthread.h>

class MutexEx
{
private:
    pthread_mutex_t m;

public:
    MutexEx()
    {
        pthread_mutex_init(&m, NULL);
    }

    ~MutexEx()
    {
        pthread_mutex_destroy(&m);
    }

    bool try_lock()
    {
        return pthread_mutex_trylock(&m) == 0;
    }

    void lock()
    {
        pthread_mutex_lock(&m);
    }

    void unlock()
    {
        pthread_mutex_unlock(&m);
    }
};

struct MutexScopeLock
{
    MutexEx& m_mutex;
    MutexScopeLock(MutexEx& m)
        : m_mutex(m)
    {
        m_mutex.lock();
    }

    ~MutexScopeLock()
    {
        m_mutex.unlock();
    }
};

#endif // MUTEXEX_H
