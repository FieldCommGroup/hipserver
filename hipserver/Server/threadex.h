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

#ifndef THREADEX_H
#define THREADEX_H

#include "pthread.h"
#include "datatypes.h"
/**
*  Abstract class for Thread management
*/
class ThreadEx
{
 public:

     /**
      *   Default Constructor for thread
      */
    ThreadEx();

    /**
      *   virtual destructor
      */
    virtual ~ThreadEx();


    /**
     *   Function to start thread.
     */
    void Start();
    
    void ThreadStarted();


    /**
     *   Function to join thread.
     */
    void Join();

     /**
     *   Function to stop thread.
     */
    void Stop();

     /**
     *   Function to check running thread.
     */
    bool_t IsRunning();

 protected:
    /**
      *   Thread functionality Pure virtual function  , it will be re implemented in derived classes
      */
    virtual void Run() = 0;
    bool_t		m_isRunning;
 private:


     /**
     *   private Function to create thread.
     */
     void CreateThread();

     /**
     *   Call back Function Passing to pthread create API
     */
     static void* ThreadFunc(void* pTr);

     /**
     *   Internal pthread ID..
     */
     pthread_t m_Tid;
     

};
#endif // THREADEX_H
