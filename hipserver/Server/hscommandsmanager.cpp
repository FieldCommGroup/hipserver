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

#include "hscommandsmanager.h"

#define START_COMMANDS_COUNT 8

typedef std::vector<ICommand *> command_vector;
typedef std::vector<ICommand *>::iterator command_vector_iterator;

CommandsManager::CommandsManager() : m_listCommands(0)
{
    m_listCommands.clear();
}

CommandsManager::~CommandsManager()
{
    for(size_t i = 0; i < m_listCommands.size(); ++i )
    {
        delete m_listCommands[i];
    }
}

void CommandsManager::AddCommand(ICommand* pCommand)
{
    if(pCommand == NULL)
    {
        return;
    }

    m_listCommands.push_back(pCommand);
}

void CommandsManager::RemoveProcessedCommands()
{
    command_vector_iterator iter = m_listCommands.begin();
    while(iter != m_listCommands.end())
    {
        ICommand* command = *iter;

        if(command != NULL && command->m_isProcessed == TRUE)
        {
            m_listCommands.erase(iter);

            delete command;
        }
        else
        {
            ++iter;
        }
    }
}

void CommandsManager::RemoveCommandsBySender(IResponseSender* pSender)
{
    command_vector_iterator iter = m_listCommands.begin();
    while(iter != m_listCommands.end())
    {
        ICommand* command = *iter;

        if(command != NULL && command->m_resSender == pSender)
        {
            m_listCommands.erase(iter);

            delete command;
        }
        else
        {
            ++iter;
        }
    }
}
