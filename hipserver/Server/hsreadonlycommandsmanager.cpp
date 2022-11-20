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

#include <fstream>
#include <unistd.h>
#include "debug.h"
#include "hsreadonlycommandsmanager.h"
#include <jsoncpp/json/json.h>
#include "factory_reset.h"
#include "toolutils.h"

Range::Range(uint32_t min, uint32_t max) : m_min(min), m_max(max) 
{}
    
    
bool_t Range::IsWithin(uint32_t n) const
{
    return m_min <= n && m_max >= n ? TRUE : FALSE;
}

 bool Range::operator<(const Range& r) const
 {
     return m_min < r.m_min;
 }


//class CReadOnlyCommandsManager
std::string ReadOnlyCommandsManager::s_fileName = "/var/lib/hipServer/readonly.json";

ReadOnlyCommandsManager& ReadOnlyCommandsManager::Instance()
{
    static ReadOnlyCommandsManager instance;
    return instance;    
}

void ReadOnlyCommandsManager::SetFileName(const std::string& name)
{
    s_fileName = name;
}

ReadOnlyCommandsManager::ReadOnlyCommandsManager()
{
    m_writeCommands = {6,17,18,19,22,35,53,79,103,104,107,108,109,116,117,118,521,539,540,541,542,544,545,546,547};
    m_writeProtectedCommands = {6,17,18,19,22,35,53,79,103,104,107,108,109,116,117,118,521,539,540};

    std::ifstream file(s_fileName);
    if(!file.is_open())
    {
        return;
    }

    Json::Reader reader;
    Json::Value root;
    reader.parse(file, root);

    const Json::Value commands = root["commands"];
    for (const Json::Value& command : commands)
    {
        const uint32_t cmdNumber = command.asUInt(); 
        m_commandRanges.insert({cmdNumber, cmdNumber});
    }

    const Json::Value ranges = root["ranges"];
    for (const Json::Value& range : ranges)
    {
        m_commandRanges.insert({range[0].asUInt(), range[1].asUInt()});
    }

    file.close();
}

bool_t ReadOnlyCommandsManager::WriteProtectIsSet() const
{
    #if !defined(__x86_64__)
        //CODE FOR HARWARE PINS on RaspPI3 only
        // Short GPIO 3 (SCL) to any GND pin on WaveShare board
        if (write_protect())
        {
            return TRUE;
        }
    #endif

    return FALSE;
}

bool_t ReadOnlyCommandsManager::IsCommandReadOnly(uint32_t cmdNumber) const
{
    if (m_writeCommands.count(cmdNumber))
    {
        return FALSE;
    }
    return TRUE;

    //return m_writeCommands.find(cmdNumber) != m_writeCommands.end() ? FALSE : TRUE;

    //file implementation
    // return  m_commandRanges.end() != std::find_if(m_commandRanges.begin(), m_commandRanges.end(), 
    //         [&cmdNumber](const Range& r) 
    //         {
    //             return r.IsWithin(cmdNumber) == TRUE;
    //         }) 
    //         ? TRUE : FALSE;
}

bool_t ReadOnlyCommandsManager::IsWriteProtected(uint32_t cmdNumber) const
{
    if (WriteProtectIsSet() == TRUE)
    {
        if (m_writeProtectedCommands.count(cmdNumber))
        {
            return TRUE;
        }
    }
    return FALSE;
}
