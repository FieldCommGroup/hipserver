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

#ifndef _HSREAD_ONLY_COMMANDS_MANAGER_H_
#define _HSREAD_ONLY_COMMANDS_MANAGER_H_

#include <set>
#include <algorithm>
#include "hstypes.h"

class Range
{
public:
    Range(uint32_t min, uint32_t max);
    bool_t IsWithin(uint32_t n) const;
    bool operator < (const Range& r) const;

private:
    uint32_t m_min;
    uint32_t m_max;
};


class ReadOnlyCommandsManager
{
public:
    static ReadOnlyCommandsManager& Instance();
    static void SetFileName(const std::string& name);

public:
    bool_t IsCommandReadOnly(uint32_t cmdNumber) const;
    bool_t IsWriteProtected(uint32_t cmdNumber) const;
    bool_t WriteProtectIsSet() const;
    
private:
    ReadOnlyCommandsManager();

private:
    static std::string s_fileName;

private:
    std::set<Range> m_commandRanges;

    std::set<int> m_writeCommands;
    std::set<int> m_writeProtectedCommands;

};

#endif
