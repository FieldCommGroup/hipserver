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

#include <string>
#include <map>
#include <unistd.h>
#include "errval.h"
#include "toolutils.h"

extern std::string SETTINGS_FOLDER_PATH;
extern std::string SETTINGS_FILE_NAME;

using namespace std;

//empty field are skiping for writing
struct ClientSlot
{
    string slot;
    string clientSecurityOptions;
    string password;
    string key;
    string clientIdentifier;
};

class SettingsHandler
{
public:

    SettingsHandler();
    ~SettingsHandler();

    static SettingsHandler* Instance();

    errVal_t SetDefaultSettings();
    errVal_t AddRootItem(string name, string value);
    errVal_t AddSlotItem(ClientSlot value);
    errVal_t LoadSettings();

public:
    string m_settingsFilePath;
    string m_def_version;
    string m_def_supUDPPort;
    string m_def_supTCPPort;
    
    string m_def_syslogIPPort; 
    string m_def_syslogHOSTNAME;
    string m_def_syslogPassword;
    string m_def_syslogKey;
    
    map<int, ClientSlot> m_def_Slots;
};
