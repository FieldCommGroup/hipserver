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

#include "hssettingshandler.h"
#include "hsnetworkmanager.h"
#include "hssyslogger.h"
#include "hssecurityconfiguration.h"
#include "hssettings.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <jsoncpp/json/json.h>
#include <fstream>
#include <iostream>

bool isFileExist(const char* file)
{
    if(file == NULL)
    {
        return false;
    }
    return access(file, F_OK) == 0;
}

SettingsHandler* SettingsHandler::Instance()
{
    static SettingsHandler settingsHandler;
    return &settingsHandler;    
}

std::string convert_utf8_to_latin1(const std::string& in)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i)
    {
    	unsigned int shiftUtf8Value = 0xc2;
    	unsigned int byteValueCurrentIndex = static_cast<unsigned int>(static_cast<unsigned char>(in[i]));

    	if (shiftUtf8Value == byteValueCurrentIndex || (shiftUtf8Value + 0x01) == byteValueCurrentIndex)
    	{
    		unsigned int incrementValue = 0x00;
    		if ((shiftUtf8Value + 0x01) == byteValueCurrentIndex)
    		{
    			incrementValue = 0x40;
    		}
    		i++;
    		byteValueCurrentIndex = static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    		byteValueCurrentIndex += incrementValue;
    	}
        ss << static_cast<unsigned char>(byteValueCurrentIndex);
    }
    return ss.str();
}


SettingsHandler::SettingsHandler()
{
    m_settingsFilePath = SETTINGS_FOLDER_PATH + "/" + SETTINGS_FILE_NAME;

    m_def_version = "0";

    m_def_supUDPPort = "0";
    m_def_supTCPPort = "0";
    
    m_def_syslogIPPort = "514"; 
    m_def_syslogHOSTNAME = "";
    m_def_syslogPassword = "";
    m_def_syslogKey = "";
    
    ClientSlot clientSlot = {"0", "0", "!1HARTIPhighway", "7777772e68617274636f6d6d2e6f7267", "HART-IPClient"};
    m_def_Slots.insert(make_pair(0, clientSlot));
}
SettingsHandler::~SettingsHandler(){}

errVal_t SettingsHandler::SetDefaultSettings()
{
    if(isFileExist(m_settingsFilePath.c_str()))
	{
        remove(m_settingsFilePath.c_str()); // Remove old settings file
	}
	
    Json::Value root(Json::objectValue);

    root["version"] = m_def_version;
	root["supUDPPort"] = m_def_supUDPPort;
    root["supTCPPort"] = m_def_supTCPPort;

    root["syslogIPPort"] = m_def_syslogIPPort;
    root["syslogHOSTNAME"] = m_def_syslogHOSTNAME;
    root["syslogPassword"] = m_def_syslogPassword;
    root["syslogKey"] = m_def_syslogKey;

    Json::Value slots(Json::arrayValue);
	for (map<int, ClientSlot>::iterator it = m_def_Slots.begin(); it != m_def_Slots.end(); ++it)
	{
        Json::Value slot(Json::objectValue);

        slot["slot"] = to_string(it->first);
        slot["clientSecurityOptions"] = it->second.clientSecurityOptions;
        slot["password"] = it->second.password;
        slot["key"] = it->second.key;
        slot["clientIdentifier"] = it->second.clientIdentifier;
        slots.append(slot);
    }
    root["slots"] = slots;
    system(("mkdir -p " + SETTINGS_FOLDER_PATH).c_str()); // Creating a directory
    Json::FastWriter writer;
    std::ofstream file;

    file.open(m_settingsFilePath);
    if(!file.is_open())
    {
        print_to_both(p_toolLogPtr, "Can not create settings file.\n");
        return LINUX_ERROR;
    }

    file << writer.write(root);
    file.close();

    return NO_ERROR;
}

errVal_t SettingsHandler::AddRootItem(string name, string value)
{

    if(!isFileExist(m_settingsFilePath.c_str()))
	{
        if (SetDefaultSettings() == LINUX_ERROR) 
        {
            return LINUX_ERROR;      
        }
    }

    std::ifstream ifile;
    ifile.open(m_settingsFilePath);
    if(!ifile.is_open())
    {
        print_to_both(p_toolLogPtr, "I/O error while reading file.\n");
        return LINUX_ERROR;
    }
    Json::Value root;
    Json::Reader reader;
    if(!reader.parse(ifile, root))
    {
        print_to_both(p_toolLogPtr, ("Parse error: " + reader.getFormattedErrorMessages() + "\n").c_str());
        ifile.close();
        return LINUX_ERROR;
    } 
    ifile.close();

    root[name] = value;


    std::ofstream ofile;
    ofile.open(m_settingsFilePath);
    if(!ofile.is_open())
    {
        print_to_both(p_toolLogPtr, ("I/O error while writing file: " + m_settingsFilePath + "\n").c_str());
        return LINUX_ERROR;
    }
    Json::FastWriter writer;
    ofile << writer.write(root);
    ofile.close();
    return NO_ERROR;
}

errVal_t SettingsHandler::AddSlotItem(ClientSlot value)
{
    if(!isFileExist(m_settingsFilePath.c_str()))
	{
        SetDefaultSettings();      
    }

   std::ifstream ifile;
    ifile.open(m_settingsFilePath);
    if(!ifile.is_open())
    {
        print_to_both(p_toolLogPtr, "I/O error while reading file.\n");
        return LINUX_ERROR;
    }
    Json::Value root;
    Json::Reader reader;
    if(!reader.parse(ifile, root))
    {
        print_to_both(p_toolLogPtr, ("Parse error: " + reader.getFormattedErrorMessages() + "\n").c_str());
        ifile.close();
        return LINUX_ERROR;
    } 
    ifile.close();

    Json::Value& slots = root["slots"];
    if(slots.isNull())
    {
        slots = Json::Value(Json::arrayValue);
        root["slots"] = slots;
        
        //slot.add("slot", Setting::TypeString) = value.slot;
        //slot.add("clientSecurityOptions", Setting::TypeString) = value.clientSecurityOptions;
        //slot.add("password", Setting::TypeString) = value.password;
        //slot.add("key", Setting::TypeString) = value.key;
        //slot.add("clientIdentifier", Setting::TypeString) = value.clientIdentifier;
    }

    bool slotExisted = false;
    int count = slots.size();
    for(int i = 0; i < count; ++i)
    {
        Json::Value &slot = slots[i];
        if(slot.isNull())
            continue;
        if(!slot.isMember("slot"))
        {
            continue;
        }
        std::string slotNum = slot["slot"].asString();
        if (slotNum == value.slot)
        {
            if (value.clientSecurityOptions != "")
            {
                slot["clientSecurityOptions"] = value.clientSecurityOptions;
            }
            if (value.password != "")
            {
                slot["password"] = value.password;
            }
            if (value.key != "")
            {

                slot["key"] = value.key;
            }
            if (value.clientIdentifier != "")
            {
                slot["clientIdentifier"] = value.clientIdentifier;
            }
            slotExisted = true;
            break;
        }
    }

    if (!slotExisted)
    {
        Json::Value newSlot(Json::objectValue);
        
        newSlot["slot"] = value.slot;
        newSlot["clientSecurityOptions"] = value.clientSecurityOptions;
        newSlot["password"] = value.password;
        newSlot["key"] = value.key;
        newSlot["clientIdentifier"] = value.clientIdentifier;
        slots.append(newSlot);
    }               

  
    std::ofstream ofile;
    ofile.open(m_settingsFilePath);
    if(!ofile.is_open())
    {
        print_to_both(p_toolLogPtr, ("I/O error while writing file: " + m_settingsFilePath + "\n").c_str());
        return LINUX_ERROR;
    }
    Json::FastWriter writer;
    ofile << writer.write(root);
    ofile.close();

    return NO_ERROR;
}

errVal_t SettingsHandler::LoadSettings()
{
    bool isFinishedConfigure = true;
    if(!isFileExist(m_settingsFilePath.c_str()))
	{
        isFinishedConfigure = false;
        SecurityConfigurationTable::Instance()->SetDefaultValue();
        SetDefaultSettings();      
    }

   std::ifstream ifile;
    ifile.open(m_settingsFilePath);
    if(!ifile.is_open())
    {
        print_to_both(p_toolLogPtr, "I/O error while reading file.\n");
        return LINUX_ERROR;
    }
    Json::Value root;
    Json::Reader reader;
    if(!reader.parse(ifile, root))
    {
        print_to_both(p_toolLogPtr, ("Parse error: " + reader.getFormattedErrorMessages() + "\n").c_str());
        ifile.close();
        return LINUX_ERROR;
    } 
    ifile.close();

    int deviceVersion = atoi(root["version"].asString().c_str());
    if (deviceVersion != 0)
    {
        print_to_both(p_toolLogPtr, "Locking HART-IP Server to V%d\n", deviceVersion);
        Settings::Instance()->SetLockedHipVersion(deviceVersion);
    }

    int supUDPPort = atoi(root["supUDPPort"].asString().c_str());
    if (supUDPPort != 0)
    {
        if (NO_ERROR != NetworkManager::Instance()->CreateNewProcessor(supUDPPort, UDP))
        {
            print_to_both(p_toolLogPtr, "Failed to load Supplemental UDP port.\n");
        }
    }

    int supTCPPort = atoi(root["supTCPPort"].asString().c_str());
    if (supTCPPort != 0)
    {    
        if (NO_ERROR != NetworkManager::Instance()->CreateNewProcessor(supTCPPort, TCP))
        {
            print_to_both(p_toolLogPtr, "Failed to load Supplemental TCP port.\n");
        }
    }

    int syslogIPPort = atoi(root["syslogIPPort"].asString().c_str());
    if (syslogIPPort != 0)
    {
        setPortToHipSyslogger(syslogIPPort);
    }

    string syslogHOSTNAME = root["syslogHOSTNAME"].asString();
    if (syslogHOSTNAME != "")
    {
        setHostnameToHipSyslogger(syslogHOSTNAME.c_str());
    }

    string syslogPassword = root["syslogPassword"].asString();
    if (syslogPassword != "")
    {
        setPasswordToHipSyslogger(syslogPassword.c_str());
    }

    string syslogKey = root["syslogKey"].asString();
    if (syslogKey != "")
    {
        setPreSharedKeyToHipSyslogger(syslogKey.c_str());
    }

    Json::Value &slotsSettings = root["slots"];
    if(slotsSettings.isNull())
    {   
        if(isFinishedConfigure)
            SecurityConfigurationTable::Instance()->FinishConfigure();
        return NO_ERROR;
    }
    int count = slotsSettings.size();
    for(int i = 0; i < count; ++i)
    {
        Json::Value &slot = slotsSettings[i];

        ClientCommunication cliCom;

        int slotNum = atoi(slot["slot"].asString().c_str());
        int clientSecurityOptions = atoi(slot["clientSecurityOptions"].asString().c_str());
        string password = slot["password"].asString();
        string clientIdentifier = slot["clientIdentifier"].asString();
        string key = slot["key"].asString();
        for (auto c : key)
        {
            cliCom.m_keyVal.push_back(c);
        }
	
        cliCom.m_keyVal.push_back('\0');

        cliCom.m_password = convert_utf8_to_latin1(password);
        cliCom.m_cliSecOpt = clientSecurityOptions;
        cliCom.m_keyLen = cliCom.m_keyVal.size();
        cliCom.m_clientIdentifier = convert_utf8_to_latin1(clientIdentifier);
        
        print_to_both(p_toolLogPtr, "\nID: %s \nPW: %s\n", cliCom.m_clientIdentifier.c_str(), cliCom.m_password.c_str());

        SecurityConfigurationTable::Instance()->SetClientCommunication(slotNum, cliCom);
    }
    if(isFinishedConfigure)
        SecurityConfigurationTable::Instance()->FinishConfigure();


    return NO_ERROR;
}
