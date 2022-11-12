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

#include "hssecurityconfiguration.h"
#include <stdlib.h>
#include <algorithm>
#include "hssettingshandler.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "hssettings.h"
#include "hsconnectionmanager.h"
#include "hssyslogger.h"
#include <openssl/rand.h>
#include <iterator>
#include "factory_reset.h"

/* Command 541 and 542 Additional Response Codes*/
#define RC_INVALID_PASSWORD      ((uint8_t)9)
#define RC_PASSWORD_TOO_SHORT    ((uint8_t)10)
#define RC_INVALID_KEY_LENGTH    ((uint8_t)10)
#define RC_NOT_NULLFILLED        ((uint8_t)11)
#define RC_INVALID_SLOT          ((uint8_t)12)
#define RC_DUPE_CLIENT_ID        ((uint8_t)13)
#define RC_CHANGE_FAILED         ((uint8_t)65)
#define RC_INVALID_CLIENT_ID     ((uint8_t)66)
#define RC_CLIENT_ID_TOO_SHORT   ((uint8_t)67)

enum SecurityOptionFlag
{
    ReadOnly = 0x08
};

std::string string_to_hexstring(const std::vector<uint8_t>& in)
{
    std::ostringstream ss;
    
    ss << std::hex << std::setfill('0');
    vector<uint8_t>::const_iterator it;
    for (it = in.begin(); it != in.end(); it++)
    {
        ss << std::setw(2) << static_cast<unsigned>(*it);
    }

    return ss.str();
}

std::string string_to_hex(const std::string& in)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i)
    {
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    }
    return ss.str();
}

std::string hex_to_string(const std::vector<uint8_t>& in)
{
    std::ostringstream ss;
    
    ss << std::hex << std::setfill('0');
    vector<uint8_t>::const_iterator it;
    for (it = in.begin(); it != in.end(); it++)
    {
        ss << *it;
    }

    return ss.str();
}

std::string hex_to_string(const std::string& in)
{
    std::string output;
    if ((in.length() % 2) != 0)
    {
        print_to_both(p_toolLogPtr, "Invalid length of key.\n");
    }
    size_t cnt = in.length() / 2;
    for (size_t i = 0; cnt > i; ++i)
    {
        uint32_t s = 0;
        std::stringstream ss;
        ss << std::hex << in.substr(i * 2, 2);
        ss >> s;
        output.push_back(static_cast<unsigned char>(s));
    }
    return output;
}

SecurityConfigurationTable* SecurityConfigurationTable::Instance()
{
    static SecurityConfigurationTable instance;
    return &instance;
}

bool SecurityConfigurationTable::ValidatePassword(std::string password)
{
    bool upper_case = false;
    bool lower_case = false;
    bool number_case = false;
    bool special_char = false;
    bool result = false;
    std::string listPunct = "!\"#%&'()*,-./:;?@[\\]_{}¡§«¶·»";

    if (password.length() >= 12 && password.length() <= 63)
    {
        for(int i = 0; i < password.size(); i++)
        {
            if(isspace(password[i]))
            {
                //return invalid if space detected
                return false;
            }
            if(password[i] == 173)
            {
                //invalid if soft hyphen detected
                return false;
            }

            upper_case |= ('A' <= password[i] && password[i] <= 'Z');
            lower_case |= ('a' <= password[i] && password[i] <= 'z');
            number_case |= ('0' <= password[i] && password[i] <= '9');
            special_char |= (listPunct.find(password[i]) != std::string::npos);

            result = upper_case && lower_case && number_case && special_char; 
        }
    } 

    return result;  
}

bool_t SecurityConfigurationTable::ValidateClientId(std::string clientId)
{
    for(int i = 0; i < clientId.size(); ++i)
    {
        if(isspace(clientId[i]))
        {
            //return invalid if space detected
            return FALSE;
        }
        if(clientId[i] == 173)
        {
            //invalid if soft hyphen detected
            return FALSE;
        }
    }

    return TRUE;
}

bool_t SecurityConfigurationTable::CheckDuplicateClientId(std::string clientId, uint8_t slotNumber)
{
    for (uint8_t i = 0; i < m_clietsCommunications.size(); i++)
    {
        if (i == slotNumber)
            continue;

        if (m_clietsCommunications[i].m_clientIdentifier == clientId)
            return FALSE;
    }
    return TRUE;
}

void SecurityConfigurationTable::SetClientCommunication(int slotNum, ClientCommunication cliCom)
{
    m_clietsCommunications[slotNum] = cliCom;
}

void SecurityConfigurationTable::ProcessCmd541(TpPdu* req)
{
// 0.7-0.4 Bits-4 Client Security Options (See Common Table 81)
// 0.3-0.0 Unsigned-4 Client slot number. Slot 0 is reserved for HART-IP Security Manager.
// 1 Unsigned-8 Reserved (set to zero)
// 2-65 Latin-1 Password
// 66-193 Latin-1 Client Identifier
    if (Settings::Instance()->GetLockedHipVersion() == HARTIP_PROTOCOL_V1)
    {
        req->ProcessErrResponse(RC_INVALID);
        return;
    }

    uint8_t reqLen = 194;

    if(req->RequestByteCount() < reqLen)
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return;
    }

    uint8_t *reqBuffer = req->RequestBytes();

    ClientCommunication cliCom;
    uint8_t slotNum = 0;

    slotNum = reqBuffer[0] & 0x0F;

    if (slotNum > 0x0F)
    {
        req->ProcessErrResponse(RC_INVALID_SLOT);
        return;
    }

    cliCom.m_cliSecOpt = (reqBuffer[0] >> 4) & 0x0F;
    cliCom.m_reserved = reqBuffer[1];

	const int passwordPosEnd = 65;
    const int passwordPosBegin = 2;
	for (long i = passwordPosBegin; i <= passwordPosEnd; ++i)
	{
		char t = reqBuffer[i];
		if (t == '\0')
		{
            for (long j = i; j <= passwordPosEnd; ++j)
            {
                char k = reqBuffer[j];
                if (k != '\0')
		        {
                    req->ProcessErrResponse(RC_NOT_NULLFILLED);
                    return;
                }
            }
			break;
		}
		cliCom.m_password += t;
	}

	const int identifierPosEnd = 193;
    const int identifierPosBegin = 66;
	for (long i = identifierPosBegin; i <= identifierPosEnd; ++i)
	{
		char t = reqBuffer[i];
		if (t == '\0')
		{
            for (long j = i; j <= identifierPosEnd; ++j)
            {
                char k = reqBuffer[j];
                if (k != '\0')
		        {
                    req->ProcessErrResponse(RC_NOT_NULLFILLED);
                    return;
                }
            }            
			break;
		}
		cliCom.m_clientIdentifier += t;
	}

    if (cliCom.m_clientIdentifier.size() < 8)
    {
        req->ProcessErrResponse(RC_CLIENT_ID_TOO_SHORT);
        return;
    }

    if (cliCom.m_password.size() >= 12) 
    {
        bool_t validClientId = ValidateClientId(cliCom.m_clientIdentifier);
        if (!validClientId)
        {
            req->ProcessErrResponse(RC_INVALID_CLIENT_ID);
            return;
        }

        bool_t uniqueId = CheckDuplicateClientId(cliCom.m_clientIdentifier, slotNum);

        if (!uniqueId)
        {
            req->ProcessErrResponse(RC_DUPE_CLIENT_ID);
            return;
        }

        bool validPassword = ValidatePassword(cliCom.m_password);
        if (!validPassword)
        {
            req->ProcessErrResponse(RC_INVALID_PASSWORD);
            return;
        }

        MutexScopeLock lock(m_mutex);
        if (m_clietsCommunications[slotNum].m_keyLen)
        {
            cliCom.m_keyLen = m_clietsCommunications[slotNum].m_keyLen;
        }

        std::string keyVal = hex_to_string(m_clietsCommunications[slotNum].m_keyVal);

        if (m_clietsCommunications[slotNum].m_keyVal.size())
        {
            cliCom.m_keyVal.clear();

            int maxKeyLength = m_clietsCommunications[slotNum].m_keyVal.size();
            if (maxKeyLength > 32)
            {
                maxKeyLength = 32;
            }
            
            cliCom.m_keyVal.reserve(maxKeyLength);
            
            int currentKeySize = 0;
	    for (auto c: keyVal)
            {
    	        if (currentKeySize == maxKeyLength)
    	            break;
    	        cliCom.m_keyVal.push_back(c);
    	        currentKeySize++;
            }
            
            keyVal = hex_to_string(cliCom.m_keyVal);

            cliCom.m_keyVal.push_back('\0');
        }

        cliCom.m_password = cliCom.m_password;
        SettingsHandler settingsHandler;
        ClientSlot clientSlot = {to_string(slotNum), to_string(cliCom.m_cliSecOpt), cliCom.m_password, keyVal, cliCom.m_clientIdentifier};
        settingsHandler.AddSlotItem(clientSlot);

        m_clietsCommunications[slotNum] = cliCom;

        uint8_t statusBytes = 2;
        uint8_t dataSize = reqLen + statusBytes;
        uint8_t resBuffer[dataSize];
        memset_s(resBuffer, dataSize, 0);
            
        memcpy_s(resBuffer, TPPDU_MAX_DATALEN, req->RequestBytes(), reqLen);

        req->SetByteCount(2 /*RC+DC*/);
        req->ProcessOkResponse(RC_SUCCESS, resBuffer, dataSize);
        req->SetRCStatus(RC_SUCCESS, req->getSavedDevStatus()); // #165
        req->SetCheckSum();

        Settings::Instance()->SetLockedHipVersion(HARTIP_PROTOCOL_VERSION);

        log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command 541");
        log2HipSyslogger(36, 301, 8, NULL, "Client Password Changed");
    }
    else
    {
        req->ProcessErrResponse(RC_PASSWORD_TOO_SHORT);
        return;
    }
}

void SecurityConfigurationTable::ProcessCmd542(TpPdu* req)
{
// 0.7-0.4 Bits-4 Client Security Options (See Common Table 81)
// 0.3-0.0 Unsigned-4 Client slot number. Slot 0 is reserved for HART-IP Security Manager.
// 1 Unsigned-8 Reserved (set to zero)
// 2 Unsigned-8 Key Length (in bytes)
// 3 - 68 Unsigned-8 [ ] Key Value
// 69 - 195 Latin-1 Client Identifier
    if (Settings::Instance()->GetLockedHipVersion() == HARTIP_PROTOCOL_V1)
    {
        req->ProcessErrResponse(RC_INVALID);
        return;
    }

    uint8_t reqLen = 197;

    if(req->RequestByteCount() < reqLen)
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return;
    }

    uint8_t *reqBuffer = req->RequestBytes();

    ClientCommunication cliCom;
    uint8_t slotNum = 0;

    slotNum = reqBuffer[0] & 0x0F;

    if (slotNum > 0x0F)
    {
        req->ProcessErrResponse(RC_INVALID_SLOT);
        return;
    }
    cliCom.m_cliSecOpt = (reqBuffer[0] >> 4) & 0x0F;
    cliCom.m_reserved = reqBuffer[1];
    cliCom.m_keyLen = reqBuffer[2];

    if (cliCom.m_keyLen < MIN_KEY_LENGTH || cliCom.m_keyLen > MAX_KEY_LENGTH)
    {
        req->ProcessErrResponse(RC_INVALID_KEY_LENGTH);
        return;
    }

    //check client identifier is null filled
    const int identifierPosEnd = 196;
    const int identifierPosBegin = 69;
	for (long i = identifierPosBegin; i <= identifierPosEnd; ++i)
	{
		char t = reqBuffer[i];
		if (t == '\0')
		{
            for (long j = i; j <= identifierPosEnd; ++j)
            {
                char k = reqBuffer[j];
                if (k != '\0')
		        {
                    req->ProcessErrResponse(RC_NOT_NULLFILLED);
                    return;
                }
            }            
			break;
		}
		cliCom.m_clientIdentifier += t;
	}

    if (cliCom.m_clientIdentifier.size() < 8)
    {
        req->ProcessErrResponse(RC_CLIENT_ID_TOO_SHORT);
        return;
    }

    bool_t validClientId = ValidateClientId(cliCom.m_clientIdentifier);
    if (!validClientId)
    {
        req->ProcessErrResponse(RC_INVALID_CLIENT_ID);
        return;
    }

    bool_t uniqueId = CheckDuplicateClientId(cliCom.m_clientIdentifier, slotNum);

    if (!uniqueId)
    {
        req->ProcessErrResponse(RC_DUPE_CLIENT_ID);
        return;
    }

    //check key value is null filled
	const int keyPosEnd = 68;
    const int keyPosBegin = 3;
	for (long i = keyPosBegin; i <= keyPosEnd; ++i)
	{
		char t = reqBuffer[i];

        //need to add checking when i is 21 since if this is not checked, 00s in the middle of the psk would trigger error code 11
		if (i == 21 && t == '\0')
		{
            for (long j = i; j <= keyPosEnd; ++j)
            {
                char k = reqBuffer[j];
                if (k != '\0')
		        {
                    req->ProcessErrResponse(RC_NOT_NULLFILLED);
                    return;
                }
            }
			break;
		}
        uint8_t val = reqBuffer[i];
        print_to_both(p_toolLogPtr, "%02x",reqBuffer[i]);
        cliCom.m_keyVal.push_back(reqBuffer[i]);
	}  

    int crc = 0xFFFF;
    int polynomial = 0x1021; //x^12+x^5+1 (only 2byte)

    if(cliCom.m_keyVal.size() != cliCom.m_keyLen)
    {
        //make sure the keyval retrieved is the same as the one sent over from the client. 
        //if not return an error to prevent crashes for unevent keyvalues.

        req->ProcessErrResponse(RC_INVALID_KEY_LENGTH);
        return;
    }

    for(int k = 0 ; k < cliCom.m_keyVal.size() - 2; ++k)
    {
        uint8_t b = cliCom.m_keyVal[k];
        for (int i = 0; i < 8; i++) 
        {
            bool bit = ((b >> (7 - i) & 1) == 1);
            bool c15 = ((crc >> 15 & 1) == 1);
            crc <<= 1;
            if (c15 ^ bit)
                crc ^= polynomial;
        }
    }

    crc &= 0xffff;

    int sendedCrc = (cliCom.m_keyVal[cliCom.m_keyVal.size() - 2] << 8) + (cliCom.m_keyVal[cliCom.m_keyVal.size() - 1] & 0x0FF);

    if (crc != sendedCrc)
    {
        req->ProcessErrResponse(RC_CHANGE_FAILED);
        return;
    }

    MutexScopeLock lock(m_mutex);
    if (!m_clietsCommunications[slotNum].m_password.empty())
    {
        cliCom.m_password = m_clietsCommunications[slotNum].m_password;
    }
    cliCom.m_keyVal.pop_back();
    cliCom.m_keyVal.pop_back();
    
    cliCom.m_keyLen = cliCom.m_keyVal.size();

    m_clietsCommunications[slotNum] = cliCom;

    std::string keyVal = string_to_hexstring(cliCom.m_keyVal);
    SettingsHandler settingsHandler;
    ClientSlot clientSlot = {to_string(slotNum), to_string(cliCom.m_cliSecOpt), cliCom.m_password, keyVal, cliCom.m_clientIdentifier};
    settingsHandler.AddSlotItem(clientSlot);

    cliCom.m_keyVal.clear();
    for (auto c: keyVal)
    {
    	cliCom.m_keyVal.push_back(c);
    }

    cliCom.m_keyVal.push_back('\0');
    m_clietsCommunications[slotNum] = cliCom;

    uint8_t statusBytes = 2;
    uint8_t dataSize = reqLen + statusBytes;
    uint8_t resBuffer[dataSize];
    memset_s(resBuffer, dataSize, 0);
    
    memcpy_s(resBuffer, dataSize, req->RequestBytes(), reqLen);

    req->SetByteCount(2 /*RC+DC*/);
    req->ProcessOkResponse(RC_SUCCESS, resBuffer, dataSize);
    req->SetRCStatus(RC_SUCCESS, req->getSavedDevStatus()); // #165
    req->SetCheckSum();

    Settings::Instance()->SetLockedHipVersion(HARTIP_PROTOCOL_VERSION);

    log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command 542");
    log2HipSyslogger(36, 300, 8, NULL, "Pre-Shared Key Changed");
}

void SecurityConfigurationTable::AddConnection(SSL* ssl, const int& slotNumber)
{
    if (m_clietsCommunications.find(slotNumber) == m_clietsCommunications.end())
    {
        return;
    }

    m_connections[slotNumber].push_back(ssl);
}

void SecurityConfigurationTable::DeleteConnection(SSL* ssl)
{
    for (std::pair<const int, std::vector<SSL*>>& connection : m_connections)
    {
        std::vector<SSL*>& sslList = connection.second;
        std::vector<SSL*>::iterator it = std::find(sslList.begin(), sslList.end(), ssl);
        if (it != sslList.end())
        {
            sslList.erase(it);
            return;
        }
    }

    return;
}

bool_t SecurityConfigurationTable::IsConnectionReadOnly(SSL* ssl)
{
    for (std::pair<const int, std::vector<SSL*>>& connection : m_connections)
    {
        std::vector<SSL*>& sslList = connection.second;
        std::vector<SSL*>::iterator it = std::find(sslList.begin(), sslList.end(), ssl);
        
        if (it != sslList.end())
        {
            SlotMap::iterator it1 = m_clietsCommunications.find(connection.first);
            return  it1 != m_clietsCommunications.end() &&
                    it1->second.m_cliSecOpt & SecurityOptionFlag::ReadOnly
                    ? TRUE 
                    : FALSE;
        }
    }

    return FALSE;
}

int SecurityConfigurationTable::GetSlotNumber(SSL* ssl)
{
    for (std::pair<const int, std::vector<SSL*>>& connection : m_connections)
    {
        std::vector<SSL*>& sslList = connection.second;
        std::vector<SSL*>::iterator it = std::find(sslList.begin(), sslList.end(), ssl);
        
        if (it != sslList.end())
        {
            SlotMap::iterator it1 = m_clietsCommunications.find(connection.first);

            return it1->first;
        }
    }

    return 0;
}

void SecurityConfigurationTable::FinishConfigure()
{
    print_to_both(p_toolLogPtr, "Finish configuration\n");
    
    MutexScopeLock lock(m_mutex);
    m_isConfigured = true;
    const int count = 16;
    ClientCommunication& first = m_clietsCommunications[0];

    // check if unmodified, you can only reach this if you're v2 and you haven't executed 541/542
    if(Settings::Instance()->GetLockedHipVersion() == 0)
    {
        Settings::Instance()->SetLockedHipVersion(-255);// bricked hipversion
    }

}

bool SecurityConfigurationTable::IsConfigured()
{
    MutexScopeLock lock(m_mutex);
    return m_isConfigured;
}

SecurityConfigurationTable::SecurityConfigurationTable() : c_defaultPassword("!1HARTIPhighway"),
    c_defaultIdentity("HART-IPClient"), m_isConfigured(false)
{
    c_defaultKey.push_back(0x77);
    c_defaultKey.push_back(0x77);
    c_defaultKey.push_back(0x77);
    c_defaultKey.push_back(0x2E);
    c_defaultKey.push_back(0x68);
    c_defaultKey.push_back(0x61);
    c_defaultKey.push_back(0x72);
    c_defaultKey.push_back(0x74);
    c_defaultKey.push_back(0x63);
    c_defaultKey.push_back(0x6F);
    c_defaultKey.push_back(0x6D);
    c_defaultKey.push_back(0x6D);
    c_defaultKey.push_back(0x2E);
    c_defaultKey.push_back(0x6F);
    c_defaultKey.push_back(0x72);
    c_defaultKey.push_back(0x67);
}

void SecurityConfigurationTable::SetDefaultValue()
{
    ClientCommunication cliCom;

	cliCom.m_clientIdentifier = c_defaultIdentity;
    cliCom.m_password = c_defaultPassword;

    for(int i = 0; i < c_defaultKey.size(); ++i)
    {
        cliCom.m_keyVal.push_back(c_defaultKey[i]);
    }

    cliCom.m_keyLen = cliCom.m_keyVal.size();

    m_clietsCommunications[0] = cliCom;

    m_isConfigured = false;
}

