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

#ifndef _HS_SECURITY_CONFIGURATION_
#define _HS_SECURITY_CONFIGURATION_
#include "mutex2.h"
#include <string>
#include <map>
#include <vector>
#include "tppdu.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>

#define MIN_PSK_LENGTH 16 /* 128bits */
#define CRC_LENGTH 2
#define MIN_KEY_LENGTH (MIN_PSK_LENGTH + CRC_LENGTH)
#define MAX_KEY_LENGTH 66

struct ClientCommunication
{

	ClientCommunication()
{
    m_cliSecOpt = 0;
    m_reserved = 0;
    m_password = "";
    m_keyLen = 0;
    m_clientIdentifier = "";
}
    uint8_t m_cliSecOpt;
    uint8_t m_reserved;
    uint8_t m_keyLen;
    std::vector<uint8_t> m_keyVal;    
    std::string m_password;
    std::string m_clientIdentifier;
};

using Slot = std::pair<int, ClientCommunication>;
using SlotMap = std::map<Slot::first_type, Slot::second_type>;

class SecurityConfigurationTable
{
private:
    const std::string c_defaultPassword;
    const std::string c_defaultIdentity;
    std::vector<uint8_t> c_defaultKey;

    MutexEx m_mutex;
    bool    m_isConfigured;
    bool ValidatePassword(std::string password);
    bool_t ValidateClientId(std::string clientId);
    bool_t CheckDuplicateClientId(std::string clientId, uint8_t slotNumber);
    SecurityConfigurationTable();
    

    SlotMap m_clietsCommunications;
    std::map<int, std::vector<SSL*>> m_connections; // slot number + list of connections


public:
    std::map<int, ClientCommunication>& Slots() { return m_clietsCommunications; }

public:
    static SecurityConfigurationTable* Instance();

    void SetDefaultValue();
    void AddConnection(SSL* ssl, const int& slotNumber);
    void DeleteConnection(SSL* ssl);
    bool_t IsConnectionReadOnly(SSL* ssl);
    int GetSlotNumber(SSL* ssl);

    void SetClientCommunication(int slotNum, ClientCommunication cliCom);

    void ProcessCmd541(TpPdu* req);
    void ProcessCmd542(TpPdu* req);

    bool IsConfigured();
    void FinishConfigure();   
};

#endif
