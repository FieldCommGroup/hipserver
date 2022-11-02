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

#include "hssettings.h"
#include "hssettingshandler.h"
#include "hshostnamesystem.h"
#include "debug.h"
#include <unistd.h>

Settings::Settings() : m_version(0), m_isFirstUnitTagSet(false)
{
    char hostname[1024];
    gethostname(hostname, sizeof(hostname) - 1);
    m_hostName = hostname;
}
Settings::~Settings(){}

void Settings::SetLockedHipVersion(int version)
{
    print_to_both(p_toolLogPtr, "Setting hipserver version to %d\n", version);

    if (m_version != 0 || version == 0)
    {
        print_to_both(p_toolLogPtr, "HART-IP Server Version is already configured to %d\n", m_version);
        return;
    }

    m_version = version;

    SettingsHandler::Instance()->AddRootItem("version", to_string(m_version));
}

void Settings::SetLongTag(TpPdu* req)
{
    std::string tag = GetTag(req);

    print_to_both(p_toolLogPtr, "Set Long Tag: %s\n", tag.c_str());

    if(!tag.empty() || tag != m_longTag)
    {
        m_longTag = tag;
    }
}

void Settings::SetLongTag(const std::string& longTag)
{
    m_longTag = longTag;
}

void Settings::SetProcessUnitTag(TpPdu* req)
{
    std::string tag = GetTag(req);

    print_to_both(p_toolLogPtr, "Set Unit Tag: %s\n", tag.c_str());

    if(!tag.empty() || tag != m_processUnitTag)
    {
        m_processUnitTag = tag;
    }

    if(!m_isFirstUnitTagSet)
    {
        //called after the first time getting the unit tag
        print_to_both(p_toolLogPtr, "Attempting to set hostname after getting long tag and unit tag...\n");

        Settings::Instance()->SetHostName(); //setting hostname

        m_isFirstUnitTagSet = true;
    }
}

void Settings::SetProcessUnitTag(const std::string& processUnitTag)
{
    m_processUnitTag = processUnitTag;
}

int Settings::GetLockedHipVersion()
{
    //0 - not provisioned
    //1 - V1
    //2 - V2
    //-255 - bricked
    return m_version;
}

Settings* Settings::Instance()
{
    static Settings instance;
    return &instance;
}

const std::string& Settings::GetHostName()
{
    return m_hostName;
}

errVal_t Settings::CheckHostName(TpPdu* req)
{
    /* Long tag data size = unit tag data size
     so it is possible to use HART_LONGTAG_LEN for both cases.
     Command 545 uses a HOSTNAME which is 64 Bytes.*/

    // #134
    bool isCmd22 = (req->CmdNum() == 22);
    bool isCmd521 = (req->CmdNum() == 521);
    bool isCmd545 = (req->CmdNum() == 545);

    uint32_t length = HART_LONGTAG_LEN;

    if (isCmd545)
    {
        length = (HART_LONGTAG_LEN*2);
    }

    if (length > req->RequestByteCount())
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return PARAM_ERROR;
    }

    errVal_t res = NO_ERROR;
    bool onlyNull = true;

    char lastCharacter = 'a'; //to check hyphen
    // #136
    for(uint32_t i = 0; i < length; ++i)
    {
        char t = req->RequestBytes()[i];

        if(t != '\0')
        {
            onlyNull = false;
        }
        else
        {
            if(i == 0 && (isCmd521 || isCmd545))
            {
                onlyNull = false;
                break;
            }
            else if (i > 0)
            {
                lastCharacter = req->RequestBytes()[i - 1];
                break;
            }
        }

        bool isValidChar = false;

        if (i == 0)
        {
            isValidChar = ((t >= 'a' && t <= 'z') || (t >= 'A' && t <= 'Z') || (t >= '0' && t <= '9'));
        }
        else
        {
            isValidChar = ((t >= 'a' && t <= 'z') || (t >= 'A' && t <= 'Z') || (t >= '0' && t <= '9') || (t == '-') || (t == '\0'));
        }

        if (!isValidChar)
        {
            res = PARAM_ERROR;
            if (isCmd545)
            {
                req->ProcessErrResponse(RC_MULTIPLE_9);
            }
            else
            {
                req->ProcessErrResponse(RC_DEV_SPEC);
            }

            break;
        }

        if(isCmd521 && (i == 30 || i == 31))
        {
            //for checking cmd521 greater than 30 characters
            if(t != '\0')
            {
                res = PARAM_ERROR;
                req->ProcessErrResponse(RC_DEV_SPEC);
                break;
            }
        }
    }

    if ((lastCharacter == '-' && res != PARAM_ERROR) || onlyNull)
    {
        res = PARAM_ERROR;
        if (isCmd545)
        {
            req->ProcessErrResponse(RC_MULTIPLE_9);
        }
        else
        {
            req->ProcessErrResponse(RC_DEV_SPEC);
        }
    }

    return res;
}

errVal_t Settings::CheckCmd22(TpPdu* req)
{
    return CheckHostName(req);
}
errVal_t Settings::CheckCmd521(TpPdu* req)
{
    return CheckHostName(req);
}
errVal_t Settings::CheckCmd545(TpPdu* req)
{ // #134
    return CheckHostName(req);
}

std::string Settings::GetTag(TpPdu* req)
{
    std::string tag;

    if (!req->IsACK())
    {
        req->ProcessErrResponse(RC_DEV_SPEC);
        return tag;
    }
    if (req->ResponseCode() != RC_SUCCESS)
    {
        return tag;
    }

    uint8_t length = HART_LONGTAG_LEN;
    if(req->CmdNum() == 521)
    {
        length = HART_PROCESSUNITTAG_LEN;
    }

    /*  Long tag data size = unit tag data size
        so it is possible to use HART_LONGTAG_LEN for both cases. */
    if (length > req->ResponseByteCount())
    {
        req->ProcessErrResponse(RC_TOO_FEW);
        return tag;
    }

    for (uint32_t i = 0; i < length; ++i)
    {
        char t = req->ResponseBytes()[i];
        if(t == '\0')
        {
            break;
        }
        tag += t;
    }

    return tag;
}

errVal_t Settings::SetHostName()
{
    if(m_longTag.empty() && m_processUnitTag.empty())
    {
        print_to_both(p_toolLogPtr, "Unit tag and long tag both empty.\n");

        return PARAM_ERROR;
    }

    std::string newHostname = "";
    if (m_processUnitTag.empty())
    {
        print_to_both(p_toolLogPtr, "Unit tag empty.\n");

        newHostname = m_longTag;
    }

    else
    {
        if(m_longTag.empty())
        {
            print_to_both(p_toolLogPtr, "Long tag empty.\n");

            newHostname = m_processUnitTag;
        }
        else
        {
            newHostname = m_processUnitTag + "-" + m_longTag;
        }
    }

    if(newHostname != m_hostName)
    {
        print_to_both(p_toolLogPtr, "Attempting to set new hostname...\n");

        m_hostName = newHostname;
        if(setNewHostName(m_hostName) != NO_ERROR)
        {
            dbgp_log("could not set new hostname\n");
        }
    }
    return NO_ERROR;
}

void Settings::Process22(TpPdu* req)
{
    std::string tag = GetTag(req);
    if(!tag.empty() || tag != m_longTag)
    {
        SetLongTag(tag);
        if (SetHostName() == NO_ERROR)
            return;
    }
}
void Settings::Process521(TpPdu* req)
{
     std::string tag = GetTag(req);
    if(!tag.empty() || tag != m_processUnitTag)
    {
        SetProcessUnitTag(tag);
        if (SetHostName() == NO_ERROR)
            return;
    }
}
