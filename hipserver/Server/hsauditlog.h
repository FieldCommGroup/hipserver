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

#ifndef __HS_AUDIT_LOG_H__
#define __HS_AUDIT_LOG_H__

#include "hstypes.h"
#include <vector>
#include <map>
#include "hsconnectionmanager.h"
#include "tppdu.h"
#include "mutex2.h"
#include "hsresponsesender.h"
#include "hscommands.h"
#include <signal.h>

#define EVENT_1200 SIGRTMAX - 1

#define CONFIGURATION_COUNTER_INDEX 14

#define AuditLogger AuditLog::Instance()

void Handle1200Event();
/*  
0x0001 = Unable to locate syslog Server
0x0002 = Syslog Server located but Connection Failed
0x0004 = Insecure syslog connection
*/
enum ServerStatus
{
   UnableToLocateSyslogServer = 0x0001,
   SyslogServerConnectionFailed = 0x0002,
   InsecureSyslogConnection = 0x0004
};

/*
0x0001 = Writes Occurred
0x0002 = Bad Session Initialization
0x0004 = Aborted Session
0x0008 = Session Timeout
0x0010 = In-Secure Session
*/

enum SessionStatus
{
    WritesOccured = 0x0001,
    BadSessionInitialization = 0x0002,
    AbortedSession = 0x0004,
    SessionTimeout = 0x0008,
    InsecureSession = 0x0010
};

struct StatisticSession
{

	StatisticSession()
{
    m_timeConnected = -1 ;
    m_timeDisconnected = -1;

    m_stxCounter = 0;
    m_ackCounter = 0;
    m_backCounter = 0;
    m_startingConfiguration = 0;
    m_endingConfiguration = 0;

    m_status = 0;

}
    time_t m_timeConnected;
    time_t m_timeDisconnected;

    uint32_t m_stxCounter;
    uint32_t m_ackCounter;
    uint32_t m_backCounter;
    uint32_t m_startingConfiguration;
    uint32_t m_endingConfiguration;
    sockaddr_in_t m_address;
    sockaddr_in6_t m_address6;

    uint16_t m_serverPort;

    uint16_t m_status;
};

class UpdaterEndConfigurationCounter : public TPCommand
{
    std::vector<StatisticSession*> m_closedSession;
    std::vector<std::pair<hartip_msg_t, IResponseSender*> > m_message5Reqests;
    bool_t m_isProcessing;

    MutexEx m_mutex;
public:

    UpdaterEndConfigurationCounter();
    virtual errVal_t SendMessage(TpPdu tppdu, int transaction);

    void AddMessage5Requst(hartip_msg_t& request, IResponseSender* sender);
    void AddRecordDisconnectedSession(StatisticSession* session);
    void RemoveRequst(HARTIPConnection* session);
    void RemoveCloseSession(StatisticSession* record);
};

class AuditLog
{
protected:
    time_t m_powerUp;
    time_t m_lastSecurityChange;

    uint16_t m_statusSyslogServer;
    uint16_t m_serverPort;
    std::vector<StatisticSession*> m_tableRecords;
    std::map<HARTIPConnection*, StatisticSession*> m_mapActiveSessions;
    uint16_t m_currentIndex;
    uint16_t m_countRecords;

    UpdaterEndConfigurationCounter m_updaterConfigCounter;
    MutexEx m_mutex;

    timer_t* m_idTimer;
    uint32_t m_lastConfigurationCounter;
    AuditLog();
    AuditLog(AuditLog& second);
    ~AuditLog();
    AuditLog& operator=(AuditLog& second);

    StatisticSession* FindRecord(HARTIPConnection* session);
    errVal_t StartTimer(bool_t isOn = TRUE);

    void Handle1200Event();

    char* GetSysLogString(StatisticSession *session);


public:
    static AuditLog* Instance();
    errVal_t SendLogs(hartip_msg_t* pResponce, IResponseSender* sender);

    void UpdateSecurituChange();
    void ServerStarted(uint16_t port);
    void SetStatusSyslogServer(uint16_t syslog, bool_t isOn = TRUE);
    
    errVal_t CreateNewRecordAuditLog(HARTIPConnection* session, uint16_t portNumber);

    errVal_t UpdateAckCounter(HARTIPConnection *session, uint16_t count = 1);
    errVal_t UpdateBackCounter(HARTIPConnection *session);
    errVal_t UpdateStxCounter(HARTIPConnection *session);

    errVal_t SetStatusSession(HARTIPConnection *session, uint16_t status, bool_t isOn = TRUE);
    errVal_t SessionDisconnected(HARTIPConnection *session);

    errVal_t UpdateEndConfigurationCounter(StatisticSession* session, uint16_t value);
    errVal_t UpdateEndConfigurationCounterActiveSession(uint16_t value);
    errVal_t UpdateStartConfigurationCounter(HARTIPConnection* session, uint16_t value);

    errVal_t ProcessMessage5(hartip_msg_t& pResponce, IResponseSender* sender);

    friend void Handle1200Event();
};

#endif
