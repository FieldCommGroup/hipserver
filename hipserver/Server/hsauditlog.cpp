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

#include "hsauditlog.h"
#include "debug.h"
#include "hssyslogger.h"
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tpdll.h"

#define MAX_RECORD_COUNT 128
#define NOT_FOUND_RECORD 255

#define FIRST_RECORD_INDEX 0
#define NUMBER_RECORDS_INDEX 1

#define START_RECORD_LENGTH 1
#define COUNT_RECORD_LENGTH 1
#define STARTUP_SERVER_LENGTH 8
#define SECURITY_CHANGE_LENGTH 8
#define SERVER_STATUS_LENGTH 2
#define RECORD_SIZE_LENGTH 2
#define IPV4_ADDRESS_LENGTH 4
#define IPV6_ADDRESS_LENGTH 16
#define CLIENT_PORT_LENGTH 2
#define SERVER_PORT_LENGTH 2
#define CONNECTED_TIME_LENGTH 8
#define DISCONNECTED_TIME_LENGTH 8
#define SESSION_STATUS_LENGTH 2
#define START_CONFIGURATION_LENGTH 2
#define END_CONFIGURATION_LENGTH 2
#define COUNTER_STX_LENGTH 4
#define COUNTER_ACK_LENGTH 4
#define COUNTER_BACK_LENGTH 4

#define DEVICE_SPECIFICATION_ERROR 6
#define WARNING_CODE 8

#define RECORD_LENGTH (IPV4_ADDRESS_LENGTH + IPV6_ADDRESS_LENGTH + \
                         CLIENT_PORT_LENGTH + SERVER_PORT_LENGTH + \
                         CONNECTED_TIME_LENGTH + DISCONNECTED_TIME_LENGTH +\
                         SESSION_STATUS_LENGTH + START_CONFIGURATION_LENGTH + \
                         END_CONFIGURATION_LENGTH + COUNTER_STX_LENGTH + \
                         COUNTER_ACK_LENGTH + COUNTER_BACK_LENGTH)

#define SERVER_LOG_LENGTH (START_RECORD_LENGTH + COUNT_RECORD_LENGTH + \
                         STARTUP_SERVER_LENGTH + SECURITY_CHANGE_LENGTH + \
                         SERVER_STATUS_LENGTH + RECORD_SIZE_LENGTH)

#define HOUR 3600

#define SYSLOG_STRING_LENGTH 50 // "xxx.xxx.xxx.xxx:ppppp: sssss, ttttt, aaaaa, bbbbb" = 49 + 1 (\0) = 50 

#define AUDIT_LOG_HEADER_SIZE 2


void Handle1200Event()
{
    AuditLogger->Handle1200Event();
}

UpdaterEndConfigurationCounter::UpdaterEndConfigurationCounter() : TPCommand(TpPduStore(), NULL, FALSE)
{
    memset_s(m_tppduStore.Store(), TPPDU_MAX_FRAMELEN, 0);
    TpPdu pdu(m_tppduStore);
    *pdu.Delim() = *pdu.Delim() | TPDELIM_STX_POLL;
}

errVal_t UpdaterEndConfigurationCounter::SendMessage(TpPdu tppdu, int transaction)
{
    MutexScopeLock lock(m_mutex);
    uint16_t configurationCounter = 0;
    memcpy_s(&configurationCounter, sizeof(configurationCounter), tppdu.ResponseBytes() + CONFIGURATION_COUNTER_INDEX, sizeof(configurationCounter));

    configurationCounter = ntohs(configurationCounter);

    for(int i = 0 ; i < m_closedSession.size(); ++i)
    {
        AuditLogger->UpdateEndConfigurationCounter(m_closedSession[i], configurationCounter);
    }
    m_closedSession.clear();
    AuditLogger->UpdateEndConfigurationCounterActiveSession(configurationCounter);


    for(int i = 0; i < m_message5Reqests.size(); ++i)
    {
        AuditLogger->SendLogs(&m_message5Reqests[i].first, m_message5Reqests[i].second);
    }
    m_message5Reqests.clear();

    m_isProcessing = FALSE;
}

void UpdaterEndConfigurationCounter::AddMessage5Requst(hartip_msg_t& request, IResponseSender* sender)
{
    MutexScopeLock lock(m_mutex);

    m_message5Reqests.push_back(std::pair<hartip_msg_t, IResponseSender*>(request, sender));

    if( m_isProcessing == FALSE)
    {
    	setAlMsg(TRUE); // #61
        Execute();
        m_isProcessing = TRUE;
        setAlMsg(FALSE); // #61
    }

}
void UpdaterEndConfigurationCounter::AddRecordDisconnectedSession(StatisticSession* session)
{
    MutexScopeLock lock(m_mutex);

    m_closedSession.push_back(session);

    if( m_isProcessing == FALSE)
    {
    	setAlMsg(TRUE); // #61
        Execute();
        setAlMsg(FALSE); // #61
        m_isProcessing = TRUE;
    }
}

void UpdaterEndConfigurationCounter::RemoveRequst(HARTIPConnection* session)
{
    MutexScopeLock lock(m_mutex);

    for(int i = 0; i < m_message5Reqests.size(); ++i)
    {
        if(m_message5Reqests[i].second->GetSession() == session)
        {
            m_message5Reqests.erase(m_message5Reqests.begin() + i);
            break;
        }
    }
}

void UpdaterEndConfigurationCounter::RemoveCloseSession(StatisticSession* session)
{
    MutexScopeLock lock(m_mutex);

    for(int i = 0 ; i < m_closedSession.size(); ++i)
    {
        if( m_closedSession[i] == session)
        {
            m_closedSession.erase(m_closedSession.begin() +  i);
        }
    }
}


AuditLog::AuditLog() : m_powerUp(-1), m_lastSecurityChange(-1),  m_serverPort(0), m_idTimer(NULL), m_statusSyslogServer(0), m_lastConfigurationCounter(0), m_currentIndex(0), 
m_countRecords(0), m_tableRecords(MAX_RECORD_COUNT, NULL)
{}

void AuditLog::ServerStarted(uint16_t port)
{
    time(&m_powerUp);
    m_lastSecurityChange = m_powerUp;
    m_serverPort = port;
}

AuditLog::AuditLog(AuditLog& second) {}

AuditLog::~AuditLog() 
{
     if(m_idTimer == NULL)
        return;
    timer_delete(*m_idTimer);
    
    delete m_idTimer;
    m_idTimer = NULL;

    for(int i = 0; i < m_tableRecords.size(); ++i)
    {
        if(m_tableRecords[i] != NULL)
        delete m_tableRecords[i];
    }
    m_tableRecords.clear();
}

AuditLog& AuditLog::operator=(AuditLog& second) {return *this; }

StatisticSession* AuditLog::FindRecord(HARTIPConnection* session)
{
    std::map<HARTIPConnection*, StatisticSession*>::iterator finded = m_mapActiveSessions.find(session);
    if(finded == m_mapActiveSessions.end())
    {
        dbgp_log("Didn't found active session");
        return NULL;
        
    }
    return finded->second;
}

void AuditLog::UpdateSecurituChange()
{
    MutexScopeLock mutexLock(m_mutex);
    time(&m_lastSecurityChange);
}

void AuditLog::SetStatusSyslogServer(uint16_t syslog, bool_t isOn)
{
    MutexScopeLock mutexLock(m_mutex);
    if(isOn == TRUE)
        m_statusSyslogServer |= syslog;
    else
    {
         m_statusSyslogServer &= ~syslog;
    }
    
}

errVal_t AuditLog::CreateNewRecordAuditLog(HARTIPConnection* session, uint16_t portNumber)
{
    m_mutex.lock();
    StatisticSession *statistic;

    if(m_mapActiveSessions.size() == 0)
    {
        StartTimer();
    }

    if(m_currentIndex == MAX_RECORD_COUNT)
    {
        m_currentIndex = 0;
    }

    //m_tableRecords.push_back(new StatisticSession());
    statistic = m_tableRecords[m_currentIndex];
    if(statistic != NULL)   // remove deadlock with m_updaterConfigCounter;
    {
        for(std::map<HARTIPConnection*, StatisticSession*>::iterator iter = m_mapActiveSessions.begin(); iter != m_mapActiveSessions.end(); ++iter)
        {
            if(iter->second == statistic)
            {
                m_updaterConfigCounter.AddRecordDisconnectedSession(statistic); // run update scc
                m_mapActiveSessions.erase(iter);
                break;
            }
        }
        m_mutex.unlock();
        m_updaterConfigCounter.RemoveCloseSession(statistic);
        m_mutex.lock();  

        delete statistic;
        statistic = NULL;
    }
    statistic = new StatisticSession();
    m_mapActiveSessions[session] = statistic;
    m_tableRecords[m_currentIndex] = statistic;


    session->GetAddress(&statistic->m_address);
    session->GetAddress6(&statistic->m_address6);
    statistic->m_startingConfiguration = m_lastConfigurationCounter;
    statistic->m_serverPort = portNumber;
    time(&statistic->m_timeConnected);

    m_currentIndex++;
    if(m_countRecords < MAX_RECORD_COUNT)
    {
        ++m_countRecords;
    }
    m_mutex.unlock();

    return NO_ERROR;
}

errVal_t AuditLog::UpdateAckCounter(HARTIPConnection *session, uint16_t count)
{
    MutexScopeLock mutexLock(m_mutex);
    StatisticSession* statistic = FindRecord(session);
    if(statistic == NULL)
    {
        return SESSION_ERROR;
    }
    statistic->m_ackCounter += count;
    return NO_ERROR;
}

errVal_t AuditLog::UpdateBackCounter(HARTIPConnection *session)
{
    MutexScopeLock mutexLock(m_mutex);
    StatisticSession* statistic = FindRecord(session);
    if(statistic == NULL)
    {
        return SESSION_ERROR;
    }
    
    ++statistic->m_backCounter;
    return NO_ERROR;
}

errVal_t AuditLog::UpdateStxCounter(HARTIPConnection *session)
{
    MutexScopeLock mutexLock(m_mutex);
    StatisticSession* statistic = FindRecord(session);
    if(statistic == NULL)
    {
        return SESSION_ERROR;
    }
    ++statistic->m_stxCounter;
    return NO_ERROR;
}

errVal_t AuditLog::SetStatusSession(HARTIPConnection *session, uint16_t status, bool_t isOn)
{
    if(status == AbortedSession)
    {
        log2HipSyslogger(36, 1004, 8, session, "Session aborted - invalid PDU or field.");
    }

    MutexScopeLock mutexLock(m_mutex);
    StatisticSession* statistic = FindRecord(session);
    if(statistic == NULL)
    {
        return SESSION_ERROR;
    }
    if(isOn == TRUE)
    {
        statistic->m_status |= status;
    }
    else
    {
        statistic->m_status &= ~status;
    }

    return NO_ERROR;
}

errVal_t AuditLog::SessionDisconnected(HARTIPConnection *session)
{
    StatisticSession *removeRecord = NULL;
    {
        MutexScopeLock mutexLock(m_mutex);
        StatisticSession* statistic = FindRecord(session);
        if(statistic == NULL)
        {
            return SESSION_ERROR;
        }
        time(&statistic->m_timeDisconnected);

        char* logString = GetSysLogString(statistic);
        log2HipSyslogger(134, 1200, 1, session, logString);

        m_mapActiveSessions.erase(session);
        if(m_mapActiveSessions.size() == 0)
        {
            StartTimer(FALSE);
        }
        removeRecord = statistic;
    }
    if(removeRecord != NULL)
    {
        m_updaterConfigCounter.RemoveRequst(session);
        m_updaterConfigCounter.AddRecordDisconnectedSession(removeRecord);
    }
    return NO_ERROR;
}

AuditLog* AuditLog::Instance()
{
    static AuditLog audit;
    return &audit;    
}

void WriteToPayload(uint8_t* payload, uint8_t* data, uint8_t size)
{
    for(int i = 0; i < size; ++i)
    {
        payload[i] = data[size - i - 1];
    }
}

errVal_t AuditLog::SendLogs(hartip_msg_t* pRequest, IResponseSender* sender)
{
    if (pRequest->hipHdr.msgType != HARTIP_MSG_TYPE_REQUEST)
    {
        return NO_ERROR;
    }

    hartip_msg_t response;

    const int ONE_RECORD = 1;
    uint8_t status = 0;

    uint8_t* payload = response.hipTPPDU;

    uint8_t firstRecord = pRequest->hipTPPDU[FIRST_RECORD_INDEX];
    uint8_t countRecord = pRequest->hipTPPDU[NUMBER_RECORDS_INDEX];

    response.hipHdr.msgID = pRequest->hipHdr.msgID;
    response.hipHdr.msgType = HARTIP_MSG_TYPE_RESPONSE;
    response.hipHdr.seqNum = pRequest->hipHdr.seqNum;
    

    uint16_t index = START_RECORD_LENGTH + COUNT_RECORD_LENGTH;

    WriteToPayload(payload + index, (uint8_t*)&m_powerUp, STARTUP_SERVER_LENGTH);
    index += STARTUP_SERVER_LENGTH;
    
    WriteToPayload(payload + index, (uint8_t*)&m_lastSecurityChange, SECURITY_CHANGE_LENGTH);
    index += SECURITY_CHANGE_LENGTH;

    WriteToPayload(payload + index, (uint8_t*)&m_statusSyslogServer, SERVER_STATUS_LENGTH);
    index += SERVER_STATUS_LENGTH;

    uint16_t recordLength = RECORD_LENGTH;

    WriteToPayload(payload + index, (uint8_t*)&recordLength, RECORD_SIZE_LENGTH);
    index += RECORD_SIZE_LENGTH;

    if(firstRecord >= m_countRecords)
    {
        status = WARNING_CODE;

        firstRecord = m_countRecords > 0 ? m_countRecords - ONE_RECORD : 0;
        countRecord = m_countRecords > 0 ? ONE_RECORD : 0;
    }

    if((HARTIP_MAX_PYLD_LEN - SERVER_LOG_LENGTH) < (RECORD_LENGTH * countRecord))
    {
        status = WARNING_CODE;
        countRecord = (HARTIP_MAX_PYLD_LEN - SERVER_LOG_LENGTH) / RECORD_LENGTH;        
    }

    if(countRecord + firstRecord > m_countRecords)
    {
        status = WARNING_CODE;
        countRecord = m_countRecords - firstRecord;
    }
    payload[FIRST_RECORD_INDEX] = firstRecord;
    payload[NUMBER_RECORDS_INDEX] = countRecord;
    response.hipHdr.byteCount = RECORD_LENGTH * countRecord + SERVER_LOG_LENGTH + HARTIP_HEADER_LEN;

    for(int8_t i = firstRecord, count = 0; count < countRecord; ++i, ++count)
    {
        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_address.sin_addr.s_addr, IPV4_ADDRESS_LENGTH);
        index += IPV4_ADDRESS_LENGTH;
        
        WriteToPayload(payload + index, m_tableRecords[i]->m_address6.sin6_addr.__in6_u.__u6_addr8, IPV6_ADDRESS_LENGTH);
        index += IPV6_ADDRESS_LENGTH;

        uint16_t port = ntohs(m_tableRecords[i]->m_address.sin_port);
        WriteToPayload(payload + index, (uint8_t*)&port, CLIENT_PORT_LENGTH);
        index += CLIENT_PORT_LENGTH;
        
        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_serverPort, SERVER_PORT_LENGTH);
        index += SERVER_PORT_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_timeConnected, CONNECTED_TIME_LENGTH);
        index += CONNECTED_TIME_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_timeDisconnected, DISCONNECTED_TIME_LENGTH);
        index += DISCONNECTED_TIME_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_status, SESSION_STATUS_LENGTH);
        index += SESSION_STATUS_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_startingConfiguration, START_CONFIGURATION_LENGTH);
        index += START_CONFIGURATION_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_endingConfiguration, END_CONFIGURATION_LENGTH);
        index += END_CONFIGURATION_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_backCounter, COUNTER_BACK_LENGTH);
        index += COUNTER_BACK_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_stxCounter, COUNTER_STX_LENGTH);
        index += COUNTER_STX_LENGTH;

        WriteToPayload(payload + index, (uint8_t*)&m_tableRecords[i]->m_ackCounter, COUNTER_ACK_LENGTH);
        index += COUNTER_ACK_LENGTH;

    }

    response.hipHdr.status = status;

    return sender->SendResponse(&response);
}

errVal_t AuditLog::StartTimer(bool_t isOn)
{
    if(m_idTimer == NULL)
    {
        m_idTimer = new timer_t;
        int32_t sessSig = EVENT_1200;
        struct sigevent se;
        se.sigev_notify = SIGEV_SIGNAL;
        se.sigev_signo = sessSig;
        se.sigev_value.sival_ptr = m_idTimer;
        timer_create(CLOCK_REALTIME, &se,
                            m_idTimer);
    }

    struct itimerspec its;

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_nsec = 0;
    if(isOn = TRUE)
    {
	    its.it_value.tv_sec = HOUR;
        its.it_value.tv_nsec = 0;
    }
    else 
    {
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 0;
    }

	timer_settime(*m_idTimer, 0, &its, NULL);
}

void AuditLog::Handle1200Event()
{
    MutexScopeLock mutexLock(m_mutex);
    for(std::map<HARTIPConnection*, StatisticSession*>::iterator it = m_mapActiveSessions.begin(); it != m_mapActiveSessions.end() ; it++)
    {
        char* logString = GetSysLogString(it->second);

        log2HipSyslogger(134, 1200, 1, it->first, logString);
    }
    StartTimer();
}

char* AuditLog::GetSysLogString(StatisticSession *session)
{
    static char resultString[SYSLOG_STRING_LENGTH];

    memset_s(resultString, SYSLOG_STRING_LENGTH, 0);

    // vulnerability check by inspection is OK:  this method is not accessible by the client  --  tjohnston 11/09/2021
    sprintf_s(resultString, SYSLOG_STRING_LENGTH, "%s:%hu: %hu, %hu, %hu, %hu", inet_ntoa(session->m_address.sin_addr), session->m_address.sin_port,
                     session->m_status, session->m_stxCounter, session->m_ackCounter, session->m_backCounter);

    return resultString;
}

errVal_t AuditLog::UpdateEndConfigurationCounter(StatisticSession *session, uint16_t value)
{
    MutexScopeLock mutexLock(m_mutex);
    session->m_endingConfiguration = value;

    if(session->m_endingConfiguration != session->m_startingConfiguration)
    {
        session->m_status |= SessionStatus::WritesOccured;
    }

    return NO_ERROR;
}
errVal_t AuditLog::UpdateEndConfigurationCounterActiveSession(uint16_t value)
{
    MutexScopeLock mutexLock(m_mutex);
    for(std::map<HARTIPConnection*, StatisticSession*>::iterator it = m_mapActiveSessions.begin(); it != m_mapActiveSessions.end() ; it++)
    {
        it->second->m_endingConfiguration = value;
    }
    m_lastConfigurationCounter = value;
    return NO_ERROR;
}

errVal_t AuditLog::UpdateStartConfigurationCounter(HARTIPConnection* session, uint16_t value)
{
    MutexScopeLock mutexLock(m_mutex);
    StatisticSession* statistic = FindRecord(session);
    if(statistic == NULL)
    {
        return SESSION_ERROR;
    }
    
    if(statistic->m_ackCounter != 0) //no first command
        return NO_ERROR;

    statistic->m_startingConfiguration = value;
    m_lastConfigurationCounter = value;

    return NO_ERROR;
}

errVal_t AuditLog::ProcessMessage5(hartip_msg_t& pResponce, IResponseSender* sender)
{
    if(pResponce.hipHdr.byteCount - HARTIP_HEADER_LEN != AUDIT_LOG_HEADER_SIZE)
    {
        return VALIDATION_ERROR;
    }
    m_updaterConfigCounter.AddMessage5Requst(pResponce, sender);
    return NO_ERROR;
}
