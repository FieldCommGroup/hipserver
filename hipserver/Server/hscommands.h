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

#ifndef _HS_COMMAND_H_
#define _HS_COMMAND_H_

#include "tppdu.h"
#include "hsresponsesender.h"
#include <vector>
#include "hsconnectionmanager.h"

typedef enum
{
	No_Command_Specific_Errors = 0, 
	Undefined_1 = 1,
	Undefined_2 = 2,
	Undefined_3 = 3,
	Undefined_4 = 4,
	Too_Few_Data_bytes_received = 5, 
	Device_Specific_Command_Error = 6
} command_specific_response_codes_t;

const int cHostLen = 64;
const int cMinimumDirectPDULength = /*Device Status and ExtendedStatus*/ 2+ /*Command Number*/2+ /*ByteCount*/ 1;
const int cMinimumTPPDULengthLongFrame = 9;
const int cMinimumTPPDULengthShortFrame = 5;

class CommandsManager;
// basic interface for command
class ICommand
{
public:
    ICommand(IResponseSender* responseSender, uint16_t seqNumber, bool_t noMessResponse);
    virtual errVal_t Execute() = 0;
    virtual errVal_t SendMessage(TpPdu tppdu, int transaction) = 0;
    virtual errVal_t CreateMessage(hartip_msg_t& message) = 0;
    virtual char* ToHex() = 0;
    virtual time_t GetTime();
    virtual bool_t IsGood();
    virtual bool_t IsValid();
    virtual bool_t IsSecurityCommand();
    virtual bool_t IsReadOnlyCommand();
    bool_t IsResponse();
    static ICommand* ParseMessage(hartip_msg_t* requst, IResponseSender* sender, bool_t noMessResponse);
    
public:
    bool_t              m_noMessResponse;

protected:
    IResponseSender*    m_resSender;
    time_t              m_time;
    uint16_t            m_seqNumber;
    bool_t              m_isProcessed;
    bool_t              m_isResponse;
    bool_t              m_isGood;
    bool_t              m_isValid; // #61
    bool_t				m_isAL;
    bool_t              m_isSecurityCommand;
    bool_t              m_isReadOnlyCommand;

    virtual ~ICommand(){}

    friend class CommandsManager;
};

class TPCommand : public ICommand
{
public: 
    TPCommand(uint8_t* data, uint16_t byteCount, uint16_t seqNumber,  IResponseSender* responseSender, bool_t noMessResponse);
    TPCommand(TpPduStore tppdustore, IResponseSender* responseSender, bool_t noMessResponse);
    virtual errVal_t Execute();
    virtual errVal_t SendMessage(TpPdu tppdu, int transaction);
    virtual errVal_t CreateMessage(hartip_msg_t& message);
    virtual char* ToHex();
    TpPdu& GetTpPdu() { return m_tppdu; }
	uint8_t getSavedDevStatus() { return savedDeviceStatus; } // #165
	
	void 	setSavedDeviceStatus(uint8_t src) { savedDeviceStatus = src; } // #165



    static uint32_t GetNewTransactionNumber()
    {
        uint32_t transaction = TPCommand::s_currentTransaction;
        TPCommand::s_currentTransaction++;
        if(TPCommand::s_currentTransaction == 0) // 
            TPCommand::s_currentTransaction++;
        return transaction;    
    }

    int GetNumberTransaction() { return m_transactionNumber; }

    static void RunSimulatedCommand20();
    static void RunSimulatedCommand520();
    bool_t IsDmMsg() { return isDM; } // #58
    void setDmMsg(bool_t set) { isDM = set; }
    bool_t IsAlMsg() { return m_isAL; } // #61
    void setAlMsg(bool_t set) { m_isAL = set; }

protected:
    TpPduStore      m_tppduStore;
    TpPdu           m_tppdu;
    AppMsg          m_txMsg;
    uint32_t        m_transactionNumber;
    bool_t          m_isSrvrCommand;
    uint8_t 		savedDeviceStatus;
    static uint32_t s_currentTransaction;
    bool_t			isDM; // #58


    int process_cmd257();
    int process_cmd258();
    int process_cmd543();
    int process_cmd544();
    int process_cmd545();
    int process_cmd546();
    int process_cmd547();
    void SetTpPdu(TpPdu tppdu);

    void ProcessOkResponse(uint8_t bc);
    void ProcessOkResponse(uint8_t *data, uint8_t datalen);

private:
    bool_t IsCmdHandledByServer(uint16_t comandNumber);
    void ModifyTag();
};

class DMCommands: public ICommand, public IResponseSender
{
public:
    DMCommands(uint8_t* data, uint16_t byteCount, uint16_t seqNumber, IResponseSender* responseSender, bool_t noMessResponse);
    virtual errVal_t Execute();
    virtual errVal_t SendMessage(TpPdu tppdu, int transaction);
    virtual errVal_t CreateMessage(hartip_msg_t& message);

    virtual errVal_t SendResponse(hartip_msg_t *p_response);
	virtual errVal_t SendBinaryResponse(void* pData, int size);
    virtual char* ToHex();

    virtual uint16_t GetSessionNumber();
    virtual IResponseSender* GetParentSender();
    TPCommand* CreateCommand48();

    virtual HARTIPConnection* GetSession();

protected:
    ~DMCommands();

    std::vector<TPCommand*>    m_listCommands;
    std::vector<uint16_t>      m_activeCommand;
    uint8_t                    m_deviceStatus;
    uint8_t                    m_extendedStatus;
    TPCommand*                 m_command48;
    HARTIP_MSG_TYPE            m_typeRes;
};
#endif
