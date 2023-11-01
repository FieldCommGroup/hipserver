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

#include "hscommands.h"
#include "hssems.h"
#include "debug.h"
#include "time.h"
#include "hsqueues.h"
#include "app.h"
#include "hssubscribe.h"
#include "hssigs.h"
#include "hsrequest.h"
#include "hssyslogger.h"
#include "hsauditlog.h"
#include "hsnetworkmanager.h"
#include "hssecurityconfiguration.h"
#include "hssettings.h"
#include "hssettingshandler.h"
#include "hsreadonlycommandsmanager.h"
#include "hssyslogger.h"

#define DEVICE_STATUS_IDX 0
#define EXTENDED_STATUS_IDX 1
#define FIRST_COMMAND_IDX 2

#define COMMAND_NUMBER_LENGTH 2
#define COMMAND_BYTE_LENGTH 1
#define DEVICE_STATUS_BYTE_LENGTH 1
#define EXTENDED_STATUS_BYTE_LENGTH 1
#define DIRECT_MESSAGE_COMMAND_LENGTH (COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH)

#define COMMAND_48 48
#define COMMAND_48_BYTE_COUNT 9 // min byte command
#define EXTENDED_STATUS_BYTE 6

#define DM_HEADER_LENGTH (DEVICE_STATUS_BYTE_LENGTH + EXTENDED_STATUS_BYTE_LENGTH)

int process_cmd258(hsmessage_t *hsmsg);
int process_cmd257(hsmessage_t *hsmsg);

ICommand::ICommand(IResponseSender *responseSender, uint16_t seqNumber, bool_t noMessResponse) : m_resSender(responseSender), m_seqNumber(seqNumber), m_noMessResponse(noMessResponse),
																		  m_isProcessed(FALSE), m_isResponse(FALSE), m_isGood(TRUE), m_isSecurityCommand(FALSE), m_isReadOnlyCommand(FALSE) {}
time_t ICommand::GetTime() { return m_time; }
bool_t ICommand::IsResponse() { return m_isResponse; }
bool_t ICommand::IsGood() { return m_isGood; }
bool_t ICommand::IsValid() { return m_isValid; } // #61
bool_t ICommand::IsSecurityCommand() { return m_isSecurityCommand; }
bool_t ICommand::IsReadOnlyCommand() { return m_isReadOnlyCommand; }

ICommand *ICommand::ParseMessage(hartip_msg_t *request, IResponseSender *sender, bool_t noMessResponse)
{
	switch (request->hipHdr.msgID)
	{
	case HARTIP_MSG_ID_TP_PDU:
	{
		dbgp_logdbg("TP Request\n");
		ICommand *command = new TPCommand(request->hipTPPDU, request->hipHdr.byteCount - HARTIP_HEADER_LEN, request->hipHdr.seqNum, sender, noMessResponse);
		return command;
	}
	case HARTIP_MSG_ID_DM_PDU:
	{
		dbgp_logdbg("DirectMessage Request\n");
		ICommand *command = new DMCommands(request->hipTPPDU, request->hipHdr.byteCount - HARTIP_HEADER_LEN, request->hipHdr.seqNum, sender, noMessResponse);
		return command;
	}
	}
	return NULL;
}

//--------------------TPCommand------------------------------------------------------------------------------

uint32_t TPCommand::s_currentTransaction = 1;

TPCommand::TPCommand(uint8_t *data, uint16_t byteCount, uint16_t seqNumber, IResponseSender *responseSender, bool_t noMessResponse) : ICommand(responseSender, seqNumber, noMessResponse),
																						   m_tppduStore(data), m_tppdu(m_tppduStore)
{
	//check minimal TPPDU size
	if(byteCount < cMinimumTPPDULengthShortFrame)
	{
		m_isGood = FALSE;
	}
	else
	{
		//Check size according deliminiter
		uint16_t expectedMinimalByteCount = (m_tppdu.IsLongFrame() ? cMinimumTPPDULengthLongFrame : cMinimumTPPDULengthShortFrame);
		if(byteCount < expectedMinimalByteCount)
		{
			m_isGood = FALSE;
		}

		expectedMinimalByteCount += m_tppdu.ByteCount();

		if(byteCount < expectedMinimalByteCount)
		{ // #61
			m_isValid = FALSE;
		}
		else
		{
			m_isValid = TRUE;
		}
	}

	if(m_tppdu.CmdNum() == 541 || m_tppdu.CmdNum() == 542)
	{
		m_isSecurityCommand = TRUE;
	}

	if(m_isGood == TRUE)
	{
		setDmMsg(FALSE); // #58
		uint16_t commandNumber = m_tppdu.CmdNum();
		m_isSrvrCommand = IsCmdHandledByServer(commandNumber);
		m_transactionNumber = m_isSrvrCommand == TRUE ? 0 : GetNewTransactionNumber();
		m_tppdu.setReqByteCount(m_tppdu.ByteCount()); // #36 #170
		if(responseSender != NULL && responseSender->GetParentSender() == NULL)
			AuditLogger->UpdateStxCounter(m_resSender->GetSession());
	}	
}

TPCommand::TPCommand(TpPduStore tppdustore, IResponseSender *responseSender, bool_t noMessResponse) : ICommand(responseSender, -1, noMessResponse),
																			   m_tppduStore(tppdustore), m_tppdu(m_tppduStore)
{
	uint16_t commandNumber = m_tppdu.CmdNum();
	m_isSrvrCommand = IsCmdHandledByServer(commandNumber);
	m_transactionNumber = m_isSrvrCommand == TRUE ? 0 : GetNewTransactionNumber();

	//Set bytecount anyway for error response
	m_tppdu.setReqByteCount(m_tppdu.ByteCount()); 

	if(commandNumber == 541 || commandNumber == 542)
	{
		m_isSecurityCommand = TRUE;
	}
}

bool_t TPCommand::IsCmdHandledByServer(uint16_t commandNumber)
{
				return (commandNumber == 257 ||
					   commandNumber == 258 ||
					   /*
					 *  if APP is an IO system:
					 *  	pass subscription commands on
					 *  else
					 *  	hipserver handles the subscriptions
					 */
					   (commandNumber == 532 && connectionType != hipiosys) ||
					   (commandNumber == 533 && connectionType != hipiosys) ||
					   commandNumber == 538 ||
					   commandNumber == 539 ||
					   commandNumber == 540 ||
					   commandNumber == 541 ||
					   commandNumber == 542 ||
					   commandNumber == 543 ||
					   commandNumber == 544 ||
					   commandNumber == 545 ||
					   commandNumber == 546 ||
					   commandNumber == 547)
						  ? TRUE
						  : FALSE;
}

errVal_t TPCommand::Execute()
{
	const char *funcName = "TPCommand::Execute";
	dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

	errVal_t errval = NO_ERROR;

	sem_wait(p_semServerTables); // lock server tables when available
	{
		do
		{
			bool isReadOnly = false;

			uint16_t commandNumber = m_tppdu.CmdNum();
			uint8_t delimiter = *m_tppdu.Delim();

			//only 'read-only' command can be executed. otherwise session must be closed
			if (m_resSender != NULL)
			{
				HARTIPConnection* currentSession = m_resSender->GetSession();
				if (currentSession->IsReadOnly())
				{
					if(FALSE == ReadOnlyCommandsManager::Instance().IsCommandReadOnly(commandNumber))
					{
						print_to_both(p_toolLogPtr,"Session in readonly mode, command is a write command: %d\n", commandNumber);
						isReadOnly = true;
					}
				}
			}
			
			/* Start with a clean slate */

			memset_s(&m_txMsg, APP_MSG_SIZE, 0);
			memcpy_s(m_txMsg.pdu, TPPDU_MAX_FRAMELEN, m_tppdu.GetPdu(), TPPDU_MAX_FRAMELEN);

			time(&m_time); // timestamp
			m_tppdu.setSavedDeviceStatus(getSavedDevStatus()); //#165
			if(IsDmMsg() == TRUE)
			{
				m_txMsg.setDmMsg(1); // #62
			}
			if(IsDmMsg() == FALSE)
			{
				if((delimiter == 0x02) && (commandNumber != 0))
				{ // #58
					errval = LINUX_ERROR;
					continue;
				}
			}
			if (TRUE == ReadOnlyCommandsManager::Instance().IsWriteProtected(commandNumber))
			{
				m_tppdu.ProcessErrResponse(RC_WRT_PROT);
				SendMessage(m_tppdu, 0);
			}
			else if(isReadOnly)
			{
				m_tppdu.ProcessErrResponse(READ_ONLY_ACCESS_ERROR);
				errval = READ_ONLY_ACCESS_ERROR;
			}
			else
			{
				if((!IsValid()) && (!IsDmMsg()) && (!IsAlMsg()))
				{ // #61
					break;
				}

				if (m_isSrvrCommand)
				{ // these msgs processed by server

					dbgp_intfc("Server received msg from cmdQueue\n");
#ifdef HTS
					if (commandNumber == 257)
					{ // #6005
						process_cmd257();
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 258)
					{
						process_cmd258();
						SendMessage(m_tppdu, 0);
						shutdown_server();
					}
#endif
					if (commandNumber == 532)
					{
						SubscribesTable::Instance()->HandleCommand532(m_resSender, &m_tppdu);
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 533)
					{
						SubscribesTable::Instance()->HandleCommand533(m_resSender, &m_tppdu);
						SendMessage(m_tppdu, 0);
						log2HipSyslogger(134, 1100, 1, NULL, "Client subscribes to to publications from device.");
					}
#ifndef HTS
					if (commandNumber == 543)
					{
						process_cmd543();
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 544)
					{
						process_cmd544();
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 545)
					{
						process_cmd545();
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 546)
					{
						process_cmd546();
						SendMessage(m_tppdu, 0);
					}
					else if (commandNumber == 547)
					{
						process_cmd547();
						SendMessage(m_tppdu, 0);
					}
					else if(commandNumber == 538)
					{
						NetworkManager *manager = NetworkManager::Instance();
						manager->ProcessCmd538(&m_tppdu);
						SendMessage(m_tppdu, 0);
					}
					else if(commandNumber == 539)
					{
						NetworkManager *manager = NetworkManager::Instance();
						manager->ProcessCmd539(&m_tppdu);
						SendMessage(m_tppdu, 0);
						if(m_tppdu.ResponseCode() == RC_SUCCESS)
						{
							print_to_both(p_toolLogPtr, "539 success, configuring supp port.\n");

							manager->ConfigureSupplementaryPort(UDP);
						}
					}
					else if(commandNumber == 540)
					{
						NetworkManager *manager = NetworkManager::Instance();
						manager->ProcessCmd540(&m_tppdu);
						SendMessage(m_tppdu, 0);
						if(m_tppdu.ResponseCode() == RC_SUCCESS)
						{
							print_to_both(p_toolLogPtr, "540 success, configuring supp port.\n");

							manager->ConfigureSupplementaryPort(TCP);
						}
					}
					else if(commandNumber == 541)
					{
						SecurityConfigurationTable::Instance()->ProcessCmd541(&m_tppdu);
						SendMessage(m_tppdu, 0);
					}
					else if(commandNumber == 542)
					{
						SecurityConfigurationTable::Instance()->ProcessCmd542(&m_tppdu);
						SendMessage(m_tppdu, 0);
					}
#endif					
					else
					{
						print_to_both(p_toolLogPtr,
									"Server received unknown command msg from cmdQueue\n");
					}
				}
				else
				{
#ifndef HTS				
					if(commandNumber == 22)
					{
						if(Settings::Instance()->CheckCmd22(&m_tppdu) != NO_ERROR)
						{
							SendMessage(m_tppdu, 0);
							break;
						}
						else
						{
							ModifyTag();
						}
					}

					if(commandNumber == 521)
					{
						if(Settings::Instance()->CheckCmd521(&m_tppdu) != NO_ERROR)
						{
							SendMessage(m_tppdu, 0);
							break;
						}
						else
						{
							ModifyTag();
						}
					}
#endif
					// add message to request table, used to match responses from a device
					m_txMsg.transaction = m_transactionNumber;
					add_request_to_table(m_txMsg.transaction, this);
					snd_msg_to_app(&m_txMsg);
				}
			}
			m_txMsg.setDmMsg(0); // #62
		} while (FALSE);
	}
	sem_post(p_semServerTables); // unlock server tables when done
	return errval;
}

void TPCommand::ModifyTag()
{
	uint length = HART_LONGTAG_LEN;

	// hostnameissue
	bool fillWithNull = false;

	// COPIED FROM DataBytes()
	uint8_t databytesIndex = m_tppdu.IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;
	databytesIndex = m_tppdu.IsSTX() ? databytesIndex : databytesIndex + 2;

	uint8_t *pdu = m_tppdu.GetPdu();

	uint iterationCount = length + databytesIndex;
	for(uint32_t i = databytesIndex; i < iterationCount; ++i)
	{
		if(fillWithNull == false)
		{
			char t = pdu[i];
			if(t == '\0')
			{
				fillWithNull = true;
			}
		}
		else
		{
			pdu[i] = '\0';
		}
	}

	m_tppdu.InsertCheckSum();
	memcpy_s(m_txMsg.pdu, TPPDU_MAX_FRAMELEN, m_tppdu.GetPdu(), TPPDU_MAX_FRAMELEN);
}

errVal_t TPCommand::SendMessage(TpPdu tppdu, int transaction)
{
	m_isResponse = TRUE;
	SetTpPdu(tppdu);
	hartip_msg_t hipmsg;
	CreateMessage(hipmsg);
	errVal_t res = NO_ERROR;
	if (!m_noMessResponse)
	{
		if(m_resSender != NULL)
		{
			res = m_resSender->SendResponse(&hipmsg);
		}
	}
	
	if(tppdu.CmdNum() == 0)
	{
		uint16_t configurationCounter = 0;
		memcpy_s(&configurationCounter, sizeof(configurationCounter), tppdu.ResponseBytes() + CONFIGURATION_COUNTER_INDEX, sizeof(configurationCounter));

		AuditLogger->UpdateStartConfigurationCounter(m_resSender->GetSession(), ntohs(configurationCounter));

		// see spec 127 for these constants
		unsigned char* buff = tppdu.ResponseBytes() + 1;
		unsigned short expandedDeviceType = *(unsigned short*)buff;
		expandedDeviceType = ntohs(expandedDeviceType);

		buff = tppdu.ResponseBytes() + 5;
		unsigned char deviceRevision = *(unsigned char*)buff;

		buff = tppdu.ResponseBytes() + 9;
		unsigned short deviceIDPart1 = *(unsigned short*)buff;
		deviceIDPart1 = ntohs(deviceIDPart1);
		unsigned int deviceID = deviceIDPart1;
		deviceID = deviceID << 8;
		buff = tppdu.ResponseBytes() + 11;
		deviceID = deviceID | *(unsigned char*)buff;


		buff = tppdu.ResponseBytes() + 17;
		unsigned short manufacture = *(unsigned short*)buff;
		manufacture = ntohs(manufacture);

		setDeviceIdentification(manufacture, expandedDeviceType, deviceRevision, deviceID);
	}
	
	if(m_tppdu.CmdNum() == 22 && m_tppdu.ResponseCode() == 0)
    {
        Settings::Instance()->Process22(&m_tppdu);
    }
    if(m_tppdu.CmdNum() == 521 && m_tppdu.ResponseCode() == 0)
    {
        Settings::Instance()->Process521(&m_tppdu);
    }
	if(m_tppdu.CmdNum() == 20 && res == NO_ERROR)
	{
		Settings::Instance()->SetLongTag(&m_tppdu);
	}
	
	if(m_tppdu.CmdNum() == 520 && res == NO_ERROR)
	{
		Settings::Instance()->SetProcessUnitTag(&m_tppdu);
	}
	
	if(res == NO_ERROR && m_resSender != NULL && m_resSender->GetParentSender() == NULL)
	{
		AuditLogger->UpdateAckCounter(m_resSender->GetSession());
	}
	if(!m_tppdu.IsLongFrame())
		attach_device(m_tppdu.GetPdu());
	m_isProcessed = TRUE;
	return res;
}

errVal_t TPCommand::CreateMessage(hartip_msg_t &message)
{
	message.hipHdr.version = HARTIP_PROTOCOL_VERSION;
	message.hipHdr.status = 0;
	message.hipHdr.msgType = HARTIP_MSG_TYPE_RESPONSE;
	message.hipHdr.msgID = HARTIP_MSG_ID_TP_PDU;
	memcpy_s(message.hipTPPDU, TPPDU_MAX_FRAMELEN, m_tppdu.GetPdu(), TPPDU_MAX_FRAMELEN);
	message.hipHdr.byteCount = HARTIP_HEADER_LEN + m_tppdu.PduLength();
	message.hipHdr.seqNum = m_seqNumber;
	// hsmsg.message.hipHdr.seqNum exists already
	return NO_ERROR;
}

char* TPCommand::ToHex()
{
	return m_tppdu.ToHex();
}

void TPCommand::ProcessOkResponse(uint8_t bc)
{
	m_tppdu.ProcessOkResponse(RC_SUCCESS, bc);

	uint16_t cmdNum = m_tppdu.CmdNum();

	if (FALSE == ReadOnlyCommandsManager::Instance().IsCommandReadOnly(cmdNum))
	{
		log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command %d", cmdNum);
	}
}

void TPCommand::ProcessOkResponse(uint8_t *data, uint8_t datalen)
{
	m_tppdu.ProcessOkResponse(RC_SUCCESS, data, datalen);

	uint16_t cmdNum = m_tppdu.CmdNum();

	if (FALSE == ReadOnlyCommandsManager::Instance().IsCommandReadOnly(cmdNum))
	{
		log2HipSyslogger(109, 2000, 3, NULL, "Configuration Change - HART Command %d", cmdNum);
	}
}

// #6004
int TPCommand::process_cmd258()
{
	const uint8_t bc = 4; // byte count for success response

	if (m_tppdu.Validate(0))
	{
		dbgp_log("Received to shutdown server.\n");
		ProcessOkResponse(bc);
		m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
		m_tppdu.SetCheckSum();
	}

	return STS_OK; // request is copied into table
}

// #6005
int TPCommand::process_cmd257()
{
	const uint8_t bc = 5; // byte count for success response with added data bytes.

	if (m_tppdu.Validate(0))
	{
		uint8_t dataSize = 1;
		uint8_t data[dataSize];
		data[0] = connectionType;
		ProcessOkResponse(bc);
		// look inside *hsmsg
		m_tppdu.AddData(data, dataSize);
		m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
		m_tppdu.SetCheckSum();
		// Modify the data based on the byte count.
		//findme.ProcessOkResponseAddData(RC_SUCCESS, bc, connectionType);
	}

	return STS_OK; // request is copied into table
}

int TPCommand::process_cmd543()
{
	// read syslog server Host and Port
	int port = getPortToHipSyslogger();

	char host[cHostLen];
	memset_s(host, sizeof(host), 0);
	getHostnameToHipSyslogger(host, cHostLen);

	uint16_t hostLen = sizeof(host);
	uint8_t portLen = 2;
	uint8_t extendedCMDBytes = 2;

	uint8_t dataSize = hostLen + portLen + extendedCMDBytes;
	uint8_t data[dataSize];
	memset_s(data, sizeof(data), 0);

	data[0] = port >> 8;
	data[1] = port & 0x0FF;

    memcpy_s(&(data[2]), dataSize, host, hostLen);

    m_tppdu.SetByteCount(2 /*RC+DS*/);
	ProcessOkResponse(data, dataSize); //extended CMD is set in this call
	m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
	m_tppdu.SetCheckSum();

	return STS_OK;
}

int TPCommand::process_cmd544()
{
    int requestByteCount = m_tppdu.RequestByteCount();
	if (requestByteCount < 2)
	{
        m_tppdu.ProcessErrResponse(Too_Few_Data_bytes_received);
		return STS_OK;
	}

	// write syslog port
	uint8_t *pPdu = m_tppdu.RequestBytes();
	int port = ((pPdu[0] << 8) + (pPdu[1] & 0x0ff));
	setPortToHipSyslogger(port);

	int newPort = getPortToHipSyslogger();

    uint8_t extendedCMDBytes = 2;
	uint8_t portLen = 2;
	uint8_t dataSize = portLen + extendedCMDBytes;
	uint8_t data[dataSize];
	memset_s(data, sizeof(data), 0);
	data[0] = port >> 8;
	data[1] = port & 0x0FF;

    m_tppdu.SetByteCount(2 /*RC+DS*/);
	ProcessOkResponse(data, dataSize); //extended CMD is set in this call
	m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
	m_tppdu.SetCheckSum();

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("syslogIPPort", to_string(newPort));

	return STS_OK;
}

int TPCommand::process_cmd545()
{
    int requestByteCount = m_tppdu.RequestByteCount();
    if (requestByteCount < cHostLen)
    {
        m_tppdu.ProcessErrResponse(Too_Few_Data_bytes_received);
        return STS_OK;
    }

    if(Settings::Instance()->CheckCmd545(&m_tppdu))
    { // #134
    	return STS_OK;
    }

	//write syslog server Host
	uint8_t *pPdu = m_tppdu.RequestBytes();
	string host;
	for (long i = 0; i < cHostLen; ++i)
	{
		char t = pPdu[i];
		if (t == '\0')
		{
			break;
		}
		host += t;
	}

	setHostnameToHipSyslogger(host.c_str());

	char newHost[cHostLen];
    memset_s(newHost, sizeof(newHost), 0);
	getHostnameToHipSyslogger(newHost, cHostLen);

    uint8_t extendedCMDBytes = 2;
	uint8_t dataSize = cHostLen + extendedCMDBytes;
	uint8_t data[dataSize];
	memset_s(data, sizeof(data), 0);
    memcpy_s(data, cHostLen, newHost, cHostLen);

    m_tppdu.SetByteCount(2 /*RC+DS*/);
	ProcessOkResponse(data, dataSize); //extended CMD is set in this call
	m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
	m_tppdu.SetCheckSum();

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("syslogHOSTNAME", newHost);

	return STS_OK;
}

int TPCommand::process_cmd546()
{
	// write syslog Server Pre-shared key
	uint8_t *pPdu = m_tppdu.RequestBytes();
	uint8_t reqBC = m_tppdu.ByteCount();

	const int maxKeyValueLen = 66; // #160
	const int keyLen = 1;
	uint8_t extendedCMDBytes = 2;
	const int len = keyLen + maxKeyValueLen + extendedCMDBytes;

	// Only Error Code Too Few Data Bytes is being process at this time.
	if(reqBC < len)
	{ // #160
		m_tppdu.ProcessErrResponse(RC_TOO_FEW);
		return STS_OK;
	}

	const int keyLenBytes = pPdu[0];
	string keyValue;
	for (long i = 1; i <= keyLenBytes; ++i)
	{
		char t = pPdu[i];
		keyValue += t;
	}

	setPreSharedKeyToHipSyslogger(keyValue.c_str());

	char newKeyValue[keyLenBytes];
	getPreSharedKeyToHipSyslogger(newKeyValue, keyLenBytes);

	uint8_t dataSize = keyLen + keyLenBytes + extendedCMDBytes;
	uint8_t data[dataSize];
	memset_s(data, sizeof(data), 0);
	data[0] = keyLenBytes;
	for (long i = 0; i < keyLenBytes; ++i)
	{
		data[i + 1] = (int)newKeyValue[i];
	}

	m_tppdu.SetByteCount(2 /*RC+DS*/);
	ProcessOkResponse(data, dataSize); //extended CMD is set in this call
	m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
	m_tppdu.SetCheckSum();

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("syslogKey", newKeyValue);

	return STS_OK;
}

int TPCommand::process_cmd547()
{
	// write syslog server  PAKE password
	//write syslog server Host
	uint8_t *pPdu = m_tppdu.RequestBytes();

	const int passwordLen = 64;
	uint8_t extendedCMDBytes = 2;
	const int len = passwordLen + extendedCMDBytes;

	string password;
	for (long i = 0; i < len; ++i)
	{
		char t = pPdu[i];
		if (t == '\0')
		{
			break;
		}
		password += t;
	}

	setPasswordToHipSyslogger(password.c_str());

	char newPassword[passwordLen];
	getPasswordToHipSyslogger(newPassword, passwordLen);

	uint8_t dataSize = passwordLen + extendedCMDBytes;
	uint8_t data[dataSize];
	memset_s(data, sizeof(data), 0);
	for (long i = 0; i < passwordLen; ++i)
	{
		data[i] = (int)newPassword[i];
	}

	m_tppdu.SetByteCount(2 /*RC+DS*/);
	ProcessOkResponse(data, dataSize); //extended CMD is set in this call
	m_tppdu.SetRCStatus(0, getSavedDevStatus()); // #165
	m_tppdu.SetCheckSum();

    SettingsHandler settingsHandler;
    settingsHandler.AddRootItem("syslogPassword", newPassword);

	return STS_OK;
}

void TPCommand::SetTpPdu(TpPdu tppdu)
{
	m_tppduStore.SetStore(tppdu.GetPdu());
	if(m_isSrvrCommand == false)
	{
		setSavedDeviceStatus(tppdu.DeviceStatus()); // #165
	}
}

void TPCommand::RunSimulatedCommand20()
{
    uint8_t buf[TPPDU_MAX_DATALEN] = {0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00};
    TpPdu tppdu(buf);

    tppdu.SetByteCount(9);
    tppdu.SetPdu(buf);
    tppdu.setCommandNumber(20);
    tppdu.SetCheckSum();
		
    TPCommand *command = new TPCommand(buf, 9, 0, NULL, TRUE);
	command->m_isValid = TRUE;
	command->setDmMsg(TRUE);
	command->setAlMsg(FALSE);
    command->Execute();
}

void TPCommand::RunSimulatedCommand520()
{
    uint8_t buf[TPPDU_MAX_DATALEN] = {0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x02, 0x02, 0x08};
    TpPdu tppdu(buf);

    tppdu.SetByteCount(9);
    tppdu.SetPdu(buf);
    tppdu.setCommandNumber(520);
    tppdu.SetCheckSum();
    
    TPCommand *command = new TPCommand(buf, 9, 0, NULL, TRUE);
	command->m_isValid = TRUE;
	command->setDmMsg(TRUE);
	command->setAlMsg(FALSE);
    command->Execute();
}

//--------------------DMCommands------------------------------------------------------------------------------

struct DirectPDUCommand
{
	uint8_t *m_pCommand;	// size HARTIP_MAX_PYLD_LEN

	uint16_t GetNumberCommand();
	uint8_t GetByteData();
	uint8_t GetByteCommand();
	uint8_t *GetData();

	void SetNumberCommand(uint16_t nmb);
	void SetByteData(uint8_t cntByte);
	void SetData(uint8_t *data, uint8_t cntByte, bool_t isExpCmd);
};

uint16_t DirectPDUCommand::GetNumberCommand()
{
	uint16_t commandNumber;
	memcpy_s(&commandNumber, COMMAND_NUMBER_LENGTH, m_pCommand, sizeof(uint16_t));
	return ntohs(commandNumber);
}

uint8_t DirectPDUCommand::GetByteData()
{
	return m_pCommand[COMMAND_NUMBER_LENGTH];
}

uint8_t DirectPDUCommand::GetByteCommand()
{
	return GetByteData() + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH;
}

uint8_t *DirectPDUCommand::GetData()
{
	return m_pCommand + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH;
}

void DirectPDUCommand::SetNumberCommand(uint16_t nmb)
{
	nmb = htons(nmb);
	memcpy_s(m_pCommand, COMMAND_NUMBER_LENGTH, &nmb, sizeof(uint16_t));
}

void DirectPDUCommand::SetByteData(uint8_t cntByte)
{
	m_pCommand[COMMAND_NUMBER_LENGTH] = cntByte;
}

void DirectPDUCommand::SetData(uint8_t *data, uint8_t cntByte, bool_t isExpCmd)
{
	const int rclength = 1;	  // response code byte count;
	const int rcdslength = 2; // response code and device status byte count

	m_pCommand[COMMAND_NUMBER_LENGTH] = cntByte + rclength - rcdslength;

	if (!isExpCmd)
	{	
		memcpy_s(m_pCommand + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH, HARTIP_MAX_PYLD_LEN, data, rclength);
		if (cntByte - rcdslength > 0)
		{
			memcpy_s(m_pCommand + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH + rclength, HARTIP_MAX_PYLD_LEN, data+rcdslength, cntByte - rcdslength);
		}
	}
	else
	{
		const int expCommandLength = 2;
		memcpy_s(m_pCommand + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH, HARTIP_MAX_PYLD_LEN, data, rclength);
		if (cntByte - rcdslength > 0)
		{
			memcpy_s(m_pCommand + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH + rclength, HARTIP_MAX_PYLD_LEN, data + expCommandLength+rcdslength, cntByte - rcdslength);
		}
	}
}

TpPduStore ToTpPduAck(uint8_t *data)
{
	uint16_t commandNumber;
	memcpy_s(&commandNumber, sizeof(commandNumber), data, sizeof(uint16_t));
	commandNumber = ntohs(commandNumber);
	bool isExtendedCommand = commandNumber > 255;

	uint8_t commandNumberData = isExtendedCommand ? 31 : commandNumber;
	uint8_t byteCommand = data[COMMAND_NUMBER_LENGTH];
	uint8_t offsetData = 4;

	if (isExtendedCommand)
	{
		byteCommand += 2; // for extanded command
		offsetData += 2;
	}

	uint8_t buf[TPPDU_MAX_DATALEN] = {TPDELIM_FRAME_STX, 0, commandNumberData, byteCommand};
	uint8_t *dataPointer = data + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH;
	memcpy_s(buf + offsetData, TPPDU_MAX_DATALEN - offsetData, dataPointer, data[COMMAND_NUMBER_LENGTH]);

	if (isExtendedCommand)
	{
		uint16_t extendedCommand = htons(commandNumber);
		memcpy_s(buf + offsetData - 2, TPPDU_MAX_DATALEN, &extendedCommand, sizeof(extendedCommand));
	}
	return TpPduStore(buf);
}

DMCommands::DMCommands(uint8_t *data, uint16_t byteCount, uint16_t seqNumber, IResponseSender *responseSender, bool_t noMessResponse) : ICommand(responseSender, seqNumber, noMessResponse),
																												 m_command48(NULL), m_typeRes(HARTIP_MSG_TYPE_RESPONSE)
{
	if (data == NULL || byteCount < cMinimumDirectPDULength )
	{
		m_isGood = FALSE;
		return;
	}
	m_deviceStatus = data[DEVICE_STATUS_IDX];
	m_extendedStatus = data[EXTENDED_STATUS_IDX];
	uint16_t currentByte = FIRST_COMMAND_IDX;
	while (currentByte < byteCount)
	{
		if(byteCount - currentByte < COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH ||
		 *(data+currentByte + COMMAND_NUMBER_LENGTH) + COMMAND_NUMBER_LENGTH + COMMAND_BYTE_LENGTH > byteCount - currentByte)
		{
			m_listCommands.clear();
			m_isGood = FALSE;
			return;
		}
		TpPduStore store =  ToTpPduAck(data + currentByte);
		TPCommand *command = new TPCommand(store, this, m_noMessResponse);

		if(command->IsSecurityCommand() == TRUE)
		{
			print_to_both(p_toolLogPtr,"Direct PDU secure command\n");

			m_isSecurityCommand = TRUE;
		}

		if(FALSE == ReadOnlyCommandsManager::Instance().IsCommandReadOnly(command->GetTpPdu().CmdNum()))
		{
			print_to_both(p_toolLogPtr, "Direct PDU Read Only Command found\n");

			m_isReadOnlyCommand = TRUE;
		}

		m_listCommands.push_back(command);
		currentByte += command->GetTpPdu().RequestByteCount() + DIRECT_MESSAGE_COMMAND_LENGTH;
	}
	AuditLogger->UpdateStxCounter(m_resSender->GetSession());
}

errVal_t DMCommands::Execute()
{
	errVal_t res = NO_ERROR;
	m_activeCommand.reserve(m_listCommands.size());
	for (size_t i = 0; i < m_listCommands.size(); ++i)
	{
		if (!m_listCommands[i]->GetTpPdu().IsSTX())
		{
			continue;
		}

		int transaction = m_listCommands[i]->GetNumberTransaction();
		if (transaction != 0)
		{
			int command = m_listCommands[i]->GetTpPdu().CmdNum();
			m_activeCommand.push_back(command);
		}
		m_listCommands[i]->setDmMsg(TRUE); // #58
		errVal_t errval = m_listCommands[i]->Execute();

		if (errval != NO_ERROR)
		{
			res = errval;
		}
		m_listCommands[i]->setDmMsg(FALSE);
	}
	m_command48 = CreateCommand48();
	m_command48->setDmMsg(TRUE); // #58
	errVal_t errval = m_command48->Execute();
	if (errval != NO_ERROR)
	{
		res = errval;
	}
	m_command48->setDmMsg(FALSE); // #58
	return res;
}

errVal_t DMCommands::SendMessage(TpPdu tppdu, int transaction)
{
	return NO_ERROR;
}

errVal_t DMCommands::CreateMessage(hartip_msg_t &message)
{
	message.hipHdr.version = HARTIP_PROTOCOL_VERSION;
	message.hipHdr.status = 0;
	message.hipHdr.msgType = m_typeRes;
	message.hipHdr.msgID = HARTIP_MSG_ID_DM_PDU;
	message.hipHdr.byteCount = HARTIP_HEADER_LEN;
	message.hipHdr.seqNum = m_seqNumber;

	uint16_t currentByte = 2;

	message.hipTPPDU[DEVICE_STATUS_IDX] = m_command48->GetTpPdu().DeviceStatus();
	message.hipTPPDU[EXTENDED_STATUS_IDX] = m_command48->GetTpPdu().ResponseBytes()[EXTENDED_STATUS_BYTE];

	for (size_t i = 0; i < m_listCommands.size(); ++i)
	{
		TpPdu tppdu = m_listCommands[i]->GetTpPdu();
		if (HARTIP_MAX_PYLD_LEN < currentByte + tppdu.ResponseByteCount() - 1 /*no Device Status*/ + DIRECT_MESSAGE_COMMAND_LENGTH)
		{
			return MSG_ERROR;
		}
		DirectPDUCommand command;
		command.m_pCommand = message.hipTPPDU + currentByte;
		command.SetNumberCommand(tppdu.CmdNum());

		bool_t isExpCmd = tppdu.IsExpCmd() ? TRUE : FALSE;
		uint8_t responseByteCount = tppdu.ResponseByteCount();

		if(tppdu.IsSTX())
		{
			print_to_both(p_toolLogPtr,"IsSTX\n");

			command.SetData(tppdu.DataBytes(), responseByteCount, isExpCmd);
		}
		else
		{
			print_to_both(p_toolLogPtr,"Non STX\n");

			command.SetData(tppdu.DataBytes()-2, responseByteCount, isExpCmd);
		}

		currentByte += responseByteCount - 1 /*no Device Status*/ + DIRECT_MESSAGE_COMMAND_LENGTH;
	}
	message.hipHdr.byteCount += currentByte;

	return NO_ERROR;
}

DMCommands::~DMCommands()
{
	for (size_t i = 0; i < m_listCommands.size(); ++i)
	{
		delete m_listCommands[i];
	}
	if (m_command48 != NULL)
		delete m_command48;
}

errVal_t DMCommands::SendBinaryResponse(void* pData, int size)
{
	return VALIDATION_ERROR;
}

errVal_t DMCommands::SendResponse(hartip_msg_t *p_response)
{
	errVal_t err = NO_ERROR;
	TpPdu pdu(p_response->hipTPPDU);
	bool complete = true, finded = true;
	for (size_t i = 0; i < m_listCommands.size(); ++i)
	{
		if (!m_listCommands[i]->IsResponse())
		{
			finded = false;
		}
	}
	if (finded && m_command48 != NULL && m_command48->IsResponse())
	{
		m_isResponse = TRUE;
		hartip_msg_t hartipmsg;
		err = CreateMessage(hartipmsg);
		if (err != NO_ERROR)
			return err;
		err = m_resSender->SendResponse(&hartipmsg);
		if (err == NO_ERROR)
		{
			AuditLogger->UpdateAckCounter(m_resSender->GetSession());
		}
		m_isProcessed = TRUE;
	}
	return err;
}

char *DMCommands::ToHex()
{
	return NULL;
}

uint16_t DMCommands::GetSessionNumber()
{
	return m_resSender->GetSessionNumber();
}

TPCommand *DMCommands::CreateCommand48()
{
	uint8_t buf[TPPDU_MAX_DATALEN] = {TPDELIM_FRAME_STX, /*PollingAddress*/ 0, COMMAND_48, COMMAND_48_BYTE_COUNT, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	TpPdu tppdu(buf);
	tppdu.SetCheckSum();
	TPCommand *command = new TPCommand(TpPduStore(tppdu.GetPdu()), this, m_noMessResponse);

	return command;
}

IResponseSender *DMCommands::GetParentSender()
{
	return m_resSender;
}

HARTIPConnection *DMCommands::GetSession()
{
	return m_resSender->GetSession();
}
