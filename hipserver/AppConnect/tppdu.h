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

/**********************************************************
 * File Name:
 *   tppdu.h
 * File Description:
 *   Lightweight class modeling Token-passing PDU's
 *
 *   This class does not store the binary pdu, only a pointer
 *   to it. It does not manage this memory, the client code
 *   is responsible for this.  Therefore, this class is not
 *   intended to persist.
 *
 *   It uses methods to extract the parts of the
 *   PDU.
 *
 **********************************************************/

#ifndef TPPDU_H_
#define TPPDU_H_

#include "tpdll.h"
#include "hartdefs.h"
#include "safe_lib.h"

#include <string.h>

#define ERR_RC_BYTECOUNT   2 // Bytecount of rsp in case of error

#define INIT_APP_CMD			1
#define TERMINATE_APP_CMD	2

// simple storage mechanism to persist the PDUs when need be
class TpPduStore
{
	uint8_t pdustore[TPPDU_MAX_FRAMELEN];

public:
	TpPduStore()
	{
	}
	;
	TpPduStore(uint8_t *data)
	{
		SetStore(data);
	}
	;
	void SetStore(uint8_t *data)
	{
		memcpy_s(pdustore, TPPDU_MAX_FRAMELEN, (const void *) data, TPPDU_MAX_FRAMELEN);
	}
	;
	uint8_t *Store()
	{
		return pdustore;
	}
	;
};

class TpPdu
{
  protected:
    uint8_t *pPDU;
    uint8_t addedByteCount; // number of bytes added to data in response,
                              // not including RC+STATUS bytes
    uint8_t reqByteCount;
    uint8_t savedDeviceStatus;

  public:
    TpPdu() {};
    TpPdu(uint8_t *data){ SetPdu(data); };;
    TpPdu(TpPduStore &store);

    uint8_t *GetPdu() { return pPDU; };
	void     SetPdu(uint8_t *data){ pPDU = data;  addedByteCount = 0;};

    bool IsSTX()  { return TPDELIM_FRAME_STX   == (*Delim() & TPDELIM_FRAME_MASK); };
    bool IsACK()  { return TPDELIM_FRAME_ACK   == (*Delim() & TPDELIM_FRAME_MASK); };
    bool IsBACK() { return TPDELIM_FRAME_BACK  == (*Delim() & TPDELIM_FRAME_MASK); };

    uint8_t *Delim();					// the delimiter byte (we can read or write it)
    bool IsLongFrame();
    uint8_t  AddressLen();				// number of bytes in the address 1 or 5)
    uint8_t *Address();			        // fetch ptr into raw pkt to address byte 0 (not const, we have to be able to set it)
    bool AddressMatch(const uint8_t *a);// compares passed in address to pkt address, true at match
    bool ExpectResponse();
    bool IsControlMessage();

    bool IsExpCmd();

	uint8_t *DataBytes();   // -> beginning of data, may have exp command number
	uint8_t *RequestBytes();
	uint8_t *ResponseBytes();
	uint8_t *ResponseCodeBytes();	// RC, BC, response bytes starts here
	uint8_t RequestByteCount();
	uint8_t ResponseByteCount();

	uint16_t CmdNum();     // handles expanded commands
	uint16_t CmdNum1Byte();      // returns 1 byte command number after the address
	uint8_t ByteCount();
	uint8_t ResponseCode();
	uint8_t DeviceStatus();
	uint8_t PduLength(); // calculate total length of PDU with check byte, handles request/response
	uint8_t TotalLength(); // 4devices...of packet, without preamble

    void SetRCStatus(uint8_t rc, uint8_t status);
    void SetByteCount(uint8_t bc);
	void setCommandNumber(uint16_t newCmd);
	
	void setReqByteCount(uint8_t src) { reqByteCount = src; }
	void setSavedDeviceStatus(uint8_t src) { savedDeviceStatus = src; } // #165

	uint8_t getReqByteCount() { return reqByteCount; } // #36
	uint8_t getSavedDevStatus() { return savedDeviceStatus; } // #165

	bool Matches(TpPdu &other); // address+cmd match - test if response matches request

	// RESPONSE PROCESSING NOTES:
	//
	//  Long and short frame messages are processed
	//
	// Both Ok and Err response processing construct their pdu's IN-PLACE, including the checksum
	//  * the request data at pdu is replaced with the proper response pdu
	//  * Err responses do not return response bytes
	//
	// In the case where a response adds data to the request bytes:
	//  * a subclass of TpPdu adds new data directly to the end of the request bytes
	//  * the number of new bytes added are tracked in the  member addedByteByteCnt
	bool Validate(uint8_t requestBC);
	void ProcessErrResponse(uint8_t rc);
	void ProcessOkResponse(uint8_t rc, uint8_t bc);
	void ProcessOkResponse(uint8_t rc, uint8_t *data, uint8_t datalen);
	uint8_t CheckSum(uint8_t *p, uint8_t plen);
	void SetCheckSum();
	void InsertCheckSum();// 4devices
	void ProcessOkResponseAddData(uint8_t rc, uint8_t bc, uint8_t addData); // #6005
	void AddData(uint8_t *addData, uint8_t bc); // #6005

	virtual void printMsg();
	char *ToHex();

	bool IsErrorResponse();
};

// specific  messages classes for APP INIT and TERMINATE control messages

#define TPPDU_INIT_LABEL_SIZE	80

class InitAppPdu : public TpPdu
{
	TpPduStore store;

public:

	// INIT message request
	InitAppPdu();

	// initialize the PDU from a request message in a buffer
	InitAppPdu(uint8_t *data);

	// create INIT message response using label
	// Label: 80 bytes Latin-1 string label that is unique to the APP,
	// including its version number
	void ProcessOkResponse(char *label);

	// pick label out of response bytes
	char *GetLabel();
};

class TerminateAppPdu : public TpPdu
{
	TpPduStore store;

	// TERMINATE message request
	TerminateAppPdu();

	// initialize the PDU from a request message in a buffer
	TerminateAppPdu(uint8_t *data);
};

/******************************************
 ***** Syslog`s constants (From Spec 85) **
 ******************************************/
#define SYSLOG_PRIORITY_LEN     2
#define SYSLOG_STATUS_LEN       2
#define SYSLOG_TIMESTAMP_LEN    17
#define SYSLOG_HOSTNAME_LEN     64
#define SYSLOG_MANUFACTURER_LEN 2
#define SYSLOG_PRODUCT_LEN      2
#define SYSLOG_DEV_REV_LEN      1
#define SYSLOG_EVENT_ID_LEN     2
#define SYSLOG_DESC_LEN         158
#define SYSLOG_SEVERITY_LEN     1
#define SYSLOG_EXTENSION_LEN    4

class SyslogAppPdu : public TpPdu
{
	TpPduStore store;
public:
	// initialize the PDU from a request message in a buffer
	SyslogAppPdu(uint8_t *data)
	:store(data)
	{};

	unsigned short Priority();
	unsigned short Status();
	void GetDate(char* to, int len);
	void GetHost(char* to, int len);
	unsigned short Manufacturer();
	unsigned short ExtendedDeviceType();
	unsigned char DeviceRevision();
	unsigned short EventId();
	void GetDescription(char* to, int len);
	unsigned char Severity();
	unsigned int DeviceID();

};


#endif /* TPPDU_H_ */
