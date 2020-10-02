/*************************************************************************************************
 * Copyright 2020 FieldComm Group, Inc.
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
 *   Lightweight class modeling Tonken-passing PDU's
 *
 **********************************************************/

#include "tppdu.h"
#include <string.h>
#include <stdio.h>
#include "toolutils.h"



TpPdu::TpPdu(TpPduStore &store)
{
  pPDU = store.Store();
  addedByteCount = 0;
};

uint8_t *TpPdu::Delim()
{
  uint8_t *p_delim = &(pPDU[TP_OFFSET_DELIM]);
  return p_delim;
}

bool TpPdu::IsLongFrame()
{
    bool longframe = (TPDELIM_ADDR_MASK & *Delim()) == TPDELIM_ADDR_MASK;
    return longframe;
}

uint8_t TpPdu::AddressLen()
{
  uint8_t addresslen = IsLongFrame() ? TPHDR_ADDRLEN_UNIQ : TPHDR_ADDRLEN_POLL;
  return addresslen;
}

uint8_t *TpPdu::Address()
{
  uint8_t *address = &pPDU[TP_OFFSET_ADDR];
  return address;
}

bool TpPdu::AddressMatch(const uint8_t *a)
{
  int len = AddressLen();
  uint8_t buf1[TPHDR_ADDRLEN_UNIQ];
  uint8_t buf2[TPHDR_ADDRLEN_UNIQ];
  memcpy_s(buf1, TPHDR_ADDRLEN_UNIQ, Address(), len);
  memcpy_s(buf2, TPHDR_ADDRLEN_UNIQ, a, len);

  //// mask off primary master bit
  //buf1[0] &= 0x7f;
  //buf2[0] &= 0x7f;
  // mask off primary master bit AND burst mode bit
  buf1[0] &= 0x3f;
  buf2[0] &= 0x3f;

  bool match = (memcmp(buf1, buf2, AddressLen()) == 0);
  return match;
}

/*
 * A ExpectResponse should be true unless address
 * is from HSniffer or WiAnalys.
 */
bool TpPdu::ExpectResponse()
{
  uint8_t buf1[TPHDR_ADDRLEN_UNIQ] = {0x26,0x46,0xde,0xad,0x99};
  uint8_t buf2[TPHDR_ADDRLEN_UNIQ] = {0x2F,0xEA,0x0A,0x23,0x45};
  return ((!AddressMatch(buf1)) && (!AddressMatch(buf2)));
}

bool TpPdu::IsControlMessage()
{
	uint8_t buf1[TPHDR_ADDRLEN_UNIQ] =
	{ 0, 0, 0, 0, 0 };
	return IsLongFrame() && AddressMatch(buf1);
}

uint8_t *TpPdu::DataBytes()
{
  // get index of data field
  uint8_t index = IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;

  // correct it for RC+STATUS
  index = IsSTX() ? index : index+2;

  return &pPDU[index];
}

bool TpPdu::IsExpCmd()
{
  int index = IsLongFrame() ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;
  uint32_t cmd = pPDU[index];
  return (HART_CMD_EXP_FLAG == cmd);
}

uint8_t *TpPdu::RequestBytes()
{
  return IsExpCmd() ?  (DataBytes() + 2) : DataBytes();
}

uint8_t *TpPdu::ResponseBytes()
{
	return RequestBytes();  // already corrected for RC+STATUS
}

uint8_t *TpPdu::ResponseCodeBytes()
{
	return ResponseBytes() - 4;
}

uint8_t TpPdu::RequestByteCount()
{
  return IsExpCmd() ?  (ByteCount() - 2 ) : ByteCount();
}

uint8_t TpPdu::ResponseByteCount()
{
  return IsExpCmd() ?  (ByteCount() - 2 ) : ByteCount();
}

uint16_t TpPdu::CmdNum()
{
  int index = IsLongFrame() ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;
  uint32_t cmd = pPDU[index];
  if (HART_CMD_EXP_FLAG == cmd)
  {
	  int minbc = IsSTX() ? 0 : 2;

	  if (ByteCount() > minbc)
	  {
	    // get index of expanded cmd #
	    index = IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;

	    // correct it for RC+STATUS
	    index = IsSTX() ? index : index+2;

	    cmd = (pPDU[index] << 8) + pPDU[index+1];
	  }
	  else
	  {
		  // no data bytes => leave command number as 31
	  }
  }

  return cmd;
}

uint8_t TpPdu::ByteCount()
{
  int bcindex = (IsLongFrame()) ?
      TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  return pPDU[bcindex];
}

void TpPdu::SetByteCount(uint8_t bc)
{
  int bcindex = (IsLongFrame()) ?
      TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  pPDU[bcindex] = bc;
}

uint8_t TpPdu::ResponseCode()
{
  int bcindex = (IsLongFrame()) ?
      TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  return pPDU[bcindex + 1];  // response code next byte past byte count
}

uint8_t TpPdu::DeviceStatus()
{
  int bcindex = (IsLongFrame()) ?
      TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  return pPDU[bcindex + 2];  // status is 2 bytes past byte count
}

// return total length of PDU
uint8_t TpPdu::PduLength()
{
  int bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  //  delim     1 or 5 addr    cm  BC  DATA        CHK
  //  xx		xxxxxxxxxx     xx  xx  xxxxxxxxxx  xx

  int bc = pPDU[bcindex];
	int len = bcindex + 1 + bc + 1;// + (index to counting number) + checksum
	// if the byte count doesn't already include the RC & DevStatus then somebody screwed up!
	// Don't add it here when you have nothing to put in it.                stevev 28mar2019
	//if (false == IsSTX())
	//{
	//	len += 2;   // +2 for RC+STATUS
	//}


	return len;
}

// current pdu size counting address, data and checksum
uint8_t TpPdu::TotalLength()
{
	int bcindex;  
	// index number of the Byte Count byte, adjusted for address length
	bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

	//  delim     1 or 5 addr       cmd  BC  DATA        CHK
	//  xx		xx xx xx xx xx     xx  xx  xxxxxxxxxx  xx
	//  BC is number of bytes in the DATA section

	int bc = pPDU[bcindex];
	bcindex += 1; // convert index to counting number (length thru BC)

	// length thru byte count, + data + chcksum
	int len = bcindex + bc + 1;// +1 (checksum)

	return len;// number of bytes in the pdu
}

void TpPdu::SetRCStatus(uint8_t rc, uint8_t status)
{
  int bcindex = (IsLongFrame()) ?
      TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

  pPDU[bcindex+1] = rc;
  pPDU[bcindex+2] = status;
}


// PDU's "match" if address and command # match
bool TpPdu::Matches(TpPdu &other)
{
  bool    retval = false;

  // Check if Address byte(s) + Cmd byte # match
  if (AddressMatch(other.Address())  &&  CmdNum() == other.CmdNum())
  {
    // PDUs match thus far
    retval = true;
    uint8_t index = IsLongFrame() ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;

    if (IsExpCmd() /*pPDU[index] == HART_CMD_EXP_FLAG*/)
    { // test expanded command #s

      if ((IsSTX() && ByteCount() == 0) || (other.IsSTX() && other.ByteCount() == 0))
      {
    	  // if either is a request with 0 bytes,
    	  // then we can't consider the expanded command number

    	  retval = true;	// for clarity
      }
      else
      {
		  index = IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;
		  if ((PduLength() > index+1) && (other.PduLength() > index+1))
		  { // PDUs are big enough to hold expanded byte
			if (CmdNum() != other.CmdNum())
			{ // expanded cmd #s do not match
			  retval = false;
			}
		  }
      }
    } // if (pPDU[index] == HART_CMD_EXP_FLAG)
  }

  return (retval);
}

// request bytes are not returned on Err responses
void TpPdu::ProcessErrResponse(uint8_t rc)
{
  // *this is the request PDU augmented with response data

  /* Build Response PDU in temp buffer, then copy to pPDU */
  uint8_t  rspBuff[TPPDU_MAX_FRAMELEN];
  memset_s(rspBuff, TPPDU_MAX_FRAMELEN, 0);

  /* Set response bytes starting with the Delimiter */
  uint16_t index = TP_OFFSET_DELIM; // Byte 0 of TP PDU
  rspBuff[index] = TPDELIM_ACK_UNIQ;

  /* Set Long Frame Address */
  uint8_t addrLen = TPHDR_ADDRLEN_UNIQ;
  index += TPHDR_DELIMLEN;
  memcpy_s(&rspBuff[index], addrLen, &pPDU[index], addrLen);

  /* Apply bit masks for Master Address and Burst Mode (sometimes,
   * the Master may have these bits set wrong). Only Primary Master
   * expected.
   */
  rspBuff[index]  = rspBuff[index] | TPPOLL_PRIM_MASTER_MASK;
  rspBuff[index] &= (~TPPOLL_FDEV_BURST_MASK);

  /* Set Command Number */
  uint8_t cmdNum = pPDU[TP_OFFSET_CMD_UNIQ];
  index += addrLen;
  rspBuff[index] = cmdNum;

  /* Set Byte Count starting with a byte each for RC and Device Status */
  uint8_t rspLen = ERR_RC_BYTECOUNT;

  /* Adjust byte count for Cmd 31, based on if it is used as an
   * expansion flag or a pure command in the request PDU.
   */
  bool_t is16BitCmd = FALSE;
  if (cmdNum == HART_CMD_EXP_FLAG)
  {
    uint8_t reqBC = pPDU[TP_OFFSET_BCOUNT_UNIQ];

    /* A valid Expansion Flag Cmd has at least 2 data bytes
     * for the 16-bit command value.
     */
    if (reqBC >= 2)
    {
      rspLen += 2;
      is16BitCmd = TRUE;
    }
  }

  index += TPHDR_CMDLEN;
  rspBuff[index] = rspLen;

  /* Set RC and Status Bytes */
  index += TPHDR_BCOUNTLEN;
  rspBuff[index++] = rc;
  rspBuff[index++] = STATUS_OK;

  /* Set 16-bit cmd number, if applicable */
  if (is16BitCmd)
  {
    uint8_t ind16BitCmd = TP_OFFSET_CMD_UNIQ + 2;

    rspBuff[index++] = pPDU[ind16BitCmd];
    rspBuff[index++] = pPDU[ind16BitCmd + 1];
  }

  rspBuff[index++] = CheckSum(rspBuff, index);

  // save completed response PDU
  memcpy_s(pPDU, TPPDU_MAX_FRAMELEN, rspBuff, index);
}

void TpPdu::ProcessOkResponse(uint8_t rc, uint8_t *data, uint8_t datalen)
{
	uint8_t bc = ByteCount() + datalen;
	ProcessOkResponse(rc, bc);
	memcpy_s(ResponseBytes(), TPPDU_MAX_FRAMELEN, data, datalen);
	SetCheckSum();
}

// request bytes are returned on Ok responses
void TpPdu::ProcessOkResponse(uint8_t rc, uint8_t bc)
{
  // *this is the request PDU augmented with response data

  /* Build Response PDU in temp buffer, then copy to pPDU */
  uint8_t  rspBuff[TPPDU_MAX_FRAMELEN];
  memset_s(rspBuff, TPPDU_MAX_FRAMELEN, 0);

  /* Set response bytes starting with the Delimiter */
  uint16_t index = TP_OFFSET_DELIM;                   // Byte 0 of TP PDU

  uint8_t highbit = pPDU[index] & TPDELIM_ADDR_UNIQ;   // get high bit of request delimiter (& 0x80)
//  rspBuff[index] = highbit | TPDELIM_FRAME_ACK;       // reply correctly for short and long frame

  if (highbit)
    rspBuff[index] = TPDELIM_ACK_UNIQ;  // 86
  else
    rspBuff[index] = TPDELIM_FRAME_ACK; // 06

  /* Set Long or Short Frame Address */
  uint8_t addrLen = highbit ? TPHDR_ADDRLEN_UNIQ : TPHDR_ADDRLEN_POLL;
  index += TPHDR_DELIMLEN;
  memcpy_s(&rspBuff[index], addrLen, &pPDU[index], addrLen);

  /* Apply bit masks for Master Address and Burst Mode (sometimes,
   * the Master may have these bits set wrong). Only Primary Master
   * expected.
   */
  rspBuff[index]  = rspBuff[index] | TPPOLL_PRIM_MASTER_MASK;
  rspBuff[index] &= (~TPPOLL_FDEV_BURST_MASK);

  /* Set Command Number */
  index += addrLen;
  rspBuff[index] = pPDU[index];

  /* Set Byte Count */
  uint8_t rspLen = ByteCount() + addedByteCount;

  /* Add 1 byte each for RC and Device Status */
  rspLen += 2;

	//rspLen = bc < rspLen ? bc : rspLen; // BC can't exceed what device knows about
	rspLen = bc;

  index += TPHDR_CMDLEN;
  rspBuff[index] = rspLen;

  /* Set RC and Status Bytes */
  index += TPHDR_BCOUNTLEN;
  rspBuff[index++] = rc;
  rspBuff[index++] = STATUS_OK;

  // copy all data bytes, including exp cmd #
  memcpy_s(&rspBuff[index], TPPDU_MAX_DATALEN, DataBytes(), rspLen);

  index += rspLen;
  rspBuff[index++] = CheckSum(rspBuff, index);

  // save completed response PDU
  memcpy_s(pPDU, TPPDU_MAX_FRAMELEN, rspBuff, index);
}

/*
 * #6005
 * Takes a buffer (addData) and the new byte count
 * (added bytes + original Byte Count) as arguments.
 * Calculates the original pduSize and copies it to a temp buffer.
 * Creates a new message with new data and copies it
 * back to the pdu.
 */
void TpPdu::AddData(uint8_t *addData, uint8_t addedBytes)
{
	uint8_t tempBuff[TPPDU_MAX_FRAMELEN] = {'\0'};
	uint8_t *p = GetPdu();

	int index = 0;
	int orgPduSize = (PduLength() - (addedBytes+1)) ; // PduLength has added bytes and checksum count included. Recalculate.

	while(index < orgPduSize)
	{ // Copy everything to where the added data needs to go.
		tempBuff[index] = *(p+index);
		index++;
	}

	for(int i = 0; i < addedBytes; i++)
	{
		// Add in data.
		tempBuff[index++] = addData[i];
	}

	tempBuff[index++] = CheckSum(tempBuff, index);
	memcpy_s(pPDU, TPPDU_MAX_FRAMELEN, tempBuff, index);
}

uint8_t TpPdu::CheckSum(uint8_t *p, uint8_t plen)
{
  uint8_t  i;
  uint8_t  chkSum = 0;

  for (i = 0; i < plen; i++)
  {
    chkSum ^= p[i];
  }

 return (chkSum);
}

void TpPdu::SetCheckSum()
{
	int len = PduLength();
	pPDU[len + 1] = CheckSum(pPDU, len);
}


void TpPdu::InsertCheckSum()
{
	int len   = TotalLength() - 1;// -1 convert counting number to index
	pPDU[len] = CheckSum(pPDU, len);// checksum doesn't include the checksum byte
}

// return true if PDU is valid
// else do Err processing
bool TpPdu::Validate(uint8_t requestBC)
{
  if (RequestByteCount() < requestBC)
  {
    ProcessErrResponse(RC_TOO_FEW);
    return false;
  }

  // adjust BC downwards for extra data bytes
  if (RequestByteCount() > requestBC)
  {
    uint8_t deltabc = RequestByteCount() - requestBC; // too large by this much
    SetByteCount(ByteCount() - deltabc);  // accommodate cases with excessive byte count
  }

  return true;
}

char *TpPdu::ToHex()
{
  const int bufsiz = 2000;
	static char buf[bufsiz];
	memset_s(buf, bufsiz, 0);

  const int bytevalsiz = 10;
	char byteval[bytevalsiz]; // #689
	int len = PduLength() + 1;
	for (int i = 0; i < len; i++)
	{
		sprintf_s(byteval, bytevalsiz, "%02X ", pPDU[i]);
		strcat_s(buf, bufsiz, byteval);
	}
	return buf;
}

void TpPdu::printMsg()
{
	if (pPDU == NULL)
	{
	printf("ERROR   ERROR   ERROR   ERROR   ERROR   ERROR   ERROR   ERROR \n");
	}
	else
	{
		for (int i = 0; i < PduLength(); i++)
		{
			printf(" 0x%02X", pPDU[i]);
			if (i == 5 || i == 6 || i == 7)
			{
				printf(" ");// delineate cmd & BC
			}
		}
		printf("\n");
	}
}



void TpPdu::setCommandNumber(uint16_t newCmd)
{
	int cindex = (IsLongFrame()) ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;
  
	if ( newCmd < 256 )
	{
		pPDU[cindex] = newCmd;
	}
	else // has to be  < 65536 due to 16 bit cmd# in
	{
		pPDU[cindex] = HART_CMD_EXP_FLAG;
		
		// get index of expanded cmd #, corrected for RC & DEVSTAT
		cindex = 2 + (IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL);
		pPDU[cindex] = (uint8_t)(newCmd & 0xff);
		pPDU[cindex+1] = (uint8_t)((newCmd>>8) & 0xff);
	}
}

bool TpPdu::IsErrorResponse()
{
	bool status = false;

	// 1-7, 16-23, 32-64,
	// 9-13, 15, 28, 29, 65-95
	int rc = ResponseCode();
	if (rc & 0x80)
		status = true;	// COMM ERROR

	else
		status = 	( 1 <= rc  &&  rc <= 7) ||
					(16 <= rc  &&  rc <= 23) ||
					(32 <= rc  &&  rc <= 64) ||
					( 9 <= rc  &&  rc <= 13) ||
					(15 == rc) ||
					(28 == rc) ||
					(29 == rc) ||
					(65 <= rc  &&  rc <= 95);

	return status;
}


//////////////////////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////////////////////

// INIT message request
InitAppPdu:: InitAppPdu()
{
	addedByteCount = 0;

	// pPDU must be set for the various TpPdu methods to operate
	pPDU = store.Store();	// set pointer to data storage

	// INIT message request = 82, long address 0, command 1, no data, check byte
	uint8_t buf[TPPDU_MAX_DATALEN] = { 0x82, 0, 0, 0, 0, 0, 1, 0, 0 };
	int len = PduLength();
	buf[len - 1] = CheckSum(buf, len);

	store.SetStore(buf);	// copy buf into store
}

// initialize the PDU from a request message in a buffer
InitAppPdu::InitAppPdu(uint8_t *data) : store(data)
{
	addedByteCount = 0;
}

// create INIT message response using label
// Label: 80 bytes Latin-1 string label that is unique to the APP,
// including its version number
void InitAppPdu::ProcessOkResponse(char *label)
{
	addedByteCount = 0;

	// convert request into success response, allocate space for label
	TpPdu::ProcessOkResponse(0, TPPDU_INIT_LABEL_SIZE+2);

	// put label into 80 byte buffer, padded with nulls
	uint8_t buf[TPPDU_INIT_LABEL_SIZE];
	memset_s(buf, TPPDU_INIT_LABEL_SIZE, 0);

	// copy the label to be returned into the response bytes
	memcpy_s(ResponseBytes(), TPPDU_MAX_DATALEN, label, strnlen_s(label, 80));
}

// pick label out of response bytes
char *InitAppPdu::GetLabel()
{
	// label is the only data in the response data, 0 padded to the right
	return (char *) ResponseBytes();
}

// TERMINATE message request
TerminateAppPdu::TerminateAppPdu()
{
	addedByteCount = 0;

	// INIT message request = 82, long address 0, command 2, no data, check byte
	uint8_t buf[TPPDU_MAX_DATALEN] = { 0x82, 0, 0, 0, 0, 0, 2, 0, 0 };
	buf[PduLength() - 1] = CheckSum(buf, PduLength());

	store.SetStore(buf);	// copy buf into store
	pPDU = store.Store();	// set pointer to data storage
}

// initialize the PDU from a request message in a buffer
TerminateAppPdu::TerminateAppPdu(uint8_t *data) : store(data)
{
	addedByteCount = 0;
}

