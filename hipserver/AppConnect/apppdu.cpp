/*************************************************************************************************
 *
 * Workfile: appdu.cpp
 * 30Mar18 - paul
 *
 *************************************************************************************************
 * The content of this file is the 
 *     Proprietary and Confidential property of the FieldComm Grup
 * Copyright (c) 2018, Fieldcomm Group Inc., All Rights Reserved 
 *************************************************************************************************
 *
 * Description:
 *		This is the pdu handler for the native device.
 *		Built on tppdu.
 *
*/

#include "apppdu.h"
extern unsigned char respCode,    devStat;// in APP.Cpp

/* long address and short address must be set from outside */
AppPdu::AppPdu()
{	
	// give the TpPdu class a pointer to the data buffer in the AppMsg
	SetPdu(&(pdu[0]));
}

void AppPdu::copy( const AppPdu &src )
{
	shrtAddr = src.shrtAddr;
	memcpy(&(longAddr[0]), &(src.longAddr[0]), 5);
	bytesLoaded = src.bytesLoaded;
	AppMsg * pMsg = dynamic_cast<AppMsg *>(this);
	*pMsg = src;    // operator=
	setupAddress( TPDELIM_ACK_UNIQ );// default to longFrame address/ACK pkt 
	SetPdu(&(pMsg->pdu[0]));
}

// copy constructor
AppPdu::AppPdu( const AppPdu &src )
{
	copy(src);
}


AppPdu::~AppPdu()
{
	SetPdu(NULL);
}

void AppPdu::clear()
{
	AppMsg::clear();
}


// this base class has nothing to do right now
// may be over-ridden by the main class
int AppPdu::processPdu()
{
	return 0;
}


int AppPdu::evalMsg()
{
    char frameType = *Delim() & TPDELIM_FRAME_MASK;

    if ( (( frameType == TPDELIM_FRAME_STX ) || ( frameType == TPDELIM_FRAME_PSK_STX )) )// our type
    {
		if ( AddressMatch(myAddress()))/* APP: we have an address match */
		{
//			msg2Ack(frameType);  // we may want to do this later in the processing
								// yes absolutely, must be done in the processMessage()
			return FOR_US;       /* we be ready to go */
		}// else not ours
	}// else it's not our type
	return NOT_OURS; // for now, we don't want to return an error message for this case
}

/* make the addressed packet into an ACK */
void  AppPdu::msg2Ack(char frameType)
{
	if ( frameType == TPDELIM_FRAME_STX ) 
	{
		*Delim() &= (unsigned char)(~TPDELIM_FRAME_MASK);
		*Delim() |= TPDELIM_FRAME_ACK;
	}
	else 
	{
		*Delim() &= (unsigned char)(~TPDELIM_FRAME_MASK);
		*Delim() |= TPDELIM_FRAME_PSK_ACK;
	}

	*Address() &= (unsigned char)(~TPPOLL_FDEV_BURST_MASK);
}
void AppPdu::setBurstModeInAddr(bool isBursting)
{
	uint8_t M = (isBursting) ? 0x40 : 0x00;
	pdu[1] = (pdu[1] & 0xbF) | M;
}

void AppPdu::setMasterAddr( bool isPrimary )
{
	uint8_t M = (isPrimary)? 0x80 : 0x00;
	longAddr[0] = pdu[1] = (pdu[1] & 0x7F) | M;
}

bool AppPdu::isPrimary()
{
	return ((pdu[1] & 0x7F) != 0 );
}

/* set up the pdu with delim and address */
void AppPdu::setupAddress( uint8_t newDelim )
{
	pdu[TP_OFFSET_DELIM] = newDelim;
	memcpy( &(pdu[TP_OFFSET_ADDR]), longAddr, 5 );
	pdu[TP_OFFSET_CMD_UNIQ] = 0;
}

// for short-frame cmd 0 ACK, remember short- and long-frame addresses
void AppPdu::learnAddress()
{
	if (IsACK() && IsLongFrame()==false && CmdNum() == 0)
	{
		uint8_t ln[TPHDR_ADDRLEN_UNIQ];
		int expDeviceTypeByte = 1;	// see spec 127 for these constants
		int expDeviceTypeSize = 2;
		int deviceIdByte = 9;
		int deviceIdSize = 3;

		memcpy(ln, ResponseBytes()+expDeviceTypeByte, expDeviceTypeSize);	// expanded device type
		memcpy(ln+expDeviceTypeSize, ResponseBytes()+deviceIdByte, deviceIdSize);	// device ID

		setLong(ln);
		setShort(*Address());
	}
}
