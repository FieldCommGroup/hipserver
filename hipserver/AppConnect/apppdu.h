/*************************************************************************************************
 *
 * Workfile: apppdu.h
 * 30Mar18 - paul
 *
 *************************************************************************************************
* The content of this file is the 
 *     Proprietary and Confidential property of the HART Communication Foundation
 * Copyright (c) 2018, FieldComm Group, Inc., All Rights Reserved 
 *************************************************************************************************
 *
 * Description: This is the pdu handler for the native device.
 *	
 * NOTE: Template class implementation must be included in all uses. Implementation is at the end.
 *	
 * #include "apppdu.h"
 */
#pragma once

#ifndef _APPPDU_H
#define _APPPDU_H

#ifdef INC_DEBUG
#pragma message("In apppdu.h")
#endif


#include <stdint.h>
#include <mqueue.h>
#include "appmsg.h"
#include "tppdu.h"

#ifdef INC_DEBUG
#pragma message("    Finished Includes::apppdu.h")
#endif

#define FOR_US            0
#define NOT_OURS         -1
#define ERROR_OCCURRED  -34

#define CONFIG_CHNG_BIT  0x40

class AppPdu : public AppMsg, public TpPdu
{
	uint8_t shrtAddr;   // this can change via command
	uint8_t longAddr[5];// this is normally constant for the lifetime of the class

public: // data
	size_t  bytesLoaded;// total number of bytes read into AppMsg

public:	// Construction
	AppPdu();
	AppPdu( const AppPdu &src );// copy constructor
	void copy( const AppPdu &src );
	virtual ~AppPdu();


public: // Operations
	virtual int  processPdu();// decodes the incoming message and sets proper piece-parts
	virtual int  evalMsg();   // checks for address match

	virtual void clear();

	virtual void msg2Ack(char frameType = TPDELIM_FRAME_STX);// turns the stx msg into an ack message
	virtual void setMasterAddr( bool isPrimary );
	virtual void setBurstModeInAddr(bool isBursting);
	virtual void setAPPCmd(uint32_t newCmd) { command = newCmd; };//app command...
	virtual void setAPPtrans(uint32_t newTrans){ transaction =  newTrans; };
	virtual void setupAddress( uint8_t newDelim );
	virtual void setErrorPkt( void ) {  ProcessErrResponse(1); };// 4devices.. make this over-ridable

public: // accessors
	AppMsg* baseStruct(){ return dynamic_cast<AppMsg*>(this);};
	uint8_t *myAddress() {  return  IsLongFrame()?&(longAddr[0]):&(shrtAddr); };
	bool    isPrimary();// 4devices  host address, false: secondary
	void setShort(uint8_t poll) { shrtAddr= poll; };
	void setLong(uint8_t lng[]){ memcpy(longAddr, lng, 5); };
	void learnAddress();
};


#endif //_APPPDU_H
