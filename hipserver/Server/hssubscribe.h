/*****************************************************************
 * Copyright (C) 2017 FieldComm Group
 *
 * All Rights Reserved.
 * This software is CONFIDENTIAL and PROPRIETARY INFORMATION of
 * FieldComm Group, Austin, Texas USA, and may not be used either
 * directly or by reference without permission of FieldComm Group.
 *
 * THIS SOFTWARE FILE AND ITS CONTENTS ARE PROVIDED AS IS WITHOUT
 * WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION, WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND BEING FREE OF DEFECT.
 *
 *****************************************************************/

/*
 * hssubscribe.h
 *
 *  Created on: Nov 10, 2017
 *      Author: tjohnston
 */

#ifndef HIP_SERVER_HSSUBSCRIBE_H_
#define HIP_SERVER_HSSUBSCRIBE_H_

#include "hsmessage.h"

/****************
 *  Definitions
 ****************/

/*************
 *  Typedefs
 *************/
typedef enum
{
	STS_OK = 0, STS_EOF, STS_ERROR
} subscription_table_status_t;

/************
 *  Globals
 ************/

/************************
 *  Function Prototypes
 ************************/

subscription_table_status_t process_cmd532(hsmessage_t *hsmsg);
subscription_table_status_t process_cmd533(hsmessage_t *hsmsg);

// these 3 funcs model a list of attached devices
// every time a longframe command 0 response is observed, the
// address is added to this list.  duplicates are not stored
// this server is a single attached device for now, but will
//  be enhanced to be an IO at some point
void attach_device(uint8_t *addr);
bool is_attached(const uint8_t *addr);
void clear_attached_devices();

// send burst BACK messages to subscribed clients
void send_burst_to_subscribers(hartip_msg_t *p_response);

#endif /* HIP_SERVER_HSSUBSCRIBE_H_ */
