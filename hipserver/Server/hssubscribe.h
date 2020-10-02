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
