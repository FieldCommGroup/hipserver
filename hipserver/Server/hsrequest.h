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
 *****************************************************************/

/*
 * hsrequest.h
 *
 *  Created on: Nov 10, 2017
 *      Author: tjohnston
 *
 *   Functions to create and find request records in the request_table.

 *
 *   The request_table keeps a copy of the requests received from the
 *   client in FIFO order.  Each record contains a request containing
 *   IP session data + the HART-IP request PDU + a time stamp.
 *
 *   New requests are added to the end of the table.
 *
 *   When a PDU arrives and is ready to be sent to the client,
 *   we look up the matching PDU in this table and return it.
 *   We also delete the matched request from this table.
 *
 *   The table is purged of records older than MAX_REQUEST_TABLE_AGE
 *   seconds old.
 */

#ifndef HIP_SERVER_HSREQUEST_H_
#define HIP_SERVER_HSREQUEST_H_

#include "common.h"
#include "hsmessage.h"

#include <time.h>

/****************
 *  Definitions
 ****************/

#define MAX_REQUEST_TABLE_AGE  600 /* seconds */

/*************
 *  Typedefs
 *************/

typedef enum
{
	RTS_OK = 0, RTS_EOF, RTS_ERROR
} request_table_status_t;

/************
 *  Globals
 ************/

class ICommand;

/************************
 *  Function Prototypes
 ************************/

// add a request to the request table
request_table_status_t add_request_to_table(int transaction, ICommand *rqst);

// find a matching PDU, request is returned in result
// RTS_OK      if matching PDU found
// RTS_ERROR   if len is insufficient
// RTS_EOF     if no match is found
request_table_status_t find_request_in_table(int transaction, ICommand **result /*returned*/);

// empty the request_table
request_table_status_t clear_request_table();

#endif /* HIP_SERVER_HSREQUEST_H_ */
