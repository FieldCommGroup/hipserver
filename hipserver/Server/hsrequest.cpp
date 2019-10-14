/*************************************************************************************************
 * Copyright 2019 FieldComm Group, Inc.
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
 *
 * File Name:
 *   hsrequest.cpp
 *
 * File Description:
 *   Functions to create, delete and use records in the request_table
 *
 **********************************************************/
#include <assert.h>
#include <list>
#include <map>
#include <string.h>
#include <toolsems.h>

#include "hartdefs.h"
#include "tpdll.h"
#include "tppdu.h"

#include "hsrequest.h"
#include "debug.h"

/************
 *  Globals
 ************/

/************************************
 *  Private variables for this file
 ************************************/
//std::list<hsmessage_t> request_table;
std::map<int, hsmessage_t> request_table;


/**********************************************
 *  Private functions for this file
 **********************************************/

static int dump_request_table()
{
	dbgp_logdbg("request table dump:\n");

	int n = 0;
	std::map<int, hsmessage_t>::iterator it = request_table.begin();
	while (it != request_table.end())
	{
		hsmessage_t &rqst = (*it).second;
		TpPdu reqpdu(rqst.message.hipTPPDU);
		dbgp_logdbg("request table [0x%08X] = %s\n", (*it).first, reqpdu.ToHex());
		n++;
		it++;
	}
	return n;	// table row count
}

/**********************************************
 *  Public functions for this file
 **********************************************/

request_table_status_t add_request_to_table(int transaction, hsmessage_t *rqst)
{
#if 0
	TpPdu pdu(rqst->message.hipTPPDU);
	dbgp_logdbg("Add request to table: %s\n", pdu.ToHex());
#endif

	request_table[transaction] = *rqst;  // copy new request

	// purge old records:
	// remove first record if it is too old to keep in the table
	// checking only the first record will keep the list pruned
	time_t timenow;
	time(&timenow);

	std::map<int, hsmessage_t>::iterator it = request_table.begin();
	while (it != request_table.end())
	{ // there is a first record
		hsmessage_t &first_rqst = (*it).second;
		time_t deltat = timenow - first_rqst.time;
		if (deltat > MAX_REQUEST_TABLE_AGE)
		{
			request_table.erase(it); // remove aged record from table
		}
		it++;
	}

	return RTS_OK;          // request is copied into table
}

request_table_status_t find_request_in_table(int transaction, hsmessage_t *result /*returned*/)
{
	request_table_status_t status = RTS_EOF;

	assert(result);

	if (request_table.find(transaction) != request_table.end())
	{
		// found
		status = RTS_OK;
		*result = request_table[transaction];	// copy to returned value
		request_table.erase(transaction);  		// remove the request from the table
	}
	else
	{
		// matching request not found: dump the table contents
		status = RTS_EOF;
		dbgp_logdbg("No matching request found for this transaction: %08X\n", transaction);

		int n = dump_request_table();
		if (n == 0)
			dbgp_logdbg("<request table is empty>\n");
	}

	return status;
}

request_table_status_t clear_request_table()
{
	request_table.clear();
	return RTS_OK;            // table is empty
}

