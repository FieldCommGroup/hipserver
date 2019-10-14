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

/*
 * File Name:
 * hssubscribe.cpp
 *
 * File Description:
 *   Functions to create, delete and use records in the subscription_table
 *
 *   The subscription_table
 *
 *   Created on: Nov 10, 2017
 *      Author: tjohnston
 */


// Uncomment as needed
#include <assert.h>
#include <list>
#include <string.h>
#include <time.h>
#include <toolsems.h>

#include "tppdu.h"

#include "hsmessage.h"
#include "hssubscribe.h"


/************
 *  Globals
 ************/


/**********************************************
 *  Private class for this file
 **********************************************/

// Subscription commands 532+533 common
class SubscriptionPdu : public TpPdu
{
public:
    enum SubFlags {
      PROCESS_DATA=0x1,
      EVENT_NOTIFICATION=0x2,
      DEVICE_STATUS=0x4,
      DEVICE_CONFIG=0x8,
      WIRELESS_NETWORK_STATS=0x100,
      WIRELESS_HEALTH=0x200
    };
    bool IsBroadcastAddress();
    uint8_t *TargetUniqID();
    uint16_t SubscriptionFlags();
    void SetSubscriptionFlags(uint16_t flags);  // 532 only

    SubscriptionPdu(uint8_t *data) : TpPdu(data) {};
};


class Subscription
{
public:
//    sockaddr_in_t clientAddr;             // client address
    uint8_t sessNum;                      // session number
    uint8_t UniqueID[TPHDR_ADDRLEN_UNIQ]; // device address
    uint16_t flags;

    bool AddressMatch(uint8_t *address);
    void SetAddress(const uint8_t *address);
    bool IsBroadcastAddress();
};


bool SubscriptionPdu::IsBroadcastAddress()
{
  uint8_t baddress[TPHDR_ADDRLEN_UNIQ] = {0};
  return (memcmp(TargetUniqID(), baddress, TPHDR_ADDRLEN_UNIQ) == 0);
}

uint8_t *SubscriptionPdu::TargetUniqID()
{
  return RequestBytes();
}

uint16_t SubscriptionPdu::SubscriptionFlags()
{
  uint8_t *p = TargetUniqID() + TPHDR_ADDRLEN_UNIQ;
  uint16_t flags = ((*p++) << 8);
  flags += (*p);
  return flags;
}

void SubscriptionPdu::SetSubscriptionFlags(uint16_t flags)
{
  uint8_t *p = TargetUniqID() + TPHDR_ADDRLEN_UNIQ;
  *p++ = flags >> 8;
  *p = flags & 0xff;
  addedByteCount += 2;
}

bool Subscription::AddressMatch(uint8_t *address)
{
	// make copies of the 2 addresses, then
	// 1011 1111  mask off field device in burst mode bit

	uint8_t a1[TPHDR_ADDRLEN_UNIQ];
	memcpy(a1, address, TPHDR_ADDRLEN_UNIQ);
	a1[0] &= 0xBF;

	uint8_t a2[TPHDR_ADDRLEN_UNIQ];
	memcpy(a2, UniqueID, TPHDR_ADDRLEN_UNIQ);
	a2[0] &= 0xBF;

	bool match = (memcmp(a1, a2, TPHDR_ADDRLEN_UNIQ)==0);
  return match;
}

void Subscription::SetAddress(const uint8_t *address)
{
  memcpy(UniqueID, address, TPHDR_ADDRLEN_UNIQ);
}

bool Subscription::IsBroadcastAddress()
{
  // all zero address is the broadcast address
  uint8_t baddress[TPHDR_ADDRLEN_UNIQ] = {0};
  bool result = AddressMatch(baddress);
  return result;
}

/************************************
 *  Private variables for this file
 ************************************/

//Subscription table consists of subscription records:
//  Client tcp session number +
//    unique device address (may be 0 for broadcast) +
//    subscription flags
//
//For a particular client, table will contain:
//  Zero records (not subscribed)
//  One record with a broadcast address
//  1+ records with specific device addresses

static std::list<Subscription> subtable;

// device table retains the command 0 response from each device attached
static std::list<TpPduStore> devtable;

/**********************************************
 *  Private functions for this file
 **********************************************/


// discard records for all devices subscribed to by client
static void discard_all_subscriptions(uint8_t sessNum)
{
  for (std::list<Subscription>::iterator itr = subtable.begin(); itr != subtable.end(); /*nothing*/)
  {
    Subscription record = *itr;
    if (sessNum == record.sessNum)
    {
      itr = subtable.erase(itr);
    }
    else
      ++itr;
  }
}

// discard records for client subscribed to particular device
static void discard_all_subscriptions(uint8_t sessNum, const uint8_t *devAddr)
{
  for (std::list<Subscription>::iterator itr = subtable.begin(); itr != subtable.end(); /*nothing*/)
  {
    Subscription record = *itr;
    if (sessNum == record.sessNum && record.AddressMatch((uint8_t *)devAddr))
    {
      itr = subtable.erase(itr);
    }
    else
      ++itr;
  }
}

// return record found for this client+address
static Subscription *find_subscription(uint8_t sessNum, const uint8_t *devAddr)
{
  for (std::list<Subscription>::iterator itr = subtable.begin(); itr != subtable.end(); itr++)
  {
    Subscription record = *itr;
    bool admatch = (record.AddressMatch((uint8_t *)devAddr) || record.IsBroadcastAddress());
    if (sessNum == record.sessNum && admatch)
    {
      return &(*itr);
    }
  }
  return NULL;
}

static void print_unique_id(uint8_t *id)
{
  for (int i=0; i<5; i++)
  {
    printf("%02x", *id++);
  }
}

// print the subscription table to console
static void print_subscription_table(char *msg, uint8_t *id, uint16_t flags)
{
  int n = subtable.size();

  printf("\n%s ", msg);
  print_unique_id(id);
  printf("  %04x", flags);
  printf("\n");

  printf("\nSubscription Table has %d records:\n", n);
  n = 0;
  for (std::list<Subscription>::iterator itr = subtable.begin(); itr != subtable.end(); itr++)
  {
    Subscription record = *itr;
    uint8_t *p = record.UniqueID;
    printf("%d]  ", n++);
    print_unique_id(p);
    printf("\n");
  }
  printf("\n");
}

static void add_subscription(hsmessage_t *hsmsg)
{
  Subscription record;
  record.sessNum = hsmsg->pSession->sessNum;
  SubscriptionPdu subpdu(hsmsg->message.hipTPPDU);
  record.SetAddress(subpdu.TargetUniqID());
  record.flags = subpdu.SubscriptionFlags();

  if (find_subscription(record.sessNum, record.UniqueID) == NULL)
  {
    subtable.push_back(record);
  }
  // else record for this device already exists
}



/**********************************************
 *  Public functions for this file
 **********************************************/

// add a subscription, return 533 response
subscription_table_status_t process_cmd533(hsmessage_t *hsmsg)
{
	const uint8_t bc = 11;  // byte count for success response
	SubscriptionPdu subpdu(hsmsg->message.hipTPPDU);

	if (subpdu.Validate(7))
	{
	if (subpdu.IsBroadcastAddress())
	{
	  // broadcast and device subscriptions may not co-exist
	  discard_all_subscriptions(hsmsg->pSession->sessNum);

	  if (subpdu.SubscriptionFlags() != 0)
	  {
		add_subscription(hsmsg);
	  }
	  // else no records ==> cancels all subscriptions for this client

	  subpdu.ProcessOkResponse(RC_SUCCESS, bc);
	}
	else
	{// request has specific device address

	  // find first record for this client in subscription table
	  Subscription *subscription = find_subscription(hsmsg->pSession->sessNum, subpdu.TargetUniqID());

	  if (subscription)
	  { // found
		if (subscription->IsBroadcastAddress())
		{
		  // can't replace a broadcast subscription with a single device subscription
		  subpdu.ProcessErrResponse(9);  // RC=Individual Subscription Not Allowed
		}
		else
		{
		  // we only have ONE device attached as we are not an IO device
		  discard_all_subscriptions(hsmsg->pSession->sessNum, subpdu.TargetUniqID());
		  if (subpdu.SubscriptionFlags())
		  {
			add_subscription(hsmsg);
		  }
		  // else don't add a record for flags=0000 b/c no record means no subscription

		  subpdu.ProcessOkResponse(RC_SUCCESS, bc);
		}
	  }
	  else
	  { // no record is found in subscription table for this client
		if (is_attached(subpdu.TargetUniqID()))
		{ // we are adding a subscription for a device that is attached
		  add_subscription(hsmsg);
		  subpdu.ProcessOkResponse(RC_SUCCESS, bc);
		}
		else
		{// the device that is being subscribed is not attached
		  subpdu.ProcessErrResponse(65);  // RC=Unknown unique ID
		}
	  }
	}
	}
	// else error processing for invalid command is complete
#if (DEBUG_SUB)
	print_subscription_table((char*)"Add a subscription: ", subpdu.TargetUniqID(), subpdu.SubscriptionFlags());
#endif
	return STS_OK;
}


// find a subscription, return 532 response in PDU
subscription_table_status_t process_cmd532(hsmessage_t *hsmsg)
{
	const uint8_t bc = 11;  // byte count for success response
	SubscriptionPdu findme(hsmsg->message.hipTPPDU); // subscription we are searching for

	if (findme.Validate(5))
	{
	// find first subscription in table matching client and target unique ID
	Subscription *subscription = find_subscription(hsmsg->pSession->sessNum, findme.TargetUniqID());

	if (subscription)
	{
	  if (subscription->IsBroadcastAddress() && findme.IsBroadcastAddress()==false)
	  {
		// can't look up specific device when a broadcast subscription is in place
		findme.ProcessErrResponse(9);  // RC=Individual Subscription Not Allowed
	  }
	  else
	  {
		// update the subscription flags in the PDU that is returned to the client
		findme.SetSubscriptionFlags(subscription->flags);
		findme.ProcessOkResponse(RC_SUCCESS, bc);
	  }
	}
	else
	{ // no subscription matches the 532 request
	  if(findme.IsBroadcastAddress())
	  {
		// we are looking for a broadcast address in an empty table
		findme.ProcessErrResponse(65); // RC=Unknown unique ID
	  }
	  else
	  {
		// we are looking for a device address
		findme.ProcessErrResponse(65); // RC=Target Unique ID must be Broadcast Address 
	  }
	}
	}
	// else error processing for invalid command is complete


	return STS_OK;          // request is copied into table
}

// forward pdu from rspQueue to subscribed clients
void send_burst_to_subscribers(hartip_msg_t *p_response)
{
	TpPdu tppdu(p_response->hipTPPDU);
	for (std::list<Subscription>::iterator itr = subtable.begin(); itr != subtable.end(); /*nothing*/)
	{
		Subscription record = *itr;
		if (record.IsBroadcastAddress() || tppdu.AddressMatch(record.UniqueID))
		{
			send_burst_to_client(p_response, record.sessNum); // manages seq#
		}

		++itr;
	}

}

/*
 * p points to a response PDU. if the PDU is a command 0 response and a matching PDU
 * is not found, then add it to the table of attached devices.
 */
void attach_device(uint8_t *p)
{
	TpPdu cmd(p);
	if (p  &&  cmd.IsLongFrame()  &&  cmd.IsACK()  &&  cmd.CmdNum() == 0  &&  cmd.ResponseCode() == 0)
	{
		if (is_attached((uint8_t *)cmd.Address()) == false)
		{
			TpPduStore saveme(p);
			devtable.push_back(saveme);
		}
	}
}


/*
 * a points to a long address. return true if a matching PDU is found in the table.
 */
bool is_attached(const uint8_t *a)
{
  bool found = false;
  for (std::list<TpPduStore>::iterator itr = devtable.begin(); itr != devtable.end(); )
  {
    TpPdu record(*itr);

    int len = 5;
    uint8_t buf1[5];
    uint8_t buf2[5];
    memcpy(buf1, record.Address(), len);
    memcpy(buf2, a, len);
    int x = memcmp(buf1, buf2, len );

    if (record.AddressMatch(a)) // first request bytes are 5-byte address.
    {
      found = true;
      break;
    }
    ++itr;
  }
  return found;
}

/*
 * initialize the attached device table
 */
void clear_attached_devices()
{
  int n = devtable.size();
  devtable.clear();
  n = devtable.size();
}
