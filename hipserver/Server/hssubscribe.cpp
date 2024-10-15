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
#include "hssyslogger.h"
#include <toolsems.h>

#include "tppdu.h"
#include "hsmessage.h"
#include "hssubscribe.h"
#include "hsauditlog.h"

#include "debug.h"

/************
 *  Globals
 ************/

enum SubFlags
{
    PROCESS_DATA=0x1,
    EVENT_NOTIFICATION=0x2,
    DEVICE_STATUS=0x4,
    DEVICE_CONFIG=0x8,
    WIRELESS_NETWORK_STATS=0x100,
    WIRELESS_HEALTH=0x200,
	DEVICE_SPECIFIC_COMMANDS=0x8000
	};

/**********************************************
 *  Private class for this file
 **********************************************/

// Subscription commands 532+533 common

bool SubscriptionPdu::IsBroadcastAddress()
{
  uint8_t baddress[TPHDR_ADDRLEN_UNIQ] = {0};
  int diff;
  memcmp_s(TargetUniqID(), TPHDR_ADDRLEN_UNIQ, baddress, TPHDR_ADDRLEN_UNIQ, &diff);
  return diff == 0;
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
	memcpy_s(a1, TPHDR_ADDRLEN_UNIQ, address, TPHDR_ADDRLEN_UNIQ);
	a1[0] &= 0xBF;

	uint8_t a2[TPHDR_ADDRLEN_UNIQ];
	memcpy_s(a2, TPHDR_ADDRLEN_UNIQ, UniqueID, TPHDR_ADDRLEN_UNIQ);
	a2[0] &= 0xBF;

  int diff;
	memcmp_s(a1, TPHDR_ADDRLEN_UNIQ, a2, TPHDR_ADDRLEN_UNIQ, &diff);
  bool match = (diff == 0);

  return match;
}

void Subscription::SetAddress(const uint8_t *address)
{
  memcpy_s(UniqueID, TPHDR_ADDRLEN_UNIQ, address, TPHDR_ADDRLEN_UNIQ);
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

// return record found for this client+address
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


/**********************************************
 *  Public functions for this file
 **********************************************/

// add a subscription, return 533 response


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
 * p points to a PDU. if the address of PDU is exist do nothing,
 * otherwise the PDU will be added to the table of attached devices.
 */
void attach_device_by_address(uint8_t *p)
{
    TpPdu cmd(p);
    if (is_attached((uint8_t *)cmd.Address()) == false)
    {
        TpPduStore saveme(p);
        devtable.push_back(saveme);
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

    const int len = 5;
    uint8_t buf1[len];
    uint8_t buf2[len];
    memcpy_s(buf1, len, record.Address(), len);
    memcpy_s(buf2, len, a, len);

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

SubscribesTable::SubscribesTable()
{
}

SubscribesTable::~SubscribesTable()
{
}

SubscribesTable* SubscribesTable::Instance()
{
  static SubscribesTable table;
  return &table;
}

void SubscribesTable::AddSubscriber(IResponseSender* sender, SubscriptionPdu& subpdu)
{
  Subscription subs;
  subs.sender = sender;
  subs.SetAddress(subpdu.TargetUniqID());
  subs.flags = subpdu.SubscriptionFlags();

  SubscriptionFlagsUnion subFlagsUnion;
  subFlagsUnion.i = subs.flags;
  subs.subFlags = subFlagsUnion.b;

  {
    MutexScopeLock lock(m_mutex);
    m_subscribersTable.push_back(subs);
  }
}

void SubscribesTable::RemoveSubscriber(IResponseSender* sender)
{
  MutexScopeLock lock(m_mutex);
  bool found = false;
  do
  {
      found = false;
      for(int i = 0; i < m_subscribersTable.size(); ++i)
      {
          if(sender == m_subscribersTable[i].sender)
          {
              m_subscribersTable.erase(m_subscribersTable.begin() + i);
              found = true;
              break;
          }
      }
  }
  while (found);
}

void SubscribesTable::RemoveSubscriber(IResponseSender* sender, uint8_t *address)
{
  MutexScopeLock lock(m_mutex);
  for(int i = 0; i < m_subscribersTable.size(); ++i)
  {
    if(sender == m_subscribersTable[i].sender && m_subscribersTable[i].AddressMatch(address))
    {
      m_subscribersTable.erase(m_subscribersTable.begin() + i);
      break;
    }
  }
}

errVal_t SubscribesTable::SendResponse(hartip_msg_t *p_response)
{
  MutexScopeLock lock(m_mutex);
  TpPdu tppdu(p_response->hipTPPDU);
  for(int i = 0; i < m_subscribersTable.size(); ++i)
  {
    if(IsNeedSend(&tppdu, m_subscribersTable[i].subFlags) == TRUE)
    {
      p_response->hipHdr.seqNum = m_subscribersTable[i].sender->GetSession()->NextSequnce();
      m_subscribersTable[i].sender->SendResponse(p_response);
      AuditLogger->UpdateBackCounter(m_subscribersTable[i].sender->GetSession());
    }
  }
}

subscription_table_status_t SubscribesTable::HandleCommand532(IResponseSender* sender, TpPdu* tppdu)
{
  const uint8_t bc = 11;

  SubscriptionPdu findme(tppdu->GetPdu()); // subscription we are searching for
  IResponseSender* tsender = sender->GetParentSender();
  tsender = tsender == NULL ? sender : tsender;

  if (findme.Validate(5))
  {
    // find first subscription in table matching client and target unique ID
    Subscription *subscription = FindSubscriber(tsender, findme.TargetUniqID());
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
    {
        if(false == findme.IsBroadcastAddress())
        {
            // check requested uniqueID is ower own
            bool b = is_attached(findme.TargetUniqID());
            if ((b) && (SubscribedToBroadcast == true))
            { // #133
            	findme.ProcessErrResponse(RC_MULTIPLE_9);
            }
            else if (b)
            {
                findme.SetSubscriptionFlags(0);
                findme.ProcessOkResponse(RC_SUCCESS, bc);
            }
            else
            {
                // it is not broadcast and not ower own
                findme.ProcessErrResponse(65); // RC=Unknown unique ID
            }
        }
        else
        {
            // we are looking for a broadcast address, no found but ok.
            findme.SetSubscriptionFlags(0);
            findme.ProcessOkResponse(RC_SUCCESS, bc);
        }
    }
  }
  findme.SetRCStatus(findme.ResponseCode(), tppdu->getSavedDevStatus()); // #165
  findme.InsertCheckSum();
}

subscription_table_status_t SubscribesTable::HandleCommand533(IResponseSender *sender, TpPdu *tppdu)
{
  const uint8_t bc = 11;

  SubscriptionPdu subpdu(tppdu->GetPdu());
  IResponseSender* tsender = sender->GetParentSender();
  tsender = tsender == NULL ? sender : tsender;

  if (subpdu.Validate(7))
  {
    if (subpdu.IsBroadcastAddress())
    {
      // if (subpdu.SubscriptionFlags() == 0)
      // {
      //   RemoveSubscriber(tsender);
      // }
      // AddSubscriber(tsender, subpdu);

      RemoveSubscriber(tsender);
      if (subpdu.SubscriptionFlags() != 0)
      {
        AddSubscriber(tsender, subpdu);
      }
      subpdu.ProcessOkResponse(RC_SUCCESS, bc);
    }
    else
    { // request has specific device address
      // find first record for this client in subscription table
      Subscription *subscription = FindSubscriber(tsender, subpdu.Address());
      if (subscription)
      { // found
        if (subscription->IsBroadcastAddress())
        {
          // can't replace a broadcast subscription with a single device subscription
          subpdu.ProcessErrResponse(9); // RC=Individual Subscription Not Allowed
        }
        else if (is_attached(subpdu.TargetUniqID()) == false)
        { // #133
        	subpdu.ProcessErrResponse(65);
        }
        else
        {
          // we only have ONE device attached as we are not an IO device
          RemoveSubscriber(tsender);
          if (subpdu.SubscriptionFlags() != 0)
          {
            AddSubscriber(tsender, subpdu);
          }
          subpdu.ProcessOkResponse(RC_SUCCESS, bc);
        }
      }
      else
      { // no record is found in subscription table for this client
    	if(SubscribedToBroadcast == true)
    	{ // #133
    		subpdu.ProcessErrResponse(RC_MULTIPLE_9);
    	}
    	else if (is_attached(subpdu.TargetUniqID()))
        { // we are adding a subscription for a device that is attached
          AddSubscriber(tsender, subpdu);
          subpdu.ProcessOkResponse(RC_SUCCESS, bc);
        }
        else
        {                                // the device that is being subscribed is not attached
          subpdu.ProcessErrResponse(65); // RC=Unknown unique ID
        }
      }
    }
  }
  subpdu.SetRCStatus(subpdu.ResponseCode(), tppdu->getSavedDevStatus()); // #165
  subpdu.InsertCheckSum();
  // else error processing for invalid command is complete
#if (DEBUG_SUB)
  print_subscription_table((char *)"Add a subscription: ", subpdu.TargetUniqID(), subpdu.SubscriptionFlags());
#endif
  return STS_OK;
}

Subscription* SubscribesTable::FindSubscriber(IResponseSender* sender, uint8_t *address)
{
    SubscribedToBroadcast = false;
    uint8_t brodcastAddr[] = {0x00,0x00,0x00,0x00,0x00};
    int res = -1;
    {
        MutexScopeLock lock(m_mutex);
        for (int i = 0; i < m_subscribersTable.size(); ++i)
        {
            if (m_subscribersTable[i].sender == sender && m_subscribersTable[i].AddressMatch(brodcastAddr))
            { // #133
            	SubscribedToBroadcast = true;
            }

            if (m_subscribersTable[i].sender == sender && m_subscribersTable[i].AddressMatch(address))
            {
                res = i;
                break;
            }
        }
    }
    if (res != -1)
    {
        return &m_subscribersTable[res];
    }
    return NULL;
}

bool_t SubscribesTable::IsNeedSend(TpPdu *tppdu, SubscriptionFlags flags)
{
  const uint16_t command = tppdu->CmdNum();

  // Added command checking for process data subscription flag #2278
  if(flags.processData == 1 && (command == 1 || command == 2 || command == 3 || command == 9 || command == 78))
  {
    return TRUE;
  }

  //corrected event notification command from 109 to 119
  if(flags.eventNotification == 1 && command == 119)
  {
    return TRUE;
  }
  if(flags.deviceStatus == 1 && command == 48)
  {
    return TRUE;
  }
  if(flags.deviceConfiguration == 1 && command == 38)
  {
    return TRUE;
  }
  if(flags.wirelessNetworkStatistics == 1 && (command == 846))
  {
    return TRUE;
  }
  if(flags.wirelessHealth == 1 && (768 <= command && command <= 1023))
  {
    return TRUE;
  }
  if(flags.deviceSpecificCommands == 1 && ((128 <= command && command <= 253) 
                                       || (64768 <= command && command <= 65023))
                                       || (64512 <= command && command <= 64767) )
  {
    return TRUE;
  }

  return FALSE;

}
