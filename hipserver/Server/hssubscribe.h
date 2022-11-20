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
 * hssubscribe.h
 *
 *  Created on: Nov 10, 2017
 *      Author: tjohnston
 */

#ifndef HIP_SERVER_HSSUBSCRIBE_H_
#define HIP_SERVER_HSSUBSCRIBE_H_

#include "hsmessage.h"
#include <vector>
#include "hsresponsesender.h"
#include "hsconnectionmanager.h"
#include "mutex2.h"

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

typedef struct subscribe_message
{
	TpPdu m_tppdu;
	uint16_t m_sessionNumber;
} subscribe_message_t;

/************
 *  Globals
 ************/

/************************
 *  Function Prototypes
 ************************/

subscription_table_status_t process_cmd532(subscribe_message_t *hsmsg);
subscription_table_status_t process_cmd533(subscribe_message_t *hsmsg);

// these 3 funcs model a list of attached devices
// every time a longframe command 0 response is observed, the
// address is added to this list.  duplicates are not stored
// this server is a single attached device for now, but will
//  be enhanced to be an IO at some point
void attach_device(uint8_t *addr);
void attach_device_by_address(uint8_t *addr);
bool is_attached(const uint8_t *addr);
void clear_attached_devices();

struct SubscriptionFlags
{
    //bitfield  for subscription flags
    unsigned int processData: 1;
    unsigned int eventNotification: 1;
    unsigned int deviceStatus: 1;
    unsigned int deviceConfiguration : 1;
    unsigned int reserved1: 4;
    unsigned int wirelessNetworkStatistics: 1;
    unsigned int wirelessHealth: 1;
    unsigned int reserved2: 5;
    unsigned int deviceSpecificCommands: 1;
};

union SubscriptionFlagsUnion
{
    // union for uint16 to bitfield conversion
    SubscriptionFlags b;
    uint16_t i;
};

class Subscription
{
public:
//    sockaddr_in_t clientAddr;             // client address
    IResponseSender* sender;                      // session number
    uint8_t UniqueID[TPHDR_ADDRLEN_UNIQ]; // device address
    uint16_t flags;
    SubscriptionFlags subFlags; //caching subflags on subscription

    bool AddressMatch(uint8_t *address);
    void SetAddress(const uint8_t *address);
    bool IsBroadcastAddress();
};

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

class SubscribesTable
{
public: 
	static SubscribesTable* Instance();
	void RemoveSubscriber(IResponseSender* sender);
	void RemoveSubscriber(IResponseSender* sender, uint8_t *address);
	subscription_table_status_t HandleCommand532(IResponseSender* sender, TpPdu *tppdu);
	subscription_table_status_t HandleCommand533(IResponseSender* sender, TpPdu *tppdu);

	virtual errVal_t SendResponse(hartip_msg_t *p_response);
	bool_t IsNeedSend(TpPdu *tppdu, SubscriptionFlags flags);

private:
	std::vector<Subscription> m_subscribersTable;

	void AddSubscriber(IResponseSender* sender, SubscriptionPdu& subs);
	Subscription* FindSubscriber(IResponseSender* sender, uint8_t* address);
	SubscribesTable();
	virtual ~SubscribesTable();
    MutexEx m_mutex;
    bool SubscribedToBroadcast; // #133
};

#endif /* HIP_SERVER_HSSUBSCRIBE_H_ */
