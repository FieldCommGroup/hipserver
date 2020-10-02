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
 * File Name:
 *   interface.c
 * File Description:
 *   Functions for the interface between the Hart-IP Server
 *   and the APP.
 *
 **********************************************************/


#include <assert.h>
#include <errno.h>
#include <mqueue.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include "debug.h"
#include "toolsems.h"
#include "toolutils.h"

#include "errval.h"
#include "hartdefs.h"
#include "tppdu.h"
#include "appmsg.h"
#include "hsqueues.h"
#include "hsrequest.h"
#include "hssems.h"
#include "hsudp.h"
#include "hssubscribe.h"
#include "serverstate.h"

#include <string>

#include "safe_lib.h"

/************
 *  Globals
 ************/
/* Queue descriptors for the message queues between the HART-IP Server
 * and the APP.
 */

static int appRecdMsgCount = 0;    // count of messages received from APP
static ssize_t numBytesRead;       // for debugging
int connectionType;

/************************************
 *  Private variables for this file
 ************************************/


/**********************************************
 *  Private function prototypes for this file
 **********************************************/

static errVal_t handle_msg_from_srvr(uint8_t *p_reqMsg, uint8_t *p_rspMsg);


/****************************************************
 *          Private functions for this file
 ****************************************************/
static errVal_t handle_control_msg_from_app(AppMsg *p_rxMsg)
{
  const char *funcName = "handle_msg_from_app";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_logdbg("\nServer processing control msg recd from APP...\n");

  errVal_t errval = NO_ERROR;
  do
  {
    if (p_rxMsg == NULL)
    {
      errval = POINTER_ERROR;
      print_to_both(p_toolLogPtr,
          "Null Ptr (req) in handle_token_passing_req()\n");
      break;
    }

    switch (p_rxMsg->command)
    {
    case INIT_APP_CMD:
    { // #6005
      // APP has responded to INIT_APP_CMD
      eAppState = APP_READY;
      int initPduLength = strnlen_s((char *)p_rxMsg->pdu, TPPDU_MAX_FRAMELEN);
      char cConnectionType[2] = {'\0'};
      const int maxAppNameSize = 100;
      char appName[maxAppNameSize] = {'\0'};
      cConnectionType[0] = (p_rxMsg->pdu[initPduLength-1]);
      connectionType = strtol(cConnectionType,NULL,10);
      memcpy_s(appName, maxAppNameSize, p_rxMsg->pdu, (initPduLength-1));
      dbgp_log("Connected to: %s\n", appName);
      ++appRecdMsgCount;
      break;
    }

    case TERM_APP_CMD:
    {
      /*
       *  Termination scenarios:
       *
       *  Case 1. server and APP launched from same command line:
       *    The APP catches the ctrl-C, sends a TERM_APP_CMD response, shuts down and exits.
       *    In appThrFunc on server, the system() call that launched the APP returns
       *        and the thread exits.
       *    Server catches the TERM response and shuts down orderly.
       *
       *  Case 2. server and APP launched from different command lines and terminals (usual debugging case):
       *    The server catches the ctrl-C, sends a TERM_APP_CMD request to the APP and waits for response.
       *    The APP sends a TERM_APP_CMD response and shuts down.
       *    Server is not responsible to kill APP process in this case.
       *    Server catches the TERM response and shuts down orderly.
       *
       *  Case 2. server and APP launched from different command lines and terminals (usual debugging case):
       *    The APP catches the ctrl-C and shutdown is same as case 1.
       */

      // APP has responded to TERM_APP_CMD
      dbgp_log("Disconnected from APP.\n");
      dbgp_sem(
          "Posting StopMainThr semaphore from handle_control_msg_from_app()\n");
      ++appRecdMsgCount;
      int errval = sem_post(p_semStopMainThr);
      if (errval == LINUX_ERROR)
      {
        print_to_both(p_toolLogPtr, "System error %d in sem_post()\n",
            errno);
      }

      break;
    } //   case TERM_APP_CMD:
    default:
    {
      errval = IGNORE_ERROR;
      break;
    }
    } // switch

  } while (FALSE);

  return (errval);
}

static errVal_t handle_device_msg_from_app(AppMsg *p_rxMsg)
{
  const char *funcName = "handle_device_msg_from_app";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  //dbgp_logdbg("\nServer processing msg recd from APP  %6d \n", appRecdMsgCount);

  appRecdMsgCount++;

  errVal_t errval = NO_ERROR;
  sem_wait(p_semServerTables);  // lock server tables when available
  {
    do
    {
      if (p_rxMsg == NULL)
      {
        errval = POINTER_ERROR;
        print_to_both(p_toolLogPtr,
            "Null Ptr (req) in handle_token_passing_req()\n");
        break;
      }

      TpPdu tppdu(p_rxMsg->pdu);
      hsmessage_t hsmsg;

      if (tppdu.IsBACK())
      { // BACK - distribute response to all subscribed clients

        memcpy_s(hsmsg.message.hipTPPDU, TPPDU_MAX_FRAMELEN, p_rxMsg->pdu,
            sizeof(hsmsg.message.hipTPPDU));
        hsmsg.message.hipHdr.version = HARTIP_PROTOCOL_VERSION;
        hsmsg.message.hipHdr.status = 0;
        hsmsg.message.hipHdr.msgType = HARTIP_MSG_TYPE_PUBLISH;
        hsmsg.message.hipHdr.msgID = HARTIP_MSG_ID_TP_PDU;
        hsmsg.message.hipHdr.byteCount = HARTIP_HEADER_LEN
            + tppdu.PduLength();

        send_burst_to_subscribers(&hsmsg.message);  // manages seq#
      }
      else
      { // ACK - find the matching request and reply to correct client
        request_table_status_t status = find_request_in_table(p_rxMsg->transaction, &hsmsg);

        if (RTS_EOF == status)
        {
          // not found, discard the message
        }
        else
        {

    	  memcpy_s(hsmsg.message.hipTPPDU, TPPDU_MAX_FRAMELEN, p_rxMsg->pdu, sizeof(hsmsg.message.hipTPPDU));
          hsmsg.message.hipHdr.version = HARTIP_PROTOCOL_VERSION;
          hsmsg.message.hipHdr.status = 0;
          hsmsg.message.hipHdr.msgType = HARTIP_MSG_TYPE_RESPONSE;
          hsmsg.message.hipHdr.msgID = HARTIP_MSG_ID_TP_PDU;
          hsmsg.message.hipHdr.byteCount = HARTIP_HEADER_LEN
              + tppdu.PduLength();
          // hsmsg.message.hipHdr.seqNum exists already

          /* Build payload of response for client, if not empty */
          errval = send_rsp_to_client(&hsmsg.message, hsmsg.pSession);
          /* keep command 0 responses from attached devices */
          attach_device(hsmsg.message.hipTPPDU);
        }
      }
    } while (FALSE);
  }
  sem_post(p_semServerTables);  // unlock server tables when done

  return (errval);
}

/*****************************
 *  Function Implementations
 *****************************/
int GetAppRecdMsgCount()
{
  return appRecdMsgCount;
}

/*
 * processRxQueue:
 *  messages in the rspQueue are ACK or BACK messages newly arrived from the device.
 *
 *  ACKs:  Server must match each response message with its request from the
 *  request_table and forward the response to the client that made the request.
 *
 *  BACKs: Server must determine which clients are subscribed to each response
 *  and forward a copy of the BACK to each.
 */
static void processRxQueue()
{
  errVal_t errval;
  do
  {
    AppMsg rxMsg;
    memset_s(&rxMsg, sizeof(rxMsg), 0);

    errval = rcv_msg_from_Q(rspQueue, &rxMsg, MQUEUE_NONBLOCKING);

    if (errval == MQ_EOF)
    {
      // this is the expected case where there is
      // no message in the queue to be processed.
      // break from the loop when the queue is empty
      break;
    }
    else if (errval == NO_ERROR)
    {
      dbgp_intfc("Server received msg from APP\n");

      if (rxMsg.command == HART_APP_CMD)
      {
        errval = handle_device_msg_from_app(&rxMsg);
      }
      else
      {
        errval = handle_control_msg_from_app(&rxMsg);
      }

      if (errval == NO_ERROR)
      {
        dbgp_intfc("Server processed msg recd from APP\n");
      }
      else
      {
        print_to_both(p_toolLogPtr,
            "Error processing msg received from APP\n");
      }

    } // if (errval == NO_ERROR)
    else
    {
      print_to_both(p_toolLogPtr, "Failed to receive msg from APP\n");
    }
  } while (TRUE); /* run forever */
}

void *popRxThrFunc(void *thrName)
{
  const char *funcName = "popRxThrFunc";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_intfc("\nStarting %s...\n", (char *)thrName);

  do
  {
    processRxQueue();

    usleep(QSLEEP * 1000);      // microseconds

  } while (TRUE); /* run forever */
}

errVal_t snd_msg_to_app(AppMsg *p_txMsg)
{
  errVal_t errval;
  mqd_t mqDesc = reqQueue;

  const char *funcName = "snd_msg_to_app";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_logdbg("\nServer sending message to APP...\n");

  do
  {
    if (p_txMsg == NULL)
    {
      errval = POINTER_ERROR;
      print_to_both(p_toolLogPtr, "NULL pointer passed to %s\n",
          funcName);
      break;
    }
    /* Write data to request queue */
    dbgp_intfc("\n===================\n");
    dbgp_intfc("Server sending msg to APP\n");

    errval = snd_msg_to_Q(mqDesc, p_txMsg);
    if (errval != NO_ERROR)
    {
      print_to_both(p_toolLogPtr, "Failed to send msg to APP\n");
      break;
    }
    dbgp_intfc("Msg sent from Server to APP\n");
  } while (FALSE);

  return errval;
}

errVal_t rcv_msg_from_app(AppMsg *p_rxMsg)
{
  errVal_t errval;
  mqd_t mqDesc = rspQueue;

  const char *funcName = "rcv_msg_from_app";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_init("\nServer fetching message from APP...\n");

  do
  {
    if (p_rxMsg == NULL)
    {
      errval = POINTER_ERROR;
      print_to_both(p_toolLogPtr, "NULL pointer passed to %s\n",
                    funcName);
      break;
    }
    /* Get data from Queue */
    dbgp_intfc("\n===================\n");
    dbgp_intfc("reading msg from APP\n");

    errval = rcv_msg_from_Q(mqDesc, p_rxMsg, MQUEUE_BLOCKING);
    if (errval != NO_ERROR)
    {
      print_to_both(p_toolLogPtr, "Failed to receive msg from APP\n");
      break;
    }
    dbgp_intfc("Msg received from APP\n");
  } while (FALSE);

  return errval;
}

/* send a copy of the message from the server socket thread to the popRx thread */
errVal_t echo_msg_to_srvr(mqd_t mq, void *p_msg)
{
  return snd_msg_to_Q(mq, (interface_msg_t*) p_msg);
}

