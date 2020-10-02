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

/**********************************************************
 *
 * File Name:
 *   appconnector.h 
 * File Description:
 *   This class encapsulates the interprocess communication
 *   system. Much code taken from 'interface.c'.
 *
 **********************************************************/

#ifndef _APPCONNECTOR_H
#define _APPCONNECTOR_H

#include "safe_lib.h"
#include "sprintf_s.h"

#ifdef INC_DEBUG
#pragma message("In AppConnector.h") 
#endif

#include <errno.h>
#include <mqueue.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "app.h"
#include "apppdu.h"
#include "debug.h"
#include "errval.h"
#include "toolqueues.h"

#ifdef INC_DEBUG
#pragma message("    Finished Includes::AppConnector.h") 
#endif

#define ALL_IS_WELL    0   // a return status
#define BAD_PARAM      1
#define INTERRUPTED    2
#define IS_TERMINATE   6   // returned from process message to terminate caller

#define ever   (;;)

#ifdef _FLOWAPP
extern uint32_t GetTickCount(void);
#endif

#ifdef _DEBUG
extern double rt(void);
extern unsigned debuggingBurstCnt;
extern double avgBurst;
extern double lastT, thisT;
#endif

/******************************************************************************
 * AppConnector class
 *
 *  Not meant to be used in a vector (doesn't have golden three)
 *
 ******************************************************************************/
template<class PDU_CLASS> /* PDU_CLASS  MUST be AppPdu or have it as a parent */
class AppConnector /* PDU_CLASS will be dynamically cast to a AppPdu     */
{
private:
  // data
  PDU_CLASS usersPduClass; // AppConnector only uses the AppPdu  portion
  AppPdu* pPdu;            // there is only one in HART (it's half duplex)
  bool called;             // handshake to show abortAPP has been called
  bool running;            // records the state of the run method
  bool queuesOpen;         // closing a closed queue can be ugly

  // the interface
  /* Queue descriptors for the message queues between the HART-IP Server & APP */
  mqd_t rxQueue; // server-to-APP Q
  mqd_t txQueue; // APP-to-server Q

#ifdef _FLOWAPP
  // hart has a requirement to keep comm statistics: 16 bit, volatile, rollsover
  uint16_t stxCnt;
  uint16_t ackCnt;
  uint16_t bakCnt;
  uint16_t sndCnt;// mainly to keep alignment;
#endif

  /* there can only be one interface so statics make sense */
  static bool time2stop; // abortAPP will set this via signal user2 that breaks the mq_receive
  static void abort_handler(int signo);

public:
  AppConnector();
  virtual ~AppConnector();

  // two step instantiation:  
  //    new AppConnector();  
  //    then, when the app is ready to run, call run(pApp);
  //    which will run the message pump in an infinite loop
  //    when this returns, the stop method will have been called and the process
  //    should delete this class and exit();
  void run(App * pApp);

public:
  // external functions
  /////////////
  // asynchronous sending of a burst message
  //  application determines when to send a burst message
  //  application owns the AppPdu memory and is responsible for its deletion
  //  This will return when it is finished with the AppPdu.
  //
  //  NOTE that the native pdu must be fully formed when this is called.
  //  sendBurstMsg only puts the message in the queue, it does nothing
  //  to form the message.
  //  ALSO NOTE that this function will return immediately without sending
  //  a message if run method has not received an INIT_APP_CMD cmd and
  //  returned it successfully.
  //  (that implies run method is running)
  void sendBurstMsg(PDU_CLASS *pBurst);

  /////////////
  // abort the application
  //  this function may be called asynchronously due to some internal fault, SIGINT or
  //  it may be called (but is not required to be) from the stopFunc() callback operation.
  //  This function will coordinate with stopFunc() and when the stop callback 
  //  has returned (if it was called) this will send a TERM_APP_CMD to the outgoing
  //  queue, signal the run method pend loop to terminate and return.
  //  The application is assumed to be shutdown when this function is called, all threads 
  //  terminated and all memory freed.
  void abortApp(void);

  /////////////
  // cleanup the application - orderly shutdown
  void cleanup(void);

  //////////////
  //  get an addressed packet ... usually for burst messaging
  //
  //  this gets a newd PDU_CLASS with our address set
  //
  PDU_CLASS *getNewPDU(void);

  /* external access to open/close the message queues to the server*/
  errVal_t openMQs();
  void closeMQs();

  /* the the termination command...usually asynchronously */
  void sendTerm();
  /* see if we need to close 'em */
  bool queuesAreOpen()
  {
    return queuesOpen;
  }
  ;
  
#ifdef _FLOWAPP
  void incStx() { stxCnt++; };// this needs to be done outside this class

  // hart has a requirement to keep comm statistics: 16 bit, volatile, rollsover
  uint16_t getStats(uint16_t &stxs, uint16_t &acks, uint16_t &baks)
  {
	  stxs = stxCnt; acks = ackCnt; baks = bakCnt;
	  return sndCnt;
  };
#endif

protected:
  /* helper functions */
  int waitMessage(void); // it has to be the Rxqueue, wait means blocking
  int processMessage(App *pApp);
  int sendMessage();     // it has to be the Txqueue

};

/*===========================================================================
 *
 *   template class implementation
 *
 *==========================================================================*/

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::abort_handler(int signo)
{     // we use a signal here in order to break the mq_receive pend
  dbgp_log("Abort (SIGUSR2) handler triggered!\n",0);
  time2stop = true;
}

template<class PDU_CLASS>
#ifdef _FLOWAPP
AppConnector<PDU_CLASS>::AppConnector() : stxCnt(0),ackCnt(0),bakCnt(0), sndCnt(0)
#else
AppConnector<PDU_CLASS>::AppConnector()
#endif

{										  
  /*									  
   * any error in this constructor is fatal and causes immediate exit
   */
  errVal_t errval = NO_ERROR;

  do
  {
    pPdu = dynamic_cast<AppPdu *>(&(this->usersPduClass));
    called = running = queuesOpen = time2stop = false;
    pPdu->setShort(0);     // poll address starts at 0;
    uint8_t tLn[5] = { 0,0,0,0,0 };
  //  { INIT_DEVTYPE_HI, INIT_DEVTYPE_LO, INIT_DEV_ID };    // TODO
    pPdu->setLong(tLn);  // set long address to null value


    if (signal(SIGUSR2, abort_handler) == SIG_ERR)
    {
    errval = LINUX_ERROR;
    dbgp_logdbg("\nCan't catch SIGUSR2 signal\n");
    // make it unusable
    pPdu = NULL;
    break;
    }

    /* Open RX and TX queues to server */
    rxQueue = txQueue = LINUX_ERROR;
    errval = openMQs();
    if (errval != NO_ERROR)
    {
    dbgp_log("\n===============================================\n");
    dbgp_log("Run hipserver before executing this application\n");
    dbgp_log("===============================================\n");
    break;
    }
  }
  while (false); // once

  if (errval == LINUX_ERROR)
  {
      dbgp_logdbg("\nFatal error in HART-IP application, exiting...\n");
      close_toolLog();
      exit(0);
  }
}

template<class PDU_CLASS>
AppConnector<PDU_CLASS>::~AppConnector()
{
	// closing MQs moved to clean()
}

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::cleanup(void)
{
  if (queuesOpen)
  {
    sendTerm();
    close_mqueues();
  }
}

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::run(App* pApp)
{
  int ret = 0; // mainly for debugging

  //open the queues
  errVal_t errval = NO_ERROR;

  //enter infinite loop
  while (true)
  {
    if ((ret = waitMessage()))
    {
      dbgp_logdbg("waitMessage failed. Exiting!\n");
      break; // for loop
    }

    if ((ret = processMessage(pApp)))
    {
      if (ret == IS_TERMINATE)
      {
        dbgp_log(
            "Main received a Terminate message. Exiting!\n");
        ret = 0;
      }
      else
      {
        dbgp_logdbg("handle_Message failed. Exiting!\n");
      }
      break; // out of for loop
    }

  } // next

}

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::sendBurstMsg(PDU_CLASS *pBurst) /* this may be called from any thread!  */
{
  // que the message

#ifdef _DEBUG  
  struct mq_attr mqstat;
  mq_getattr(txQueue, &mqstat);  // for debugging
  thisT = rt();
  int dbg = APP_MSG_SIZE;
#endif

#ifdef _FLOWAPP
  if (pPdu->IsACK()) ackCnt++;// error when you're bursting an ack
  if (pPdu->IsBACK())bakCnt++;

  sndCnt++;
#endif

  int status = mq_send(txQueue, (char*) &(pBurst->command), APP_MSG_SIZE, 0);

#ifdef _DEBUG
  if(status)
  {
    perror( "sendBurstMsg");
    dbgp_log("Sending 0x%03x bytes requested.\n",dbg);
  }
  else
  if ((debuggingBurstCnt % 20) == 0)
  {
    //printf("transmitted------|");
	//printf("trans%11u--|",GetTickCount());
    pBurst->printMsg();
  }
  debuggingBurstCnt++;
  if (lastT != 0.0) avgBurst = ( avgBurst + (thisT - lastT) )/2;
  lastT = thisT;
#endif
  return;

}

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::sendTerm()
{
	if (pPdu)
	{
	  pPdu->setAPPCmd(TERM_APP_CMD);
	  dbgp_log("Sending termination\n");
	  sendMessage();
	}
  return;
}

template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::abortApp(void) /* this may be called from any thread!  */
{
  called = true;
  // signal the run method task to terminate
  // this gives me an un-handled exception...except the handler runs...kill(getpid(),SIGUSR2);
  // try this... does exactly the same...
  raise(SIGUSR2);
}

/**
 * open_mqueues:
 *    connect to the two unidirectional message queues for the
 *    bi-directional communication between the HART-IP Server
 *    and this APP. The queues 'belong' to the server.
 *    The server is responsible for opening, closing, destroying the queues.
 */
template<class PDU_CLASS>
errVal_t AppConnector<PDU_CLASS>::openMQs(void)
{
  errVal_t errval = NO_ERROR;
  char instance[COM_MSGSIZE];

  do
  {  // The Server creates and owns the MQs, the APP only connects to them

   // read the APPCOM MQ to get the unique instance string that the server has left there for us
	open_appcom(false, instance /* returned */);


    int32_t mqFlag = QOPEN_FLAG_RDONLY;
    /* Use APP.REQ to receive messages from Server in the APP...our recv queue */
    string mqName;
    mqName = make_mq_name(QNAME_REQ, instance);
    errval = open_mqueue(&rxQueue, (char *) mqName.c_str(), mqFlag, APP_MSG_SIZE, MAX_QUEUE_LEN);
    if (errval != NO_ERROR)  // double negative, we have an error
    {
      dbgp_log("Error opening rx queue (%s)\n", mqName.c_str());
      break;
    }

    mqFlag = QOPEN_FLAG_WRONLY;
    /* Use APP.RSP to send msg from APP to Server - our xmit queue */
    mqName = make_mq_name(QNAME_RSP, instance);
    errval = open_mqueue(&txQueue, (char *) mqName.c_str(), mqFlag, APP_MSG_SIZE, MAX_QUEUE_LEN);
    if (errval != NO_ERROR)
    {
      dbgp_log("Error opening tx queue (%s)\n", mqName.c_str());

      if (mq_close(rxQueue) == NO_ERROR)
      {
        /* Reset descriptor to prevent accidental misuse */
        rxQueue = LINUX_ERROR;
      }
      else
      {
        dbgp_log("System error (%d) in mq_close() for txQueue\n", errno);
      }

      break;
    }

    queuesOpen = true;

  } while (false);  // once

  return (errval);
}

/**
 * closeMQs:
 *    Close the two message queues for the
 *    bi-directional communication between the HART-IP Server
 *    and this APP. The queues 'belong' to the server.
 *    The server is responsible for destroying the queues.
 */
template<class PDU_CLASS>
void AppConnector<PDU_CLASS>::closeMQs(void)
{
  ::close_mqueues();
  queuesOpen = false;
}

// it has to be the Rxqueue, wait means blocking, data to apppdu's AppMsg
template<class PDU_CLASS>
int AppConnector<PDU_CLASS>::waitMessage(void)
{
  int errval = ALL_IS_WELL;
  struct mq_attr mqstat;

  if (pPdu == NULL) // we are shutdown, return
  {
    return BAD_PARAM;
  }

  pPdu->clear();

  do
  {
    if (rxQueue == LINUX_ERROR)
    {
      errval = BAD_PARAM; // hasn't started yet 
      dbgp_log("Invalid Q parameter passed to %s\n",
          "wait4message");
      break;
    }
#ifdef _DEBUG    
    mq_getattr(rxQueue, &mqstat);
#endif

    /* assumes server & APP on same machine (same endian) */
    try
    {
      pPdu->bytesLoaded = mq_receive(rxQueue, (char*) (pPdu->baseStruct()),
                                     APP_MSG_SIZE, NULL);
      if (pPdu->bytesLoaded == LINUX_ERROR)
      {
        dbgp_log("Error (%d) returned by mq_receive()\n",
                  errno);
      }
      else
      {
        const int bufsiz = 1000;
        char buf[bufsiz] = "APP RECV ";
        strcat_s(buf, bufsiz, pPdu->ToHex());
        dbgp_init("%s\n", buf);
      }
    }
    catch (...)
    {
      time2stop = true;
      // it's our signal (external ^C handler must send us our signal)
      errval = INTERRUPTED;
      dbgp_log("Signal %d caught in AppConnector::waitMessage.\n",errval);
      break;    // time to go
    }

//--------------------------------------------------------------------------

    if (pPdu->bytesLoaded == LINUX_ERROR)
    {
      if (errno == EINTR)    // we got a signal that interrupted our wait
      {
    	dbgp_log("Signal %d caught in AppConnector::waitMessage.\n",errno);
        // sleep??? has the sighandler already run?
        if (time2stop)
        {// it's our signal (external ^C handler must send us our signal)
          errval = INTERRUPTED;
          dbgp_log("Signal %d caught in AppConnector::waitMessage.\n",errval);
          break;    // time to go
        }    // else it's not to us, loop to wait again
        continue;
      }
      else if (errno == ETIMEDOUT)
      {
        mq_getattr(rxQueue, &mqstat);
        if (mqstat.mq_curmsgs)
          dbgp_log(
              "mq_timedreceive came back with timeout & %ld in the que.\n",
              mqstat.mq_curmsgs);
        continue;
      }
      else
      {    // EAGAIN,EINVAL,EMSGSIZE, should never happen, leaves EBADF
        dbgp_log("LINUX receive ERROR (%d)\n", errno);
        perror(NULL);
        break;
      }
    }
    else
    {    // all is well
      break;    // out of while retrying loop
    }
  } while (true);    //

  //dbgp_log("Recv Msg of %d bytes.\n",p_Pdu->bytesLoaded);
  return errval;
}

template<class PDU_CLASS>
int AppConnector<PDU_CLASS>::processMessage(App *pApp) // message is in p_Pdu->baseStruct() with p_Pdu->bytesLoaded
{
  int ret = ALL_IS_WELL;

// detect a command
  switch (pPdu->command)
  {
  case HART_APP_CMD:
  {
    if (  (ret = pApp->handleMessage(&usersPduClass)) == NO_ERROR  )
    {

      sendMessage(); // send same message back

      // if response is a short frame command 0, then learn the address
      // NOTE: this behavior may not be appropriate for an IO
      pPdu->learnAddress();
    }
	else
	if (ret == FATAL_ERROR)   // already defined in errVal_t
	{
		ret = IS_TERMINATE;// unhandled issue    
	}
	else
	{// ignore everything else - note TJ.20may19 - said to discard all errors except fatal
		ret = ALL_IS_WELL;
	}
  }
    break;
  case INIT_APP_CMD:
  { // we don't care about the address
    if (pApp->ready() == NO_ERROR) // if we are ready to run
    { // #6005
      // the response pdu of for the INIT_APP_CMD contains the application name
	  const int siz = 10;
	  char temp[siz] = { '\0' };
	  sprintf_s(temp, siz, "%d", pApp->GetConnectionType());
      strcpy_s((char*) (pPdu->pdu), TPPDU_MAX_FRAMELEN, pApp->GetName());
      strcat_s((char*) (pPdu->pdu), TPPDU_MAX_FRAMELEN, temp);

      sendMessage(); // send response back
    }
    // else do not return the message - server should timeout
    // leave ret as OK to go pend on another message...should be a terminate
  }
    break;
  case TERM_APP_CMD:
  {      // we don't care about the address
    called = false; // signal not received
    pApp->stop();
    if (!called) // stop_Func did not send the signal
    {
      //abortApp();  this no longer used, abort functionality is in cleanup
    }
    ret = IS_TERMINATE;
  }
    break;
  default:
  {
    dbgp_log("ERROR: Unknown command (%d) from server. EXITING.",
        pPdu->command);
    ret = IS_TERMINATE;
  }
    break;
  } //endswitch
  return ret;
}

template<class PDU_CLASS>
PDU_CLASS* AppConnector<PDU_CLASS>::getNewPDU(void)
{ // note that it'll be empty if the address has not been set yet
  PDU_CLASS*P = new PDU_CLASS(usersPduClass);
  return P;
}

template<class PDU_CLASS>
int AppConnector<PDU_CLASS>::sendMessage()
{
  int status;
#ifdef _DEBUG
  struct mq_attr mqstat;
  mq_getattr(txQueue, &mqstat);
#endif

#ifdef _FLOWAPP
	if (pPdu->IsACK()) ackCnt++;
	if (pPdu->IsBACK())bakCnt++;

	sndCnt++;
#endif

	status = mq_send(txQueue, (char*) &(pPdu->command), APP_MSG_SIZE, 0);

#ifdef _DEBUG
  if(status)
  perror( "sendMessage");
#endif

  return status;
}
/*=========================================================================*/

#endif //_APPCONNECTOR_H
