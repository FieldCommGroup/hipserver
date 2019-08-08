/*****************************************************************
 * Copyright (C) 2015-2018 FieldComm Group
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

/**********************************************************
 * File Name:
 *   interface.c
 * File Description:
 *   Functions for the interface between the Hart-IP Server
 *   and the APP.
 *
 **********************************************************/

#include "appmsg.h"
#include "toolqueues.h"

#include <assert.h>
#include <errno.h>
#include <mqueue.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "debug.h"
#include "toolutils.h"
#include "errval.h"
#include "hartdefs.h"
#include "toolsems.h"
#include "tppdu.h"

/************
 *  Globals
 ************/
/* Queue descriptors for the message queues between the HART-IP Server
 * and the APP.
 */
mqd_t rspQueue = LINUX_ERROR; // requests flow from server to app
mqd_t reqQueue = LINUX_ERROR; // responses flow from app to server

static ssize_t numBytesRead = 0; // for debugging

/************************************
 *  Private variables for this file
 ************************************/
/* Information about all HART-IP Server mqueues */
static queue_info_t hsrvrQueues[MAX_QUEUES]; /* array of mqueues */
static uint8_t numQueues = 0; /* total # of mqueues */

/**********************************************
 *  Private function prototypes for this file
 **********************************************/

//static errVal_t handle_msg_from_srvr(uint8_t *p_reqMsg, uint8_t *p_rspMsg);
errVal_t open_mqueue(mqd_t *p_mqDesc, char *mqName, int32_t qFlag,
    int32_t msgsize, int32_t maxmsg);

static int32_t sizeof_msg(mqd_t d);

/*
 * To handle multiple instances of servers running simultaneously, we need multiple sets
 * of message queues.  The method of handling that is to number the MQs by incrementing
 * instance number  0..n
 *
 * this func returns the highest observed MQ instance number, beginning at 0 or -1 if none found
 */
int highest_instance_number()
{
	int highest = -1;	// none found

	// get all the open resp MQs
	const char *cmd = "/bin/ls  /dev/mqueue" QNAME_RSP "_* 2>/dev/null";
	FILE *fp = popen(cmd, "r");
	if (fp == NULL)
	{
		return -1;
	}

	/* Read the output a line at a time  */
	char path[1200];
	while (fgets(path, sizeof(path)-1, fp) != NULL)
	{
		// lines look like: /dev/mqueue/APPREQ_queue_xxx\n
		char *p = path + strlen(path)-4;
		int n = atoi(p);
		highest = n > highest ? n : highest;
	}

	pclose(fp);

	return highest;
}

void make_mq_name(const char *basename, char *instance, char *fname)
{
	sprintf(fname, "%s_%s", basename, instance);
}

/*****************************
 *  Function Implementations
 *****************************/
/**
 * close_mqueues:
 *    close the message queues used for the bi-directional
 *    communication between the HIP Socket and APP
 */
void close_mqueues(void)
{
  uint8_t n, count = numQueues;
  mqd_t mqDesc;
  const char *qName;

  const char *funcName = "close_mqueues";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  /* Avoid repeated closure via different means */
  if (count)
  {
	dbgp_logdbg("\n----------------------\n");
    dbgp_logdbg("Closing %d mqueues...\n", count);

    for (n = 0; n < count; n++)
    {
      mqDesc = hsrvrQueues[n].mqDesc;

      if (mqDesc != LINUX_ERROR)
      {
        qName = hsrvrQueues[n].qName;

        if (mq_close(mqDesc) == NO_ERROR)
        {
          /* Reset descriptor to prevent accidental misuse */
          hsrvrQueues[n].mqDesc = LINUX_ERROR;
          numQueues--;

          /* Remove the closed message queue */
          if (mq_unlink(qName) == LINUX_ERROR)
          {
            // this means MQs already closed, no need to report
          }

          dbgp_logdbg("  ..%s\n", (char * )qName);
        } // if (mq_close(mqDesc) == NO_ERROR)
        else
        {
          print_to_both(p_toolLogPtr,
              "System error (%d) in mq_close() for %s\n",
              errno, qName);
        }
      } // if (mqDesc != LINUX_ERROR)
    } /* for */
    dbgp_logdbg("Total %d mqueues closed\n", n);
    dbgp_logdbg("----------------------\n");
  } // if (count)
  else
  {
    dbgp_init("\nNo mqueues exist\n");
  } // this is a Back-End-Component-only operation
}

/**
 * open_appcom for server/app:
 *    create/open the MQ named /APPCOM
 *    create a unique string identifying this instance of hipserver
 *    send/receive the string (APP will read it later)
 *    close /APPCOM
 *    unlink MQ /APPCOM so it is removed from the system
 */
void open_appcom(bool isServer, char *instance /* returned */)
{
	/*
	 * we create MQ names based on a "random" number, actually the number of seconds since the epoch
	 * each instance of hipserver will open queues with names based on this number and communicate
	 * the name to the next app to open using MQ named QNAME_COM.
	 */

	mqd_t mqcom;
    int32_t mqFlag = QOPEN_FLAG_RDWR;
	memset(instance, 0, COM_MSGSIZE);
	if (isServer)
	{
		// server will call this with isServer = true
		mqFlag = QOPEN_FLAG_RDWR | QOPEN_FLAG_CREATE;
		struct timespec ts;
		if (0 != clock_gettime(CLOCK_REALTIME, &ts))
		{
			print_to_both(p_toolLogPtr, "Cannot read the realtime clock.  Exiting...\n");
			exit(1);
		}
		sprintf(instance, "%08x", (unsigned) ts.tv_sec);	// seconds since the epoch)
	}
	// else APP will call this with create = false

	// open /APPCOM , don't use open(_mqueues() b/c we don't want to use close_mqueues to close this one
	struct mq_attr attr;
		attr.mq_flags = 0;
		attr.mq_msgsize = COM_MSGSIZE;
		attr.mq_maxmsg  = MAX_QUEUE_LEN;
		attr.mq_curmsgs = 0;
    mqcom = mq_open(QNAME_COM, mqFlag, QMODE_PERMISSION, &attr);
	if (mqcom == LINUX_ERROR)
	{
		print_to_both(p_toolLogPtr, "System Error %s (%d) in mq_open()\n", strerror(errno), errno);
		exit(1);
	}
	dbgp_intfc("  Opened Server-APP Communication queue\n");

	if (isServer)
	{
		if (LINUX_ERROR == mq_send(mqcom, instance, COM_MSGSIZE, 0))
		{
		  print_to_both(p_toolLogPtr, "System error (%d) in mq_send()\n", errno);
		  exit(1);
		}
	}
	else
	{
		if (LINUX_ERROR == mq_receive(mqcom, instance, COM_MSGSIZE, 0))
		{
		  print_to_both(p_toolLogPtr, "System error (%d) in mq_receive()\n", errno);
		  exit(1);
		}
	}
	mq_close(mqcom);	// DO NOT unlink this MQ, the APP will need it

	if (isServer == false)
	{
		// destroy an existing /APPCOM (and any messages that might be left in it). ignore errors
		mq_unlink(QNAME_COM);
	}
}


/**
 * create_mqueues:
 *    create the two unidirectional message queues for the
 *    bi-directional communication between the HART-IP Server
 *    and Gateway
 */
errVal_t create_mqueues(mqueue_usage_t usage)
{
  const char *funcName = "create_mqueues";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  errVal_t errval = NO_ERROR;

  dbgp_logdbg("  ----------------------------------\n");
  dbgp_logdbg("  Creating Queues...\n");

  //int instance = highest_instance_number(); // 0..n, or -1 if no other MQs open
  char instance[COM_MSGSIZE];

  do
  {
    // The Server creates and owns the MQs, the APP only opens them
    int32_t mqFlag = QOPEN_FLAG_RDWR;
    if (usage == MQUSAGE_SERVER)
    {
		mqFlag |= QOPEN_FLAG_CREATE;

		open_appcom(true, instance);
    }

    /* Use RSP to send msg to Server */
    char mqName[80];
    make_mq_name(QNAME_RSP, instance, mqName);
    errval = open_mqueue(&rspQueue, mqName, mqFlag,
    APP_MSG_SIZE, MAX_QUEUE_LEN);
    if (errval != NO_ERROR)
    {
      print_to_both(p_toolLogPtr, "Error opening APP-To-Server queue\n");
      break;
    }
    dbgp_intfc("  Created APP-To-Server queue\n");

    /* mqueue for Server to send msg to APP */
    make_mq_name(QNAME_REQ, instance, mqName);
    errval = open_mqueue(&reqQueue, mqName, mqFlag,
    APP_MSG_SIZE, MAX_QUEUE_LEN);
    if (errval != NO_ERROR)
    {
      print_to_both(p_toolLogPtr, "Error opening Server-To-APP queue\n");
      break;
    }
    dbgp_intfc("  Created Server-To-APP queue\n");

  } while (false);

  if (errval == NO_ERROR)
  {
	  dbgp_logdbg("  Total %d Msg Queues Created\n", numQueues);
  }
  else
  {
    print_to_both(p_toolLogPtr, "Failed to Create Queues\n");
  }
  dbgp_logdbg("  ----------------------------------\n");

  return (errval);
}

/**
 * snd_msg_to_Q(): send a message to hartip server
 *
 * RETURN:
 *         NO_ERROR for success or error code
 */
errVal_t snd_msg_to_Q(mqd_t mq, void *p_msg)
{
  errVal_t errval = NO_ERROR;

  do
  {
    if (p_msg == NULL)
    {
      errval = POINTER_ERROR;
      print_to_both(p_toolLogPtr, "NULL pointer passed to %s\n",
          "snd_msg_to_Q");
      break;
    }

    if (mq == LINUX_ERROR)
    {
      errval = MQ_INVALID_PARAM_ERROR;
      break;
    }

    struct mq_attr mqstat;
    mq_getattr(mq, &mqstat);  // for debugging
    int status = mq_send(mq, (char*) p_msg, sizeof_msg(mq), 0);

    if (LINUX_ERROR == status)
    {
      errval = LINUX_ERROR;
      print_to_both(p_toolLogPtr,
                    "System error (%d) in mq_send()\n", errno);
      break;
    }
  } while (false);

  return errval;
}

/**
 * rcv_msg_from_Q(): retrieve message from the queue

 * RETURN:
 *         NO_ERROR for success or error code
 */
errVal_t rcv_msg_from_Q(mqd_t mq, void *p_msg, mqueue_blocking_t blocking)
{
  errVal_t errval = NO_ERROR;
  char recvBuff[APP_MSG_SIZE];

  memset(recvBuff, 0, sizeof(recvBuff));

  do
  {
    if (p_msg == NULL)
    {
      errval = POINTER_ERROR;
      print_to_both(p_toolLogPtr, "NULL pointer passed to %s\n",
                    "rcv_msg_from_Q");
      break;
    }
    if (mq == LINUX_ERROR)
    {
      errval = MQ_INVALID_PARAM_ERROR;
      print_to_both(p_toolLogPtr, "Invalid Q parameter passed to %s\n",
                    "rcv_msg_from_Q");
      break;
    }

    struct mq_attr mqstat;
    mq_getattr(mq, &mqstat);  // for debugging
    if (blocking)
    {
      numBytesRead = mq_receive(mq, recvBuff, sizeof_msg(mq), NULL);
    }
    else
    {
      // return immediately if no msg in queue
      const struct timespec timeout = { 0, 0 };
      numBytesRead = mq_timedreceive(mq, recvBuff, sizeof_msg(mq),
                                     NULL, &timeout);
      if (numBytesRead <= 0)
      {
        errval = MQ_EOF;
        break;
      }
    }
    if (numBytesRead == LINUX_ERROR)
    {
      errval = LINUX_ERROR;
      print_to_both(p_toolLogPtr, "LINUX_ERROR (%d)\n", errno);
      break;
    }

    memcpy(p_msg, recvBuff, numBytesRead);
  } while (false);

  return errval;
}

/**
 * open_mqueue(): open the queue with specified flags.
 *
 * Return:
 *         the queue descriptor or (mqd_t)-1 on failure.
 */
errVal_t open_mqueue(mqd_t *p_mqDesc, char *mqName, int32_t qFlag,
                     int32_t msgsize, int32_t maxmsg)
{
  if (qFlag)
  {
    struct mq_attr attr;

    attr.mq_flags = 0;
    attr.mq_msgsize = msgsize;
    attr.mq_maxmsg  = maxmsg;
    attr.mq_curmsgs = 0;

    *p_mqDesc = mq_open(mqName, qFlag, QMODE_PERMISSION, &attr);
  }
  else
  {
    *p_mqDesc = mq_open(mqName, qFlag);
  }

  errVal_t errval = NO_ERROR;

  if (*p_mqDesc == LINUX_ERROR)
  {
    print_to_both(p_toolLogPtr, "System Error %s [%d] in mq_open()\n", strerror(errno), errno);

    errval = LINUX_ERROR;
  }
  else
  {
    /* Save mqueue info in the array */
    hsrvrQueues[numQueues].mqDesc = *p_mqDesc;
    hsrvrQueues[numQueues].qName  = mqName;
    numQueues++;
  }

  if (qFlag & QOPEN_FLAG_CREATE)
  {
    /*
     * this section removes any messages remaining in the queue from
     * prior runs of the program. If a prior instance of the program
     * terminates in an error and the queues are not emptied, this
     * scarce system resource may not be available to this instance
     * of the program.
     */
    char msgBuff[APP_MSG_SIZE + 100]; // large enough
    memset(msgBuff, 0, sizeof(msgBuff));

//  BYTE *buf = (BYTE *) malloc(msgsize);
//  if (buf)
//  {
      do
      {
        errval = rcv_msg_from_Q(*p_mqDesc, msgBuff, MQUEUE_NONBLOCKING);

        if (errval == MQ_EOF)
        { // run till empty
          errval = NO_ERROR;
          break;
        }
        else if (errval == MQ_INCONSISTENT_MSG_ERROR)
        {
          // size of message less than requested - not an error
          continue;
        }
        else if (errval != NO_ERROR)
        {
          print_to_both(p_toolLogPtr,
                        "Failed to receive msg from APP\n");
          break;
        }
      } while (true);
//    free(buf);
//  }
  }

  return errval;
}
/****************************************************
 *          Private functions for this file
 ****************************************************/

/* lookup the size data to be sent in the MQ */
static int32_t sizeof_msg(mqd_t mq)
{
  int32_t size = LINUX_ERROR;

  struct mq_attr mqstat;
  if (mq_getattr(mq, &mqstat) == 0)
  {
    size = mqstat.mq_msgsize;
  }

  return size;
}

