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
 *   toolthreads.c
 * File Description:
 *   Functions to create and delete the threads used in 
 *   the tool and do the necessary initializations and
 *   setups for the tool.
 *
 **********************************************************/
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>        
#include <string.h>        
#include <time.h>        

#include "common.h"
#include "debug.h"
#include "tooldef.h"
#include "toolsems.h"
#include "toolsigs.h"
#include "toolthreads.h"
#include "toolutils.h"

/************
 *  Globals
 ************/
pthread_t mainThrID = (pthread_t) NULL;

/************************************
 *  Private variables for this file  
 ************************************/
/* Information about all tool threads except the main thread */
static thr_info_t htoolThrs[MAX_THRS]; /* array of threads */
static uint8_t numThrs = 0; /* total number of threads */

/*****************************
 *  Function Implementations
 *****************************/

void delete_threads(void)
{
  uint8_t n, count = numThrs;
  const char *thrName;
  pthread_t thrID;

  const char *funcName = "delete_threads";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  /* Avoid repeated deletion via different means */
  if (count)
  {
    dbgp_init("\n**********************\n");
    dbgp_logdbg("Deleting %s threads...\n", TOOL_NAME);

    for (n = 0; n < count; n++)
    {
      thrID = htoolThrs[n].thrID;
      thrName = htoolThrs[n].thrName;
      if (thrID != (pthread_t) NULL)
      {
        if (pthread_cancel(thrID) == NO_ERROR)
        {
          /* Wait for the cancelled thread to terminate */
          if (pthread_join(thrID, NULL) == NO_ERROR)
          {
            /* Reset ID to prevent accidental misuse */
            htoolThrs[n].thrID = (pthread_t) NULL;
            numThrs--;
            dbgp_thr("  ..%s\n", (char *)thrName);
          }
          else
          {
            print_to_both(p_toolLogPtr,
                "Error in pthread_join() for %s!! \n",
                (char *) thrName);
          }
        }
	 // else nothing to delete
      } // if (thrID != NULL)
    } /* for */
    dbgp_logdbg("Total %d threads deleted\n", n);
    dbgp_logdbg("**********************\n");
  } /* if (count) */
  else
  {
	  dbgp_logdbg("\nNo threads exist\n");
  }
}

uint8_t get_thread_count(void)
{
  return (numThrs);
}

errVal_t start_a_thread(pthread_t *p_thrID, void *(*p_thrFunc)(void *),
    const char *thrName)
{
  errVal_t errval = THREAD_ERROR;
  int32_t errNo;

  const char *funcName = "start_a_thread";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  do
  {
    if (numThrs >= MAX_THRS)
    {
      print_to_both(p_toolLogPtr, "Cannot create more threads\n");
      print_to_both(p_toolLogPtr,
          "%d threads exist, max capacity %d threads\n", numThrs,
          MAX_THRS);
      break;
    }

    dbgp_thr("...Creating next thread (current total = %d) - %s\n",
        numThrs, thrName);

    errNo = pthread_create(p_thrID, NULL, p_thrFunc, (void *) thrName);
    if (errNo != NO_ERROR)
    {
      errval = THREAD_ERROR;
      print_to_both(p_toolLogPtr, "Error %d in creating thread!!\n",
          errNo);
      break;
    }

    /* Save thread info in the thread array */
    htoolThrs[numThrs].thrID = *p_thrID;
    htoolThrs[numThrs].thrName = thrName;
    errval = NO_ERROR;
    numThrs++;

    dbgp_thr("...Created next thread (current total = %d) - %s\n",
        numThrs, thrName);
  } while (FALSE);

  return (errval);
}

