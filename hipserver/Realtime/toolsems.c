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
 *   toolsems.c
 * File Description:
 *   Functions to create, delete and use semaphores, and
 *   access data protected by semaphores in the tool.
 *
 **********************************************************/
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "debug.h"
#include "tooldef.h"
#include "toolsems.h"
#include "toolutils.h"

#include "safe_lib.h"

/************
 *  Globals
 ************/
/* Semaphores for process synchronization */
sem_t *p_semEndAll; /* sync main() with Main Thread */

/************************************
 *  Private variables for this file
 ************************************/
static sem_info_t htoolSems[MAX_SEMS]; /* array of all semaphores */
static uint8_t numSems = 0; /* total number of sems used */

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static errVal_t remove_sem(sem_t *p_sem, const char *semName);

/*****************************
 *  Function Implementations
 *****************************/
errVal_t create_semaphores(uint8_t createFlag)
{
  errVal_t errVal = SEM_ERROR;
  uint8_t initVal;

  const char *funcName = "create_semaphores";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  do
  {
    /* Proceed only if no errors */

    /* Create/open all generic synchronization semaphores */
    initVal = (createFlag ? SEMTAKEN : SEMIGN);

    p_semEndAll = open_a_semaphore("semEndAll", createFlag, initVal);
    if (p_semEndAll)
    {
      errVal = NO_ERROR;  // success
    }

  } while (FALSE); /* Run the loop at most once */

  return (errVal);
}

void delete_semaphores(void)
{
  uint8_t n, count = numSems;
  const char *semName;
  sem_t *p_sem;

  const char *funcName = "delete_semaphores";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  /* Avoid repeated deletion via different means */
  if (count)
  {
    dbgp_init("\n**********************\n");
    dbgp_logdbg("Deleting %s semaphores...\n", TOOL_NAME);
    for (n = 1; n <= count; n++)
    {
      p_sem = htoolSems[count - n].p_sem;
      semName = htoolSems[count - n].semName;

      if (p_sem != NULL)
      {
        if (remove_sem(p_sem, semName) == LINUX_ERROR)
        {
          fprintf(p_toolLogPtr, "Error %d deleting semaphore %s!!\n",
          errno, semName);
        }
        else
        {
          /* Reset pointer to prevent accidental misuse */
          htoolSems[count - n].p_sem = NULL;
          numSems--;
          dbgp_sem("  ..%s\n", semName);
        }
      } // if (p_sem != NULL)
    } /* for */

    dbgp_logdbg("Total %d semaphores deleted\n", (count - numSems));
    dbgp_logdbg("**********************\n");
  } /* if (count) */
  else
  {
	  dbgp_logdbg("\nNo semaphores exist\n");
  }
}

uint8_t get_sem_count(void)
{
  return (numSems);
}


sem_t *open_a_semaphore(const char *semName, uint8_t createFlag,
    uint8_t initVal)
{
  sem_t *p_sem;

  const char *funcName = "open_a_semaphore";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  if (createFlag)
  {
    p_sem = sem_open(semName, O_CREAT, SEMPERMS, initVal);
  }
  else
  {
    p_sem = sem_open(semName, 0);
  }

  if (p_sem == SEM_FAILED)
  {
    fprintf(p_toolLogPtr, "Error %d in sem_open(%s)\n", errno, semName);
    p_sem = NULL;
  }
  else if (createFlag)
  {
    /* Save semaphore info in the array */
    htoolSems[numSems].p_sem = p_sem;
    htoolSems[numSems].semName = semName;
    numSems++;
    dbgp_sem("Created semaphore #%d (%s)\n", numSems, semName);
  }

  return (p_sem);
}

// avoid unintended returns when sem_wait is interrupted
int sem_wait_nointr(sem_t *sem)
{
  while (sem_wait(sem))
  {
    if (errno == EINTR)
      errno = NO_ERROR;
    else
      return LINUX_ERROR;  // error code is in errno
  }
  return NO_ERROR;
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
static errVal_t remove_sem(sem_t *p_sem, const char *semName)
{
  errVal_t errVal = LINUX_ERROR;

  const char *funcName = "remove_sem";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  if (p_sem != NULL)
  {
    if (sem_close(p_sem) != LINUX_ERROR)
    {
      if (sem_unlink(semName) != LINUX_ERROR)
      {
        /* Reset pointer to prevent accidental misuse */
        p_sem = NULL;
        errVal = NO_ERROR;
      }
    }
  }
  return (errVal);
}

