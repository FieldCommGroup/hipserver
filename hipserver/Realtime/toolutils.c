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
 *   toolutils.c
 * File Description:
 *   Misc. utility functions for the tool.
 *
 **********************************************************/
#ifndef _GNU_SOURCE 
#define  _GNU_SOURCE   1    /* for TEMP_FAILURE_RETRY */
#endif

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "debug.h"
#include "errval.h"
#include "tooldef.h"
#include "toolsems.h"
#include "toolthreads.h"
#include "toolutils.h"


/************
 *  Globals
 ************/
FILE *p_toolLogPtr = NULL; /* File pointer for the generic tool log */

/************************************
 *  Private Variables for this file
 ************************************/
static char TOOLLOG_NAME[FILENAME_LEN] = TOOL_NAME;

/**********************************************
 *  Private function prototypes for this file
 **********************************************/
static void sleep_thru_intrpts(timeval_t *p_timer);

/*****************************
 *  Function Implementations
 *****************************/
void close_logfile(FILE *p_filePtr)
{
  const char *funcName = "close_logfile";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  if ((p_filePtr != NULL)   &&
      (p_filePtr != stderr) &&
      (p_filePtr != stdout))
  {
    fprintf(p_filePtr, "\n");
    fclose(p_filePtr);
  }
  else
  {
    fprintf(stderr, "File was not open\n");
  }
  fflush(stderr);
}

void close_toolLog(void)
{
  const char *funcName = "close_toolLog";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  close_logfile(p_toolLogPtr);
  if (p_toolLogPtr != NULL)
  {
    fprintf(stderr, "File %s closed\n", TOOLLOG_NAME);
    p_toolLogPtr = NULL;
  }
}

errVal_t open_logfile(FILE **pp_filePtr, char *p_fileName)
{
  errVal_t errval = NO_ERROR;

  const char *funcName = "open_logfile";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  if (*pp_filePtr == NULL)
  {
#ifdef DEBUG_MODE
    fprintf(stderr, "\n----------------------------------\n");
    fprintf(stderr, "  Opening %s...\n", p_fileName);
#endif
    *pp_filePtr = fopen(p_fileName, "w");
    if (*pp_filePtr == NULL)
    {
      *pp_filePtr = stderr;
      errval = FILE_ERROR;
#ifdef DEBUG_MODE
      fprintf(stderr, "  Error opening log file %s!!!\n", p_fileName);
      fprintf(stderr, "    All logging will be redirected to stderr\n");
#endif
    }
    else
    {
      time_t ltime = time(NULL);
      struct tm *Tm = localtime(&ltime);

      dbgp_logdbg("++++++++++++++ %s ++++++++++++++\n",
          p_fileName);
      dbgp_logdbg("\n%d/%d/%d - %d:%d:%d\n\n",
          Tm->tm_year + 1900, Tm->tm_mon + 1, Tm->tm_mday,
          Tm->tm_hour, Tm->tm_min, Tm->tm_sec);

      dbgp_logdbg("  Log File %s Opened\n", p_fileName);
    }
  } /* if (*pp_filePtr == NULL) */

  dbgp_logdbg("----------------------------------\n");

  return (errval);
}

errVal_t open_toolLog(void)
{
  errVal_t errval = NO_ERROR;

  const char *funcName = "open_toolLog";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  /* p_toolLogPtr is the global log file pointer for the tool */
  if (p_toolLogPtr == NULL)
  {
    /* Log does not exist yet */
    strcat(TOOLLOG_NAME, "_log.txt");
    errval = open_logfile(&p_toolLogPtr, TOOLLOG_NAME);
  } /* if (p_toolLogPtr == NULL) */
  else
  {
    fprintf(stderr, "Log is already open\n");
  }

  return (errval);
}


void print_hexbytes(uint8_t *bytes, uint8_t numBytes, FILE *fptr)
{
  if ((bytes != NULL) && (numBytes))
  {
    if (fptr == NULL)
    {
      fptr = stderr;
    }

    fprintf(fptr, "\nData Info (%d bytes):\n", numBytes);
    fprintf(fptr, "  0x");
    for (uint8_t i = 0; i < numBytes; i++)
    {
      fprintf(fptr, "%.2X ", bytes[i]);
    }
    fprintf(fptr, "\n");
  }
}


void print_to_both(FILE *p_log, const char *format, ...)
{
  /* Format the data and print it both to the log and the screen */
  va_list args;
  va_start(args, format);

  char buffer[1024];
  memset(buffer, 0, sizeof(buffer));
  vsnprintf(buffer, 1024, format, args);

  if (strlen(buffer) > 0)
  {
    if (p_log == NULL)
    {
#ifdef DEBUG_MODE
      fprintf(stderr, "\nLog file is not initialized\n");
      fprintf(stderr, "Printing only to screen\n");
#endif
    }
    else
    {
      // print to log file if we have a FILE *
      fprintf(p_log, "%s", buffer);
      fflush(p_log);
    }

    // always print to both
    fprintf(stderr, "%s", buffer);
  }

  va_end(args);
}

void print_to_log(FILE *p_filePtr, const char *format, ...)
{
	  /* Format the data and print it to the log */
	  va_list args;
	  va_start(args, format);

	  char buffer[1024];
	  memset(buffer, 0, sizeof(buffer));
	  vsnprintf(buffer, 1024, format, args);

	  if (strlen(buffer) > 0)
	  {
	    if (p_filePtr == NULL)
	    {
	      fprintf(stderr, "\nLog file is not initialized\n");
	    }
	    else
	    {
	      fprintf(p_filePtr, "%s", buffer);
	      fflush(p_filePtr);
	    }
	  }

	  va_end(args);
}


void script_sleep(uint32_t sec)
{
  timeval_t thisTimer;

  thisTimer.tv_sec = sec;
  thisTimer.tv_usec = 0;
  sleep_thru_intrpts(&thisTimer);
}

void script_usleep(uint32_t uSec)
{
  timeval_t thisTimer;

  thisTimer.tv_sec = uSec / USEC_PER_SEC;
  thisTimer.tv_usec = uSec % USEC_PER_SEC;
  sleep_thru_intrpts(&thisTimer);
}

/****************************************************
 *          Private functions for this file
 ****************************************************/
static void sleep_thru_intrpts(timeval_t *p_timer)
{
  /* This executes select() repeatedly if function fails due
   * to an interrupt, i.e., errno is EINTR.  It will restart
   * the timer with the unelapsed/remainder of the original
   * time again when interrupted by a signal. If not interrupted,
   * and there is no other error, there is no retry, and timer
   * counts down to 0 in one attempt.  If something else causes
   * a premature return, then error msg is printed.
   */

  if (LINUX_ERROR
      == TEMP_FAILURE_RETRY(
          select(FD_SETSIZE, NULL, NULL, NULL, p_timer)))
  {
    fprintf(stderr, "Error %d setting sleep time!!\n", errno);
  }


#if 0  // alternate version
  int retval;
  while (TRUE)
  {
    retval = select(FD_SETSIZE, NULL, NULL, NULL, p_timer);
    if (retval == LINUX_ERROR)
    {
      if (errno != EINTR)
      {
        break;
      }
    }
    else
    {
      break;
    }
  }

  if (LINUX_ERROR == retval)
  {
    print_to_both(p_toolLogPtr, "Error %d setting sleep time\n", errno);
  }
#endif
}

double get_elapsed_time()
{
	struct timespec ts;
	double secs = 0;

	if (0 == clock_gettime(CLOCK_REALTIME, &ts))
	{
		secs = (double) ts.tv_sec + ((double) ts.tv_nsec)/1000000000.0;
	}

	return secs;
}

uint32_t GetTickCount(void) {
	struct timespec ts;
	unsigned theTick = 0U;
	clock_gettime(CLOCK_REALTIME, &ts);
	theTick = ts.tv_nsec / 1000000;
	theTick += ts.tv_sec * 1000;
	return theTick;
}