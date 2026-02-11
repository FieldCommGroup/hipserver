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

/**********************************************************
 *
 * File Name:
 *   main.c
 * File Description:
 *   File that launches everything required to run the tool.
 *
 **********************************************************/
#include "debug.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "toolqueues.h"
#include "toolsigs.h"
#include "toolthreads.h"
#include "toolutils.h"
#include "datatypes.h"
#include "errval.h"
#include "tooldef.h"
#include "hsthreads.h"
#include "hsutils.h"
#include "hsudp.h"
#include "hssems.h"
#include "hssigs.h"
#include "hshostnamesystem.h"
#include "hsnetworkmanager.h"
#include "hssubscribe.h"
#include "hsconnectionmanager.h"
#include "serverstate.h"
#include "hsauditlog.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "hssyslogger.h"
#include "hssettingshandler.h"
#include "onetcpprocessor.h"
#include "hsreadonlycommandsmanager.h"
#include "factory_reset.h"
#include <stdexcept>

enum ServerState eServerState = SRVR_INIT;
enum AppState eAppState = APP_STOP;
enum AppLaunch eAppLaunch = LNCH_MANUAL;

char AppCommandLine[500] = "";

/*
 * Global Data
 */
uint16_t portNum = HARTIP_SERVER_PORT;
uint16_t maxSessionNumber = DEFINE_MAX_COUNT_SESSION;
char     pathToCertificate[255] = "";
std::string SETTINGS_FOLDER_PATH = "/var/lib/hipServer";
std::string SETTINGS_FILE_NAME = "hipServer.conf";

// Set default encryption type to PSK
uint8_t clientEncryptionType = HARTIP_ENCRYPTION_TYPE_PSK;

bool inhibitHostnameChange = false; // inhibit changing the hostname to the MAC address on first launch

/*****************************
 *  Function Implementations
 *****************************/
// Print a one line description of the command line arguments
void print_help()
{
  printf("HART-IP Server for the HART Test System\n\n");
  printf("Usage:\n");
  printf(" %s [Option(s)]  <optional HART-IP Application command line>\n\n", TOOL_NAME);
  printf("\nOptions:\n");
  printf(" -h Print command usage information and quit.\n");
  printf(" -v Print version number and quit.\n");
  printf(" -c Maximum count of client.\n");
  printf(" -s Use this as a Linux service (not as a native HART-IP device). \n");
#ifdef OPEN_SSL_SUPPORT
  printf(" -C Path to tls certificate file.\n");
#endif
  printf(" -p port to listen for UDP and TCP\n");
  printf(" -psk,-srp  Specify encryption type with Client.\n");
  printf(" Default is PSK if no encryption type is specified.\n");
  printf("\nHART-IP Application command line:\n");
  printf(" The hipserver program is always paired with a HART-IP application program.\n");
  printf(" The hipserver manages HART-IP communications with a client(s).\n");
  printf(" The HART-IP application handles token-passing request and response PDUs.\n");
  printf(" hipserver and the application inter-operate by exchanging token-passing PDUs.\n");
  printf("\nExamples of HART-IP applications are:\n");
  printf("* Pass-through messages to and from a wired HART device.\n");
  printf("* Pass-through messages to and from a wireless-HART device.\n");
  printf("* Native HART-IP device.\n");
  printf("* A simulated HART device.\n");
  printf("\nEach HART-IP application has a unique command line, which is used\n");
  printf("as the argument to the hipserver program.\n");
  printf("\nExample:\n");
  printf(" If the command line for the HART Token-passing master application is:\n");
  printf("    hiptp -p /dev/ttyS0\n");
  printf(" Then the complete command lie to launch the HART-IP server would be:\n");
  printf("    hipserver hiptp -p /dev/ttyS0\n");
  printf("\nUse Ctrl-C to end the HART-IP Server application.\n");
  printf("\nUse the -h command line option to enquire the command line options for any HART-IP Application program.\n");
}

const rsize_t maxarg = 255; //bytes
// compare const with commandline argument
int argcmp(const char *dest, const char *src)
{
    int diff = 0;

    strcmp_s(dest, maxarg, src, &diff);
    return diff;
}

uint8_t process_command_line(int argc, char* argv[])
{
  uint8_t errval = NO_ERROR;
  char path[200];

  // If command line options are present, errval is initialized
  // to an error value. It is then set to NO_ERROR only if all
  // command line options are found to be valid.
  if (argc > 1)
  {
    errval = INVALID_INPUT_ERROR;
  }

  // #6003
  uint8_t i = 1;


  while(i < argc)
  {
    if (argcmp(argv[i], "-h") == 0)
    {
      i++;
      print_help();
      exit(0);
    }
    if (argcmp(argv[i], "-v") == 0)
    {
      i++;
      printf("%s, %s\n", TOOL_NAME, TOOL_VERS);
      exit(0);
    }

    if (argcmp(argv[i], "-psk") == 0)
    {
      clientEncryptionType = HARTIP_ENCRYPTION_TYPE_PSK;
      i++;
      printf("User selected encryption type PSK\n");
      continue;
    }

    if (argcmp(argv[i], "-srp") == 0)
    {
      clientEncryptionType = HARTIP_ENCRYPTION_TYPE_SRP;
      i++;
      printf("User selected encryption type SRP\n");

      continue;
    }

      if (argcmp(argv[i], "-s") == 0)
      {
        inhibitHostnameChange = false; // for HART Test System
      }

    if (argcmp(argv[i], "-p") == 0)
    {
      char *substr;
    	strstr_s(argv[i-1], maxarg, TOOL_NAME, sizeof(TOOL_NAME)+1, &substr);
      if (substr != NULL)
    	{
    		i++;
    		//argv[0] is the program name atol = ascii to int
    		portNum = atol(argv[i]);
    		if((portNum < 1024) || (portNum > 65535))
    		{ // -p used but invalid number provided
    			portNum = HARTIP_SERVER_PORT;
    			dbgp_log("\nPrivleged or invalid port: %d\nUsing default port: %d\n",atol(argv[i]),portNum);
    		}
        i++;
    	}
    }
    else if(argcmp(argv[i], "-c") == 0)
    {
      i++;
      maxSessionNumber = atol(argv[i]);
      i++;
    }
    else if(argcmp(argv[i], "-f") == 0)
    {
      i++;
      SETTINGS_FOLDER_PATH = argv[i];
      size_t pos = SETTINGS_FOLDER_PATH.rfind("/");
      if (pos != SETTINGS_FOLDER_PATH.npos && pos != SETTINGS_FOLDER_PATH.size() - 1)
      {
          SETTINGS_FILE_NAME = SETTINGS_FOLDER_PATH.substr(pos + 1, SETTINGS_FOLDER_PATH.size() - pos - 1);
          SETTINGS_FOLDER_PATH = SETTINGS_FOLDER_PATH.erase(pos, SETTINGS_FOLDER_PATH.size() - pos);
      }
      i++;
    }
    else if(argcmp(argv[i], "-r") == 0)
    {
      i++;
      ReadOnlyCommandsManager::SetFileName(argv[i]);
      i++;
    }
#ifdef OPEN_SSL_SUPPORT
    else if(argcmp(argv[i], "-C") == 0)
    {
      i++;
      memset_s(pathToCertificate, sizeof(pathToCertificate), 0);
      memcpy_s(pathToCertificate, maxarg, argv[i], strnlen(argv[i], maxarg) + 1);
      i++;
    }
#endif
    else
    {
    	dbgp_log("\nConnecting %s at port: %d\n", TOOL_NAME, portNum);
    	break;
    }
  }

  // build up the path to the device APP executable:
  //
  //  1.  the bash shell handles the parsing of these args
  //
  //  2.  the args concatenated together with spaces in between
  //      constitutes the command line for the APP program
  //
  //  3.  the command lines for the APPs differ substantially,
  //      so this server cannot know what they are in advance
  //
  //  4.  if there is a problem with the commandline construction,
  //      the system() call will fail with a message
  //

  for (i; i < argc; i++)
  {
    strcat_s(AppCommandLine, sizeof(AppCommandLine), argv[i]);
    strcat_s(AppCommandLine, sizeof(AppCommandLine), " ");
  } // #689

  if (strnlen_s(AppCommandLine, sizeof(AppCommandLine))+1 > sizeof(AppCommandLine))
  {
    printf("Command line arguments are too large\n");
    exit(1);
  }
  errval = NO_ERROR;

  return (errval);
}

/*
 * orderly shutdown
 */
void end_all(void)
{
  const char *funcName = "end_all";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_logdbg("Ending all %s ...\n", TOOL_NAME);

  /* Wait for main thread to terminate */
  if (mainThrID != (pthread_t) NULL)
  {
    int32_t errval = pthread_join(mainThrID, NULL);
    if (errval == NO_ERROR)
    {
      /* Reset ID to prevent accidental misuse */
      mainThrID = (pthread_t) NULL;
      dbgp_logdbg("Main Thread terminated\n");
    }
    else
    {
    	dbgp_logdbg(
          "Error %d in pthread_join() for Main Thread termination!!\n",
          errval);
    }
  }

  NetworkManager::Destroy();

  ConnectionsManager::DeleteManager();

  OneTcpProcessor::Cleanup();
  UdpProcessor::Cleanup();
  CleanupSSL();

  /* Generic shutdown operations */
  delete_threads();

  delete_semaphores();

  /* HART-IP Server specific shutdown_hs operations */
  close_mqueues();
  close_hsLog();

  /* Close system log at the end */
  close_toolLog();

  /* Close linux syslog at the end */
  disconnectFromSyslog();
  destroyHipSyslogger();
}

void *mainThrFunc(void *thrName)
{
  errVal_t errval = NO_ERROR;

  const char *funcName = "mainThrFunc";
  dbgp_trace("~~~~~~ %s ~~~~~~\n", funcName);

  dbgp_init("\n==================================\n");
  dbgp_logdbg("Starting %s...\n", (char * )thrName);

  std::string checkCommand = "lsof -i:" + std::to_string(portNum) +" | grep dhclient  | awk '{print $2}' | uniq";
  int n1 = checkCommand.length();
  char checkCommandArray[n1 + 1];
  strcpy_s(checkCommandArray, n1+1, checkCommand.c_str());

  std::string killCommand = checkCommand + " | xargs kill -9";
  int n2 = killCommand.length();
  char killCommandArray[n2 + 1];
  strcpy_s(killCommandArray, n2+1, killCommand.c_str());
  
  do
  {
    std::string execResults = execCommand(checkCommandArray);

    if(execResults != "")
    {
      print_to_both(p_toolLogPtr, "\nKilling all active dhclient instances on the same port before run...\n");
      
      system(killCommandArray);
	  
      script_sleep(1); //putting sleep because the process might not be totally killed before hipserver tries to use the port
    }
    errval = initialize_hs_signals();
    if (errval != NO_ERROR)
    {
      print_to_both(stderr, "\nSignals could not be initialized\n");
      break;
    }

    /* HART-IP Server Initializations */
    errval = do_hs_setup();
    if (errval != NO_ERROR)
    {
      print_to_both(stderr, "\nHART-IP Server setup failed\n");
      break;
    }

    if (eAppLaunch == LNCH_MANUAL)
    {
    	dbgp_log("No command line to start the APP was supplied.\n");
    	dbgp_log("Please start your APP program now.\n\n");
    }

    dbgp_init("\nAll System Initializations Done\n");
    dbgp_init("Ready for test/application...\n");
    script_sleep(1);
    dbgp_log(" [Quit with kbd interrupt (Ctrl-C)]\n");

    /* Sleep till user quits (or sends kbd interrupt) */
    dbgp_thr("Waiting for p_semStopMainThr\n");
    errval = (errVal_t) sem_wait_nointr(p_semStopMainThr);
    if (errval == LINUX_ERROR)
    {
      print_to_both(p_toolLogPtr,
          "Error (%d) getting semaphore p_semStopMainThr\n",
          errno);
    } dbgp_thr("Got semStopMainThr\n");
  } while (FALSE);

  if (errval != NO_ERROR)
  {
    print_to_both(p_toolLogPtr, "\nInitialization Error!!\n");
    print_to_both(p_toolLogPtr, "  See log.\n");
  }

  if (ifEndApp)
  {
	  dbgp_log("\nTerminate interrupted application\n");
  }

  dbgp_init("Main thread done...\n");
  dbgp_init("==================================\n");
  dbgp_thr("Posting p_semEndAll from Main thread\n");
  dbgp_log("Quitting %s now!\n", TOOL_NAME);
  script_sleep(2);
  sem_post(p_semEndAll);
}

void app_init(char *appName)
{
  int32_t retVal;
  const char *mainThrName = "Main Thread";

  InitSSL();
  OneTcpProcessor::Init();
  UdpProcessor::Init();
  // init log subsystem
  initHipSyslogger(pathToCertificate);
  connect2HipSyslogger();
  do
  {
    clear_attached_devices();

    retVal = open_toolLog();

    if (retVal != NO_ERROR)
    {
      dbgp_logdbg("\n%s log could not be opened!!\n", TOOL_NAME);
    }
#ifdef OPEN_SSL_SUPPORT
    dbgp_log("HART-IP Server v.%s with OpenSSL (TP10300)\n\n", TOOL_VERS);
#else
	dbgp_log("HART-IP Server v.%s  (TP10300)\n\n", TOOL_VERS);
#endif


    /*
     * end_all() called after exit() is called
     */
    retVal = atexit(end_all);
    if (retVal != NO_ERROR)
    {
      fprintf(p_toolLogPtr, "\nExit function could not be set!!!\n");
      break;
    }

    retVal = ConnectionsManager::CreateManager(maxSessionNumber);
    if(retVal != NO_ERROR)
    {
       fprintf(p_toolLogPtr, "\nSession manager could not be create!\n");
      break;
    }

    retVal = create_hs_semaphores(TRUE);  // calls common create_semaphores()
    if (retVal == SEM_ERROR)
    {
      fprintf(p_toolLogPtr, "\nSemaphores could not be created!!!\n");
      break;
    }

    /* Create main thread to do misc. setups for the tool */
    retVal = pthread_create(&mainThrID, NULL, mainThrFunc,
        (void *) mainThrName);
    if (retVal != NO_ERROR)
    {
      fprintf(p_toolLogPtr, "\nThread %s could not be created!!\n",
          mainThrName);
      break;
    }

    /* Wait till main thread is complete */
    dbgp_sem("\n=================================\n");
    dbgp_sem("Waiting in main() for the end\n");
    AuditLogger->ServerStarted(portNum);

    SettingsHandler settingsHandler;
    settingsHandler.LoadSettings();

    log2HipSyslogger(6, 100, 8, NULL, "Device startup/power up");

    retVal = sem_wait_nointr(p_semEndAll);  // not interruptible
    if (retVal == LINUX_ERROR)
    {
      fprintf(p_toolLogPtr, "Error (%d) getting semaphore p_semEndAll\n",
          errno);
    }
    dbgp_sem("Got semEndAll\n");
  } while (FALSE); /* Run the loop at most once */

  dbgp_log( "\n");
  dbgp_log( "************************************************\n");
  dbgp_log( "Please wait for %s to terminate...\n", TOOL_NAME);
  dbgp_log( "(it may take a few seconds)\n");
  dbgp_log( "************************************************\n");
  dbgp_log( "\n");
  system("dhclient -r;dhclient");
  script_sleep(2);
  exit(1);
}

int32_t main(int argc, char *argv[])
{
// Factory Reset detection doesn't apply to x86 since it uses
//  raspPI3 hardware
#if !defined(__x86_64__)
  // Initialize GPIO for reset and write_protect (GPIO 2 and GPIO3) both pins are pulled high on PI3B+ board
  if (gpioInitialise() < 0)
  {
	printf("WARNING: gpio pin initialization failed. factory_reset or write_protect state may not be correct!\n");
  }

// Determine if Factory reset condition exists on the PI3B+ board (see factory_reset.c for implementation)
  //   if so remove configuration files for hipserver and hipflow app
  
  if (reset())
  {
    //NOTE: don't fail on nativeFlow.conf missing . Hipflow app may not be used with hipserver in all cases.
    printf("Factory Reset condition detected. Removing configuration files\n");

    if (remove("/etc/nativedev/nativeFlow.conf") == 0)
	printf("/etc/nativedev/nativeFlow.conf deleted successfully\n");
    else
	printf("unable to delete the file. May already be gone or not running hipflow app here\n");


    if (remove("/var/lib/hipServer/hipServer.conf") == 0)
	printf("/var/lib/hipServer/hipServer.conf file deleted successfully\n");
    else
	printf("unable to delete the file. May already be gone.\n");

  }
#endif


  uint8_t errval = process_command_line(argc, argv);

  eServerState = SRVR_INIT;
  if (strnlen_s(AppCommandLine, sizeof(AppCommandLine)) > 0)
  {
    // a command line for the APP is provided
    eAppLaunch = LNCH_AUTO;  // server will launch APP automatically
    eAppState = APP_STOP;  // APP is not running, initially
  }
  else
  {
    // *no* command line for the APP is provided
    eAppLaunch = LNCH_MANUAL;  // user will launch APP manually
    eAppState = APP_RUN;// server assumes APP program is executing
  }

  if (errval == NO_ERROR)
  {
    app_init(argv[0]);
  }
  // else nothing

}
