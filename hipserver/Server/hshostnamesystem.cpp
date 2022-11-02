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

#include "hshostnamesystem.h"
#include <net/if.h>  
#include <fstream>
#include "debug.h"
#include <stdlib.h>  
#include "errval.h"
#include <sys/types.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>

std::string execCommand(const char* cmd) 
{
  char buffer[128];
  std::string result = "";
  FILE* pipe = popen(cmd, "r");
  if (!pipe) throw std::runtime_error("popen() failed!");
  try {
      while (fgets(buffer, sizeof buffer, pipe) != NULL) {
          result += buffer;
      }
  } catch (...) {
      pclose(pipe);
      throw;
  }
  pclose(pipe);
  return result;
}

// server hostname should already be updated
errVal_t updateDNSserver()
{
    printf("Updating DNS Server entry\n");

	errVal_t result = LINUX_ERROR;

    int status = 0;
    pid_t pid;
    extern char **environ;
    char *argv[] = {"sh", "-c", "dhclient", "-r", NULL};
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);

    int status2 = 0;
    char *argv2[] = {"sh", "-c", "dhclient", NULL};
    status2 = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv2, environ);

	if (WIFEXITED(status) && WIFEXITED(status2))
	{
		result = NO_ERROR;
	}
	return result;
}

errVal_t updateHostName(std::string& hostname)
{
    errVal_t result = NO_ERROR;

	printf("Changing server hostname to %s\n", hostname.c_str());
	int status = sethostname(hostname.c_str(), hostname.length());

    if (status != 0)
    {
        printf("Error occurred in changing hostname.\n");

        result = LINUX_ERROR;
    }
    else
    {
        char newHostname[253];
        int rc = gethostname(newHostname,sizeof(newHostname));

        printf("Hostname value after changing hostname: %s\n", newHostname);
    }
    
	return result;
}

errVal_t setNewHostName(std::string& hostname)
{
    signal(SIGCHLD, SIG_DFL);

    errVal_t res = NO_ERROR;
	//use alternate hostname update call - hostnamectl set-hostname
	res = updateHostName(hostname);
	if (res == NO_ERROR)
	{
        res = updateDNSserver();
	}

    return res;
}
