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

#ifndef HIPSYSLOGGER_H
#define HIPSYSLOGGER_H

#include <string>
#include "mutex2.h"
#include "hsconnectionmanager.h"

bool initHipSyslogger(const char* pathToCaFile);
int  getPortToHipSyslogger();
void getHostnameToHipSyslogger(char* inBuffer, int maxInBuffer);
void getPreSharedKeyToHipSyslogger(char* inBuffer, int maxInBuffer);
void getPasswordToHipSyslogger(char* inBuffer, int maxInBuffer);
void setPortToHipSyslogger(int port);
void setHostnameToHipSyslogger(const char* host);
void setPreSharedKeyToHipSyslogger(const char* host);
void setPasswordToHipSyslogger(const char* host);
void log2HipSyslogger(int priority, int eventId, int severity, HARTIPConnection* conn, const char* format, ...);
void log2HipSyslogger(int priority, int status, char* date, char* host, int manufacturer, int product, 
                      char deviceRevision, int eventId,  char* desc, int severity, unsigned int deviceID, const char* ipv4);

void connect2HipSyslogger();
void disconnectFromSyslog();
void destroyHipSyslogger();

const char* getServerIPv4();
void setDeviceIdentification(unsigned short manufacturer, unsigned short extendedDeviceType, unsigned char deviceRevision, unsigned int deviceID);

#endif // HIPSYSLOGGER_H
