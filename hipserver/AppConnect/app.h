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
 * Description: This class encapsulates the operation of the HART-IP device
 *
 * #include "app.h"
*/

#ifndef APP_H_
#define APP_H_

#include "errval.h"
#include "apppdu.h"

enum attachedDevice{
	undefined, connectionFailure, tokenPassing, wireless, HART_IP, APL, hipiosys
};

class App
{
public:
	App(const char *name, const char *ver, attachedDevice type);
	virtual ~App();

	const char *appname;
	const char *appversion;
	attachedDevice connectiontype; // #6005

	const char *GetName() { return appname; };
	const char *GetVersion() { return appversion; };
	attachedDevice GetConnectionType() { return connectiontype; };
	/*
	 * each HART-IP application will derive a class from App that implements these methods
	 */

	// parse command line args and set class attributes reflecting them
	virtual errVal_t commandline(int argc, char *argv[]) { return FATAL_ERROR; };


	// read a file and/or set static data items
	virtual errVal_t configure() { return FATAL_ERROR; };


	// programatically set data, semaphores, spin threads, etc
	virtual errVal_t initialize() { return FATAL_ERROR; };


	//This will be called when we receive a INIT_APP_CMD from the server.
	//	If it returns false, the interface will discard the INIT CMD and allow the server to time out.
	//	If the application has a serious error where it can never be 'ready', it should call the
	//	abortAPP() function shortly before returning false.
	virtual errVal_t ready() { return FATAL_ERROR; };


	//		This will be called when we receive a TERM_APP_CMD from the server.
	//	The return value is disregarded and doesn't matter.  If the abortAPP() function has not been
	//	called by this function, the AppConnector will call it immediately after this function returns.
	//	That means that the application is assumed to be shutdown when this function is returned,
	//	all threads terminated and all memory freed. run will return soon after this function returns.
	virtual errVal_t stop() { return FATAL_ERROR; };


	//		This will be called when we receive a HART_APP_CMD message from the server.
	//	This will evaluate the message packet and, if not addressed to this device, will return NOT_OURS.
	//  When it is addressed to this device, the msgFunc will handle the message, fill the AppPdu with
	//  reply data and address, and return a value of ALL_IS_WELL.  This class will then send the msg
	//	packet to the server.  It is up to the msgFunc to handle errors and form the correct error
	//  response packet, returning ALL_IS_WELL to this class to enable the error packet to be sent.
	virtual int handleMessage(AppPdu *pPDU) { return FATAL_ERROR; };


	// stop threads, delete semaphores and allocated memory
	virtual errVal_t cleanup() { return FATAL_ERROR; };
};

#endif /* APP_H_ */
