/*************************************************************************************************
 *
 * Workfile: app.cpp
 * 20Apr18 - stevev
 *
 *************************************************************************************************
* The content of this file is the
 *     Proprietary and Confidential property of the FieldComm Group
 * Copyright (c) 2018, FieldComm Group, Inc., All Rights Reserved
 *************************************************************************************************
 *
 * Description: This class encapsulates the operation of the HART-IP device
 *
*/

#include "app.h"
#include "errval.h"

App::App(const char *name, const char *ver, attachedDevice type)
{
	appname = name;
	appversion = ver;
	connectiontype = type; // #6005
}

App::~App()
{

}

