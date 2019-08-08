/*************************************************************************************************
 *
 * Workfile: Common2Server.h 
 * 27Mar18 - paul
 *
 *************************************************************************************************
* The content of this file is the 
 *     Proprietary and Confidential property of the HART Communication Foundation
 * Copyright (c) 2018, FieldComm Group, Inc., All Rights Reserved 
 *************************************************************************************************
 *
 * Description: This holds the definitions used by both the Server and this APP.
 *	
 *		
 *	
 * #include "Common2Server.h"
 */
#pragma once

#ifndef _COMMON2SERVER_H
#define _COMMON2SERVER_H
#ifdef INC_DEBUG
#pragma message("In Common2Server.h") 
#endif

#include "tpdll.h"		/* includes datatypes.h                   */
//#include "interface.h"	/* includes mqueue.h,datatypes.h,errval.h */

#ifdef INC_DEBUG
#pragma message("    Finished Includes::Common2Server.h") 
#endif

typedef
enum message_type_e
{
    hart_msg    = 0,
    init_msg,    //1
    term_msg,    //2
    brst_msg    = 4
}message_type_t;

/*tim went with the smaller...no use to fight...was:[TPPDU_MAX_FRAMLEN]; */
#define MY_MSG_BUF_LEN	TPPDU_MAX_DATALEN  

typedef
struct msg_struct_s
{
	message_type_t    mt;
	unsigned          trans_num;
	uint8_t           frameBuf[MY_MSG_BUF_LEN];
}msg_struct_t;


#endif //_COMMON2SERVER_H
