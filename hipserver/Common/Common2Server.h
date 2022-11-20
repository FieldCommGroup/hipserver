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

/*we went with the smaller...no use to fight...was:[TPPDU_MAX_FRAMLEN]; */
#define MY_MSG_BUF_LEN	TPPDU_MAX_DATALEN  

typedef
struct msg_struct_s
{
	message_type_t    mt;
	unsigned          trans_num;
	uint8_t           frameBuf[MY_MSG_BUF_LEN];
}msg_struct_t;


#endif //_COMMON2SERVER_H
