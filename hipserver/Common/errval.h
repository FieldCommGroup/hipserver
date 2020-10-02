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
 *   errval.h
 * File Description:
 *   Header file to define the various error values used
 *   to keep track of the success/failure of functions.
 *
 **********************************************************/
#ifndef _ERRVAL_H
#define _ERRVAL_H

/*************
 *  Typedefs
 *************/
typedef enum 
{
  LINUX_ERROR = -1,
  NO_ERROR = 0,

  /* Keep these in alphabetical order for ease of maintenance */
  BAD_DATA_ERROR,
  BAUD_ERROR,
  BLDMSG_ERROR,
  CBUFF_READ_ERROR,
  CBUFF_WRITE_ERROR,
  CCMDECR_ERROR,
  CCMENCR_ERROR,
  CCMKEY_ERROR,
  CHKSUM_ERROR,
  CMD_ERROR,
  COMM_ERROR,
  CRC_ERROR,
  DEVID_ERROR,
  EMPTY_ERROR,
  FATAL_ERROR,
  FILE_ERROR,
  FRAME_ERROR,
  FTYPE_ERROR,
  IGNORE_ERROR,
  INST_ERROR,
  INVALID_INPUT_ERROR,
  ITIMER_ERROR,
  LICENSE_ERROR,
  MALLOC_ERROR,
  MIC_ERROR,
  MISMATCH_ERROR,
  MQ_INVALID_PARAM_ERROR,
  MQ_INCONSISTENT_MSG_ERROR,
  MQ_EOF,	/* no message found in non-blocking read */
  MSG_ERROR,
  MSG_ID_ERROR,
  MSG_TYPE_ERROR,
  NOMSGRCD_ERROR,
  NONCE_ERROR,
  NWK_ERROR,
  OVERFLOW_ERROR,
  PARAM_ERROR,
  PAYLD_ERROR,
  PDU_ERROR,
  PORTINIT_ERROR,
  PORTOP_ERROR,
  POINTER_ERROR,
  QUENUM_ERROR,
  RCVMSG_ERROR,
  READ_BUFF_ERROR,
  READ_ERROR,
  SEM_ERROR,
  SESSION_ERROR,
  SHMEM_ERROR,
  SIGSET_ERROR,
  SNDMSG_ERROR,
  SOCKET_BIND_ERROR,
  SOCKET_CREATION_ERROR,
  SOCKET_PORT_USED_ERROR,
  SOCKET_RECVFROM_ERROR,
  SOCKET_SELECT_ERROR,
  SOCKET_SENDTO_ERROR,
  THREAD_ERROR,
  TIMEOUT_ERROR,
  UNKNOWN_ERROR,
  VALIDATION_ERROR,
  VERSION_ERROR,
  WRITE_ERROR,
  XMIT_ERROR,

  MISC_ERROR = 0xFF      /* Keep this at end */

} errVal_t;


#endif /* _ERRVAL_H */

