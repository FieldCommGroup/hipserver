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
 *   tpdll.h
 * File Description:
 *   Header file to define the various constants and
 *   typedefs used in the HART Token-Passing Data Link Layer.
 *
 **********************************************************/
#ifndef _TPDLL_H
#define _TPDLL_H

#include  "datatypes.h"


/****************
 *  Definitions
 ****************/
/* Default and limits for preambles */
#define HART_DEFAULT_PREAMBLES   ((uint8_t)15)
#define HART_MAX_PREAMBLES       ((uint8_t)40)
#define HART_MIN_PREAMBLES       ((uint8_t)5)


/******************************************
 ***** TPDLL constants (From Spec 81) *****
 ******************************************/

/*
 * TP data link layer should retry up to three times
 * (for a total of 4 STX's on communication error
 */

#define MAXRETRIES 3
#define MAXTRIES MAXRETRIES + 1

/* Length (in bytes) of the various fields of the TPDLL header */
#define TPHDR_ADDRLEN_POLL       ((uint8_t)1)
#define TPHDR_ADDRLEN_UNIQ       ((uint8_t)5)
#define TPHDR_BCOUNTLEN          ((uint8_t)1)
#define TPHDR_CMDLEN             ((uint8_t)1)
#define TPHDR_DELIMLEN           ((uint8_t)1)
#define TPHDR_EXPLEN             ((uint8_t)0)   /* currently not used */

#define TPHDR_ADDRLEN_DIFF       (TPHDR_ADDRLEN_UNIQ - TPHDR_ADDRLEN_POLL)
#define TPHDR_MAX_ADDRLEN        TPHDR_ADDRLEN_UNIQ

/* Max length (in bytes) of the entire TPDLL header  */
#define TPPDU_MAX_HDRLEN         ((uint8_t)(TPHDR_DELIMLEN +  \
                                  TPHDR_MAX_ADDRLEN    +     \
                                  TPHDR_EXPLEN         +     \
                                  TPHDR_CMDLEN         +     \
                                  TPHDR_BCOUNTLEN))


/* Offsets for the fields of a TPDLL header for short (polling) address
 * format (derived from header information in Spec 81)
 */
#define TP_OFFSET_DELIM          0
#define TP_OFFSET_ADDR           (TP_OFFSET_DELIM + TPHDR_DELIMLEN)
#define TP_OFFSET_EXP_POLL       (TP_OFFSET_ADDR + TPHDR_ADDRLEN_POLL)
#define TP_OFFSET_CMD_POLL       (TP_OFFSET_EXP_POLL + TPHDR_EXPLEN)
#define TP_OFFSET_BCOUNT_POLL    (TP_OFFSET_CMD_POLL + TPHDR_CMDLEN)
#define TP_OFFSET_DATA_POLL      (TP_OFFSET_BCOUNT_POLL + TPHDR_BCOUNTLEN)


/* Offsets for the fields of a TPDLL header for long (unique) address
 * format (derived from header information in Spec 81)
 */
#define TP_OFFSET_EXP_UNIQ       (TP_OFFSET_EXP_POLL + TPHDR_ADDRLEN_DIFF)
#define TP_OFFSET_CMD_UNIQ       (TP_OFFSET_CMD_POLL + TPHDR_ADDRLEN_DIFF)
#define TP_OFFSET_BCOUNT_UNIQ    (TP_OFFSET_BCOUNT_POLL + TPHDR_ADDRLEN_DIFF)
#define TP_OFFSET_DATA_UNIQ      (TP_OFFSET_DATA_POLL + TPHDR_ADDRLEN_DIFF)


/* Max length (in bytes) of the non-header fields of the TPDLL PDU */
#define TPPDU_MAX_CHECKSUMLEN    ((uint8_t)1)
#define TPPDU_MAX_DATALEN        ((uint8_t)255)


/* Max length (in bytes) of a TPDLL Frame.
 *
 * Msg Length (264 bytes)
 * TPDLL Header (8) + DataBytes (255) + CheckByte (1)
 * (8 hdr = 1 delim + 5 addr + 0 exp + 1 cmd + 1 byte count)
 */
#define TPPDU_MAX_FRAMELEN       (TPPDU_MAX_HDRLEN   +   \
                                  TPPDU_MAX_DATALEN  +   \
                                  TPPDU_MAX_CHECKSUMLEN)


/* Values of the sub-fields of the TPDLL Delimiter */
#define TPDELIM_ADDR_POLL        0
#define TPDELIM_ADDR_UNIQ        ((uint8_t)0x80)
#define TPDELIM_NUM_EXP_BYTES    0
#define TPDELIM_FRAME_ACK        0x06
#define TPDELIM_FRAME_BACK       0x01
#define TPDELIM_FRAME_STX        0x02
#define TPDELIM_PHY_LAYER_FSK    0x00
#define TPDELIM_PHY_LAYER_PSK    0x08

#define TPDELIM_FRAME_PSK_ACK    (TPDELIM_FRAME_ACK  | TPDELIM_PHY_LAYER_PSK)    
#define TPDELIM_FRAME_PSK_BACK   (TPDELIM_FRAME_BACK | TPDELIM_PHY_LAYER_PSK) 
#define TPDELIM_FRAME_PSK_STX    (TPDELIM_FRAME_STX  | TPDELIM_PHY_LAYER_PSK)  

/* Masks to extract values of the sub-fields of the TPDLL Delimiter */
#define TPDELIM_ADDR_MASK        ((uint8_t)0x80)

#define TPDELIM_EXP_BYTE_MASK    0x60
#define TPDELIM_FRAME_MASK       0x1F /* includes PSK frames too */
#define TPDELIM_PHY_LAYER_MASK   0x18

#define TPDELIM_ACK_POLL         (TPDELIM_ADDR_POLL | TPDELIM_FRAME_ACK)
#define TPDELIM_STX_POLL         (TPDELIM_ADDR_POLL | TPDELIM_FRAME_STX)
#define TPDELIM_ACK_UNIQ         (TPDELIM_ADDR_UNIQ | TPDELIM_FRAME_ACK)
#define TPDELIM_BACK_UNIQ        (TPDELIM_ADDR_UNIQ | TPDELIM_FRAME_BACK)
#define TPDELIM_STX_UNIQ         (TPDELIM_ADDR_UNIQ | TPDELIM_FRAME_STX)


/* Masks to set/extract values of the sub-fields of the TPDLL
 * Short Frame (Polling) Address or first byte of Long Frame
 * (unique) Address.
 */
#define TPPOLL_PRIM_MASTER_MASK  0x80u
#define TPPOLL_FDEV_BURST_MASK   0x40
#define TPPOLL_FDEV_ADDR_MASK    0x3F

#define CMD0_LEN       22      // Read Unique Identifier

#endif /* _TPDLL_H */

