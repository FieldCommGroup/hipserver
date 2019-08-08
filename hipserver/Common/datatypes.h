/*****************************************************************
 * Copyright (C) 2015-2017 FieldComm Group
 *
 * All Rights Reserved.
 * This software is CONFIDENTIAL and PROPRIETARY INFORMATION of
 * FieldComm Group, Austin, Texas USA, and may not be used either
 * directly or by reference without permission of FieldComm Group.
 *
 * THIS SOFTWARE FILE AND ITS CONTENTS ARE PROVIDED AS IS WITHOUT
 * WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION, WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 * A PARTICULAR PURPOSE AND BEING FREE OF DEFECT.
 *
 *****************************************************************/

/**********************************************************
 *
 * File Name:
 *   datatypes.h
 * File Description:
 *   Header file to typedef the 8, 16, 32 and 64-bit data 
 *   types to be used in the rest of the code. It uses the 
 *   sizes of the basic data types from the system.
 *
 **********************************************************/
#ifndef _DATATYPES_H
#define _DATATYPES_H

#include <limits.h>
#include <stdint.h>

#ifndef SIZE8_T
#define SIZE8_T
# if UCHAR_MAX == 0xFFu
//in stdint.h    typedef char int8_t;
typedef unsigned char uint8_t;
# else
#   error Define uint8_t as an 8-bit unsigned integer type in this file
#   error Define int8_t as an 8-bit integer type in this file
# endif   /* if UCHAR_MAX == 0xFFu */
#endif   /* ifndef SIZE8_T */

#ifndef SIZE16_T
#define SIZE16_T
# if USHRT_MAX == 0xFFFFu
    typedef short int16_t;
    typedef unsigned short uint16_t;
# else
#   error Define uint16_t as a 16-bit unsigned short type in datatypes.h
#   error Define int16_t as a 16-bit short type in datatypes.h
# endif /* if USHRT_MAX == 0xFFFFu */
#endif /* ifndef SIZE16_T */


#ifndef SIZE32_T
#define SIZE32_T
# if UINT_MAX == 0xFFFFFFFFu
    typedef int int32_t;
    typedef unsigned int uint32_t;
# elif ULONG_MAX == 0xFFFFFFFFul
    typedef long int32_t;
    typedef unsigned long uint32_t;
# else
#   error Define uint32_t as a 32-bit unsigned integer type in datatypes.h
#   error Define int32_t as a 32-bit integer type in datatypes.h
# endif /* if UINT_MAX == 0xFFFFFFFFu */
#endif /* ifndef SIZE32_T */

#ifndef SIZE64_T
#define SIZE64_T
# if defined(UINT_MAX) && UINT_MAX > 0xFFFFFFFFu
#   if UINT_MAX == 0xFFFFFFFFFFFFFFFFu
      typedef int int64_t;
      typedef unsigned int uint64_t;
#   endif
# elif defined(ULONG_MAX) && ULONG_MAX > 0xFFFFFFFFu
#   if ULONG_MAX == 0xFFFFFFFFFFFFFFFFul
      typedef long int64_t;
      typedef unsigned long uint64_t;
#   endif
# elif defined(ULLONG_MAX) && ULLONG_MAX > 0xFFFFFFFFu
#   if ULLONG_MAX == 0xFFFFFFFFFFFFFFFFull
      typedef long long int64_t;
      typedef unsigned long long uint64_t;
#    endif
# elif defined(ULONG_LONG_MAX) && ULONG_LONG_MAX > 0xFFFFFFFFu
#   if ULONG_LONG_MAX == 0xFFFFFFFFFFFFFFFFull
      typedef long long int64_t;
      typedef unsigned long long uint64_t;
#   endif
# else
      typedef long long int64_t;
      typedef unsigned long long uint64_t;
# endif
#endif   /* ifndef SIZE64_T */

typedef enum
{
  FALSE,
  TRUE
} bool_t;

typedef enum hartTypes_e
{
	ht_Unknown,	// 0
	ht_int8,	// 1 - 8 bit int
	ht_int16,
	ht_int24,
	ht_int32,
	ht_int40,	// 5
	ht_int48,
	ht_int56,
	ht_int64,
	ht_float,
	ht_double,	//10
	ht_ascii,
	ht_packed   // 4devices
}
/*typedef*/hartTypes_t;

// castor - - 
#define USS(a) ((uint16_t)(a))	/* 2 bytes */
#define ULL(b) ((uint32_t)(b))	/* 4 bytes */
#define UHH(c) ((uint64_t)(c))  /* 8 bytes */

// in-situ converters
#define REVERSE_S(s) (  USS( USS(s) << 8 ) | USS( USS(s) >> 8 )  )
#define REVERSE_L(l) (  ULL( ULL(REVERSE_S(ULL(l))) << 16) | ULL( REVERSE_S(ULL(l) >> 16) &0xFFFF)  )
#define REVERSE_H(L) (  (( UHH(REVERSE_L(UHH(L))) << 32) & 0xFFFFFFFF00000000) | (REVERSE_L( UHH(L) >> 32) & 0xFFFFFFFF ))
          
#ifndef NULL		/* 4devices */
#define NULL (void*)0
#endif

////// hart types ////////

typedef enum hartTriggerCodes_e /* Common Table 33 */
{
	htc_Continuous,	// 0 -published continuously at (worst case) the Minimum Update Period.
	htc_Window,	    // 1 - source value deviates more than the specified trigger value
	htc_Rising,     // 2 - source value Rises Above the specified trigger value
	htc_Falling,	// 3 - source value Falls Below the specified trigger value
	htc_On_Change	// 4 - any value in the message changes.
}
/*typedef*/hartTriggerCodes_t;

typedef enum hartBurstControlCodes_e /* Common Table 33 */
{
	hbcc_Disabled,		// 0 - Off
	hbcc_TokPass,		// 1 - Enable on Token Passing
	hbcc_TDMA,			// 2 - Enable on TDMA only
	hbcc_TDMAnTokPass,	// 3 - Enable on both TDMA & Token Passing
	hbcc_HART_IP		// 4 - Enable on HART-IP network
}
/*typedef*/hartBurstControlCodes_t;

#endif /* _DATATYPES_H */

