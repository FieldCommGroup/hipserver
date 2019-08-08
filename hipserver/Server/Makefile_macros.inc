#********************************************************************
#* Copyright (C) 2015-2017 FieldComm Group
#*
#* All Rights Reserved.
#* This software is CONFIDENTIAL and PROPRIETARY INFORMATION of
#* FieldComm Group, Austin, Texas USA, and may not be used either
#* directly or by reference without permission of FieldComm Group.
#*
#* THIS SOFTWARE FILE AND ITS CONTENTS ARE PROVIDED AS IS WITHOUT
#* WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING
#* WITHOUT LIMITATION, WARRANTIES OF MERCHANTABILITY, FITNESS FOR
#* A PARTICULAR PURPOSE AND BEING FREE OF DEFECT.
#*
#********************************************************************

#**********************************************************
#*
#* File Name:
#*   Makefile_macros.inc
#* File Description:
#*   Include file for basic macros used in the Makefile.
#*
#**********************************************************


CC        = g++ -c
CXX        = g++ -c
CFLAGS     = -g -DLINUX -I. -I../Common  -I../Realtime  -I../AppConnect
CXXFLAGS   = -g -DLINUX -I. -I../Common  -I../Realtime  -I../AppConnect
ECHO       = @echo
INCL_LIBS  = -lpthread -lrt
LD         = g++
RM         = @rm

