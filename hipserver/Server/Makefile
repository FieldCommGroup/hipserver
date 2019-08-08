#********************************************************************
#* Copyright (C) 2015-2018 FieldComm Group
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
#*   Makefile
#* File Description:
#*   Makefile for HART-IP Server
#*
#**********************************************************

SHELL=/bin/bash

DIR_SRVR  = $(shell pwd)
DIR_HSRVR = $(shell cd ..; pwd)

# DIR_HSRVR (parent) Subdirectories
DIR_APPC = $(DIR_HSRVR)/AppConnect
DIR_COMN = $(DIR_HSRVR)/Common
DIR_RLTM = $(DIR_HSRVR)/Realtime
# subdir DIR_SRVR is already defined at top

# Leave RHS blank if no subdirs to be built
SUBDIRS_HSRVR = $(DIR_APPC) $(DIR_COMN) $(DIR_RLTM) $(DIR_SRVR)
hsrvr_children = 

# include the various Makefile.inc files in the directory
# tree (DIR_SRVR must be defined before the inclusion).
include Makefile_macros.inc
include Makefile.inc

# Misc. definitions (leave RHS blank if no sub-*)
COMMON_OBJS  = $(TOP_OBJS) $(COMMON_HFILES)
OBJS_ALL     = $(COMMON_OBJS)
TOP_OBJS     = $(HSRVR_OBJS)

#SUBEXECS_TOP = $(SUBEXEC_HS)

# Build everything using all subdirs/subtools
EXEC_NAME = hipserver
EXEC_TOP  = all

$(EXEC_TOP): $(COMMON_OBJS)
	$(ECHO)
	$(ECHO) Building $(EXEC_TOP)
	$(ECHO)
	$(LD) $(CFLAGS) -o $(EXEC_NAME) $(OBJS_ALL) $(INCL_LIBS)
	$(ECHO)

# ===============================================================

.PHONY: clean
clean:
	$(ECHO)
	$(RM) -f $(EXEC_NAME)      >  /dev/null 2>&1
	$(RM) -f *.gch             >  /dev/null 2>&1
	$(RM) -f *.o               >  /dev/null 2>&1
	@-for d in $(SUBDIRS_HSRVR); do ( echo Cleaning $$d; cd $$d; rm -f *.o; echo ); done
		
.PHONY: cleanall
cleanall:
	@$(MAKE) -s clean
	$(ECHO)

