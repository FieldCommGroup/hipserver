#**************************************************************************
# Copyright 2019-2024 FieldComm Group, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#**************************************************************************

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
DIR_SAFE = $(DIR_HSRVR)/safestringlib
# subdir DIR_SRVR ($(DIR_HSRVR)/Server) is already defined at top

# Leave RHS blank if no subdirs to be built
SUBDIRS_HSRVR = $(DIR_APPC) $(DIR_COMN) $(DIR_RLTM) $(DIR_SRVR) $(DIR_SAFE)
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
	cd ../safestringlib && $(MAKE)
	cd ..
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
	cd ../safestringlib && $(MAKE) clean
	cd ..
		
.PHONY: cleanall
cleanall:
	@$(MAKE) -s clean
	$(ECHO)

# This is used by HTS Apps (VG)
.PHONY: cleanallbutsafestrlib
cleanallbutsafestrlib:
	@mv -f $(DIR_SAFE)/libsafestring.a   .  >  /dev/null 2>&1
	@$(MAKE) -s clean
	@mv -f libsafestring.a  $(DIR_SAFE)     >  /dev/null 2>&1
	$(ECHO)

.PHONY: test_basic
test_basic: $(COMMON_OBJS)
	$(ECHO)
	cd ../safestringlib && $(MAKE)
	cd ..
	$(ECHO)
	$(ECHO) Building $(EXEC_TOP)
	$(ECHO)
	$(LD) $(CFLAGS) -DTestBasic -o $(EXEC_NAME).TestBasic $(OBJS_ALL) $(INCL_LIBS)
	$(ECHO)
