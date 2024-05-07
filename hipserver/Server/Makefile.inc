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
# 
#**************************************************************************

#**********************************************************
#*
#* File Name:
#*   Makefile.inc
#* File Description:
#*   Include file for Makefile to build the tool hipserver.
#*
#**********************************************************

#include $(DIR_SRVR)/Makefile_macros.inc

# Header files with definitions that are used in multiple files for the tool
COMMON_HFILES = $(DIR_COMN)/common.h      \
                $(DIR_COMN)/datatypes.h   \
                $(DIR_COMN)/errval.h      \
                $(DIR_COMN)/hartdefs.h    \
                $(DIR_APPC)/tpdll.h       \
                $(DIR_APPC)/appmsg.h      \
                $(DIR_SRVR)/hssyslogger.h \
                debug.h                   \
                mutex2.h                  \
                tooldef.h


# List all HART-IP Server .c files (without extension)
# First list all .c files that have a corresponding .h file
# (1a)
HSRVR_CFILES = $(DIR_RLTM)/toolsems     \
               $(DIR_RLTM)/toolsigs     \
               $(DIR_RLTM)/toolthreads  \
               $(DIR_RLTM)/toolutils    \
               hssems                   \
               hssigs                   \
               hsthreads                \
               hsutils                  \
               factory_reset

# Then list all .c files that have no corresponding .h file
# (1b)
HSRVR_NOH_CFILES = main

# ===================================================

# List all HART-IP .cpp files here (without extension)
# First list all .cpp files that have a corresponding .h file
# (1c)
HSRVR_CPPFILES = $(DIR_APPC)/tppdu       \
                 $(DIR_RLTM)/toolqueues  \
                 hshostnamesystem        \
                 hssettings              \
                 hsauditlog              \
                 hsreadonlycommandsmanager \
                 hssecurityconfiguration \
                 hscommands              \
                 hscommandsmanager       \
                 hsconnectionmanager     \
                 hsqueues                \
                 hsrequest               \
                 hssubscribe             \
                 hshandlermessages       \
                 hsudp                   \
                 onetcpprocessor         \
                 tcpprocessor            \
                 threadex                \
                 hsnetworkmanager        \
                 hssyslogger             \
                 hssettingshandler
                 
# Then list all .cpp files that have no corresponding .h file
# (1d)
HSRVR_NOH_CPPFILES =

# ===================================================

# List all HART-IP .h files here (without extension)
# (2a + 2b + 2c)
HSRVR_ALL_HFILES = $(HSRVR_C_HFILES) $(HSRVR_CPP_HFILES)  \
                   $(HSRVR_NOC_HFILES)

# HSRVR_C_HFILES are .h files derived from the corresponding .c files
# (2a)
HSRVR_C_HFILES = $(HSRVR_CFILES:%=%.h)

# HSRVR_CPP_HFILES are .h files derived from the corresponding .cpp files
# (2b)
HSRVR_CPP_HFILES = $(HSRVR_CPPFILES:%=%.h)

# HSRVR_NOC_HFILES are .h files that have no corresponding .c/.cpp file
# (2c)
HSRVR_NOC_HFILES =

# ===================================================

# HART-IP Server Objects (1a + 1b + 1c + 1d)
HSRVR_OBJS = $(HSRVR_CFILES:%=%.o) $(HSRVR_NOH_CFILES:%=%.o)      \
             $(HSRVR_CPPFILES:%=%.o) $(HSRVR_NOH_CPPFILES:%=%.o)

