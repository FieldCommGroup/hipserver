#*************************************************************************************************
# Copyright 2020 FieldComm Group, Inc.
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
CFLAGS     = -g -DLINUX -I. -I../Common  -I../Realtime  -I../AppConnect  -I../safestringlib/include
CXXFLAGS   = -g -DLINUX -I. -I../Common  -I../Realtime  -I../AppConnect  -I../safestringlib/include
ECHO       = @echo
INCL_LIBS  = -lpthread -lrt   ../safestringlib/libsafestring.a
LD         = g++
RM         = @rm

