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
#*   Makefile_macros.inc
#* File Description:
#*   Include file for basic macros used in the Makefile.
#*
#**********************************************************

CRYPTO_LIB_SWITCH =
CRYPTO_FLAGS = 
CRYPTO_INCL = 

ifeq ($(CRYPTO_LIB_SWITCH), openssl)
CRYPTO_FLAGS = -DOPEN_SSL_SUPPORT
CRYPTO_INCL = -lssl -lcrypto
endif


CC         = g++ -c -std=c++11
CXX        = g++ -c -std=c++11
CFLAGS     = -g -DLINUX -DHTS $(CRYPTO_FLAGS) -I. -I../Common  -I../Realtime  -I../AppConnect  -I../safestringlib/include
CXXFLAGS   = -g -DLINUX -DHTS $(CRYPTO_FLAGS) -I. -I../Common  -I../Realtime  -I../AppConnect  -I../safestringlib/include
ECHO       = @echo
INCL_LIBS  = -L/usr/lib $(CRYPTO_INCL) -lpthread -lrt -lssl -lcrypto -ljsoncpp  ../safestringlib/libsafestring.a
LD         = g++
RM         = @rm

