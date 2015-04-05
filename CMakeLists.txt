
#/**
# Copyright (C) 2012-2014 Chincisan Octavian-Marius(udfjj39546284@gmail.com) - coinscode.com - N/A
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#*/

###############################################################################################
##  this header in CMakeLists.tx is mandatory in every project from HERE { << find closing pair
###############################################################################################
cmake_minimum_required(VERSION 2.6)

################################################################################################
# To HERE                                                                   }
################################################################################################
PROJECT(BUFLEA)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

set(CMAKE_CXX_FLAGS "-std=c++0x -Wall -fexceptions -fpermissive -D__USE_MISC")


ADD_EXECUTABLE(buflea configprx.cpp
                    context.cpp
                    context4.cpp
                    context5.cpp
                    contexthttp.cpp
                    contextdns.cpp
                    contextctl.cpp
                    contextpass.cpp
                    contextreg.cpp
                    ctxqueue.cpp
                    ctxthread.cpp
                    dnsthread.cpp
                    listeners.cpp
                    main.cpp
                    tcppipe.cpp
                    threadpool.cpp
                    tinyclasses.cpp
                    httphdr.cpp
                    tasker.cpp
                    ../mcoinclude/sslcrypt.cpp
                    ../mcoinclude/config.cpp
                    ../mcoinclude/minidb.cpp )

include_directories (../mcosocks ../mcoinclude ../dnsprx_common)
link_directories(../lib/)

TARGET_LINK_LIBRARIES(buflea pthread dl ${CMAKE_CURRENT_LIST_DIR}/../lib/libmcosock.a)

SET(EXECUTABLE_OUTPUT_PATH ../bin)
