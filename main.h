/**
# Copyright (C) 2012-2014 Chincisan Octavian-Marius(mariuschincisan@gmail.com) - coinscode.com - N/A
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
*/


#ifndef MAIN_H
#define MAIN_H

#include <dlfcn.h>
#include <os.h>

//-----------------------------------------------------------------------------
class Listeners;
class ThreadPool;
class DnsHtps;
extern bool        __alive;
extern int         __alivethrds;
//-----------------------------------------------------------------------------

struct Uid{
    Uid():_unicid(0){}
    u_int32_t _unicid;
};




#endif// MAIN_H
