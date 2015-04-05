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

#ifndef DNSTHREASD_H
#define DNSTHREASD_H

#include <sstream>
#include <set>
#include <os.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <map>
#include <list>
#include <algorithm>
#include <matypes.h>
#include "tinyclasses.h"
#include "ctxqueue.h"
#include "minidb.h"


//-----------------------------------------------------------------------------
// ssh dns reeived from dns database
class DnsHtps
{
public:

    DnsHtps(int);
    virtual ~DnsHtps();

    bool    deque_host(const SADDR_46& ipcli, const uint64_t sigbuff, DnsCommon& dest);
    void    queue_host(DnsCommon& dest);
    void    update_host(const SADDR_46& ipcli, const uint64_t sig);

private:
    void    do_cleanup();
private:

    //       addr         request-guess   Dns IP's
    std::map<SADDR_46, std::map<uint64_t, DnsCommon> >  _clients;
    mutex                                               _m;
    int                                                 _maxrecs;
};

extern DnsHtps*    __dnsssl;

#endif //
