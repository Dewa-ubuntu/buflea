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


#include <assert.h>
#include <iostream>
#include <sstream>
#include <consts.h>
#include "main.h"
#include <strutils.h>
#include <sock.h>
#include <string>
#include "dnsthread.h"
#include "ctxthread.h"
#include "context.h"
#include "ctxqueue.h"
#include "listeners.h"
#include "minidb.h"
#include "configprx.h"

//-----------------------------------------------------------------------------
DnsHtps*    __dnsssl;

//-----------------------------------------------------------------------------
DnsHtps::DnsHtps(int records):_maxrecs(records)
{
    assert(__dnsssl==0);
    __dnsssl=this;
    /* load ssl guess file */
}

//-----------------------------------------------------------------------------
DnsHtps::~DnsHtps()
{
}

void    DnsHtps::queue_host(DnsCommon& dest)
{
    if(_clients.size() > (size_t)_maxrecs)
        do_cleanup();

    AutoLock __a(&_m);

    dest.now       = time(0);

    std::map<uint64_t, DnsCommon>   el;
    el[0] = dest;

    SADDR_46  ca(dest.client);   // htonl(dest.client));
    _clients[ca] = el;

#ifdef DEBUG
    for(auto client : _clients)
    {
        GLOGD("DNS_FORWARD: CLIENT:" << client.first.c_str());
        for(auto route : client.second)
        {
            GLOGD("ROUTE:" << route.first << " -> CLIIP:" << IP2STR(route.second.client) << ", domainip: "<< IP2STR(route.second.domainip) << ", " << route.second.hostname)
        }
    }


#endif
}

void    DnsHtps::update_host(const SADDR_46& ipcli, const uint64_t buff)
{
    AutoLock __a(&_m);

    auto  rec = _clients.find(ipcli);
    if(rec == _clients.end())
    {
        return;
    }
    auto entr = rec->second.find(buff);
    if(entr != rec->second.end())           //already have it, update it
    {
        entr->second.now=time(0);
        return;
    }
    entr = rec->second.find(0);
    rec->second[buff]=entr->second;

    GLOGX("storing host <- [" << IP2STR(entr->second.client) <<  "]="<< "("<<buff<<")" << entr->second.hostname << "] ");
}


bool    DnsHtps::deque_host(const SADDR_46& ipcli, const uint64_t sigbuff, DnsCommon& dest)
{
    const SADDR_46 key(ipcli);
    AutoLock __a(&_m);
    auto const& record = _clients.find(key);

    if(record == _clients.end())
    {
        GLOGD("Finding host in dns records: " << key.c_str() << " failed");
        return false;
    }
    auto const&  dns = record->second.find(sigbuff);
    if(dns != record->second.end())
    {
        dest = dns->second;
        GLOGX("getting ssh host -> [" << IP2STR(dest.client) <<  "]=" << dest.hostname << "] PRX");
        return true;
    }

    auto const&  dns2 = record->second.find(0);   //default one
    dest = dns2->second;
    GLOGX("getting ssh host -> [" << IP2STR(dest.client) <<  "]=" << dest.hostname << "] PRX");
    return true;
}




void DnsHtps::do_cleanup()
{
    if(_clients.size()==0)
        return;

    time_t now = time(0);
    AutoLock __a(&_m);

    auto  rec = _clients.begin();
    while(rec != _clients.end())
    {
        auto  ips = rec->second.begin();
        while(ips != rec->second.end())
        {
            if(now - ips->second.now >  (time_t)GCFG->_glb.dnsssltout)
            {
                rec->second.erase(ips++);
                continue;
            }
            ++ips;
        }
        if(rec->second.size()==0)
        {
            _clients.erase(rec++);
            continue;
        }
        ++rec;
    }
}






