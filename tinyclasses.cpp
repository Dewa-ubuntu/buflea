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


#include <sock.h>
#include <strutils.h>
#include "configprx.h"
#include "tinyclasses.h"


//-----------------------------------------------------------------------------
bool bind_udp_socket(udp_sock& s_side, std::string& inaddr)
{
    std::string     addr = inaddr.substr(4);//udp:*:IP  or tcp:
    size_t          pport = addr.find(':');

    if(pport == string::npos)
    {
        printf("no port on udp port for \n");
        return false;
    }
    char ifaddr[32];
    ::strcpy(ifaddr, addr.substr(0,pport).c_str());
    int nport = ::atoi(addr.substr(pport+1).c_str());


    if(s_side.create(nport, IPPROTO_UDP, ifaddr[0]=='*' ? 0 : ifaddr) < 0)
    {
        printf("cannot create udp port \n");
        return false;
    }
    if(s_side.bind() < 0)
    {
        printf("cannot bind udp port \n");
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------
bool bind_listener_socket(tcp_srv_sock& s_side, std::string& inaddr)
{
    std::string     addr = inaddr.substr(4);//udp:
    size_t          pport = addr.find(':');

    if(pport == string::npos)
    {
        return false;
    }

    char ifaddr[32];
    int nport = ::atoi(addr.substr(pport+1).c_str());

    ::strcpy(ifaddr, addr.substr(0,pport).c_str());
    if(s_side.create(nport, 0, ifaddr[0]=='*' ? (const char*)0 : ifaddr) < 0)
        return false;
    if(s_side.listen(32)==-1)
        return false;
    s_side.set_blocking(0);
    return true;
}

//-----------------------------------------------------------------------------
bool   rec_some(udp_sock& s_side, fd_set& r, char* outb, size_t maxb, SADDR_46& sin)
{
    int      bytes = 0;
    timeval  tv = {0, 0xFFF};
    int      s =  s_side.socket();

    FD_SET(s, &r);
    if(select(s+1, &r, 0, 0, &tv) > 0 && FD_ISSET(s, &r))
    {
        ::memset(&sin,0,sizeof(sin));
        bytes=s_side.receive(outb, maxb, sin);
        if(bytes > 0 )
        {
            outb[bytes] = 0;
        }
    }
    FD_ZERO(&r);
    return bytes > 0;
}


