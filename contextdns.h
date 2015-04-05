/**
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
*/

#ifndef CONTEXTD_H
#define CONTEXTD_H

#ifndef _PERSONAL

#include <list>
// SSL port connection
//-----------------------------------------------------------------------------
// SSL,  client connect here with gibrish...
// The dns masq should have already pated this proxy with the
// IP of the client and what domain name was asking the DNS.
// the contextD should have thet IP to know where to link the client
class CtxDns : public Ctx
{
public:
    CtxDns(const ConfPrx::Ports* pconf, tcp_xxx_sock& s);
    virtual ~CtxDns();
    void    send_exception(const char* desc);

protected:
    int     _s_send_reply(u_int8_t code, const char* info=0);
    bool    _new_request(const u_int8_t* buff, int sz);

slots
    CALLR  _create_ctx();
    CALLR   _r_is_connected();
    CALLR   _get_hostname();
    CALLR   _s_is_connected();
    CALLR   _io();

};


#endif //_PERSONAL

#endif // CONTEXTH_H
