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

#ifndef CONTEXTA_H
#define CONTEXTA_H

#ifndef _PERSONAL

#include <string>
//-----------------------------------------------------------------------------
// ACL receives ACL from ph sign on page
// DNS coming from DNS Our DNS server

class CtxCtl : public Ctx
{
public:
    CtxCtl(const ConfPrx::Ports* pconf, tcp_xxx_sock& s);
    virtual ~CtxCtl();
protected:
    void  send_exception(const char* desc);
    int   _s_send_reply(u_int8_t code, const char* info=0);

    int  _close();
    bool  _postprocess();
    bool _new_request(const u_int8_t* buff, int sz);

slots
    CALLR  _s_is_connected();
    CALLR  _create_ctx();
private:

};


#endif //#ifndef _PERSONAL

#endif // CONTEXTA_H
