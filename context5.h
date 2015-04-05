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


#ifndef CONTEXT5_H
#define CONTEXT5_H

#include "context.h"
//-----------------------------------------------------------------------------
// socks 5
class Ctx5 : public Ctx
{
public:
    Ctx5(const ConfPrx::Ports* pconf, tcp_xxx_sock& s);
    virtual ~Ctx5();
    virtual void    send_exception(const char* desc);
protected:

    int  _s_send_reply(u_int8_t code, const char* info=0);
    bool _new_request(const u_int8_t* buff, int sz);

slots
    CALLR  _create_ctx();
    CALLR  _negociate_header();
    CALLR  _r_is_connected();
    CALLR  _s_is_connected();
};

#endif // CONTEXT5_H
