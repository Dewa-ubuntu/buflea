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


#ifndef CONTEXTH_H
#define CONTEXTH_H


#include <list>
//-----------------------------------------------------------------------------
// http proxy HTTP protocol, Allows open or allows plain redirected HTTP header
//-----------------------------------------------------------------------------

class CtxHttp : public Ctx
{
public:
    CtxHttp(const ConfPrx::Ports* pconf, tcp_xxx_sock& s);
    virtual ~CtxHttp();
protected:
    int     _s_send_reply(u_int8_t code, const char* info=0);
    bool    _new_request(const u_int8_t* buff, int sz);
    virtual void send_exception(const char* desc);
    int     _get_hdr();
    int     _connect_to_host();

slots
    CALLR  _create_ctx();
    CALLR   _s_is_connected();
    CALLR  _empty_host();
    CALLR  _r_is_connected();
    CALLR  _sr_http_read_write();
    CALLR  _get_from_host();
    CALLR  _overwrite_connection(const SADDR_46& ap);
    CALLR  _io();
private:
    SADDR_46 _rip;
    bool     _hdr_has_open;
    int      _tflush;
    int      _loops;
    string   _curhost;
};

#endif // #ifndef _PERSONAL
