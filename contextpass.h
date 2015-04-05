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


#ifndef CtxTranspAll_H
#define CtxTranspAll_H


//-----------------------------------------------------------------------------
// port forwarding, transparent Host overwritter
class CtxPasstru : public Ctx
{
public:
    CtxPasstru(const ConfPrx::Ports* pconf, tcp_xxx_sock& s);
    virtual ~CtxPasstru();


    virtual void    send_exception(const char* desc){};
    virtual bool _new_request(const u_int8_t* buff, int bytes){return true;};

protected:

slots
    CALLR  _s_is_connected();
    CALLR  _r_is_connected();
    CALLR  _io();
    CALLR  _create_ctx();

private:
    CALLR _overwrite_hosts(const char* =0);
};

#endif // #ifndef




