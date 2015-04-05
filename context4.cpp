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
#include <sock.h>
#include <strutils.h>
#include "main.h"
#include "configprx.h"
#include "context.h"
#include <consts.h>
#include "threadpool.h"
#include "ctxthread.h"
#include "listeners.h"
#include "context4.h"


/*
    SOCKS 4 PROXY PROTOCOL
*/

//----------------------------------------------------------------------------
Ctx4::Ctx4(const ConfPrx::Ports* pconf, tcp_xxx_sock& s):
    Ctx(pconf, s)
{
    _tc= '4';
    _mode= P_SOCKS4;
}

//----------------------------------------------------------------------------
Ctx4::~Ctx4()
{
    //dtor
}

CALLR  Ctx4::_create_ctx()
{
    _pcall=(PFCLL)&Ctx4::_s_is_connected;
    return _s_is_connected();
}

//-----------------------------------------------------------------------------
/*
    [4][1][port,2][ip,4]------------>[PRX]
                        <------------[4][CODE][port,1][ip,4]
    dont support bind for FTP
*/
CALLR  Ctx4::_s_is_connected()
{
    _rec_some();
    size_t  nfs  = _hdr.bytes();

    if(nfs < 8)
    {
        return R_CONTINUE; //need more
    }
    const   u_int8_t*  pbuff = _hdr.buf();

    if(nfs < 8)
    {
        if(nfs<=3)
        {
            if(pbuff[0] != 4)
            {
                _s_send_reply(GENFAILURE, "bytes count bismatch");
            }
            throw Mex(INVALID_4_HEADER,__FILE__,__LINE__);    //should be 1
        }
        return R_CONTINUE;
    }
    if(pbuff[1] != 1 || pbuff[0] != 4) // socks4 negociation
    {
        _s_send_reply(GENFAILURE);
        throw Mex(INVALID_4_HEADER,__FILE__,__LINE__);    //should be 1
    }

    _raddr.set(htonl(*((long*)&pbuff[4])), htons(*((short*)&pbuff[2])));
    LOGH("o -> [SOCKS-4]: Open-IP: "<<_raddr.c_str());

    if(_is_access_blocked(_raddr,0,0))
    {
        return R_CONTINUE;
    }
    _set_rhost(_raddr);
    return _host_connect(_r_socket);
}

//-----------------------------------------------------------------------------
int  Ctx4::_s_send_reply(u_int8_t code, const char* info)
{

    static const u_int8_t errors[]= {
                                     90,   91,   92,   93,   92,
                                     92,   92,   91,   91,   91
                                    };

    Ctx::_s_send_reply( code, info);
    SADDR_46 ip4 =  _r_socket.getsocketaddr();
    u_int16_t np =  _r_socket.getsocketport();
    const struct
    {
        unsigned char vn;
        unsigned char cd;
        u_int16_t port;
        u_int32_t ip;
    } __attribute__((packed)) response =
    {
        0,errors[code],np, ip4.ip4()
    };
    LOGH("o <- [SOCKS-4]:" << socks_err(code));
    _c_socket.sendall((const u_int8_t*)&response, sizeof(response), SS_TOUT);
    return 1;
}

void  Ctx4::send_exception(const char* desc)
{

}

//-----------------------------------------------------------------------------
CALLR  Ctx4::_r_is_connected()
{
    _s_send_reply(SUCCESS);
    _clear_header();
    return Ctx::_r_is_connected();
}

bool Ctx4::_new_request(const u_int8_t* buff, int sz)
{
	if(buff[1] == 1 && buff[0] == 4)
	{
		_hdr.clear();
		_hdr.append((const char*)buff, sz);
		_pcall = (PFCLL)&Ctx4::_s_is_connected;
		return true;
	}
	return false;
}


