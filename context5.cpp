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
#include <errorstrings.h>
#include "main.h"
#include "config.h"
#include "context.h"
#include <consts.h>
#include "threadpool.h"
#include "ctxthread.h"
#include "listeners.h"
#include "context5.h"


/*
    SOCKS 5 PROXY PROTOCOL
*/


//----------------------------------------------------------------------------
Ctx5::Ctx5(const ConfPrx::Ports* pconf, tcp_xxx_sock& s):
    Ctx(pconf, s)
{
    _tc= '5';
    _mode= P_SOCKS5;
}

//----------------------------------------------------------------------------
Ctx5::~Ctx5()
{
    //dtor
}

CALLR  Ctx5::_create_ctx()
{
    _pcall=(PFCLL)&Ctx5::_s_is_connected;
    return Ctx5::_s_is_connected();
}

//-----------------------------------------------------------------------------
/*
    [5][X][options]-------------->
                   <-----------------[5][option]

*/
CALLR  Ctx5::_s_is_connected()
{
    _rec_some();

    size_t  nfs = _hdr.bytes();

    if(nfs < 3)
    {
        return R_CONTINUE;
    }

    const u_int8_t* pbuff = (const u_int8_t*)_hdr.buf();

    if(pbuff[0] != 0x5)
    {
        _s_send_reply(PROTOMISMATCH,"no 5 protocol");
        throw Mex(INVALID_5_HEADER,__FILE__,__LINE__);
    }

    if(nfs < ((size_t)pbuff[1] + (size_t)2))
    {
        return R_CONTINUE;
    }

    u_int8_t response[2]= {5, 0xFF};
    const u_int8_t nmeths = pbuff[1];

    for(u_int8_t methods = 0; methods < nmeths; ++methods)
    {
        switch(pbuff[methods+2] & 0xFF)
        {
        case  NOAUTH: //we support only these
            response[1] = NOAUTH;
            goto done;
            break;
        default:
            response[1]=NOMETHS;
            break;
        }
    }
done:
    if(_c_socket.sendall(response, 2, SS_TOUT)!=0)
    {
        _destroy_clis();
        throw Mex(CLIENT_CLOSED,__FILE__,__LINE__);
    }

    if(response[1] == NOMETHS)
    {
        throw Mex(NO_5_KNOWNMETHODS,__FILE__,__LINE__);
    }
    //
    // we accepted option
    //

//// mco-latest
    _hdr.clear();
    _pcall=(PFCLL)&Ctx5::_negociate_header;
    return R_CONTINUE;
}

//-----------------------------------------------------------------------------
/*
    [5][1][0][IP....][PORT]--------------->
     connecting...
    <---------------------[5][CODE][][IP...][PORT]
*/
CALLR  Ctx5::_negociate_header()
{
    _rec_some();
    size_t  nfs = _hdr.bytes();
    const u_int8_t* pbuff = (const u_int8_t*)_hdr.buf();

    if(nfs < 10)
    {
        return R_CONTINUE;
    }
    const u_int8_t   expected[]= {0x5,SCONNECT,0x0};
    if(memcmp(pbuff, expected, 3))
    {
        _s_send_reply(INVALIDCMD);
        throw Mex(INVALID_5_COMMAND,__FILE__,__LINE__);    //ver, cmd, rsv
    }

    switch(pbuff[3])
    {
    case DN_IPV4:
    {
        _raddr.set(htonl(*((u_int32_t*)&pbuff[4])), htons(*((u_int16_t*)&pbuff[8])));
    }
    break;
    case DN_DNAME:
    {
        size_t len = pbuff[4];
        if((size_t)nfs < len + 7)
        {
            return R_CONTINUE; // receive more
        }
        char sip[256] = {0};
        strncpy(sip, (const char*) &pbuff[5], len);
        SADDR_46 rsin = __db->dnsgetip(sip);
        _raddr.set(htonl(rsin.ip4()), htons(*((u_int16_t*)&pbuff[4+len+1])));
    }
    break;
    case DN_IPV6:
    default:
        _s_send_reply(BADADDRESS,"ipv6 not implemeted");
        throw Mex(NOT_5_IMPLEMENTEDIPV6,__FILE__,__LINE__);
        break;
    }
    if(_is_access_blocked(_raddr,0,0))
    {
        return R_CONTINUE;
    }

    LOGH("o -> [SOCKS-5]: Open-IP: "<<_raddr.c_str());
    _set_rhost(_raddr);

    return _host_connect(_r_socket);
}

//-----------------------------------------------------------------------------
int  Ctx5::_s_send_reply(u_int8_t code, const char* info)
{
    static const u_int8_t errors[]= {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    SADDR_46 ap;

    Ctx::_s_send_reply( code, info);

    SADDR_46 ip4 =  _r_socket.getsocketaddr();
    u_int16_t np =  _r_socket.getsocketport();

    const struct
    {
        u_int8_t ver;
        u_int8_t cmd;
        u_int8_t rsv;
        u_int8_t ayt;
        u_int32_t ip;
        u_int16_t port;
    } __attribute__((packed)) response =
    {0x5, errors[code], 0, DN_IPV4, ip4.ip4(), np};

    LOGH("o <- [SOCKS-5]:" << socks_err(code));
    _c_socket.sendall((const u_int8_t*)&response, sizeof(response), SS_TOUT);
    return 1;
}

//-----------------------------------------------------------------------------
CALLR  Ctx5::_r_is_connected()
{
    _s_send_reply(SUCCESS);
    return Ctx::_r_is_connected();
}

void  Ctx5::send_exception(const char* desc)
{
}


bool Ctx5::_new_request(const u_int8_t* buff, int bytes)
{
    if(buff[0] == 5)
    {
        _clear_header();
        _hdr.append((const char*)buff, bytes);
        _pcall = (PFCLL)&Ctx5::_s_is_connected;
        return true;
    }
    return false;
}


