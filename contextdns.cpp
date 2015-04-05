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
#include "config.h"
#include "context.h"
#include <consts.h>
#include <matypes.h>
#include "threadpool.h"
#include "ctxthread.h"
#include "listeners.h"
#include "contextdns.h"
#include "dnsthread.h"



/*
        SSL connects HERE
*/

//-----------------------------------------------------------------------------
CtxDns::CtxDns(const ConfPrx::Ports* pconf, tcp_xxx_sock& s):
    Ctx(pconf, s)
{
    _tc= 'P';
    _mode=P_DNSSOCK; //dns ssh
}

//-----------------------------------------------------------------------------
CtxDns::~CtxDns()
{
    //dtor
}


CALLR  CtxDns::_create_ctx()
{
    _pcall=(PFCLL)&CtxDns::_s_is_connected;
    return _s_is_connected();
}



//-----------------------------------------------------------------------------
int  CtxDns::_s_send_reply(u_int8_t code, const char* info)
{
      _rec_some();
     return 1;
}

void  CtxDns::send_exception(const char* desc)
{
    //nothing
}


CALLR  CtxDns::_s_is_connected()
{
    if(0==_rec_some())
        return R_KILL;
    size_t  nfs = _hdr.bytes();
    if(nfs > 32)
    {
        _pcall = (PFCLL)&CtxDns::_get_hostname;
    }
    return R_CONTINUE;
}


CALLR  CtxDns::_get_hostname()
{
    DnsCommon dns;

    if(__dnsssl->deque_host(_cliip, _hdr.asll(), dns))
    {
        LOGT(" found  host from dns[" << IP2STR(_cliip) << "]<="<< dns.hostname);
        if(dns.domainip==0)
        {
             _raddr = __db->dnsgetip(dns.hostname);
        }
        else
        {
            _raddr = SADDR_46(dns.domainip);
        }
        _raddr.set_port(_pconf->conport ? _pconf->conport : 80);
        _set_rhost(_raddr);
        LOGD(_cliip.c_str() << " --r/dns--> "<< _raddr.c_str() );
        return _host_connect(_r_socket);
    }
    else if(!_pconf->redirect.empty())
    {    //fallback
        _set_rhost(_pconf->toaddr, 0, 0);
        LOGD(_cliip.c_str() << " --r/cfg--> "<< _raddr.c_str() );
        return _host_connect(_r_socket);
    }
    LOGE("No destination host found in queued hosts, neither in configuration. Connection closed");
    return R_KILL;
}

CALLR  CtxDns::_r_is_connected()
{
    __dnsssl->update_host(_cliip, _hdr.asll()); //add a record by first 64 bytes of the request

//    _hdr.parse();
//    _hdr.replace_option(_hdr._nhost,_hdr._nhost_end,"enjoydecor.com");
    GLOGD("C--X-->H\n["<<_hdr.buf() << "]\n");

    if(_r_socket.sendall((const u_int8_t*)_hdr.buf(), _hdr.bytes(), SS_TOUT)!=0)
    {
        return R_KILL;
    }
    _clear_header();
    _pcall=(PFCLL)&CtxDns::_io;
    return R_CONTINUE;
}

bool CtxDns::_new_request(const u_int8_t* buff, int bytes)
{
    _clear_header();
    _hdr.append((const char*)buff, bytes);
    _pcall = (PFCLL)&CtxDns::_get_hostname;
	return true;
}


CALLR   CtxDns::_io()
{
    return Ctx::_io();
}
