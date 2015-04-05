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


#ifndef _PERSONAL

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
#include "contextctl.h"
#include "dnsthread.h"
#include "tasker.h"


/*
    PRIVATE SERVER AUTH PROTOCOL
*/

/*
    PHP authentication page comes on this request
*/
//-----------------------------------------------------------------------------
CtxCtl::CtxCtl(const ConfPrx::Ports* pconf, tcp_xxx_sock& s):Ctx(pconf, s)
{
    _tc= 'A';
    _mode=P_CONTORL; //dns ssh
    LOGI("ACL connect from:" << IP2STR(_cliip));
}


CALLR  CtxCtl::_create_ctx()
{
    _pcall=(PFCLL)&CtxCtl::_s_is_connected;
    return CtxCtl::_s_is_connected();
}


//-----------------------------------------------------------------------------
CtxCtl::~CtxCtl()
{
    //dtor
}

void CtxCtl::send_exception(const char* desc)
{

}

int CtxCtl::_s_send_reply(u_int8_t code, const char* info)
{
    Ctx::_s_send_reply( code, info);
    return 0;
};

int  CtxCtl::_close()
{
    destroy();
    return 0;
}

CALLR  CtxCtl::_s_is_connected()
{
    _rec_some();
    size_t  nfs = _hdr.bytes();
    if(nfs > 5) //&& lr==0/*have bytes and remove closed*/)
    {
        if(!_postprocess())
        {
            return R_KILL;
        }
    }
    _hdr.clear();
    return R_CONTINUE;
}

bool  CtxCtl::_postprocess()
{
    std::string  response="N/A";
    char* pb = (char*)_hdr.buf();
    int bytes = _hdr.bytes();
    std::string hostname ="localhost";

    if(pb[0])
    {
        _hdr.parse();
        hostname = _hdr.get_host();

        response="OK";
        GLOGI("--> ACL " << pb );


        char fc=pb[0];
        if(!::strncmp(pb,"GET",3))
        {
            if(::strncmp(pb,"GET / ", 6))
            {
                pb+=5;
                fc=*pb;
            }
        }
        char* eofl = strchr(pb,' ');
        if(eofl)*eofl=0;

REEVAL:
        switch(fc)
        {
        case '#':
            if(bytes>2 && pb[1]==',')
            {
                pb+=2;
                fc=pb[0];
                goto REEVAL;
            }
            return true;
            break;
        case 'R':
            __db->reload();
            break;
        case 'B':
        case 'b':
        case 'A':
        case 'a':
        case 'H':
        case 'h':
        case 'S':
        case 's':
            __task->schedule(tasker::eREDNS_REDIRECTS,"");
            __db->instertto(string(pb));
            break;
        case 'D': // Raw SEND   <__packed__ DnsCommon>
            {
                // dns server sends the IP that was obtained durring DNS request
                // we hold this in association with the IP that asked for that IP
                DnsCommon* pc = reinterpret_cast<DnsCommon*>(pb);

                SADDR_46 sad(pc->client);
                SADDR_46 dad(pc->domainip);

                GLOGI("DNS for client:" << sad.c_str()<<"/"<<pc->client << " [ to connect to-> ] "  << dad.c_str() <<
                ", " << pc->hostname <<
                " = " << pc->sizee << "\n");
                if(dad.c_str()[0]!='0')
					__dnsssl->queue_host(*pc);
				else
				{
					GLOGW("Invalid redirecting address");
				}

/*

                // add to session as well.
                std::string ip("S");


                GLOGI("DNS for client:" << sad.c_str()<<"/"<<pc->client << " [ to connect to ] "  << dad.c_str() << " = " << pc->sizee);
                ip+=sad.c_str();
                __db->instertto(ip);
*/
                response="OK";
            }
            return true;
        case '?': // Raw SEND    U.x.y.z:PPP
        {
            const SADDR_46* pad = reinterpret_cast<const SADDR_46*>(pb+1);
            if(__db->is_client_allowed(*pad))
            {
                response="OK";
            }
            else
            {
                response = "NO";
            }
        }
        break;
        case 'T': // '/Tx.y.z.k.ppp' addr of next proxy. dynamically chnage the next proxy ip and port
            {
                std::string ip = pb+1;
                if(ip.find(".")!=string::npos && ip.find(":")!=string::npos && ip.find(",")!=string::npos)
                {
                    uint32_t port = ::atoi(ip.substr(0,ip.find(",")).c_str());
                    std::string newip    = ip.substr(ip.find(",")+1);

                    for(auto & it : GCFG->_listeners)
                    {
                        ConfPrx::Ports& p = (ConfPrx::Ports&)it;

                        if(p.toaddr.port()==port) //was set
                        {
                            p.redirect = ip;
                            p.toaddr = fromstringip(ip);
                            response="OK";
                            break;
                        }
                    }
                }
                if(response!="OK")
                    response="FAIL";
            }
            break;
        case 'L': //help
            response += "<pre><\n><b>Options:</b>\n";
            response+= "A/a:IP  Adds/removes IP to current 3 hour session\n";
            response+= "B/b:IP  Adds/removes user to banned\n";
            response+= "S/s:IP  Adds/reomoves user from subscribers \n";
            response+= "R       Reloads acl files \n";
            response+= "L       Help \n";
            response+= "H/h:hIP Adds/removes host to host list (deny/access) by settings\n";
            response+= "T:CFG_PORT,REDIR_IP:PORT\n  Replaces configured forwarder listener port wit this forward IP.";
            response+= "?:IP\n Checks if ip is allowed\n</pre>";
            break;
        default:
            break;
        }
    }

    __tp->dump_metrics(_c_socket, hostname);
    _c_socket.send(( char*)response.c_str(),response.length());
    _clear_header();
    return false;
}


bool CtxCtl::_new_request(const u_int8_t* buff, int bytes)
{
    return false;
}

#endif // #ifdef _PERSONAL
