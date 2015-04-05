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
#include <stdarg.h>
#include <limits.h>
#include <strutils.h>
#include "configprx.h"

//-----------------------------------------------------------------------------
#define BIND(mem_,name_)     _bind(lpred, #name_,  mem_.name_, val);



//-----------------------------------------------------------------------------
extern const char HTTP_200[];
extern const char HTTP_400[];
//-----------------------------------------------------------------------------




ConfPrx* GCFG;


ConfPrx::ConfPrx(const char* fname)
{
    GCFG = this;
    load(fname);
}

ConfPrx::~ConfPrx()
{
    GCFG = 0;
}


SADDR_46  fromstringip(const std::string& s)
{

    string tmp = s;
    int    nport = 80;
    if(tmp.find("http://") == 0)
        tmp = s.substr(7);
    else if(tmp.find("https://") == 0)
    {
        tmp = s.substr(8);
        nport = 443;
    }

    size_t port = tmp.find(':');
    size_t doc = tmp.find('/');
    if(port!=string::npos)
    {
        nport = ::atoi(tmp.substr(port+1, doc).c_str());
    }
    else if(doc!=string::npos)
    {
        port = doc;
    }

    char phost[256];

    ::strcpy(phost, tmp.substr(0,port).c_str());
    if(isdigit(phost[0]))
        return SADDR_46(phost,nport);
    char test[32];
    SADDR_46 r = sock::dnsgetip(phost, test, nport);
    std::cout<<phost <<"="<<r.c_str() << " / " << test << "\r\n";
    return r;
}

//-----------------------------------------------------------------------------
void ConfPrx::_assign( const char* pred, const char* val, int line)
{
    char    lpred[256];
    char    loco[256];



    ::strcpy(loco,val);
    ::strcpy(lpred,pred);
    try
    {
        if(_section.substr(1,::strlen(__VERSION)) == __VERSION)
        {
            BIND(_glb,runfrom);
            BIND(_glb,slog);
            BIND(_glb,nlogbytes);
            BIND(_glb,sessiontime);
            BIND(_glb,dnsssltout);
            BIND(_glb,bouncemax);
            BIND(_glb,authurl);
            BIND(_glb,usercontrol);
            BIND(_glb,reloadacls);
            BIND(_glb, hostsfile);
            BIND(_glb, hostsfilerule);
            BIND(_glb, openacl);  //overwrites the non openacl ports.
            BIND(_glb, admins);
            BIND(_glb, maxrecs);
            BIND(_glb, domrecs);
            BIND(_glb, banned_ips);
            BIND(_glb, tickfile)
            BIND(_glb, jumpip);
            BIND(_glb, subscribers);

            if(lpred[0]=='}')
            {

                if(!_glb.signature.empty())
                {
                    fix_path(_glb.signature);
//                    _glb.signaturegz=_glb.signature.append(".gz");
                    std::ifstream t(_glb.signature);
                    std::stringstream buffer;

                    buffer << t.rdbuf();
                    _glb.signature = buffer.str();
                    t.close();
                }
                _glb.blog=0;
                if(_glb.slog=="A")
                {
                    _glb.blog=0xFFFFFFFF;
                }
                else
                {
                    _glb.blog |= _glb.slog.find('I') == string::npos ? 0 : 0x1;
                    _glb.blog |= _glb.slog.find('W') == string::npos ? 0 : 0x2;
                    _glb.blog |= _glb.slog.find('E') == string::npos ? 0 : 0x4;
                    _glb.blog |= _glb.slog.find('T') == string::npos ? 0 : 0x8;
                    _glb.blog |= _glb.slog.find('D') == string::npos ? 0 : 0x10;
                    _glb.blog |= _glb.slog.find('X') == string::npos ? 0 : 0x20;
                    _glb.blog |= _glb.slog.find('H') == string::npos ? 0 : 0x40;
                }
                _blog = _glb.blog;

                for(auto & f : _glb.jumpip)
                {
                    const SADDR_46& k=(f).first;
                    SADDR_46& v=(f).second;
                    GLOGI("Jump: " << IP2STR(k) <<" -> " << IP2STR(v) );
                }
                _glb.sessiontime *= 60;
                _glb.dnsssltout *= 60;

                if(!_glb.authurl.empty())
                    _glb.authurl_ip = fromstringip(_glb.authurl );
                else
                    _glb.authurl_ip = fromstringip("127.0.0.1:80");

                if(!_glb.tickfile.empty())
                {
                    FILE* pf = fopen(_glb.tickfile.c_str(),"wb");
                    if(pf)
                    {
                        ::fputs("#",pf);
                        ::fclose(pf);
                    }
                }

            } // eo section
        }
        if(_section == "[port]")
        {
            BIND(_ports,pending);
            BIND(_ports,bindaddr);
            BIND(_ports,port);
            BIND(_ports,blocking);
            BIND(_ports,socks);
            BIND(_ports,clientisssl);
            BIND(_ports,hostisssl);
            BIND(_ports, openacl);
            BIND(_ports, authtoken);

            BIND(_ports, redirect);
            BIND(_ports, conport);

            if(lpred[0]=='}')
            {
                if(_ports.openacl==-1)               // open port, make it as global ACL.
                    _ports.openacl = _glb.openacl;
                GLOGD("ACL:" <<_ports.socks <<"/" << _ports.port << ": " << _ports.openacl)
                ::fix(_ports.pending, 32, 256);
                ::fix(_ports.port, (size_t)64, (size_t)65534);

                if(_ports.socks=="DNSSOCK" || _ports.socks=="PASSTRU")
                {
                    if(!_ports.redirect.empty())
                    {
                        _ports.toaddr=fromstringip(_ports.redirect.c_str());
                        GLOGD("Port:" << _ports.port << " forward to " << _ports.toaddr.c_str() << ":" << _ports.toaddr.port());
                    }
                }

                // vector<Redirs>  redirs;
                // vector<string>  overs;


                _listeners.insert(_ports);
                _ports.clear();

            }
        }
        if(_section == "[pool]")
        {
            _bind(lpred, "min_threads",_pool.min_threads, val);
            _bind(lpred, "max_threads",_pool.max_threads, val);
            _bind(lpred, "clients_perthread",_pool.clients_perthread, val);
            _bind(lpred, "min_queue",_pool.min_queue, val);
            _bind(lpred, "max_queue",_pool.max_queue, val);
            _bind(lpred, "time_out",_pool.time_out, val);
            _bind(lpred, "buffsize", _pool.buffsize, val);
            _bind(lpred, "socketsize", _pool.socketsize, val);

            if(lpred[0]=='}')
            {
                if(_pool.socketsize && _pool.socketsize < _pool.buffsize)
                {
                    _pool.socketsize = _pool.buffsize;
                }
                if(_pool.min_threads==0)
                    _pool.min_threads=1;

                if(_pool.max_threads < _pool.min_threads)
                    _pool.max_threads = _pool.min_threads;


#ifdef DEBUG
                _pool.min_threads                =1;
#endif

            }
        }

        if(_section == "[ssl]")
        {
            _bind(lpred, "ssl_lib", _ssl.ssl_lib, val);
            _bind(lpred, "crypto_lib", _ssl.crypto_lib, val);

            _bind(lpred, "srv_certificate_file",_ssl.sCert, val);
            _bind(lpred, "srv_certificate_key_file",_ssl.sPrivKey, val);
            _bind(lpred, "srv_certificate_chain_file",_ssl.sChain, val);

            _bind(lpred, "cli_certificate_key_file",_ssl.cPrivKey, val);
            _bind(lpred, "cli_certificate_file",_ssl.cCert, val);

            _bind(lpred, "ca_certificate_file",_ssl.sCaCert, val);
            BIND(_ssl, version);

            if(lpred[0]=='}')
            {
                fix_path(_ssl.sCert);
                fix_path(_ssl.sPrivKey);
                fix_path(_ssl.sChain);
                fix_path(_ssl.sCaCert);
                fix_path(_ssl.cPrivKey);
                fix_path(_ssl.cCert);
                fix_path(_ssl.cCsr);

            }
        }
    }
    catch(int done) {}
}


bool ConfPrx::finalize()
{

    if(_glb.authurl.empty() && _glb.openacl==0)
    {
        printf("Error: authurl IP is missconfigured/missing in config file\n");
    }

    ::mkdir(_logs_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    std::string p = _logs_path + "/bytes";
    ::mkdir(p.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    std::string q = _logs_path + "/logs";
    ::mkdir(q.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);


    return Conf::finalize();
}


void    ConfPrx::refresh_domains()
{
    //
    // roll up ips if more tha one oon same domain
    //
    auto  i =  _listeners.begin();
    for(; i!= _listeners.end(); ++i)
    {
        if(!i->redirect.empty() && i->redirect.find("http")!=string::npos )
        {
            i->toaddr = fromstringip(i->redirect);
            GLOGD("Port:" <<  i->port << " forward to " <<  i->toaddr.c_str() << ":" << _ports.toaddr.port());
        }
    }

}

