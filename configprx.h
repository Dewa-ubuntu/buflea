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


#ifndef _CONFIGPRX_H_
#define _CONFIGPRX_H_

#include <config.h>


//#############################################################################
#define __VERSION  "Buflea-Proxy-4.1.0"
//#############################################################################

//-----------------------------------------------------------------------------
const char HTTP_200[] = "HTTP/1.0 200 Connection established\r\n"
                               "Proxy-agent: "
                               __VERSION
                               "\r\n\r\n";

//-----------------------------------------------------------------------------
const char HTTP_400[] = "HTTP/1.1 400\r\n"
                               "Connection: close\r\n"
                               "Content-Type: text/html; charset=utf-8\r\n"
                               "Proxy-agent: "
                               __VERSION
                               "\r\n\r\n";


//-----------------------------------------------------------------------------
class ConfPrx: public Conf
{
public:
    ConfPrx(const char* fname);
    virtual ~ConfPrx();
    void    ix_path(std::string& path)
    {
        if(!path.empty() && path[0]!='/')
        {
            string t= path;
            path = _glb.runfrom + path;
        }
    }
    void refresh_domains();
protected:
    bool finalize();
    void _assign( const char* pred, const char* val, int line);
    void fix_path(std::string& path)
    {
        if(!path.empty() && path[0]!='/')
        {
            string t= path;
            path = _glb.runfrom + path;
        }
    }

public:

    struct Listener
    {
        Listener():nlogbytes(256),sessiontime(300),dnsssltout(100),bouncemax(24),
                    blog(0x2),
                    slog("WE"),
                    users("acl/users.txt"),
                    hosts("acl/denyhosts.txt"),
                    tickfile("_hearthbeat"),
                    maxrecs(256),
                    domrecs(256),
                    hostsfilerule(-1),
                    openacl(0)  //deny list of hosts by defaulr
        {}

        size_t          nlogbytes;      // max of log cache before flusing to file
        size_t          sessiontime;    // database cache time
        size_t          dnsssltout;     // database cache time
        size_t          bouncemax;      // database cache time
        size_t          blog;           // log flags Info Warning Error Ttrace/raffic Ddebug eXxtra
        size_t          droptout;
        string          signature;
        string          signaturegz;
        SADDR_46        authurl_ip;     // authurl IP. web site
        string          slog;           // log pplaceholder. calc the pblog flags
        string          authurl;        // authurl entry. we calc the next ip from it
        string          usercontrol;        // notiffy user sessiontime add, and user session expire
        string          reloadacls;
        string          hostsfile;

        string          runfrom;        // run foder
        string          users;          // run foder
        string          hosts;          // run foder
        string          admins;
        string          banned_ips;
        string          tickfile;
        int             maxrecs;
        int             domrecs;
        string          subscribers;
        int             hostsfilerule;
        int             openacl;
        map<SADDR_46,SADDR_46>  jumpip;   // jumpip rures. Explicit proxing for faling to local http server if any on desired port
    } _glb;

    struct Ssl
    {
        Ssl(){}//:ssl_lib("libssl.so"),crypto_lib("libcrypto.so") {}

        string  ssl_lib;
        string  crypto_lib;
        string  sCert;
        string  sPrivKey;
        string  sChain;
        string  sCaCert;
        string  cPrivKey;
        string  cCert;
        string  cCsr;
        int     version;

    } _ssl;

    struct Ports
    {
        Ports()
        {
            clear();
        }
        void clear()
        {
            pending=8;
            bindaddr="*";
            port=8083;
            socks="SOCKS5";
            clientisssl=0;
            hostisssl=0;
            openacl=-1;
            authtoken="plain";
            blocking=0;
            conport=80;
        }
        bool operator < (const Ports& p)const
        {
            return port<p.port;
        }
        int       pending;
        string    bindaddr;
        size_t    port;
        string    socks;
        size_t    blocking;
        int       clientisssl;
        int       hostisssl;
        int       openacl;     // 1, proxies everyting, no bans
        string    authtoken;
        string    redirect;
        SADDR_46  toaddr;
        int       conport;
        map<string,string>  overs;
    } _ports;

    struct Pool
    {
        Pool():min_threads(2),max_threads(4),
            clients_perthread(32),
            min_queue(32),max_queue(128),
            time_out(8),buffsize(4096),socketsize(4096) {}
        int    min_threads;
        int    max_threads;
        int    clients_perthread;
        int    min_queue;
        int    max_queue;
        int    time_out;
        int    buffsize;
        int    socketsize;
    } _pool;

    std::set<Ports>     _listeners;

};

//-----------------------------------------------------------------------------------
extern ConfPrx* GCFG;
extern SADDR_46  fromstringip(const std::string& s);

#endif //_CONFIGPRX_H_
