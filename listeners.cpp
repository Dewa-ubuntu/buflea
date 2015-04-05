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

#include <map>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <signal.h>
#include <consts.h>
#include <fcntl.h>
#include <strutils.h>
#include "main.h"
#include "configprx.h"
#include "listeners.h"
#include "ctxqueue.h"
#include "threadpool.h"
#include "context4.h"
#include "context5.h"
#include "contexthttp.h"
#include "contextdns.h"   //  https tranparent connects to IP passed in by controling port dns  // Raw SEND   <__packed__ DnsCommon>
#include "contextctl.h"   //  authentic
#include "contextpass.h"  //  tranparent, host overwrite
#include "contextreg.h"  //  tranparent, host overwrite
#include "tcppipe.h"
//-----------------------------------------------------------------------------
using namespace std;

//-----------------------------------------------------------------------------
extern bool __alive;
Listeners*  __pl;
//-----------------------------------------------------------------------------
Listeners::Listeners(ThreadPool* pa, const DbAccess*   pdb):_pdb(pdb),_mainThread(false),_sanity(true),
    _cons(0),_pssl(0),_rejected(false)
{
    assert(__pl==0);
    __pl=this;
    _pqa = pa->get_q();
}

//-----------------------------------------------------------------------------
Listeners::~Listeners()
{
    _clear();
    if(_pssl)
        delete _pssl;
    __alive=false;
    if(!_mainThread)
        stop_thread();
}

//-----------------------------------------------------------------------------
bool Listeners::initSsl()
{
    if(0 == _pssl)
    {
        _pssl = new SslCrypt(GCFG->_ssl.ssl_lib.c_str(), GCFG->_ssl.crypto_lib.c_str(), GCFG->_ssl.version);


        if(!_pssl->init_server(GCFG->_ssl.sCert.c_str(), GCFG->_ssl.sPrivKey.c_str(),GCFG->_ssl.sCaCert.c_str(),0))
        {
            delete _pssl;
            _pssl = 0;
            return false;
        }
        if(!_pssl->init_client(GCFG->_ssl.cCert.c_str(),GCFG->_ssl.cPrivKey.c_str(), 0))
        {
            delete _pssl;
            _pssl = 0;
            return false;
        }
    }
    return true;
}

//-----------------------------------------------------------------------------
bool CancelAutoConnect(void* pVoid, ulong time)
{
    UNUS(pVoid);
    return time < 5;
}

//-----------------------------------------------------------------------------
void    Listeners::_listen_spin()
{
    _mainThread = true;  // we call it from main thread. we dont start the thread.
    if(0 == start_thread())
    {
        _bstop = false;
        thread_main();
    }
    _clear();
}

//-----------------------------------------------------------------------------
int  Listeners::start_thread()
{
    int check = 30;

    if(!GCFG->_ssl.ssl_lib.empty())
    {
        initSsl();
    }

    GLOGI("\n");
again:
    _clear();
    std::set<ConfPrx::Ports>::const_iterator sb = GCFG->_listeners.begin();
    for(; sb!= GCFG->_listeners.end() &&__alive && check>0; sb++)
    {
        const ConfPrx::Ports&   prt     = *(sb);
        SrvSock*                pss     = new SrvSock(&prt);
        const char*             pbind   = !prt.bindaddr.empty() ? prt.bindaddr.c_str() : 0;

        if(-1==pss->create(prt.port, SO_REUSEADDR, pbind))
        {

            //scr_color(scr_red);
            GLOGEN("bind, port:[" << prt.port << "] error:"<< pss->error() << " trying... " << check << " of 30");

            sleep(5);
            if(check-->0)
            {
                delete pss;
                goto again;
            }
            delete pss;
            return -1;
        }
        else
        {


            if(GCFG->_pool.socketsize > 0)
            {
                pss->set_option(SO_SNDBUF, GCFG->_pool.socketsize/4);
                pss->set_option(SO_RCVBUF, GCFG->_pool.socketsize);
            }

            fcntl(pss->socket(), F_SETFD, FD_CLOEXEC);
            pss->set_blocking(prt.blocking);

            pbind = pbind ? pbind : "*";
            if(pss->listen(prt.pending)==0)
            {

                GLOGIN("listen: " << prt.port << " "<< prt.socks <<
                       " addr:[" << pbind << "], ssl:" << prt.clientisssl <<"->"<<prt.hostisssl);
                _ss.push_back(pss);
            }
            else
            {

                GLOGEN("listen: " << prt.port << " "<< prt.socks <<
                       " addr: " << pbind << " error: " << pss->error());
                delete pss;
                return -1;
            }
        }
    }
    if(_ss.size())
    {
        if(!_mainThread)
            return OsThread::start_thread();
        return 0; //we're looping in main thread
    }
    GLOGE("Cannot find any ports section in configuration file. Exiting");
    return -1;
}

//-----------------------------------------------------------------------------
void Listeners::_clear()
{
    for(auto it : _ss)
    {
        it->destroy();
        delete it;
        usleep(0xFFFF);
    }
    _ss.clear();
}

//-----------------------------------------------------------------------------
void Listeners::stop_thread()
{
    //FT();
    AutoLock a(&_m);
    GLOGI("listeners stop thread");
    if(!_mainThread)
    {
        OsThread::signal_to_stop();
        //printf("%s\n",__PRETTY_FUNCTION__);
        sleep(1);
        OsThread::stop_thread();
    }

}

//-----------------------------------------------------------------------------
//
// we dont use eool/pool couse won wont listen more than 1000 incomming connections.
//
void Listeners::thread_main()
{
    int     looop=0;
    fd_set  rd;
    int     ndfs;// = _count + 1;
    timeval tv = {0,16384};
    time_t  tnow = time(NULL);
    int     conspesec = 0;
    ++__alivethrds;

    GLOGI("listeners starts");
    while(!_bstop && __alive)
    {

        if((++looop&0x1FF)==0x1FF && access("/tmp/buflea.stop",0)==0)
        {
            unlink("/tmp/buflea.stop");
            GLOGIN ("STOPPING SERVER DUE /tmp/buflea.stop");
            break;
        }

        usleep(0xFF);
        ndfs = 0;
        FD_ZERO(&rd);

        for (auto it : _ss)
        {
            if(!it->isopen())goto DONE;

            FD_SET(it->socket(), &rd);
            ndfs = max(it->socket(), ndfs);
        }
        tv.tv_usec = 0xFFF;
        int is = ::select(ndfs+1, &rd, 0, 0, &tv);
        if(is ==-1)
        {
            if(errno == EINTR)
            {
                usleep(0x1FF);
                continue;
            }
            GLOGE("network select error:" << errno << " exiting...");
            _sanity=false;
            break;
        }
        if(is == 0)
        {
            usleep(0xFFF);
            continue;
        }

        for (auto it : _ss)
        {
            if(!FD_ISSET(it->socket(), &rd))
            {
                FD_CLR(it->socket(), &rd);
                continue;
            }

            tcp_xxx_sock s;

            s.pre_set(GCFG->_pool.socketsize, GCFG->_pool.socketsize/4);
            SrvSock* psrv = it;
            if(psrv->accept(s)>0)
            {
                GLOGI("new incomming connection...");
                ++it->_acons;
                conspesec=0;
                if(time(NULL)- tnow > 1)   //calc cons/sec
                {
                    it->_cons = it->_acons;
                    it->_acons = 0;
                    tnow = time(NULL);
                    conspesec=1;
                }

                _put_inqueue(s, conspesec, it);
            }
            else
            {
                GLOGE("accept failed. error: " << errno);
            }
            FD_CLR(it->socket(), &rd);

        }//for
    }//while alive
DONE:
    GLOGD("Listener Thread exits");
    _sanity=false;
    __alive=false;
    --__alivethrds;
}

//-----------------------------------------------------------------------------
void Listeners::_put_inqueue(tcp_xxx_sock& s, int every_sec, const SrvSock* psrv)
{
    Ctx*                    pctx    = 0;
    const ConfPrx::Ports*   ports   = psrv->getConfig();
    const string            sockver = ports->socks;
    const SADDR_46          saddr   = s.getsocketaddr();

    if(ports->openacl==0)
    {
        if(!_previp.isequal(IP2STR(saddr),false))
        {
            GLOGD("c->p: " << IP2STR(s.getsocketaddr()));
            _previp=saddr;
            _rejected=_pdb->is_banned(saddr);
            if(_rejected)
            {
                GLOGI("IP:" <<saddr << " rejected from banned");
            }
            else if(_pdb->has_bounced_max(saddr))
            {
                _rejected=true;
                GLOGI("IP:" <<saddr << " rejected from bounce banned");
            }
        }
        if(_rejected)
        {
            s.destroy();
            return;
        }
    }

    pctx=this->_fabric(sockver,ports,s);
    if(pctx)
    {
        s.set_blocking(ports->blocking);
        s.detach();
        int r = _pqa->push(pctx); //One thd per ctx
        if((0 == every_sec) && r==0 && __tp->add_thread(true))   //scale on overflow
        {
            return;
        }
        if(-1 == r)   //queu overflow
        {
            GLOGW("queue size overflow:" << _pqa->size() << " contexts");
            delete pctx;
        }
    }
    else
    {
        GLOGE(" no context was created for this port. ckeck logs");
    }
}

//-----------------------------------------------------------------------------
void    Listeners::metrics(std::stringstream& str, SinOut& bpss)const
{
    GLOGD("1"<<"Listeners");
    auto i = _ss.begin();
    str << "<tr><th colspan='5'>Listeners ports:";
    for(; i!= _ss.end(); ++i)
    {
        str <<(*i)->getPort() << ", ";
    }
    str << "</th></tr>";
}

Ctx* Listeners::_fabric(const string& sockver,  const ConfPrx::Ports* ports, tcp_xxx_sock& s)
{
    Ctx* pctx = 0;

    if(sockver=="HTTP")
         pctx = new CtxHttp(ports, s);
    else if(sockver=="SOCKS4")                          // 4
        pctx = new Ctx4(ports, s);
    else if(sockver=="SOCKS5")                          // 5
        pctx = new Ctx5(ports, s);
    else if(sockver=="REGISTER")
         pctx = new CtsReg(ports, s);

    if(ports->openacl==1 ||
       __db->is_admin(s.getsocketaddr()) ||
       __db->is_subscribed(s.getsocketaddr()))
    {
        if( sockver=="CONTROL" && __db->is_admin(s.getsocketaddr()))
            pctx = new CtxCtl(ports, s);
        else if(sockver=="PASSTRU")
            pctx = new CtxPasstru(ports, s);
        else if(sockver=="DNSSOCK")
            pctx = new CtxDns(ports, s);
    }
    return pctx;
}



