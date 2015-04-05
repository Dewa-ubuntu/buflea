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


#ifndef LISTENERS_H
#define LISTENERS_H

#include <string>
#include <vector>
#include <sock.h>
#include "os.h"
#include "config.h"
#include "context.h"
#include "sslcrypt.h"

//-----------------------------------------------------------------------------
using namespace std;

//-----------------------------------------------------------------------------
class CtxQueue;
class CtxesThread;
class ThreadPool;
class Listeners;

//-----------------------------------------------------------------------------
class SrvSock : public tcp_srv_sock
{
public:
    friend class Listeners;
    SrvSock(const ConfPrx::Ports* p):_cons(0),_acons(0),_pconfig(p) {}
    virtual ~SrvSock() {destroy();}
    int getPort()const{return _pconfig->port;}
    int isPublic()const{return _pconfig->openacl;}
    const ConfPrx::Ports* getConfig()const{return _pconfig;}
private:
    size_t          _cons;
    size_t          _acons;
    const ConfPrx::Ports* _pconfig;
};

//-----------------------------------------------------------------------------
class Ctx;
class DbAccess;
class Listeners : public OsThread
{
public:

    Listeners(ThreadPool* pa, const DbAccess*   pdb);
    virtual ~Listeners();

    void    _listen_spin();
    mutex&  mut() {return  _m;}
    virtual int  start_thread();
    virtual void stop_thread();
    bool    initSsl();
    bool    san(){ return _sanity;}
    void    metrics(std::stringstream& str, SinOut& bpss)const;
    SslCrypt* sslglob(){return  _pssl;}

private:
    void    _put_inqueue(tcp_xxx_sock& s, int every_sec, const SrvSock* psrv);
    void    thread_main();
    void    _clear();
    Ctx*    _fabric(const string& sockver, const ConfPrx::Ports* ports, tcp_xxx_sock& s);

private:

    const DbAccess*     _pdb;
    bool                _mainThread;
    bool                _sanity;
    int                 _cons;
    SslCrypt*           _pssl;
    vector<SrvSock*>    _ss;
    CtxQueue*           _pqa;
    mutex               _m;
    SADDR_46            _previp;
    bool                _rejected;

};

extern Listeners*  __pl;


//extern Ctx   __dynamic_ctx_exit;
#endif // LISTENERS_H
