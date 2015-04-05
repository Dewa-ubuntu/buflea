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


#ifndef CTXTHREAD_H
#define CTXTHREAD_H
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include "tinyclasses.h"
#include "ctxqueue.h"


//------------------------------------------------------------------------------
class Ctx;
class CtxQueue;
class ThreadPool;
class IModule;
class CtxesThread : public OsThread
{
public:
    friend class ThreadPool;
    friend class Ctx;
    CtxesThread(ThreadPool* tp, int index, bool dynamic);
    virtual ~CtxesThread();
    int     index()const{return _index;}
    void    sc_write(const char* s);
    int     sc_getid();
    void    save_ctx_state(SADDR_46 ip, BysStat& ctx_stats, int);
    const BysStat&  get_stats()const{return _stats; }
    u_int8_t*   buffer(int& sz)const {sz = (int)_nbuff-2; return _pbuff;}
    bool    add_context(Ctx* pc){return _pctxs.push(pc);};
    void    metrics(std::stringstream& str, SinOut& bpss)const;
    mutex&  get_mutex(){return _m;}
    time_t  last_spin()const {return _curtime;}
    void    close_sockets();
protected:
    void    _close_all();
    bool    _pre_thread_foo();
    void    _post_thread_foo();
    void    stop_thread();
    void    signal_to_stop();
    void    thread_main();
    int     _get_from_q(CtxQueue* pq, size_t maxctxes);
    void    _file_tick(time_t time);
public:
    mutex           _m;

private:
    ThreadPool*     _tp;
    time_t          _curtime;
    int             _index;
    bool            _dynamic;
    bool            _flushed;
    u_int8_t*       _pbuff;
    size_t          _nbuff;
    BysStat         _stats;     // per thread
    Bucket<Ctx*, MAX_CTXES>  _pctxs;
 };
#endif // CTXTHREAD_H
