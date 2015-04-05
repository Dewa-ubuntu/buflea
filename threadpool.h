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


#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <sstream>
#include <set>
#include <os.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <map>
#include <queue>
#include <algorithm>
#include "tinyclasses.h"
#include "ctxqueue.h"
#include <minidb.h>

//-----------------------------------------------------------------------------
using namespace std;

//-----------------------------------------------------------------------------
#define MAX_THREADS 256
#define THREADS_CNT 128

//-----------------------------------------------------------------------------

struct SinOut
{
    SinOut():in(0),out(0){}
    int in;
    int out;
};

//-----------------------------------------------------------------------------
class CtxesThread;
class TcpPipe;
class ThreadPool : public OsThread
{
public:
    ThreadPool(bool sync);
    virtual ~ThreadPool();
    bool create();

    void       dec(){
        AutoLock a(&_m);
        --_alive;
    }
    void       inc(){
        AutoLock a(&_m);
        ++_alive;
    }
    CtxQueue*  get_q(){return &_q;};
    size_t  count(){return _alive;}
    size_t  capacity()const{return _max_clients;}
    bool    add_thread(bool dynamic);
    void    remove_thread(CtxesThread* );
    const   CtxesThread* thread(int index){ return _pool[index];}
    void    (stringstream& ost, const SADDR_46& cliip);
    void    save_statuses(const SADDR_46& ip, const BysStat& ctx_stats);
    void    stop_thread();
    void    signal_to_stop();
    void    thread_main();
    void    metrics(std::stringstream& str, const std::string& hname)const;
    void    dump_metrics(TcpPipe& s, const std::string& hname);
private:
    void  _check_threads(time_t now);
    bool  _pre_thread_foo();
    void  _post_thread_foo();
    void  _comit_stats_to_file(time_t t , time_t d);
    void  _check_log_size();
    bool  _pool_socket(udp_sock& u, fd_set& r);
    void  _reply_metrics(udp_sock& s, SA_46& sin);
public:
    mutex                       _m;
    mutex                       _hctxcount;
private:
    bool                        _sync;
    size_t                      _maxcount;
    size_t                      _count;
    size_t                      _alive;
    size_t                      _max_clients;
    BysStat                     _stats;
    vector<CtxesThread*>        _pool;
    CtxQueue                    _q;
    map<u_int32_t, BysStat>     _clients;

};

extern ThreadPool* __tp;

#endif //
