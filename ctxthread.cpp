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
#include <algorithm>
#include <consts.h>
#include "main.h"
#include "tinyclasses.h"
#include "ctxthread.h"
#include "threadpool.h"
#include "configprx.h"
#include "ctxqueue.h"
#include "context.h"
#include <strutils.h>

//-----------------------------------------------------------------------------
CtxesThread::CtxesThread(ThreadPool* tp, int idx,
                         bool dynamic):_tp(tp),
    _index(idx),
    _dynamic(dynamic),
    _pbuff(0),
    _nbuff(0)
{
    _nbuff  = GCFG->_pool.buffsize;    // r remote
    _pbuff = new u_int8_t[_nbuff+80];  // from browser
}

//-----------------------------------------------------------------------------
CtxesThread::~CtxesThread()
{
    this->stop_thread();
    delete[] _pbuff;
}

//-----------------------------------------------------------------------------
static void callClear(Ctx* p)
{
    p->clear();
}

//-----------------------------------------------------------------------------
void CtxesThread::signal_to_stop()
{
    OsThread::signal_to_stop();
    AutoLock a(&_m);
    std::for_each(_pctxs.begin(), _pctxs.end(), callClear);
}

//-----------------------------------------------------------------------------
void CtxesThread::stop_thread()
{
    OsThread::stop_thread();
}

//-----------------------------------------------------------------------------
bool CtxesThread::_pre_thread_foo()
{
    _tp->inc();
    return true;
}

//-----------------------------------------------------------------------------
int CtxesThread::_get_from_q(CtxQueue* pq, size_t maxctxes)
{
    if(_pctxs.size() < maxctxes && pq->size())
    {
        Ctx* pc;
        if(pq->pop(&pc))
        {
            if(0 == pc)
                return -1;
            AutoLock a(&_m);
            _pctxs.push(pc);
            return 1;
        }
    }
    return 0;
}
//-----------------------------------------------------------------------------
//
// we dont use eool/pool couse won wont handle more than 1000 conections/thread.
//
void CtxesThread::thread_main()
{
    ++__alivethrds;
    if(0 == _pbuff)
    {
        __alive=false;
        GLOGE("Thread error. Canot allocate buffer.");
        --__alivethrds;
        return;
    }

    GLOGD("T++:" << _index);

    time_t      tout = (time_t)GCFG->_pool.time_out;
    _curtime  = time(0);
    time_t      last_activ_select = _curtime;
    time_t      prevtime = _curtime;
    time_t      delay_for_bps = 10;
    size_t      maxctxes = _tp->capacity();
    CtxQueue*   pq = _tp->get_q();
    fd_set      rd,wr;
    int         ndfs;
    bool        delete_oldies=false;
    int         delaytick=0;
    timeval     tv = {0,0xFFF};


    ::fix(maxctxes, (size_t)1,(size_t) MAX_CTXES);
    if(_dynamic)  //get a load from queue
    {
        for(int i = 0; i < 8; i++)
        {
            int qn = _get_from_q(pq, maxctxes);
            if(qn<=0)break;
        }
    }

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    while(!this->_bstop && __alive )
    {
        usleep(256);
        _curtime = time(0);
        delete_oldies = false;                      // we dont bps now
        if(_curtime - prevtime > tout)               // reports every tout seconds
        {
            delay_for_bps = _curtime-prevtime;       //only now
            prevtime = _curtime;
            delete_oldies = true;
            if(++delaytick%10==0)
                _file_tick(_curtime);                // tick date in file
        }
        int qn = _get_from_q(pq, maxctxes);

        if(qn == -1)
        {
            GLOGD("end of queue. T breaks");
            break;
        }

        //
        // test for dynamicaly added threads.
        //
        if(0 == _pctxs.size())
        {
            if(_dynamic && _curtime -last_activ_select > tout)
            {
                GLOGD("dynamic T breaks");
                break; //terminate dynamic thread
            }
            usleep(0xFFFF);
            continue;
        }

        //
        // FD_SET
        //
        ndfs = 0;
        FD_ZERO(&rd);
        FD_ZERO(&wr);

        for(size_t k=0; k<_pctxs.size(); k++)
        {
            ndfs = max(_pctxs[k]->set_fd(rd,wr,this), ndfs);
        }
        ++ndfs;
        //
        // FD_ISSET
        //
        tv.tv_sec = 0;
        tv.tv_usec = 0xFFF;
        int is = ::select(ndfs+1, &rd, &wr, 0, &tv);
        if(is < 0)
        {
            if(errno == EINTR || errno == EWOULDBLOCK)
            {
                GLOGW("select(...) errno=EINTR");
                usleep(0x1F);
                continue;
            }
            char buf[128];
            strerror_r(errno, buf, sizeof(buf));
            GLOGE("select error:" << errno <<":" << buf << ": " <<__FILE__ << __LINE__);
            if(9 == errno || errno==EINVAL)
            {
                _close_all();
                continue;
            }
            break;
        }
        if(is > 0)
        {
            CALLR rv;
            for(size_t k=0; k < _pctxs.size(); k++)
            {
                assert(_pctxs[k]);
                size_t can = _pctxs[k]->is_fd_set(rd, wr);
                if(can)
                {
                    rv = _pctxs[k]->spin();
                    switch(rv)
                    {
                        case R_CONTINUE:
                            last_activ_select = time(0);
                            delete_oldies=false;
                            break;
                        case R_KILL:
                            _pctxs[k]->destroy();
                        case R_DONE:
                        default:
                            delete_oldies=true;
                            break;
                    }
                }
            }//for spin
        }
        else
        {
            usleep(0x1FF);
        }
        //
        // delete closed connection and finshed/timouts contexts
        //
        int ksz = _pctxs.size();
        for (int k =0; k < ksz; ++k)
        {
            if(0 == _pctxs[k]) continue;
            _pctxs[k]->clear_fd(rd, wr, delete_oldies, delay_for_bps, k==0);
			if(_pctxs[k]->isdead())
            {
                AutoLock a(&_m);
                delete _pctxs[k];
                _pctxs.remove(k);
            }
        }
    }//while

    //
    // clean up, we've exit
    //
    if(_pctxs.size())
    {
        AutoLock a(&_m);
        for(size_t k=0; k < _pctxs.size(); k++)
        {
            delete _pctxs[k];//_cxleng;
        }
        _pctxs.clear();
    }
    if(!_dynamic)
    {
        __alive = false;
    }
    GLOGD("T-CTX exits:" << _index);
    --__alivethrds;
}

void CtxesThread::_close_all()
{
    AutoLock a(&_m);
    for(size_t k=0; k < _pctxs.size(); k++)
    {
        _pctxs[k]->destroy();
        delete _pctxs[k];//_cxleng;
    }
    _pctxs.clear();
}

//-----------------------------------------------------------------------------
//
// clean thread context loaded libraries and values
//
void CtxesThread::_post_thread_foo()
{
    _tp->remove_thread(this);
}

//-----------------------------------------------------------------------------
void    CtxesThread::save_ctx_state(SADDR_46 ip, BysStat& ctx_stats, int firstone)
{
    if(firstone)
    {
        _stats._bps_spin[BysStat::eIN] = 0;
        _stats._bps_spin[BysStat::eOUT] = 0;
        _stats._temp_bytes[BysStat::eIN] = 0;
        _stats._temp_bytes[BysStat::eOUT] = 0;
    }
    _stats._total_bytes[BysStat::eIN]+=ctx_stats._temp_bytes[BysStat::eIN];
    _stats._total_bytes[BysStat::eOUT]+=ctx_stats._temp_bytes[BysStat::eOUT];
    _stats._bps_spin[BysStat::eIN]+=ctx_stats._bps_spin[BysStat::eIN];
    _stats._bps_spin[BysStat::eOUT]+=ctx_stats._bps_spin[BysStat::eOUT];
    __tp->save_statuses(ip, ctx_stats);
    ctx_stats._temp_bytes[BysStat::eIN] = 0;
    ctx_stats._temp_bytes[BysStat::eOUT] = 0;
}

void    CtxesThread::metrics(std::stringstream& str, SinOut& bpss)const
{
    AutoLock a(&_m);

    const size_t count = _pctxs.size();
    if(count)
    {
        str <<  "<tr><th colspan='5'>Thread:" <<_index << " Dynamic:" << _dynamic <<"</th></tr>\n" <<
                "<tr><th>BPS In/thread</th><td colspan='4'> "  << _stats._bps_spin[BysStat::eIN] << "</td></tr>\n"
                "<tr><th>BPS Out/thread</th><td colspan='4'>"  <<  _stats._bps_spin[BysStat::eOUT] << "</td></tr>\n";

        bpss.in+=_stats._bps_spin[BysStat::eIN];
        bpss.out+=_stats._bps_spin[BysStat::eOUT];

        if(count<16)
        {
            str << "<tr><th>Type</th><th>id</th><th>IN-Ops</th><th>OUT-Ops/sec</th><th>connection</th></tr>\n";

            for(size_t i=0; i< count; i++)
            {
                do{
                    AutoLock a(&_m);
                    _pctxs[i]->metrics(str, bpss, count);
                }while(0);
            }
        }
    }

}


void    CtxesThread::_file_tick(time_t time)
{
    AutoLock a((mutex*)&_m);
    FILE*    pf;
    const char* ptick = GCFG->_glb.tickfile.c_str();

#ifdef DEBUG
    GLOGI("tick:" << _index);
#endif //DEBUG

    if(::access(ptick,0)==0)
        pf = ::fopen(ptick,"ab");
    else
        pf = ::fopen(ptick,"wb");
    if(pf==0)
    {
        GLOGE("Error opening " << ptick);
        return;
    }
    ::fprintf(pf,"%s, thread: %d, tick:%d\n",str_time(),_index, int(time));
    int flen = ::ftell(pf);
    ::fclose(pf);

    if(flen > 1024)
    {
        ::unlink(ptick);
    }

}

void    CtxesThread::close_sockets()
{
    //som ssl block forever. let's see
    for(size_t k=0; k < _pctxs.size(); k++)
    {
        _pctxs[k]->close_sockets();
    }
}


