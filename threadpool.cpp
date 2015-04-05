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
#include <consts.h>
#include "main.h"
#include <strutils.h>
#include <sock.h>
#include <string>
#include "config.h"
#include "threadpool.h"
#include "dnsthread.h"
#include "ctxthread.h"
#include "context.h"
#include "ctxqueue.h"
#include "listeners.h"
#include "minidb.h"

//-----------------------------------------------------------------------------
ThreadPool*     __tp;

//-----------------------------------------------------------------------------
ThreadPool::ThreadPool(bool sync): _sync(sync),
    _alive(0),_max_clients(0)
{
    assert(__tp==0);
    __tp=this;
    _count   = GCFG->_pool.min_threads;
    _maxcount = GCFG->_pool.max_threads;
    _max_clients = GCFG->_pool.clients_perthread;

    ::fix(_count, (size_t)1, (size_t)THREADS_CNT);
    ::fix(_maxcount, (size_t)_count, (size_t)MAX_THREADS);
    ::fix(_max_clients, (size_t)1, (size_t)MAX_CTXES);

}

//-----------------------------------------------------------------------------
bool ThreadPool::create()
{
    GLOGI("STARTING "<<_count<<" threads. out of:" << _maxcount);
    for(size_t i=0; i<_count; i++)
    {
        add_thread(false);
    }
    return true;
}

//-----------------------------------------------------------------------------
ThreadPool::~ThreadPool()
{
    //for all threads
    size_t alive = _pool.size();
    do
    {
        AutoLock a(&_m);
        for(size_t i=0; i<alive; i++)
        {
            _pool[i]->signal_to_stop();
        }
    }
    while(0);

    // send the eos context
    time_t tout = time(0) + 32;

    //_q.set_sync_mode(true);   //make threads to wait
    while(count() && _alive && time(0) < tout)
    {
        _q.push(0);
        usleep(0xFFF);
    }
    _pool.clear();


}

//-----------------------------------------------------------------------------
bool    ThreadPool::add_thread(bool dynamic)
{
    if(_pool.size() < _maxcount)
    {
        AutoLock a(&_m);
        CtxesThread* ct = new CtxesThread(this, _pool.size(), dynamic);
        if (ct)
        {
            _pool.push_back(ct);
            ct->start_thread();
        }
        return true;
    }
    return false;
}

void    ThreadPool::remove_thread(CtxesThread* pt)
{
    AutoLock a(&_m);
    vector<CtxesThread*>::iterator b = _pool.begin();
    for(; b!=_pool.end(); b++)
    {
        if((*b)==pt)
        {
            dec();
            delete pt;
            _pool.erase(b);
            break;
        }
    }
}


bool ThreadPool::_pre_thread_foo()
{
    return true;
}

void ThreadPool::_post_thread_foo()
{
}

void ThreadPool::stop_thread()
{
    OsThread::stop_thread();
}

void ThreadPool::signal_to_stop()
{
    OsThread::signal_to_stop();
}


void ThreadPool::thread_main()
{
    time_t       now = time(0);
    time_t       prev = now;
    size_t       k = 0;

    ++__alivethrds;
    while(!this->is_stopped() && __alive /*&& s_side.isopen()*/)
    {

        now = time(0);
        if(k % 3 == 0)  // 3 secs
        {
            time_t diff = now - prev;
            prev = now;
            _comit_stats_to_file(now, diff);
            GCFG->check_log_size();


        }
        if(k % 5 == 0)
        {
           //// _check_threads( now);
        }
        ++k;
        sleep(1);
    }

    GLOGD("Thread pool exits");
    //_check_threads(0);
    _comit_stats_to_file(now, 10);
    unlink("/tmp/buflea.stop");
    __alive=false;
    --__alivethrds;
}

//dangerous dont call it
void ThreadPool::_check_threads(time_t now)
{

    AutoLock a(&_m);

    for(auto const& thread : _pool)
    {
        const time_t last_spin = thread->last_spin();
        if(now==0 || now - last_spin > (GCFG->_pool.time_out*2))
        {
            GLOGI("A thread was found hanging because did not spamped last time. Destroyng ctxes...");
            thread->close_sockets();
        }
    }
}


void    ThreadPool::save_statuses(const SADDR_46& ip, const BysStat& ctx_stats)
{
    AutoLock __a(&_m);

    BysStat& rs = _clients[ip.ip4()];
    rs._total_bytes[0] += ctx_stats._temp_bytes[0];
    rs._total_bytes[1] += ctx_stats._temp_bytes[1];
}

void    ThreadPool::_comit_stats_to_file(time_t now, time_t diff)
{
    bool        changes = false;
    char        fname[512];
    long int    flen = 0;
    BysStat     srvStat;
    std::map<u_int32_t,BysStat> local;


    if(diff==0)diff=1;

    do
    {
        AutoLock __a(&_m);
        local = _clients;
    }
    while(0);


    u_int64_t bytesin, bytesout, prev_bytesin, prev_bytesout, dummy;
    size_t clients = local.size();
    for(auto  b : local)
    {
        BysStat&  rs = b.second;

        sprintf(fname, "%s/bytes/%s.log0",GCFG->_logs_path.c_str(), (const char*)Ip2str(b.first));
        FILE* pf = fopen(fname,"r+");
        if(pf)
        {
            fseek(pf, 0, SEEK_END);
            flen=ftell(pf);
            if(flen<72)
            {
                fclose(pf);
                goto crea_file;
                break;
            }
            fseek(pf, -72, SEEK_END);
            fscanf(pf,"%011zu %011zu %011zu %011zu %011zu %011zu\n",
                   &dummy, &bytesin, &bytesout, &prev_bytesin, &prev_bytesout, &dummy);
            //fseek(pf,0, SEEK_SET);

            prev_bytesin = bytesin;
            prev_bytesout = bytesout;

            bytesin  += rs._total_bytes[BysStat::eIN];
            bytesout += rs._total_bytes[BysStat::eOUT];

            if(bytesin != prev_bytesin || bytesout != prev_bytesout)
            {

                rs._bps_spin[BysStat::eIN] = (bytesin - prev_bytesin) / diff;
                rs._bps_spin[BysStat::eOUT] = (bytesout - prev_bytesout) / diff;

                srvStat._bps_spin[BysStat::eIN]     += rs._bps_spin[BysStat::eIN];
                srvStat._bps_spin[BysStat::eOUT]    += rs._bps_spin[BysStat::eOUT];
                srvStat._total_bytes[BysStat::eIN]  += rs._total_bytes[BysStat::eIN];
                srvStat._total_bytes[BysStat::eOUT] += rs._total_bytes[BysStat::eOUT];

                fseek(pf, 0, SEEK_END);
                fprintf(pf, "%011zu %011zu %011zu %011zu %011zu %011zu\n",
                        now, bytesin, bytesout, prev_bytesin, prev_bytesout, diff);

                changes = true;
            }
            flen = ftell(pf);
            fclose(pf);


#ifdef XDEBUG
            if(bytesin != prev_bytesin || bytesout != prev_bytesout)
            {
                printf("%011zu %011zu %011zu %011zu %011zu %011zu\n",
                       now, bytesin, bytesout, prev_bytesin, prev_bytesout, diff);
            }
#endif

            if(flen > MAX_ROLLUP)
            {
                sprintf(fname, "bytes/%s", (const char*)IP2STR(b.first));
                GCFG->rollup_logs(fname);
            }

        }
        else
        {
crea_file:
            FILE* pf = fopen(fname,"wb");
            if(pf)
            {
                fprintf(pf, "%011zu %011zu %011zu %011zu %011zu %011zu\n",
                        (size_t)now, (size_t)0, (size_t)0, (size_t)0, (size_t)0, (size_t)diff);
                flen = ftell(pf);
                fclose(pf);
            }
            //chmod(fname,0777);
        }
    }

    if(_clients.size())
    {
        AutoLock __a(&_m);
        _clients.clear();
    }
    if(changes)
    {
        sprintf(fname, "%s/bytes/metrics.log0", GCFG->_logs_path.c_str());
        FILE* pf = fopen(fname,"ab");
        {
            fprintf(pf, "%zu,%zu,%zu,%zu,%zu,%zu\n",
                    now,
                    clients,
                    srvStat._bps_spin[BysStat::eIN],
                    srvStat._bps_spin[BysStat::eOUT],
                    srvStat._total_bytes[BysStat::eIN],
                    srvStat._total_bytes[BysStat::eOUT]);
#ifdef XDEBUG
            printf("%zu,%zu,%zu,%zu,%zu,%zu\n",
                   now,
                   clients,
                   srvStat._bps_spin[BysStat::eIN],
                   srvStat._bps_spin[BysStat::eOUT],
                   srvStat._total_bytes[BysStat::eIN],
                   srvStat._total_bytes[BysStat::eOUT]);
#endif

            flen = ftell(pf);
            fclose(pf);
        }
        if(flen > MAX_ROLLUP)
        {
            GCFG->rollup_logs("bytes/metrics");
        }
    }

}


void    ThreadPool::accumulate_log(stringstream& ost, const SADDR_46& cliip)
{
    if(!ost.str().empty())
    {
        char        logf[256];
        AutoLock    __a(&_m);


        sprintf(logf, "%s/logs/%s.log0", GCFG->_logs_path.c_str(), IP2STR(cliip));
        FILE* pf = fopen(logf,"ab");
        size_t flen = 0;
        if(pf)
        {
            fwrite(ost.str().c_str(), 1, ost.str().length(), pf);
            flen = ftell(pf);
            fclose(pf);
        }
        ost.str("");
        //ost.clear();
        //ost.seekp(0);
        //ost.seekg(0);

        if(flen > MAX_ROLLUP)
        {
            sprintf(logf, "logs/%s", IP2STR(cliip));
            GCFG->rollup_logs(logf);
        }
    }
}


void ThreadPool::dump_metrics(TcpPipe& s, const std::string& hname)
{
    std::stringstream   chunk;

    GLOGD("1"<<"ThreadPool");

    this->metrics(chunk,hname);
    s.send(chunk.str().c_str(), chunk.str().length());

    GLOGD("2"<<"ThreadPool");
}


void ThreadPool::_reply_metrics(udp_sock& s, SA_46& sin)
{
    std::stringstream   chunk;

    chunk <<"<pre>\n";
    this->metrics(chunk,"");
    chunk <<"</pre>\n";
    s.send(chunk.str().c_str(), chunk.str().length(), sin);
}

void    ThreadPool::metrics(std::stringstream& str, const std::string& hname)const
{
    str<<"HTTP/1.1 200 OK\r\n";
    str<<"Content-Type: text/html;charset=utf-8\r\n\r\n";
//    str<<"<meta http-equiv='refresh' content='30'>\n";

    str<<"<style> th, td {border-width: 0 0 1px 1px;border-style: solid;border-color: #600;}\n";
    str<<"th{background-color: #EFC;}\n";
    str<<"</style>\n";





    str<<"<table>\n";
    SinOut  bpss;

    GLOGD("1"<<"ThreadPool");

    if(__pl)
        __pl->metrics(str, bpss);

    __db->metrics(str, bpss, hname);

    GLOGD("2"<<"ThreadPool");

    str << "<tr><th colspan='4''>Thread pool</th><th>" << _pool.size() << "</th></tr>\n";
    vector<CtxesThread*>::const_iterator i = _pool.begin();
    for(; i!= _pool.end(); ++i)
    {
        (*i)->metrics(str, bpss);
    }
    GLOGD("3"<<"ThreadPool");
    str << "<tr><th colspan='3'>BPS/BUF" << "</th><td>IN:" << bpss.in<< " Ops</td><td>OUT: "<< bpss.out<< " Ops</td></tr>";



    _q.metrics(str, bpss);
    str<<"</table>\n";

    GLOGD("4"<<"ThreadPool");

}

bool    ThreadPool::_pool_socket(udp_sock& s_side, fd_set& r)
{
    char     b[64];
    SADDR_46 sin;

    if(rec_some(s_side, r, b, sizeof(b), sin))
    {
        if(b[0]=='m') // needs metrics
        {
            _reply_metrics(s_side, sin);
        }
    }
    return false;//not realtime loop
}

