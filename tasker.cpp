
#include <minidb.h>
#include "tasker.h"
#include "configprx.h"



extern  int __alivethrds;
extern  int __alive;
tasker* __task;

tasker::tasker()
{
    assert(__task==0);
    __task=this;
}

tasker::~tasker()
{
    __task=0;
}

void    tasker::schedule(E_TASKS et, const std::string& data, time_t t)
{
    TaskQueue::Task ts;

    ts._when = t;
    ts._what = et;
    ts._data = data;
    _queue.push(ts);
}

void tasker::thread_main()
{
    ++__alivethrds;
    while(!_bstop && __alive)
    {
        sleep(2);
        TaskQueue::Task t;

        if(_queue.pop(t))
        {
            switch(t._what)
            {
                case eREDNS_REDIRECTS:
                    GCFG->refresh_domains();
                    break;
                case eDNS_QUERY:

                    break;
                case eDNS_REVERSE:
                    __db->dnsgetname(SADDR_46(t._data.c_str()),true);
                    break;
                default:
                    break;
            }
        }
    }
    --__alivethrds;
    GLOGD("tasker thread exits");

}





