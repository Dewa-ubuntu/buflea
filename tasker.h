#ifndef TASKER_H
#define TASKER_H

#include <os.h>
#include <string>
#include <deque>


class tasker : public OsThread
{
public:

    typedef enum E_TASKS{
        eNA=0,
        eREDNS_REDIRECTS=1,
        eDNS_QUERY=2,
        eDNS_REVERSE=3,
    }E_TASKS;


    tasker();
    virtual ~tasker();
    void    schedule(E_TASKS et, const std::string& data, time_t t=0);
protected:
    virtual void thread_main();
private:
    class TaskQueue
    {
    public:
        struct Task{
            time_t          _when;
            tasker::E_TASKS _what;
            std::string     _data;
        };
        TaskQueue(){};
        ~TaskQueue(){};
        void push(const Task& c)
        {
            _c.lock();
            _q.push_back(c);
            _c.signal();
            _c.unlock();
        }

        bool pop(Task& ppc)
        {
            bool br = false;
            _c.lock();
            if(_q.size()) {
                ppc = _q.front();
                br = true;
                _q.pop_front();
            }
            _c.unlock();
            if(_q.size())
                _c.signal();
            return br;
        }
        void signal() {
            _c.signal();
        }
        void broadcast() {
            _c.broadcast();
        }
    private:
        std::deque<Task>     _q;
        condition       _c;
    }       _queue;

};
extern tasker* __task;

#endif // TASKER_H
