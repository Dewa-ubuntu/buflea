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

#include "os.h"
#include "ctxqueue.h"
#include "context.h"

//-----------------------------------------------------------------------------
CtxQueue::CtxQueue():_h(0),_t(0),_sync(false)
{
    _cap = (GCFG->_pool).min_queue;
    _maxcap = (GCFG->_pool).max_queue;

    ::fix(_cap, (size_t)8, (size_t)512);
    ::fix(_maxcap, (size_t)_cap+16, (size_t)1024);
}

//-----------------------------------------------------------------------------
CtxQueue::~CtxQueue()
{
    _c.lock();
    while(_q.size()) {
        delete _q.front();
        _q.pop_front();
    }
    _c.unlock();
}

//-----------------------------------------------------------------------------
int CtxQueue::push(Ctx* c)
{
    _c.lock();
    _q.push_back(c);
    _c.signal();
    _c.unlock();
    if(_q.size() < _cap)
        return 1;   // in range
    if(_q.size() > _maxcap)
        return -1;  // too big. close incomming connections
    return 0;       // overflow but still accepting
}

//-----------------------------------------------------------------------------
bool CtxQueue::pop(Ctx** ppc)
{
    bool br = false;
    _c.lock();
    if(_sync){
        while(0 == _q.size()){
            _c.wait();
            usleep(0xF);
        }
    }
    if(_q.size()) {
        *ppc = _q.front();
        br = true;
        _q.pop_front();
    }
    _c.unlock();
    if(_q.size())
        _c.signal();
    return br;
}

void    CtxQueue::metrics(std::stringstream& str, SinOut& bpss)const
{
    GLOGD("1"<<"CtxQueue");
}
