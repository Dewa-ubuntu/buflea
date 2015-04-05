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


#ifndef CTXQUEUE_H
#define CTXQUEUE_H


#include <iosfwd>
#include <deque>
#include "os.h"

using namespace std;
class Ctx;
struct SinOut;
class CtxQueue
{
public:
    CtxQueue();
    virtual ~CtxQueue();
    int push(Ctx*);
    bool pop(Ctx**);
    void set_sync_mode(bool sync) {
        _sync=sync;
    };
    void signal() {
        _c.signal();
    }
    void broadcast() {
        _c.broadcast();
    }
    int cap() {
        return _cap;
    }
    size_t size()const {
        return _q.size();
    }
    void    metrics(std::stringstream& str, SinOut& bpss)const;
private:
    int             _h;
    int             _t;
    bool            _sync;
    size_t          _cap;
    size_t          _maxcap;
    deque<Ctx*> _q;
    condition       _c;
};

//-----------------------------------------------------------------------------
#define MAX_CTXES   256
#define MAX_MODULES 32


#endif // CTXQUEUE_H

