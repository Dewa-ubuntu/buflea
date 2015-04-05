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


#ifndef TINYCLASSES_H
#define TINYCLASSES_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <string>
#include <vector>
#include <os.h>
#include <sock.h>
//-----------------------------------------------------------------------------
template <typename U>
class CntPtr
{

public:
    explicit CntPtr(U* p = 0) : _c(0) {
        if (p) _c = new cnt(p);
    }
    ~CntPtr() {
        dec();
    }
    CntPtr(const CntPtr& r) throw() {
        add(r._c);
    }
    CntPtr& operator=(const CntPtr& r) {
        if (this != &r) {
            dec();
            add(r._c);
        }
        return *this;
    }

    U& operator*()   throw()   {
        return *_c->p;
    }
    U* operator->() const throw()   {
        return _c->p;
    }
    U& obj(){
        return *_c->p;
    }
private:
    struct cnt {
        cnt(U* p = 0, u_int32_t c = 1) : p(p), c(c) {}
        U*            p;
        u_int32_t     c;
    }* _c;
    void add(cnt* c) throw() {
        //AutoLock __a(&_c->m);
        _c = c;
        if (c) ++c->c;
    }
    void dec() {
        //AutoLock __a(&_c->m);
        if (_c) {
            if (--_c->c == 0) {
                delete _c->p;
                delete _c;
            }
            _c = 0;
        }
    }
};

//-----------------------------------------------------------------------------
template <class T> class DPool // dynamic pool gets from heap when out of objs
{
public:
    class U : public T
    {
    public:
        U():_polled(0) {};
        virtual ~U() {};
        int     _polled;
    };
public:
    static void create_pool(u_int32_t cap) {
        _cs = new mutex();

        _pvect = new std::vector<U*>();
        _pvect->reserve(cap);
        _pbhead = (U*) ::malloc(cap * sizeof(U));
        _nCapacity = cap;
        U* pw	= _pbhead;
        for(u_int32_t i=0; i< cap; i++) {
            _pvect->push_back(pw++);
        }
    }

    static void destroy_pool() {
        if(0==_pvect)return;
        _pvect->clear();
        delete _pvect;
        ::free((void*)_pbhead);
        _pbhead=0;
        delete _cs;
    }

    void* operator new(size_t sz) {
        if(T::_pvect->size() > 0) {
            AutoLock q(_cs);
            int szisz = _pvect->size();
            U* pvb = (U*)_pvect->back();
            _pvect->pop_back();
            ++DPool<T>::_inUse;
            ((U*)pvb)->_polled = szisz;
            return (void*)(pvb);
        } else {
            U* pu = ::new U();
            pu->_polled=-1;
            return pu;
        }
    }

    void operator delete(void* pv) {
        if( ((U*)pv)->_polled !=-1) {
            AutoLock q(_cs);
            --DPool<T>::_inUse;
            _pvect->push_back((U*)pv);
        } else
            delete pv;
    }
    static int capacity() {
        return _nCapacity;
    }
    static int elements() {
        return _inUse;
    }
    static U*			 _pbhead;
    static std::vector<U*>*	 _pvect;
    static u_int32_t  _nCapacity;
    static u_int32_t	 _inUse;
    static mutex         *_cs;
};

//-----------------------------------------------------------------------------
template <class T> typename DPool<T>::U*            DPool<T>::_pbhead;
template <class T> std::vector<typename DPool<T>::U*>*   DPool<T>::_pvect;
template <class T> u_int32_t				                DPool<T>::_nCapacity;
template <class T> u_int32_t				                DPool<T>::_inUse;
template <class T> mutex*  		                    DPool<T>::_cs;

//-----------------------------------------------------------------------------
template <class T, size_t SZ = 64>
class  Bucket
{
public:
    Bucket():_elems(0) {}
    ~Bucket() {}
    const T& operator[](size_t idx)const {
        return t[idx];
    }
    bool push(T el) {
        if(_elems < SZ) {
            t[_elems++] = el;
            return true;
        };
        return false;
    }
    T*  pop() {
        if(_elems) {
            --_elems;
            return &t[_elems];
        }
        return 0;
    }
    void remove(size_t idx) {
        if(_elems) {
            t[idx] = t[_elems-1];
            t[_elems-1]=0;
            _elems--;
        }
    }
    void clear() {
        _elems=0;
    }
    size_t size() const{
        return _elems;
    }
    T* begin() {
        return t;
    }
    T& operator[](size_t k){
        return t[k];
    }
    T* at(size_t n) {
        return &t[n];
    }
    T* end() {
        return &t[_elems];    //this should point to 0
    }
protected:
    T	   t[SZ];
    size_t _elems;
};

//template <typename T> bool valid_ptr(T *s_){return (s_&&*s_);}
//------------------------------------------------------------------------------
struct BysStat {
    BysStat() {
        ::memset(this,0,sizeof(*this));
    }
    enum {eIN=0,eOUT=1,};

    int64_t _temp_bytes[3];
    int64_t _total_bytes[3];
    size_t  _bps_spin[3];
};

bool bind_udp_socket(udp_sock& s_side, std::string& addr);
bool bind_listener_socket(tcp_srv_sock& s_side, std::string& addr);
bool rec_some(udp_sock& s_side, fd_set& r, char* outb, size_t maxb, SADDR_46& sin);

#endif // TINYCLASSES_H
