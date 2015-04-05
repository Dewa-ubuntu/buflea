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
#ifndef HTTP_HDR
#define HTTP_HDR
#include <string>
#include <map>
#include <vector>
#include <os.h>
#include <sock.h>


//----------------------------------------------------------------------------
class SocksHdr
{
public:
    SocksHdr(){clear();}
    ~SocksHdr(){}
    SocksHdr& operator=(const SocksHdr& r){
        _buf = r._buf;
        last_len = r.last_len;
        hdr_len = r.hdr_len;
        body_len = r.body_len;
        ok = r.ok;
        has_open = r.has_open;
        _nhost = r._nhost;
        _nhost_end = r._nhost_end;
        _nprx = r._nprx;
        _nprx_end = r._nprx_end;
         _nreferer = r._nreferer;
        _nreferer_end = r._nreferer_end;
        _nencoding = r._nencoding;
        _nencoding_end = r._nencoding_end;
        return *this;
    }
    const u_int8_t*   buf()const{ return (const u_int8_t*)_buf.c_str();}
    void  append(const char* b, size_t l){
        if(l + bytes() > 16384)
        {
            throw Mex(OUT_OF_MEMORY,__FILE__,__LINE__, "overflow");
        }
        _buf.append((const char*)b, (size_t)l);
    }
    uint64_t asll()const{return *((const uint64_t*)(const char*)_buf.c_str());}
    bool  parsed(){return !_buf.empty();}
    void  clear(bool force=true){
        if(force)
            _buf.clear();
        last_len=0;
        hdr_len=0;
        body_len=0;
        ok=false;
        has_open=false;
        _nhost=0;
        _nhost_end=0;
        _nprx=0;
        _nprx_end=0;
        _nreferer=0;
        _nreferer_end=0;
        _nencoding = 0;
        _nencoding_end = 0;
    }
    int         parse();
    size_t      bytes() {return _buf.length();};
    std::string get_host(){
        //const char* pb = _buf.c_str();
        return _buf.substr(_nhost, _nhost_end - _nhost);
    }
    std::string get_referer(){
        return _buf.substr(_nreferer, _nreferer_end - _nreferer);
    }

    void prep_doc()
    {
        //const char* xdebug = 0;
        if(_nprx)
        {
            //xdebug = _buf.c_str();
            _buf.replace(_nprx, _nprx_end-_nprx,"");
            //xdebug = _buf.c_str();
        }

        if(_nhost)
        {
            std::string host = get_host();
            static std::string http = "http://";
            size_t start = _buf.find(' ');
            size_t end   = _buf.find(' ', start+1);
            if(start != string::npos && end != string::npos && end-start>2)
            {
                ++start;
                std::string doc = _buf.substr(start, end-start);
                if(doc.find(http) != string::npos)//fast search first
                {
                    size_t nhttp = _buf.find(http);
                    if(nhttp != string::npos)
                    {
                        size_t nhost = doc.find(host);
                        std::string hdoc =  http + host;
                        if(nhost == 7 && doc.find(hdoc)==0)
                        {
                            //xdebug = _buf.c_str();
                            _buf.replace(nhttp, hdoc.length(), "");
                            //xdebug = _buf.c_str();
                        }
                    }
                }
            }
        }
    }


    void replace_option(size_t start, size_t stop, const char* nh=0)
    {
        int diff = -(stop-start);

        if(nh){
            _buf.erase(start, stop-start);
            _buf.insert(start, nh);
            diff+=strlen(nh);
        }else{
            if(start==_nhost){
                _buf.erase(_nhost-_hlen, stop-start+_hlen+2);
                diff-=(_hlen+2);
                _nhost=0;
                _nhost_end=0;
            }
            else if(start==_nprx){
                _buf.erase(_nprx-_plen, stop-start+_plen+2);
                diff-=(_plen+2);
                _nprx=0;
                _nprx_end=0;
            }
            else if(start==_nreferer){
                _buf.erase(_nreferer-_reflen, stop-start+_reflen+2);
                diff-=(_reflen+2);
                _nreferer=0;
                _nreferer_end=0;
            }
            else if(start==_nencoding){
                _buf.erase(_nencoding-_enclen, stop-start+_enclen+2);
                diff-=(_enclen+2);
                _nencoding=0;
                _nencoding_end=0;
            }
        }
        GLOGD(_buf);
        if(_nhost>start)
            _nhost+=diff;
        if(_nhost_end>start)
            _nhost_end-=diff;
        if(_nprx>start)
            _nprx+=diff;
        if(_nprx_end>start)
            _nprx_end+=diff;
        if(_nreferer>start)
            _nreferer+=diff;
        if(_nreferer_end>start)
            _nreferer_end+=diff;
        if(_nencoding>start)
            _nencoding+=diff;
        if(_nencoding_end>start)
            _nencoding_end+=diff;

        last_len+=diff;
        hdr_len+=diff;
    }

private:
    std::string     _buf;
    size_t          last_len;
    size_t          hdr_len;
    size_t          body_len;
public:
    bool            ok;
    bool            has_open;
    size_t          _nhost;
    size_t          _nhost_end;
    size_t          _nprx;
    size_t          _nprx_end;
    size_t          _nreferer;
    size_t          _nreferer_end;
    size_t          _nencoding;
    size_t          _nencoding_end;
#ifdef DEBUG
    string          _hostaddr;
#endif

    static const char* _host;// = "Host: ";
    static const char* _prox;// = "Proxy-Connection: ";
    static const char* _cont;// = "Content-Length: ";
    static const char* _conn;// = "CONNECT ";
    static const char* _reff;// = "Referer: ";
    static const char* _enco;// = "Accept-Encoding: ";

    static size_t _hlen;//     = strlen(_host);
    static size_t _plen;//     = strlen(_prox);
    static size_t _clen;//     = strlen(_cont);
    static size_t _colen;//    = strlen(_conn);
    static size_t _reflen;//   = strlen(_reff);
    static size_t _enclen;//  = strlen(_enco);
};


#endif //HTTP_HDR
