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


#ifndef CONTEXT_H
#define CONTEXT_H

#include <string>
#include <map>
#include <vector>
#include <os.h>
#include <sock.h>
#include "tinyclasses.h"
#include "main.h"
#include "configprx.h"
#include "tcppipe.h"
#include "sslcrypt.h"
#include "httphdr.h"
//-----------------------------------------------------------------------------
// BASE FOR CONTEXT


class CtxesThread;
class SrvSock;
class Ctx;

//----------------------------------------------------------------------------
typedef enum __E_SOCKS{
    eALLOWED,
    eREJECTED,
    eREDIRECTED,
}E_SOCKS;

//----------------------------------------------------------------------------
#define SS_TOUT         8912
#define HTTP_HDRSZ      1000 //100 clients 100k
#define HTTP_HDR_OVER   16284

typedef TcpPipe tcp_xxx_sock;



//----------------------------------------------------------------------------
typedef enum _CALLR{
    R_KILL=-1,
    R_DONE=0,
    R_CONTINUE=1,
}CALLR;

typedef CALLR (Ctx::*PFCLL)();

//----------------------------------------------------------------------------
struct OverBuff{
    OverBuff(size_t sz):_got(0),_sent(0),
                _nbuff(sz),
                _buff(new u_int8_t[sz]){};
    ~OverBuff(){delete[] _buff;};

    inline u_int8_t* writer(){return _buff+_sent;}
    inline u_int8_t* reader(){return _buff+_got;}
    inline size_t room(){return _nbuff-_got;}
    inline size_t ammnt(){return _got-_sent;}
    inline size_t cap()const{return _nbuff;}
    inline void   sent(size_t s){ _sent += s;}
    inline void   recd(size_t s){ _got += s;}
    inline bool   can_read(){return _nbuff-_got>0;}
    inline size_t can_write(){return _got-_sent>0;}
    inline void   reset(bool force=false){if (_got==_sent || force) {_got=0;_sent=0;}}
private:
    size_t         _got;
    size_t         _sent;
    size_t         _nbuff;
    u_int8_t*      _buff;
};

//----------------------------------------------------------------------------
#define slots protected:    //
//----------------------------------------------------------------------------
class Ctx
{
protected:
    enum{
        P_NONE=0,
        P_DNSSOCK=1,
        P_HTTP=3,
        P_SOCKS4=4,
        P_SOCKS5=5,
        P_CONTORL=6,
        CTRL_SOCK=8,
        P_PASSTRU,
    };

    enum{
        SOCK_ON =0x1,
        ROCK_ON =0x2,
        SSL_IN =0x4,
        SLL_OUT =0x8,
    };

public:
    friend class CtxMod;
    friend class CtxesThread;
    friend class TcpPipe;

    Ctx();
    Ctx(const ConfPrx::Ports* conf, tcp_xxx_sock& s);
    Ctx(const Ctx* parent);
    virtual ~Ctx();

    int     set_fd (fd_set& rd, fd_set& wr , CtxesThread* pt);
    int     is_fd_set (fd_set& rd, fd_set& wr);
    size_t  uid()const{return _unicid;}
    void    destroy();
    bool    was_active(time_t delay);
    void    fill_buffer(const SocksHdr& h){_hdr = h;}
    void    fill_buffer(const uint8_t* p, int l){_hdr.append((const char*)p,(size_t)l);}
    CALLR   spin();
    CtxesThread*   pthread_ctx(){return _pt;}
    const   ConfPrx::Ports*  pconf()const{return  _pconf;};
    virtual int     clear_fd(fd_set& rd, fd_set& wr, bool delete_oldies, time_t secs, int);
    virtual void    clear();
    virtual void    send_exception(const char* desc)=0;
    bool    ssl_bind(SSL_CTX* psl, SSL_CTX* pcl);
    void    metrics(std::stringstream& str, SinOut& bpss, size_t all)const;
    void    inc(){++_refs;}
    void    dec(){--_refs;}
	bool    isdead(){
            return !_c_socket.isopen() && !_r_socket.isopen();
	}
	void    close_sockets();
protected:
    virtual int  _s_send_reply(u_int8_t code, const char* info=0);
    virtual bool _new_request(const u_int8_t* buff, int bytes)=0;

    int     _rec_some();
    int     _set_fd (fd_set& rd, fd_set& wr);
    void    _check_header(const char* buff, size_t sz);
    void    _reuse_context();
    void    _get_redirect_doc(stringstream& ost, const char* link);
    bool    _was_idling(time_t, int);
    int     _deny_dest_host(const char* fbd);
    void    _check_log_size();
    int     _spoof_cookie();
    bool    _go_redirect(const char* reason);
    bool    _is_access_blocked(const SADDR_46& addr, const char* host, const char* refh);
    void    _set_rhost(const SADDR_46& addr, const char* host=0, const char* referer=0);

    void    _cache_45hdr(const uint8_t* pbuff, int len);
    void    _clear_header(bool transp=false);
    void    _destroy_clis();
    void    _destroy_host();
    const   char*  _ls(const char c)const;
slots
    virtual CALLR _io();
    virtual CALLR  _create_ctx()=0;
    virtual CALLR _r_is_connected();
    CALLR   _r_pending();
    CALLR   _host_connect(TcpPipe& rock);
    CALLR   _redirecting();

private:
    CALLR   _ctx_init();
    CALLR   _cli2host(u_int8_t* pb, int len);
    CALLR   _host2cli(u_int8_t* pb, int len);
    CALLR    _r_redirect();
    CALLR   _ssl_accept();
    CALLR   _ssl_connect();

protected:
    mutex               _lmutex;
    PFCLL               _pcall;
    CtxesThread        *_pt;
    const ConfPrx::Ports  *_pconf;
    tcp_xxx_sock       _c_socket;
    TcpPipe            _r_socket;
    int                _mode;
    size_t             _blog;
    time_t             _last_time;
    time_t             _start_time;
    size_t             _unicid;
    bool               _working;
    bool               _negok;
    bool               _hdrsent;
    int                _refs;
    SSL_CTX *          _pcli_isssl;
    SSL_CTX *          _phost_isssl;
    BysStat            _stats;
    SADDR_46           _cliip;
    SADDR_46           _raddr;
    SocksHdr           _hdr;
    stringstream       _logcntn;
    char               _tc;
    int                _creatime;
    int                _clireqs;
    Ctx*                _pactive;
    bool               _getissued;
    string             _reason;
    bool               _des;
};


//----------------------------------------------------------------------------
#define spacein(t_)  (sizeof(t_)-1)

#ifdef DEBUG

#define LOGI(x) if(_blog & 0x1) \
do{\
    std::cout << str_time() <<" I:"<<_tc<<" [ctx:"<<this->_unicid<<"]: " << x << "\n"; \
}while(0);

#define LOGW(x) if(_blog & 0x2) \
do{\
    std::cout << str_time() <<" W:"<<_tc<<" [ctx:"<<this->_unicid<<"]: " << x << "\n"; \
}while(0);

//-----------------------------------------------------------------------------
#define LOGE(x) if(_blog & 0x4) \
do{\
    std::cout << str_time() <<" E:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n";\
}while(0);

#define LOGT(x) if(_blog & 0x8) \
do{\
    std::cout << str_time() <<" T:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; \
}while(0);

#define LOGD(x) if(_blog & 0x10) \
do{\
    std::cout << str_time() <<" D:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; \
}while(0);

#define LOGX(x) if(_blog & 0x20) \
do{\
    std::cout << str_time() <<" X:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n";\
}while(0);

#define LOGH(x) if(_blog & 0x40) \
do{\
    std::cout << str_time() <<" H:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n";\
}while(0);

#else

#define LOGI(x) if(_blog & 0x1) \
do{\
    _logcntn << str_time() <<" I:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);


#define LOGW(x) if(_blog & 0x2) \
do{\
    _logcntn << str_time() <<" W:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);

//-----------------------------------------------------------------------------
#define LOGE(x) if(_blog & 0x4) \
do{\
    _logcntn << str_time() <<" E:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);

#define LOGT(x) if(_blog & 0x8) \
do{\
    _logcntn << str_time() <<" T:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);

#define LOGD(x) if(_blog & 0x10) \
do{\
    _logcntn << str_time() <<" D:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);


#define LOGX(x) if(_blog & 0x20) \
do{\
    _logcntn << str_time() <<" X:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);

#define LOGH(x) if(_blog & 0x40) \
do{\
    _logcntn << str_time() <<" H:"<<_tc<<":[ctx:"<<this->_unicid<<"]: " << x << "\n"; _check_log_size();\
}while(0);


#endif

#endif // CONTEXT_H
