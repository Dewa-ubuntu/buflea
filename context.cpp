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
#include <sock.h>
#include <strutils.h>
#include "main.h"
#include "configprx.h"
#include "context.h"
#include <consts.h>
#include "threadpool.h"
#include "ctxthread.h"
#include "listeners.h"
#include "minidb.h"
#include "tasker.h"

//-----------------------------------------------------------------------------
#define LOCAL_SZ 8912


//-----------------------------------------------------------------------------
static int __ctx;
int        __ctxc;

//-----------------------------------------------------------------------------
Ctx::Ctx(const ConfPrx::Ports* pconf, tcp_xxx_sock& s):
    _pcall(&Ctx::_ctx_init),
    _pt(0),
    _pconf(pconf),
    _c_socket(s),
    _mode(P_NONE),
    _blog(0),
    _last_time(0),
    _start_time(0),
    _unicid(0),
    _working(false),
    _negok(false),
    _hdrsent(false),
    _refs(0),
    _pcli_isssl(0),
    _phost_isssl(0),
    _creatime(time(0)),
    _clireqs(0),
    _getissued(false),
    _des(false)
{
    _pactive = this;
    _tc = 'X';
    _blog = GCFG->_glb.blog;
    _cliip = _c_socket.getsocketaddr();
    _cliip.set_port(0); // to satisty = op when saving and searching

    do
    {
        AutoLock _a(&__tp->_hctxcount);
        usleep(0xF);
        _unicid = __ctx++;
        ++__ctxc;
    }
    while(0);

    LOGI("C+:" << _unicid << " " <<_pconf->socks
         << " from:" << IP2STR(_cliip)
         << " ctx:" << __ctxc);

}

//-----------------------------------------------------------------------------
Ctx::Ctx(const Ctx* parent)
{

}

//-----------------------------------------------------------------------------
Ctx::~Ctx()
{
    do
    {
        AutoLock _a(&__tp->_hctxcount);
        clear();
        --__ctxc;
        LOGI("C- uid:" << _unicid << " " <<_pconf->socks
             << " from:" << IP2STR(_cliip)
             << " ctx:" << __ctxc);

        if(0 == __ctxc)
        {
            LOGI("NO CONTEXTS. IDLING....");
            __ctx = 0;
        }

    }while(0);
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_ctx_init()
{
    if(_pconf->hostisssl || _pconf->clientisssl)
    {
        if(__pl->sslglob()==0)
        {
            GLOGE("CONTEXT is SSL but ssl lib was not loaded");
            return R_KILL;
        }
        else
        {
            if(!ssl_bind(_pconf->clientisssl ? __pl->sslglob()->accept_ctx() : 0,
                         _pconf->hostisssl ? __pl->sslglob()->connect_ctx() : 0))
            {
                GLOGW("Cannot bind ssl sockets");
            }
        }
    }
    if(_pcli_isssl)
    {
        if(!_c_socket.ssl_pre_accept(this))
            return R_KILL;

        LOGI(_ls('C')<<IP2STR(_cliip) << "--(o   " << IP2STR(_r_socket.getsocketaddr()) << _ls('H'));
        _pcall = &Ctx::_ssl_accept;
        return _ssl_accept();
    }
    return _create_ctx();
}


CALLR   Ctx::_ssl_accept()
{
    if(_c_socket.set())
    {
        int rv = _c_socket.ssl_accept(this);
        if(rv==0) return R_KILL;
        if(rv==-1)return R_CONTINUE;
        return _create_ctx();
    }
    return R_CONTINUE;
}


CALLR      Ctx::_ssl_connect()
{
    if(_c_socket.set())
    {
        int rv = _r_socket.ssl_connect(this);
        if(rv==0) return R_KILL;
        if(rv==-1)return R_CONTINUE;
        _pcall=(PFCLL)&Ctx::_r_is_connected;
    }
    return R_DONE;
}


//-----------------------------------------------------------------------------
bool   Ctx::ssl_bind(SSL_CTX* psl, SSL_CTX* pcl)
{
    assert(_pcli_isssl==0);
    assert(_phost_isssl==0);
    _pcli_isssl = psl;
    _phost_isssl = pcl;
/*
    if(_pcli_isssl)
    {
        return _c_socket.ssl_accept(this);
    }
*/

    return true;
}

//-----------------------------------------------------------------------------
void   Ctx::clear()
{
    destroy();
    if(_blog && _logcntn.tellp())
    {
        __tp->accumulate_log(_logcntn, _cliip);
    }
}

//-----------------------------------------------------------------------------
CALLR   Ctx::spin()
{
    CALLR done;
    try
    {
        done = (this->*_pcall)();
    }
    catch(Mex& e)
    {
        done = R_KILL;

        send_exception(e.desc());
        LOGE("mex:" <<  e.desc());
        destroy();
    }
    return done;
}

//-----------------------------------------------------------------------------
int Ctx::set_fd (fd_set& rd, fd_set& wr, CtxesThread* pt)
{
    _pt      = pt;
    return _set_fd (rd, wr);
}

//-----------------------------------------------------------------------------
/*::
int Ctx::_set_io_fd (fd_set& rd, fd_set& wr)
{
    register int n = 0;
    register int s;

    s = _c_socket.socket();
    if(_c_socket.isopen())   //rec
    {

        if(_sen_buff->can_read())
            FD_SET(s, &rd);
        FD_SET(s, &wr);
        n = max(s,n);
    }
    if(_r_socket.isopen())   //sent
    {
        s = _r_socket.socket();

        if(_rec_buff->can_read())
            FD_SET(s, &rd);
        FD_SET(s, &wr);
        n=max(s,n);
    }
    return n;
}
*/

//-----------------------------------------------------------------------------
int Ctx::_set_fd (fd_set& rd, fd_set& wr)
{
    register int n = 0;
    register int s = _c_socket.socket();
    _c_socket.reset();

    if(_c_socket.isopen())   //rec
    {
        FD_SET(s, &rd);
        FD_SET(s, &wr);
        n=max(s,n);
    }
    _r_socket.reset();
    if(_r_socket.isopen())   //sent
    {
        s = _r_socket.socket();
        FD_SET(s, &rd);
        FD_SET(s, &wr);
        n=max(s,n);
    }
    return n;
}

//-----------------------------------------------------------------------------
int  Ctx::is_fd_set(fd_set& rd, fd_set& wr)
{
    register int s = _c_socket.socket();
    if(s>0)
    {
        _c_socket.set((FD_ISSET(s, &rd) ? 0x1 : 0));
        _c_socket.set((FD_ISSET(s, &wr) ? 0x2 : 0));
    }
    s   = _r_socket.socket();
    if(s > 0)
    {
        _r_socket.set((FD_ISSET(s, &rd) ? 0x1 : 0));
        _r_socket.set((FD_ISSET(s, &wr) ? 0x2 : 0));
    }
    return (_r_socket.set()|_c_socket.set());
}

//-----------------------------------------------------------------------------
int Ctx::clear_fd(fd_set& rd, fd_set& wr,
                      bool delete_oldies, time_t delay_time,
                      int ctxIndex)
{
    register int done = 0;
    register int s = _c_socket.socket();
    _c_socket.reset();
    if(s > 0)
    {

        FD_CLR(s, &rd);
        FD_CLR(s, &wr);

        done=1;
    }

    int r = _r_socket.socket();
    _r_socket.reset();
    if(r > 0)
    {

        FD_CLR(r, &rd);
        FD_CLR(r, &wr);
        done=1;
    }
    /*
        if(_refs > 0)
        {
            return 1; //not done
        }
    */

    if((delete_oldies || done==0) && _was_idling(delay_time, ctxIndex))
    {
        if(s > 0)
        {
            if(!_working)   //cound not get over protocol
            {
                _s_send_reply(TTLERR);
            }
        }
        destroy();
    }
    return done;
}

//--------
void  Ctx::destroy()
{
    if(_c_socket.isopen())
        _destroy_clis();
    if(_r_socket.isopen())
        _destroy_host();
}


void   Ctx::_destroy_clis()
{
    _c_socket.destroy();
    LOGT(_ls('C')<<"x--o---"<<_ls('H'));

}

void   Ctx::_destroy_host()
{
    _r_socket.destroy();
    LOGT(_ls('C') << "---o--x"<<_ls('H'));
}

int  Ctx::_rec_some()
{
    if(_c_socket.set() & 0x00000001)
    {
        u_int8_t loco[2048];

        int sz = _c_socket.receive(loco, sizeof(loco)-1);
        if(sz==0)return 0; //socket closed
        if(sz > 0)
        {
            if(sz + _hdr.bytes() > 16384)
            {
                throw Mex(OUT_OF_MEMORY,__FILE__,__LINE__, "overflow");
            }
            _hdr.append((const char*)loco, sz);
        }
        return _hdr.bytes();
    }
    return -1; //kepp waiting
}

//-----------------------------------------------------------------------------
/*
    C------------- PRX
    C -----------> S45 hdr
    C <----------- OK (in redirection)
    C -----------> GET doc HTTP...
    C <----------- moved 302 master.server

*/
bool Ctx::_is_access_blocked(const SADDR_46& addr, const char* host, const char* refh)
{
    // no acl's at all
    if(_pconf->openacl==1 || __db->is_admin(addr))
    {
        GLOGD(addr.c_str());
        return false;
    }
    const int hrule = GCFG->_glb.hostsfilerule; // 0 hosts in list are deniable, 1 ire allowable,

    // user whats to see the authurl site, allow
    if(_raddr.compare_range_ip(GCFG->_glb.authurl_ip))
    {
        return false;
    }

    if(!__db->is_client_allowed(_cliip))
    {
        sleep(1);
        return _go_redirect("Not_registerred");
    }
    if(hrule>=0)
    {
        if(host)
        {
            bool b = __db->is_host_allowed(host);
            if((hrule==0 && b) ||  (hrule==1 && !b))
            {
                string msg = "Host:_"; msg += host; msg += "_is_blocked_by_proxy_host_rules";
                return _go_redirect(msg.c_str());
            }
        }
        else
        {
            if(!__db->check_hostaddr(addr))
            {
                __task->schedule(tasker::eDNS_REVERSE, addr.c_str());
                return false;//allow for now thill the name is added to the reverse dns
            }
            bool b = __db->is_host_allowed(addr);
            if((hrule==0 && b) ||  (hrule==1 && !b))
            {
                string msg = "Host:_"; msg += addr.c_str(); msg += "_is_blocked_by_proxy_host_rules";
                return _go_redirect(msg.c_str());
            }
        }
    }

    return false;
}

bool Ctx::_go_redirect(const char* reason)
{
    _reason += reason;
    LOGT(IP2STR(_cliip) <<" to authurl:" << GCFG->_glb.authurl << ", " << reason);
    _s_send_reply(0);
    if(_mode != P_HTTP)
    {
        _clear_header();
    }
    _pcall=(PFCLL)&Ctx::_redirecting;
    return true;
}

CALLR Ctx::_redirecting()
{
    LOGT(IP2STR(_cliip) <<" redirecting: " << GCFG->_glb.authurl);
    if(!_hdr.ok)
    {
        if(_rec_some()>0)
        {
            _hdr.parse();   // dont care, we jumpto the ip
            LOGH("header:[\n" << _hdr.buf() << "\n]");
        }
    }
    return _r_redirect();   //  does not return
}

//-----------------------------------------------------------------------------
int  Ctx::_deny_dest_host(const char* fbd)
{
    int         k = 16;
    u_int8_t    dontcare[64];
    bio_unblock bub(&_c_socket);

    while(_c_socket.receive(dontcare, sizeof(dontcare))>0 && --k)
        usleep(0x1F);

    stringstream ost;
    ost << HTTP_400;
    _c_socket.sendall((const u_int8_t*)ost.str().c_str(), ost.str().length(), SS_TOUT);
    throw Mex(BLOCKED_HOST,__FILE__,__LINE__);
    return 0; //not reached
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_r_redirect()
{
    char host[256] = {0};
    if(_hdr._nhost)
    {
        ::strcpy(host, _hdr.get_host().c_str());

        LOGI(" redir:" <<  IP2STR(_cliip) << "->"
             << GCFG->_glb.authurl << " with:" << host );
    }
    else
    {
        strcpy(host, IP2STR(_raddr));
        LOGI(" redir:" <<  IP2STR(_cliip) << "->"
             << GCFG->_glb.authurl << "  with:" << IP2STR(_raddr) );
    }

    stringstream ost;

    int rv =  __db->check_bounce(_cliip);
    if(rv == -1)
    {
        _reason="Many_Gotcha_Failures.IP_blocked_for_15_Minutes"; //added to blocked from bounced. will be unlocked in 1H
    }
    else if(rv == 1)
    {
        _reason="Failed-gotcha.";
    }
    _get_redirect_doc(ost, host);
    _c_socket.sendall((const u_int8_t*)ost.str().c_str(), ost.str().length(),SS_TOUT);
    _reason.clear();
    _clear_header();
    return R_KILL;
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_r_pending()
{
    if(_r_socket.set() & 0x2)
    {
        if(!_r_socket.is_really_connected())
        {
            _s_send_reply(NOHOST);
            LOGI(_ls('C')<<IP2STR(_cliip) << "---o>--x" << IP2STR(_raddr)<<_ls('H'));
            return R_KILL;
        }
        LOGI(_ls('C')<<IP2STR(_cliip) << "---o---" << IP2STR(_r_socket.getsocketaddr()) << _ls('H'));

        if(_phost_isssl)
        {
            _pcall=(PFCLL)&Ctx::_ssl_connect;
            return _ssl_connect();
        }
        else
        {
            _pcall=(PFCLL)&Ctx::_r_is_connected;
        }
    }
    return R_CONTINUE;
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_r_is_connected()
{
    _r_socket.tcp_cli_sock::setconnected();
    _working = true;
    _negok   = true;
    _pcall   = (PFCLL)&Ctx::_io;
    return R_CONTINUE;
}

//-----------------------------------------------------------------------------
// the bsp [accum, last accum, bps, total];
bool Ctx::_was_idling(time_t delay, int isfirstone)
{
    bool br = true;
    //store last spin bytes
    if((_stats._temp_bytes[BysStat::eIN] | _stats._temp_bytes[BysStat::eOUT]) != 0)
    {
        //was not idling
        _stats._total_bytes[BysStat::eIN] += _stats._temp_bytes[BysStat::eIN];
        _stats._total_bytes[BysStat::eOUT] += _stats._temp_bytes[BysStat::eOUT];
        br = false;
        //cout << "not idling\n" << delay << "\n";
    }
    if(delay==0)delay=1;
    //calc bps
    _stats._bps_spin[BysStat::eIN]  = _stats._temp_bytes[BysStat::eIN] / delay;
    _stats._bps_spin[BysStat::eOUT] = _stats._temp_bytes[BysStat::eOUT] / delay;

    _pt->save_ctx_state(_cliip, _stats, isfirstone);//store values in parent
    _stats._temp_bytes[BysStat::eOUT]=0;
    _stats._temp_bytes[BysStat::eIN]=0;
    return br;
}


//-----------------------------------------------------------------------------
CALLR  Ctx::_cli2host( u_int8_t* buff, int rsz)
{
    int sz = _c_socket.receive(buff, rsz);
    if(sz>0)
    {
        if(_working && _new_request(buff, sz))
        {
            GLOGE("_working && _new_request  ?!?!?!?!?");
            _reuse_context();
            throw (R_CONTINUE);
        }
        int ssz=_r_socket.sendall(buff, sz, SS_TOUT);
        if(ssz>0)
            return R_KILL;

        if(_negok && (_mode==P_SOCKS4 || _mode == P_SOCKS5))
        {
            _negok=false;
            _hdrsent=true; //reg first page
        }
        _stats._temp_bytes[BysStat::eOUT]+=sz;

         if((GCFG->_blog & 0x40) && (buff[0]=='G' || buff[0]=='P' || buff[0]=='H'))
         {
            if(sz > 256)
            {
                char c = buff[256];
                buff[256]=0;
                LOGH("\n"<<(const char*)buff<<","<< sz <<"\n");
                buff[256]=c;
            }else
            {
                LOGH("\n"<<(const char*)buff<<","<< sz <<"\n");
            }
        }
        LOGT(_ls('C')<<sz << "-->o-->"<<_ls('H')<<(sz-ssz));
    }
    return sz==0 ? R_KILL : R_CONTINUE;
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_host2cli(u_int8_t* buff, int rsz)
{
    int sz = _r_socket.receive(buff, rsz);
    if(sz>0)
    {
        int ssz =_c_socket.sendall(buff, sz, SS_TOUT);
        if(0==ssz)
        {
            LOGT(_ls('C')<<(sz-ssz) << "<--o<--"<<_ls('H')<<(sz));


            _stats._temp_bytes[BysStat::eIN]+=sz;

             if(GCFG->_blog & 0x40)
             {
                if(sz > 256)
                {
                    char c = buff[256];
                    buff[256]=0;
                    LOGH("\n"<<(const char*)buff<<","<< sz <<"\n");
                    buff[256]=c;
                }else
                {
                    LOGH("\n"<<(const char*)buff<<","<< sz <<"\n");
                }
            }
        }
        return ssz!=0?R_KILL:R_CONTINUE;
    }
    return sz==0?R_KILL:R_CONTINUE;
}

//-----------------------------------------------------------------------------
CALLR  Ctx::_io()
{
    int         rsz = 0;
    u_int8_t*   buff = _pt->buffer(rsz);

    if(_c_socket.set() & 0x00000001)
    {
        if(_cli2host(buff,rsz)==R_KILL)
            return R_KILL;
        return R_CONTINUE;
    }
    if(_r_socket.set() & 0x00000001)
    {
        if(_host2cli(buff, rsz)==R_KILL)
            return R_KILL;
        return R_CONTINUE;
    }
    return R_CONTINUE;
}

//----------------------------------------------------------------------------
void Ctx::_check_log_size()
{
    static size_t mlsz = GCFG->_glb.nlogbytes;
    if((size_t)_logcntn.tellp() > mlsz)
    {
        __tp->accumulate_log(_logcntn, _cliip);
    }
}

//----------------------------------------------------------------------------
void Ctx::_get_redirect_doc(stringstream& ost, const char* link)
{
    //ost<< HTTP_200;
    usleep(8912);
    ost << "HTTP/1.1 302 Found\r\n";
    ost << "Location: " << GCFG->_glb.authurl <<"?ip="<<IP2STR(_cliip)<<"&at=" <<_pconf->authtoken <<"&reason="<<_reason<<"\r\n";
    ost << "Connection: close\r\n\r\n";
    usleep(8912);
    LOGI(ost.str());
}

//----------------------------------------------------------------------------
CALLR  Ctx::_host_connect(TcpPipe& rock)
{
    assert(rock.isopen()==false);
    rock.pre_set(GCFG->_pool.socketsize/4, GCFG->_pool.socketsize);
    SADDR_46& rs = rock.Rsin();

    LOGI(_ls('C')<<IP2STR(_cliip) << "---o>>>" << IP2STR(rs)<<_ls('H'));

    assert(rs.sin_family==AF_INET);
    assert(rs.sin_port!=0);
    assert(rs.sin_addr.s_addr!=0);
    if(0 == rock.raw_connect_sin())
    {
        char err[32];
        sprintf(err,"tcp-error: %d",rock.error());
        _s_send_reply(NOHOST, err);
        throw Mex(CANNOT_CONNECT,__FILE__,__LINE__);
    }
    rock.set_blocking(_pconf->blocking);
    if(_pconf->hostisssl)
    {
        if(!rock.ssl_pre_connect(this))
            return R_KILL;
        LOGI(_ls('C')<<IP2STR(_cliip) << "---o--)" << IP2STR(_r_socket.getsocketaddr()) << _ls('H'));
    }
    if(rock.isconnecting())
    {
        LOGD(_ls('C')<<IP2STR(_cliip) << "---o>>?" << IP2STR(rs)<<_ls('H'));
        _pcall = (PFCLL)&Ctx::_r_pending;
        return R_CONTINUE;
    }
    if(_phost_isssl)
    {
        _pcall=(PFCLL)&Ctx::_ssl_connect;
        return _ssl_connect();
    }
    _pcall=(PFCLL)&Ctx::_r_is_connected;
    return _r_is_connected();
}

int  Ctx::_spoof_cookie()
{
    return 0;
}


void    Ctx::metrics(std::stringstream& str, SinOut& bpss, size_t all)const
{
    //AutoLock _a(&__tp->_hctxcount);


    str << "<tr><td>"<<_tc<<"</td>\n" <<
            "<td>" << _unicid << "</td>" <<
            "<td>" <<_stats._bps_spin[BysStat::eIN]  << "</td>\n" <<
            "<td>" <<_stats._bps_spin[BysStat::eOUT] << "</td>\n" <<
            "<td>" << _cliip.c_str() << "<-->" << _raddr.c_str() << "</td></tr>";


}

void    Ctx::_set_rhost(const SADDR_46& addr, const char* host, const char* referer)
{
    // jumpip if configured
    if(GCFG->_glb.jumpip.size())
    {
        auto f = GCFG->_glb.jumpip.find(addr);
        if(f != GCFG->_glb.jumpip.end())
        {
            const SADDR_46& r = (*f).second;
            GLOGD("Jumping host IP: (dns) " << _raddr.c_str() << ":" << _raddr.port() <<"-->"<< r.c_str() << ":"<<r.port());
            _raddr = r;
            _r_socket.raw_sethost(r);
        }
    }
    else
    {
        _raddr=addr;
        _r_socket.raw_sethost(addr);
    }
}


//-----------------------------------------------------------------------------
void  Ctx::_reuse_context()
{
    _destroy_host();
    _working = false;
    _negok = false;
    _getissued=false;
    _hdrsent = false;
    if(_blog && _logcntn.tellp())
    {
        __tp->accumulate_log(_logcntn, _cliip);
        _logcntn.str("");
        _logcntn.clear();
        _logcntn.seekp(0);
        _logcntn.seekg(0);
    }
    LOGI("C*:" << _unicid << " " <<_pconf->socks
     << " from:" << IP2STR(_cliip)
     << " ctx:" << __ctxc);
}


//-----------------------------------------------------------------------------
void    Ctx::_clear_header(bool transp)
{
    _hdr.clear();
#ifdef _PERSONAL
    if(transp)
    {
        _header._len=0;
    }
#endif //#ifdef _PERSONAL
}

//-----------------------------------------------------------------------------
int    Ctx::_s_send_reply(u_int8_t code, const char* info)
{
    if(SUCCESS != code)
    {
        _rec_some();
        if(_hdr.bytes())
        {
            LOGH("Partial request \n[" << _hdr.buf() << ","<<_hdr.bytes()<<"]\n");
        }
        if(_pconf->openacl==0)
            __db->check_bounce(_cliip);
    }
    return 0;
}


//-----------------------------------------------------------------------------
void    Ctx::close_sockets()
{
    if(_c_socket.isopen())
        _c_socket.destroy(false);
    if(_r_socket.isopen())
        _r_socket.destroy(false);
}



const char*  Ctx::_ls(const char c)const
{
    static const char* posb[8]={
                            "[ C ]",
                            "[ H ]",
                            "[(C)]",
                            "[(H)]",
                                };

    if(_pcli_isssl && _phost_isssl)
    {
        return c=='C' ? posb[2] : posb[3];
    }
    if(_pcli_isssl)
    {
        return c=='C' ? posb[2] : posb[0];
    }
    if(_phost_isssl)
    {
        return c=='C' ? posb[0] : posb[3];
    }
    return c=='C' ? posb[0] : posb[1];

}



