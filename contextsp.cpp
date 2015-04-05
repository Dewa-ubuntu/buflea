/*
    Marius C. 2012
*/
#include <assert.h>
#include <iostream>
#include <sstream>
#include <sock.h>
#include <strutils.h>
#include "main.h"
#include "config.h"
#include "context.h"
#include <consts.h>
#include "threadpool.h"
#include "ctxthread.h"
#include "listeners.h"
#include "ContextSP.h"

//-----------------------------------------------------------------------------
static const char HTTP_200[] = "HTTP/1.0 200 Connection established\r\n"
                               "Proxy-agent: mariuy/1.0.0\r\n\r\n";

//-----------------------------------------------------------------------------
static const char HTTP_400[] = "HTTP/1.1 400\r\n"
                               "Connection: close\r\n"
                               "Content-Type: text/html; charset=utf-8\r\n"
                               "Proxy-agent: mariuy/1.0.0\r\n\r\n";

//-----------------------------------------------------------------------------
ContextSP::ContextSP(const Conf::Ports* pconf, tcp_xxx_sock& s, SSL_CTX* pslctx):
    Context(pconf, s, pslctx),_sck_ssl_connect(false),_tflush(time(0)),_loops(0)
{
    _mode= 3;
    _pcall = (PFCLL)&ContextSP::_parse_header;
}

//-----------------------------------------------------------------------------
ContextSP::~ContextSP()
{
    //dtor
}
//-----------------------------------------------------------------------------
int  ContextSP::_pending_hdr()
{
    _rec_some();
    int code = _hdr.parse();
    if(0==code) {
        return 0; //get more
    }
    return 1; //header complette
}

int  ContextSP::_parse_header()
{
    if(_pending_hdr()==0)
        return 0;

    assert(!_sck_ssl_connect);
    //const bool con = _rock.check_connection();
    if(_hdr._nhost)
    {
        char        host[512]= {0};
        char        port[4] = "80";

        ::strcpy(host, _hdr.get_host().c_str());
        LOGT("H C: hdr ["<<_hdr.bytes()
              << "][" << _hdr.buf() << "]\n to: " << host);

        char* pp = strchr(host,':');
        if(pp) {
            *pp++=0;
        } else {
            pp = port;
        }

        _raddr.port = ::atoi(pp);
        _raddr.ip   = sock::dnsgetip(host);
        if(_raddr.ip.ipv4==0){
            throw Mex(CANNOT_CONNECT,__FILE__,__LINE__);
        }
        if(_working )
        {
            if(_rip == _raddr){
                LOGT("H sending hdr to:"<< IP2STR(_rip.ip) << ":" << _rip.port);
                return _r_send_header();
            } // else rip!=ap
            return _overwrite_connection(_raddr);
        }
        assert(!_rock.isopen());

        if(_check_acl())
        {
            return 0;
        }
        _rock.raw_sethost(_raddr.ip, htons(_raddr.port));
        _rip     = _raddr;
        return _rock_connect();
    }
    if(_working)
        return _r_send_header();

    throw Mex(CANNOT_PARSE_HTTP,__FILE__,__LINE__);
}

int  ContextSP::_empty_rock()
{
    if(--_tflush>0  &&
       _get_from_rock()==1)
    {
        usleep(0xfff);
        return 1;
    }
    _working = false;
    _rock.destroy();
    _rock.raw_sethost(_rip.ip, htons(_rip.port));
    return _rock_connect();
}


//-----------------------------------------------------------------------------
int  ContextSP::_r_send_header()
{
    if(_hdr.bytes()) {
        int err;
        if(_hdr.is_ssl == true) {//used when http proxy is configured in browser
            _sck_ssl_connect = true;
            LOGT("H CONNECT accepted");
            err = _sock.sendall((const u_int8_t*)HTTP_200,  strlen(HTTP_200), SS_TOUT);
        }
        else if(_hdr._nprx != 0){

            _hdr.prep_doc();
            err = _rock.sendall(_hdr.buf(), _hdr.bytes(), SS_TOUT);
            LOGT("H header sent: ["<<_hdr.bytes()
                  <<"][" << _hdr.buf() << "]\n");
        }
        _hdr.clear();
        if(0!=err) {
            _s_send_reply(GENFAILURE);
            _rock.destroy();
            throw Mex((REMOTE_CLOSED_ONSEND),__FILE__,__LINE__);
        }
    }
    if(_working)
        return 1;
    return Context::_r_send_header();
}

//-----------------------------------------------------------------------------
int  ContextSP::_s_send_reply(u_int8_t code)
{
    if(SUCCESS==code)
        return 1;

    LOGE("H <- " << socks_err(code));
    char msg[800];
    sprintf(msg,"%s <html><h1>proxy error: %s</h1></html>", HTTP_400, socks_err(code));
    if(0!=_sock.sendall((const u_int8_t*)msg, strlen(msg), SS_TOUT)) {
        throw Mex(CLIENT_CLOSED,__FILE__,__LINE__);
    }
    return 1;
}

//-----------------------------------------------------------------------------
int  ContextSP::_sr_read_write()
{
    if(_sck_ssl_connect) {
        return Context::_sr_read_write();
    }
    return _sr_http_read_write();
}

//-----------------------------------------------------------------------------
int  ContextSP::_sr_http_read_write()
{
    if(_sock.set() & 1) {
        if(0==_parse_header()){
            return 0;
        }
    }
    return _get_from_rock();
}

int  ContextSP::_get_from_rock()
{
    if(!_rock.isopen()){return 0;}

    int         rv = 0;
    int         rsz;
    u_int8_t*   buff = _pt->buffer(rsz);

    if(_rock.set() & 0x00000001) {
        size_t sz = _rock.receive(buff, rsz);
        if(sz == 0) {
            LOGW("H R xclosed");
            _rock.destroy();
            _sock.destroy();
             return rv;
        } else  if(sz > 0) {
            buff[sz] = 0;
            int ssz = _sock.sendall(buff, sz, SS_TOUT);
            if(0 != ssz) {
                LOGW("H C xclosed");
                _rock.destroy();
                _sock.destroy();
                return rv;
            }
            LOGT("H receied ["  << sz  <<"]");
            _stats._temp_bytes[BytesStats::eIN]+=sz;
            rv=1; //was some activity
            _load = (sz *100) / rsz;
        }
        return rv;
    }
    return 1;
}

void  ContextSP::send_exception(const char* desc)
{
    if(_sock.isopen() && _sock.is_really_connected())
    {
        if(_sock.sendall((const u_int8_t*)HTTP_200, strlen(HTTP_200),SS_TOUT) == 0)
            _sock.send(desc, strlen(desc));
    }
}

#if 1
int  ContextSP::_overwrite_connection(const AddrPort& ap)
{
    LOGT("H connection closed:" << IP2STR(_rip.ip) <<
          ":" << _rip.port <<  ". connnecting to:" <<
          IP2STR(ap.ip) << ":" << ap.port);
    _rip    = ap;
    //_tflush = time(0) + 1;
    _tflush = 32;
    _pcall  = (PFCLL)&ContextSP::_empty_rock;
    return _empty_rock();
}

#else

#endif

