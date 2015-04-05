#ifndef HTTPREQUEST_H
#define HTTPREQUEST_H

#include "os.h"
#include "include/modiface.h"
#include "config.h"
#include <string>
#include <map>

using namespace std;


struct Req {
    Req():_done(false) {
        clear();
    }
    ~Req()
    {
        if(_post_file)
            ::fclose(_post_file);
    }
    enum E_METHOD {eGET,ePUT,eHEADER};
    enum {MAX_REQUEST=4096, MAX_HDRS=32,};
    void clear() {::memset(this,0,sizeof(*this));}
    bool parse(size_t bytes, size_t& by_ext);
    void closeHeader(const Conf::Vhost* ph);
    int readPostData(const char* buff, size_t len);
//private:
    void _parse( char* header, size_t hdr_len);
    const char* getHeader(const char* key)const;
    const Headers&  Method()const {return _hdrs[0];}

    bool        _done;
    //parser
    char*       _get_line;
    size_t      _hdr_index;

    HASH_METH   _emethod;
    Headers     _hdrs[MAX_HDRS];
    GetPairs    _get[MAX_HDRS];
    Cookies     _cookie[MAX_HDRS];

    //pre formated
    char       _uri_dir[256];
    char       _uri_doc[512];

    // what we got from content after the  \r\n\r\n we pass to the handler
    // so it can continue processing
    char*      _body;
    size_t     _body_len;

    // big buffer where the pointer point
    char       _request[MAX_REQUEST];

    // post temp file
    int64_t    _post_length;
    FILE      *_post_file;
};

struct Hash
{
    Hash();

    static int GET;
    static int POST;
    static int HEAD;
    static int PUT;
    static int DEL;
    static int OPTIONS;
    static int TRACE;
    static int CONNECT;

    static int hash(const char* o){
        int rv = 0;
        while(*o++){
            rv += *o;
        }
        return rv;
    };
};


#endif // HTTPREQUEST_H
