#include <assert.h>
#include <sstream>
#include <libgen.h>
#include "main.h"
#include <strutils.h>
#include "httprequest.h"
#include <stdlib.h>
#include <fcntl.h>


int Hash::GET;
int Hash::POST;
int Hash::HEAD;
int Hash::PUT;
int Hash::DEL;
int Hash::OPTIONS;
int Hash::TRACE;
int Hash::CONNECT;

Hash _hash;

Hash::Hash()
{
    GET=hash("GET");
    POST=hash("POST");
    HEAD=hash("HEAD");
    PUT=hash("PUT");
    DEL=hash("DELETE");
    OPTIONS=hash("OPTIONS");
    TRACE=hash("TRACE");
    CONNECT=hash("CONNECT");
}

bool Req::parse( size_t bytes, size_t& by_ext)
{
    if(bytes > 4) {            // because we start 4 bytes ahead
        char* pos = strstr((char*)(_request + by_ext),"\r\n\r\n");
        if(pos == 0) {
            _get_line = strstr(_request, "\r\n"); // has first line
            by_ext = bytes - 4;//not found. hold on 4 bytes before end
        } else {
            ////std::cout << _request;
            _parse(_request, pos-_request);
            _body = pos+4;
            _body_len = bytes - (pos-_request) - 4;
            ////std::cout << "\nAfter header bytes: " << _body_len << "\n";
            _done = true;
        }
    }
    return _done;
}

/** parse as we go. kind of ugly but efficient
*/
void Req::_parse( char* header, size_t hdr_len)
{
    size_t          pos = 0;
    // can have blanks at begining
    while(pos < hdr_len && (header[pos]==' ' || header[pos]=='\t'))++pos;

    //printf("%s\r\n\r\n", header);
    // get GET
    char*   pwalkonHdr = header;

    Headers* ph = &_hdrs[_hdr_index];
    ph->key = str_up2chr(&pwalkonHdr ,' ', &::toupper);
    ph->val = str_up2chr(&pwalkonHdr, ' ');

    _emethod = (HASH_METH)Hash::hash(ph->key);
    char* pargs;
    if((pargs = (char*)_ttstrchr(ph->val,'?')) != 0) {
        *pargs++ = 0; // end with 0 all arguments
        // extract the GetPairs
        size_t gets = 0;
        GetPairs* pget = &_get[0];
        for(; gets < MAX_HDRS; gets++) {
            pget->key=str_up2chr(&pargs ,'=');
            if(0 == *pget->key){pget->key=0;break;}
            pget->val=str_up2chr(&pargs ,'&');
            ++pget;
        }
    }

    ++_hdr_index;
    ph = &_hdrs[_hdr_index];
    ph->key = "_VER"; //fabricates entry
    ph->val = str_up2chrs(&pwalkonHdr, "\r\n");
    ++_hdr_index;
    /// done with first line. go on all others
    //
    // extract all as we go
    //
    for(;_hdr_index < MAX_HDRS; _hdr_index++) {
        ph = &_hdrs[_hdr_index];
        const char* prekey = str_up2chrs(&pwalkonHdr, ": ", &::toupper);
        if(!strcmp(prekey,"COOKIE")) //needs separate attention
        {
            char* ptr_start = str_up2chrs(&pwalkonHdr, "\r\n");
            size_t nCooks = 0;
            Cookies* pck = _cookie;
            while(ptr_start < pwalkonHdr && nCooks < MAX_HDRS)
            {
                pck->key = str_up2chrs(&ptr_start, "=");
                if(0 == *pck->key){pck->key=0;break;}
                pck->val = str_up2chrs(&ptr_start, "; ");
                ++pck;
            }

            --_hdr_index;
            continue;
        }
        ph->key = prekey;
        ph->val = str_up2chrs(&pwalkonHdr, "\r\n");
        if(pwalkonHdr[0]=='\r' && pwalkonHdr[1]=='\n'){
            ++ph;  ph->key=0; ph->val=0;
            break;
        }
    }
    ++_hdr_index;
    return;
}


void Req::closeHeader(const Conf::Vhost* ph)
{
    char uri_fulldoc[512];

    size_t l = str_urldecode(uri_fulldoc, _hdrs[0].val, false);
    while(uri_fulldoc[l] != '/')--l;
    strcpy(_uri_doc, &uri_fulldoc[l+1]);
    strncpy(_uri_dir, uri_fulldoc, l+1);
    //fix
    if(_uri_dir[0]==_uri_doc[0] && _uri_doc[0] =='/')
    {_uri_doc[0]=0;}
    //
    // default if not
    //
    if(*_uri_doc==0){
        struct stat fstat;
        char loco[PATH_MAX];

        std::istringstream iss(ph->index);
        std::string token;
        while(getline(iss, token, ',')) {
            ::sprintf(loco, "%s%s/%s", ph->home.c_str(), _uri_dir, token.c_str());
            if(0 == stat(loco, &fstat)){
                strcpy(_uri_doc, token.c_str());
            }
        }
    }
}

int Req::readPostData(const char* buff, size_t len)
{
    if(_post_file == 0)
    {
        //const char *ptype = getHeader("CONTENT-TYPE");
        const char *plen = getHeader("CONTENT-LENGTH");
        if(0 == plen){ return 0; }

        _post_length = ::atoll(plen);
        if(0 == _post_length){
            assert(_body_len == 0); // self check
            return 0;
        }
        _post_file = ::tmpfile();
        ::fcntl(fileno(_post_file), F_SETFD, FD_CLOEXEC);

        if(0==_post_file){
            return -1;
        }
    }
    size_t written = fwrite(buff, 1, len,  _post_file);
    assert(written == len);
    _post_length -= written;
    if(0 == _post_length){
        rewind(_post_file);
    }
    return  _post_length;
 }


const char* Req::getHeader(const char* key)const
{
    for(size_t k = 0 ; k< _hdr_index; k++) {
        if(_hdrs[k].key == 0)
            break;
        if(key[0] == _hdrs[k].key[0]) {
            if(!strcmp(key, _hdrs[k].key)) {
                return _hdrs[k].val;
            }
        }
    }
    return 0;
}
