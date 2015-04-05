#ifndef MODULES_H
#define MODULES_H

#include <modiface.h>
#include "config.h"

#define MAX_IFACES  32
//------------------------------------------------------------------------------
typedef void* SoHandler;

struct SoEntry
{
    SoEntry(SoHandler);
    ~SoEntry();

    SoHandler                   _sohndl;
    pFn_getFoo                  _so_get;
    pFn_releaseFoo              _so_release;
};

typedef std::map<std::string, SoEntry*>           SoMap;
typedef std::map<std::string, SoEntry*>::const_iterator SoMapIt;

class Modules
{
public:
    Modules();
    virtual ~Modules();
    const SoEntry* getMod(const char* ext)const;
    const SoMap&   mods()const{return _mods;};
    bool hasSome()const{return _imods>0;}
protected:
private:
    SoMap   _mods;
    size_t  _imods;
};

extern Modules*  __modules;

#endif // MODULES_H
