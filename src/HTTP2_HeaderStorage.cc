#include <string.h>

#include "HTTP2_HeaderStorage.h"
#include "HTTP2.h"

#include "zeek/util.h"
#include "zeek/Val.h"
#include "zeek/Reporter.h"

#include "debug.h"

using namespace analyzer::mitrecnd;

HTTP2_HeaderStorage::HTTP2_HeaderStorage(std::string& name, std::string& value)
{
    this->name = name;
    this->val = value;
}

HTTP2_HeaderStorage::HTTP2_HeaderStorage(const HTTP2_HeaderStorage& orig)
{
    this->name = orig.name;
    this->val= orig.val;
}

HTTP2_HeaderList::HTTP2_HeaderList()
{
}

HTTP2_HeaderList::~HTTP2_HeaderList()
{
    flushHeaders();
}

void HTTP2_HeaderList::addHeader(std::string& name, std::string& value)
{
    this->addHeader(HTTP2_HeaderStorage(name, value));
}

void HTTP2_HeaderList::addHeader(HTTP2_HeaderStorage& header)
{
    DEBUG_DBG("Add Headers %s : %s!\n", header.name.c_str(), header.val.c_str());
    this->headers.push_back(header);
}

void HTTP2_HeaderList::addHeader(HTTP2_HeaderStorage&& header)
{
    this->headers.push_back(std::move(header));
}

void HTTP2_HeaderList::flushHeaders()
{
    this->headers.clear();
}

zeek::RecordValPtr HTTP2_HeaderList::BuildHeaderVal(HTTP2_HeaderStorage& h)
{
    static auto mime_header_rec = zeek::id::find_type<zeek::RecordType>("mime_header_rec");

    auto upper_name = zeek::make_intrusive<zeek::StringVal>(h.name);
    upper_name->ToUpper();

    auto header_record = zeek::make_intrusive<zeek::RecordVal>(mime_header_rec);
    header_record->Assign(0, std::move(upper_name));
    header_record->Assign(1, zeek::make_intrusive<zeek::StringVal>(h.val));
    return header_record;
}

zeek::TableValPtr HTTP2_HeaderList::BuildHeaderTable(void)
{
    static auto mime_header_list = zeek::id::find_type<zeek::TableType>("mime_header_list");
    auto t = zeek::make_intrusive<zeek::TableVal>(mime_header_list);

    for (unsigned int i = 0; i < this->headers.size(); ++i)
    {
        auto index = zeek::val_mgr->Count(i+1);  // index starting from 1
        auto header_record = BuildHeaderVal(this->headers[i]);
        t->Assign(std::move(index), header_record);
    }

    return t;
}



