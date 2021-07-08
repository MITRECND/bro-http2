#include <string.h>
#include "HTTP2_HeaderStorage.h"
#include "HTTP2.h"
#include "util.h"
#include "Val.h"
#include "debug.h"
#include "Reporter.h"

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

RecordVal* HTTP2_HeaderList::BuildHeaderVal(HTTP2_HeaderStorage& h)
{
    RecordVal* header_record = new RecordVal(mime_header_rec);
    header_record->Assign(0, mime::new_string_val(h.name.length(), h.name.c_str())->ToUpper());
    header_record->Assign(1, mime::new_string_val(h.val.length(), h.val.c_str()));
    return header_record;
}

TableVal* HTTP2_HeaderList::BuildHeaderTable(void)
{
    TableVal* t = new TableVal(mime_header_list);

    for (unsigned int i = 0; i < this->headers.size(); ++i)
    {
        Val* index = val_mgr->GetCount(i+1);  // index starting from 1

        RecordVal* header_record = BuildHeaderVal(this->headers[i]);
        t->Assign(index, header_record);

        Unref(index);
    }

    return t;
}



