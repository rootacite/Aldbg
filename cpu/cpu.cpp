//
// Created by acite on 5/1/24.
//

#include "cpu.h"

using namespace std;
using namespace Gtk;

extern TreeView* codeView;
extern Glib::RefPtr<ListStore> codeViewStore;

void add_row(const string& addr,
             const string& data,
             const string& dasm,
             const string& sts
                         ){
    auto mm = codeViewStore->append();
    Gtk::TreeModel::Row row = *mm;

    row.set_value(0, addr);
    row.set_value(1, data);
    row.set_value(2, dasm);
    row.set_value(3, sts);
}

void set_row_status(uint64_t index_addr, const string& sts)
{
    string addr;
    for(auto i : codeViewStore->children())
    {
        i.get_value(0, addr);
        if(to_string(index_addr) == addr)
        {
            i.set_value(3, sts);
            break;
        }
    }
}
