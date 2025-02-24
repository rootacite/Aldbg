
#include <gtkmm.h>
#include "../../core/MemoryMap.hpp"

class MemoryView : public Gtk::TreeView
{
private:
    Glib::RefPtr<Gtk::ListStore> _memoryViewStore;

public:
    void GetSelection(uint64_t& address)
    {
        Gtk::TreeModel::Row row = *get_selection()->get_selected();
        row.get_value(0, address);
    }

    std::vector<MapEntire> _map;

    MemoryView(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::TreeView(cobject),
                                                                                        _memoryViewStore(std::dynamic_pointer_cast<Gtk::ListStore>(get_model()))
    {

    }

    void set_data(std::vector<MapEntire>& list)
    {
        _map = list;

        _memoryViewStore->clear();

        for(auto e : list)
        {
            auto mm = _memoryViewStore->append();
            Gtk::TreeModel::Row row = *mm;

            char startAddr[32], endAddr[32], offset[32];
            std::string permission;

            permission += (e.access & READ ? "r" : "-");
            permission += (e.access & WRITE ? "w" : "-");
            permission += (e.access & EXECUTE ? "x" : "-");
            permission += (e.access & PRIVATE ? "p" : "-");
            permission += (e.access & SHARED ? "s" : "-");

            sprintf(startAddr, "%16lx", e.startAddress);
            sprintf(endAddr, "%16lx", e.endAddress);
            sprintf(offset, "%8x", e.offset);


            row.set_value(0, std::string(startAddr));
            row.set_value(1, std::string(endAddr));
            row.set_value(2, permission);
            row.set_value(3, std::string(offset));
            row.set_value(4, std::string(e.path));
        }
    }
};