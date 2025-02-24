
#include <gtkmm.h>

class RegView : public Gtk::TreeView
{
private:
    Glib::RefPtr<Gtk::ListStore> _regViewStore;

public:
    RegView(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::TreeView(cobject),
                                                                                     _regViewStore(std::dynamic_pointer_cast<Gtk::ListStore>(get_model()))
    {

    }

    void add_data(const std::string& reg, uint64_t value)
    {
        auto mm = _regViewStore->append();
        Gtk::TreeModel::Row row = *mm;

        char regv[64];
        sprintf(regv, "%lX", value);

        row.set_value(0, reg);
        row.set_value(1, std::string(regv));
    }

    void clear()
    {
        _regViewStore->clear();
    }
};