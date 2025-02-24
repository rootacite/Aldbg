//
// Created by acite on 5/1/24.
//

#include <ctime>
#include <cstring>
#include <gtkmm.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>


class LogView : public Gtk::TreeView
{
protected:
    Glib::RefPtr<Gtk::ListStore> _logStore       = nullptr;

public:
    LogView(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::TreeView(cobject),
    _logStore(std::dynamic_pointer_cast<Gtk::ListStore>(get_model()))
    {

    }

    void add_log_data(const std::string& data)
    {
        auto mm = _logStore->append();
        Gtk::TreeModel::Row row = *mm;

        time_t currentTime;
        time(&currentTime);
        tm* localTime = localtime(&currentTime);

        char time_str[64];
        sprintf(time_str, "[%d:%d:%d]", localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
        std::string cppstrtime = time_str;

        row.set_value(0, cppstrtime);
        row.set_value(1, data);
    }

    void clear()
    {
        _logStore->clear();
    }
};
