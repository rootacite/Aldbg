
#include <gtkmm.h>

class SymbolMenu;

class SelfContainedButton : public Gtk::Button
{
    typedef void(*Action)(const std::string &, SymbolMenu* menu, const Symbol& sym);

public:
    SelfContainedButton(SymbolMenu* menu, const Symbol& sym) : Gtk::Button(), _menu(menu), _sym(sym)
    {

    }

    void SetAction(Action ac)
    {
        _action = ac;
        signal_clicked().connect(sigc::mem_fun(*this, &SelfContainedButton::clicked));
    }

private:
    void clicked()
    {
        _action(get_label(), _menu, _sym);
    }

    Action _action = nullptr;
    SymbolMenu* _menu = nullptr;
    Symbol _sym;
};

class SymbolMenu : public Gtk::MenuButton
{
private:
    void sendMessage(char id, void* param) const
    {
        DebugCommand msg{id, param};
        if(port != -1)
        {
            write(port, &msg, sizeof(DebugCommand));
        }
    }

public:
    Glib::RefPtr<Gtk::Box> popoverBox = nullptr;
    std::vector<SelfContainedButton*> buttonList;
    Glib::RefPtr<Gtk::Label> childLabel = nullptr;
    int port = -1;

public:
    SymbolMenu(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::MenuButton(cobject)
    {

    }

    void UpdateList(const std::vector<Symbol> &list)
    {
        if(popoverBox)
        {
            for(const auto &k : buttonList)
            {
                popoverBox->remove(*k);
            }
            buttonList.clear();

            for(const auto &k : list)
            {
                auto b = Gtk::make_managed<SelfContainedButton>(this, k);
                b->set_label(k.name);
                b->SetAction([](const std::string& label, SymbolMenu* menu, const Symbol& sym){
                    menu->sendMessage(MSG_SWITCHSYMBOL, (void*)&sym);
                });
                buttonList.push_back(b);
                popoverBox->append(*b);
            }
        }
    }
};