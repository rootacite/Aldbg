//
// Created by acite on 5/1/24.
//

#include <gtkmm.h>
#include <capstone/capstone.h>

#include "../../core/Core.hpp"

namespace {
    class CPUModelColumns : public Glib::Object {
    public:
        Glib::PropertyProxy<bool> propertyBroke() { return _broke.get_proxy(); }
        Glib::PropertyProxy<std::vector<std::string>> propertyClasses() { return _classes.get_proxy(); }

        Glib::ustring Address;
        Glib::ustring Data;
        Glib::ustring Disassembly;
        Glib::RefPtr<Glib::Binding> BindingToCheckbutton = nullptr;

        Glib::RefPtr<Glib::Binding> BindingToAddress = nullptr;
        Glib::RefPtr<Glib::Binding> BindingToData = nullptr;
        Glib::RefPtr<Glib::Binding> BindingToDisassembly = nullptr;
        std::shared_ptr<Core> core = nullptr;


        static Glib::RefPtr<CPUModelColumns> create(bool broke, const Glib::ustring &address,
                                                    const Glib::ustring &data, const Glib::ustring &disassembly, std::shared_ptr<Core> _core){
            return Glib::make_refptr_for_instance<CPUModelColumns>(
                    new CPUModelColumns(broke, address, data, disassembly, std::move(_core)));
        }

    protected:
        CPUModelColumns(bool broke, Glib::ustring address,
                        Glib::ustring data, Glib::ustring disassembly, std::shared_ptr<Core> _core)
                : Glib::ObjectBase(typeid(CPUModelColumns)),
                  Address(std::move(address)), Data(std::move(data)), Disassembly(std::move(disassembly)),
                  _broke(*this, "broke", broke),
                  _classes(*this, "highlighted", {}), core(std::move(_core)){
            propertyBroke().signal_changed().connect(
                    sigc::mem_fun(*this, &CPUModelColumns::on_fixed_changed));
        }

        Glib::Property<bool> _broke;
        Glib::Property<std::vector<std::string>> _classes;

        void on_fixed_changed() {
            if(propertyBroke().get_value())
            {
                core->queueMessage(MSG_BREAK, (void*)std::stoull(Address, nullptr, 16));
            }
            else
            {
                core->queueMessage(MSG_DELBREAK, (void*)std::stoull(Address, nullptr, 16));
            }
        }
    };
}

class CPUView : public Gtk::ColumnView
{
public:
    uint64_t rip = 0;
    int _lastSelectedRow = -1;
    std::shared_ptr<Core> core = nullptr;

protected:
    Glib::RefPtr<Gio::ListStore<CPUModelColumns>> _codeViewStore;
    Glib::RefPtr<Gtk::SingleSelection> _model;

    [[nodiscard]]static std::vector<cs_insn> disassembly(uint8_t* data, int cc, size_t size, int address)
    {
        std::vector<cs_insn> r;

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return {};
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

        for(int i=0, sz = 0;i<cc && sz < size;i++)
        {
            count = cs_disasm(handle, (uint8_t*)data, 32, address, 1, &insn);
            if(count == 1)
            {
                cs_insn k{};
                memcpy(&k, &insn[0], sizeof(cs_insn));
                r.emplace_back(k);
                address += k.size;
                data += k.size;
                sz += k.size;
            }else break;
        }

        cs_free(insn, count);
        cs_close(&handle);

        return std::move(r);
    }

public:
    CPUView(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::ColumnView(cobject)
    {
        _codeViewStore = Gio::ListStore<CPUModelColumns>::create();
        _model = Gtk::SingleSelection::create(_codeViewStore);
        _model->set_autoselect(false);
        _model->set_can_unselect(true);
        set_model(_model);
        set_reorderable(false);
        set_hexpand();
        set_vexpand();
        add_cols();

        signal_activate().connect([this](guint i){
            auto row = _codeViewStore->get_item(i);
            bool old = row->propertyBroke().get_value();
            row->propertyBroke().set_value(!old);
        });
    }

    void setData(const std::vector<cs_insn>& insn)
    {
        _lastSelectedRow = -1;
        clear();
        for (const auto &k : insn) {
            char cmdAddr[32], insByte[32];
            std::string bytes, cmdStr;
            for(int j = 0;j<k.size;j++)
            {
                sprintf(insByte, "%2x", k.bytes[j]);
                bytes += insByte;
            }
            sprintf(cmdAddr, "%16lx", k.address);
            cmdStr = k.mnemonic;
            cmdStr += " ";
            cmdStr += k.op_str;

            add_row(cmdAddr, bytes, cmdStr, core->ContainsBreakPoint(k.address));
        }
    }

    void add_row(const std::string& addr,
                 const std::string& data,
                 const std::string& disassembly,
                 bool isBroke
    ){
        _codeViewStore->append(CPUModelColumns::create(isBroke, addr, data, disassembly, core));
    }


    void clear()
    {
        _codeViewStore->remove_all();
    }

    uint64_t GetSelected()
    {
        auto i = _model->get_selected();
        if(i == GTK_INVALID_LIST_POSITION) return 0;

        auto k = _codeViewStore->get_item(i);
        return std::stoull(k->Address, nullptr, 16);
    }

    void Select()
    {
        for (int i=0;i<_codeViewStore->get_n_items();i++) {
            auto row = _codeViewStore->get_item(i);
            std::string str = row->Address;
            if (std::stoull(str, nullptr, 16) == rip) {
                if(_lastSelectedRow >= 0)
                    _codeViewStore->get_item(_lastSelectedRow)->propertyClasses().set_value({});
                _lastSelectedRow = i;
                row->propertyClasses().set_value({"highlight"});

                _model->select_item(i, true);
                gtk_column_view_scroll_to(this->gobj(), i, nullptr, GTK_LIST_SCROLL_NONE, nullptr);
                break;
            }
        }
        queue_draw();
    }

    void add_cols()
    {
        /* column for fixed toggles */
        auto factory = Gtk::SignalListItemFactory::create();
        factory->signal_setup().connect(
                sigc::mem_fun(*this, &CPUView::onSetupCheckbutton));
        factory->signal_bind().connect(
                sigc::mem_fun(*this, &CPUView::onBindBroke));
        factory->signal_unbind().connect(
                sigc::mem_fun(*this, &CPUView::onUnbindBroke));
        auto column = Gtk::ColumnViewColumn::create("Broke", factory);
        append_column(column);

        factory = Gtk::SignalListItemFactory::create();
        factory->signal_setup().connect(sigc::bind(sigc::mem_fun(*this,
                                                                 &CPUView::onSetupLabel), Gtk::Align::START));
        factory->signal_bind().connect(
                sigc::mem_fun(*this, &CPUView::onBindAddress));
        factory->signal_unbind().connect(
                sigc::mem_fun(*this, &CPUView::onUnbindAddress));
        column = Gtk::ColumnViewColumn::create("Address", factory);
        column->set_fixed_width(150);
        append_column(column);

        factory = Gtk::SignalListItemFactory::create();
        factory->signal_setup().connect(sigc::bind(sigc::mem_fun(*this,
                                                                 &CPUView::onSetupLabel), Gtk::Align::START));
        factory->signal_bind().connect(
                sigc::mem_fun(*this, &CPUView::onBindData));
        factory->signal_unbind().connect(
                sigc::mem_fun(*this, &CPUView::onUnbindData));

        column = Gtk::ColumnViewColumn::create("Data", factory);
        append_column(column);

        factory = Gtk::SignalListItemFactory::create();
        factory->signal_setup().connect(sigc::bind(sigc::mem_fun(*this,
                                                                 &CPUView::onSetupLabel), Gtk::Align::START));
        factory->signal_bind().connect(
                sigc::mem_fun(*this, &CPUView::onBindDisassembly));
        factory->signal_unbind().connect(
                sigc::mem_fun(*this, &CPUView::onUnbindDisassembly));

        column = Gtk::ColumnViewColumn::create("Disassembly", factory);
        column->set_expand();
        append_column(column);
    }

    void onSetupCheckbutton(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto checkbutton = Gtk::make_managed<Gtk::CheckButton>();
        checkbutton->set_halign(Gtk::Align::CENTER);
        checkbutton->set_valign(Gtk::Align::CENTER);
        list_item->set_child(*checkbutton);
    }

    void onSetupLabel(
            const Glib::RefPtr<Gtk::ListItem>& list_item, Gtk::Align halign)
    {
        auto label = Gtk::make_managed<Gtk::Label>("", halign);
        list_item->set_child(*label);
    }

    void onBindBroke(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto checkbutton = dynamic_cast<Gtk::CheckButton*>(list_item->get_child());
        if (!checkbutton)
            return;
        checkbutton->set_active(col->propertyBroke());

        if (col->BindingToCheckbutton)
            col->BindingToCheckbutton->unbind();
        col->BindingToCheckbutton = Glib::Binding::bind_property(
                checkbutton->property_active(), col->propertyBroke(),
                Glib::Binding::Flags::BIDIRECTIONAL);
    }

    void onUnbindBroke(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        if (col->BindingToCheckbutton)
            col->BindingToCheckbutton->unbind();
        col->BindingToCheckbutton.reset();
    }

    void onBindAddress(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        std::string tx = label->get_text();
        label->set_text(col->Address);

        if (col->BindingToAddress)
            col->BindingToAddress->unbind();
        col->BindingToAddress = Glib::Binding::bind_property(
                label->property_css_classes(), col->propertyClasses(),
                Glib::Binding::Flags::BIDIRECTIONAL);
    }

    void onUnbindAddress(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        if (col->BindingToAddress)
            col->BindingToAddress->unbind();
        col->BindingToAddress.reset();
    }

    void onBindData(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_text(col->Data + "  ");

        if (col->BindingToData)
            col->BindingToData->unbind();
        col->BindingToData = Glib::Binding::bind_property(
                label->property_css_classes(), col->propertyClasses(),
                Glib::Binding::Flags::BIDIRECTIONAL);
    }

    void onUnbindData(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        if (col->BindingToData)
            col->BindingToData->unbind();
        col->BindingToData.reset();
    }

    void onBindDisassembly(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_text(col->Disassembly);

        if (col->BindingToDisassembly)
            col->BindingToDisassembly->unbind();
        col->BindingToDisassembly = Glib::Binding::bind_property(
                label->property_css_classes(), col->propertyClasses(),
                Glib::Binding::Flags::BIDIRECTIONAL);
    }

    void onUnbindDisassembly(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<CPUModelColumns>(list_item->get_item());
        if (!col)
            return;
        if (col->BindingToDisassembly)
            col->BindingToDisassembly->unbind();
        col->BindingToDisassembly.reset();
    }

};
