
#include <gtkmm.h>
#include <format>
#include <unordered_map>

std::unordered_map<uint32_t, int> allowedChar
{
        {'0', 1},
        {'1', 1},
        {'2', 1},
        {'3', 1},
        {'4', 1},
        {'5', 1},
        {'6', 1},
        {'7', 1},
        {'8', 1},
        {'9', 1},
        {'0', 1},
        {'a', 1},
        {'b', 1},
        {'c', 1},
        {'d', 1},
        {'e', 1},
        {'f', 1},
        {'A', 1},
        {'B', 1},
        {'C', 1},
        {'D', 1},
        {'E', 1},
        {'F', 1},
};

class NoNewlineTextView : public Gtk::TextView {
public:
    NoNewlineTextView() {

       auto buffer = get_buffer();
       buffer->signal_insert().connect(sigc::mem_fun(*this, &NoNewlineTextView::on_insert_text), false);
    }

protected:
    void on_insert_text(const Gtk::TextBuffer::iterator& pos, const Glib::ustring& text, int x) {
        for(const auto &k : text)
        {
            if(!allowedChar[k] || get_buffer()->get_text().size() + text.size() > 2)
            {
                get_buffer()->signal_insert().emission_stop();
                break;
            }
        }
    }

    void on_focus_out()
    {

    }
};

namespace {
    class EditorModelColumns : public Glib::Object {
    public:
        Glib::ustring baseAddress;

        Glib::RefPtr<Glib::Binding> bindingToValues[16];
        Glib::PropertyProxy<Glib::ustring> propertyValues(int i) { return _values[i].get_proxy(); }

        static Glib::RefPtr<EditorModelColumns> create(const Glib::ustring &baseAddress, uint8_t values[16]){
            return Glib::make_refptr_for_instance<EditorModelColumns>(new EditorModelColumns(baseAddress, values));
        }

    protected:
        Glib::Property<Glib::ustring> _values[16];

        EditorModelColumns(Glib::ustring baseAddress, uint8_t values[16]) :  Glib::ObjectBase(typeid(EditorModelColumns)), baseAddress(std::move(baseAddress)),_values{
                Glib::Property<Glib::ustring> (*this, "i1", std::format("{:02x}", values[0])),
                Glib::Property<Glib::ustring> (*this, "i2", std::format("{:02x}", values[1])),
                Glib::Property<Glib::ustring> (*this, "i3", std::format("{:02x}", values[2])),
                Glib::Property<Glib::ustring> (*this, "i4", std::format("{:02x}", values[3])),
                Glib::Property<Glib::ustring> (*this, "i5", std::format("{:02x}", values[4])),
                Glib::Property<Glib::ustring> (*this, "i6", std::format("{:02x}", values[5])),
                Glib::Property<Glib::ustring> (*this, "i7", std::format("{:02x}", values[6])),
                Glib::Property<Glib::ustring> (*this, "i8", std::format("{:02x}", values[7])),
                Glib::Property<Glib::ustring> (*this, "i9", std::format("{:02x}", values[8])),
                Glib::Property<Glib::ustring> (*this, "i10", std::format("{:02x}", values[9])),
                Glib::Property<Glib::ustring> (*this, "i11", std::format("{:02x}", values[10])),
                Glib::Property<Glib::ustring> (*this, "i12", std::format("{:02x}", values[11])),
                Glib::Property<Glib::ustring> (*this, "i13", std::format("{:02x}", values[12])),
                Glib::Property<Glib::ustring> (*this, "i14", std::format("{:02x}", values[13])),
                Glib::Property<Glib::ustring> (*this, "i15", std::format("{:02x}", values[14])),
                Glib::Property<Glib::ustring> (*this, "i16", std::format("{:02x}", values[15]))} { }
    };
}

class EditorView : public Gtk::ColumnView {
private:
    Glib::RefPtr<Gio::ListStore<EditorModelColumns>> _editorModel;
    Glib::RefPtr<Gtk::SingleSelection> _model;

public:
    EditorView(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::ColumnView(cobject)
    {
        _editorModel = Gio::ListStore<EditorModelColumns>::create();
        _model = Gtk::SingleSelection::create(_editorModel);
        _model->set_autoselect(false);
        _model->set_can_unselect(true);
        set_model(_model);
        set_reorderable(false);
        set_hexpand();
        set_vexpand();

        add_cols();
        add_row("7fff7e");
        add_row("7fff7f");
        add_row("7fff71");
        add_row("7fff72");
    }

    void add_cols()
    {
        auto factory = Gtk::SignalListItemFactory::create();
        factory->signal_setup().connect(sigc::bind(sigc::mem_fun(*this,
                                                                 &EditorView::onSetupLabel), Gtk::Align::START));
        factory->signal_bind().connect(
                sigc::mem_fun(*this, &EditorView::onBindBase));
        auto column = Gtk::ColumnViewColumn::create("Base", factory);
        column->set_fixed_width(150);
        append_column(column);

        for(int i=0;i<16;i++)
        {
            factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(sigc::bind(sigc::mem_fun(*this,
                                                                     &EditorView::onSetupEditableLabel), i));
            factory->signal_bind().connect(
                    sigc::bind(sigc::mem_fun(*this, &EditorView::onBindValue), i));
            factory->signal_unbind().connect(
                    sigc::bind(sigc::mem_fun(*this, &EditorView::onUnbindValue), i));

            column = Gtk::ColumnViewColumn::create(std::format("{:02x}", i) , factory);
            column->set_expand();
            append_column(column);
        }
    }

    void add_row(const std::string& base
    ){
        uint8_t db[16] = {0};
        _editorModel->append(EditorModelColumns::create(base, db));
    }

    void onSetupLabel(
            const Glib::RefPtr<Gtk::ListItem>& list_item, Gtk::Align halign)
    {
        auto label = Gtk::make_managed<Gtk::Label>("", halign);
        list_item->set_child(*label);
    }

    void onBindBase(const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto col = std::dynamic_pointer_cast<EditorModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        std::string tx = label->get_text();
        label->set_text(col->baseAddress);
    }

    void onSetupEditableLabel(
            const Glib::RefPtr<Gtk::ListItem>& list_item, int i)
    {
        auto label = Gtk::make_managed<NoNewlineTextView>();
        label->set_editable();
        label->set_accepts_tab(false);

//        label->signal_insert_text().connect([](const Glib::ustring& str, int* n){
//
//        });
        label->get_buffer()->property_text().signal_changed().connect(sigc::bind(sigc::mem_fun(
                *this, &EditorView::on_edited), list_item, i));
        list_item->set_child(*label);
    }

    void onBindValue(
            const Glib::RefPtr<Gtk::ListItem>& list_item, int i)
    {
        auto col = std::dynamic_pointer_cast<EditorModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<NoNewlineTextView*>(list_item->get_child());
        if (!label)
            return;

        label->get_buffer()->set_text(col->propertyValues(i).get_value());

        if (col->bindingToValues[i])
            col->bindingToValues[i]->unbind();

        col->bindingToValues[i] = Glib::Binding::bind_property(
                label->get_buffer()->property_text(), col->propertyValues(i),
                Glib::Binding::Flags::BIDIRECTIONAL);
    }

    void onUnbindValue(
            const Glib::RefPtr<Gtk::ListItem>& list_item, int i)
    {
        auto col = std::dynamic_pointer_cast<EditorModelColumns>(list_item->get_item());
        if (!col)
            return;
        if (col->bindingToValues[i])
            col->bindingToValues[i]->unbind();
        col->bindingToValues[i].reset();
    }

    void on_edited(const Glib::RefPtr<Gtk::ListItem>& list_item, int i)
    {
        auto col = std::dynamic_pointer_cast<EditorModelColumns>(list_item->get_item());
        if (!col)
            return;
        auto label = dynamic_cast<NoNewlineTextView*>(list_item->get_child());
        if (!label)
            return;
    }
};
