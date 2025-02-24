
#include <gtkmm.h>

namespace
{
    class CallstackItem
    {
    public:
        CallstackItem() = default;
        CallstackItem(Glib::ustring callPoint, Glib::ustring stackBase, Glib::ustring symbol, Glib::ustring module, Glib::ustring depth);
        CallstackItem(Glib::ustring callPoint, const std::vector<CallstackItem>& children);
        CallstackItem(const CallstackItem& src) = default;
        CallstackItem(CallstackItem&& src)  noexcept = default;
        CallstackItem& operator=(const CallstackItem& src) = default;
        CallstackItem& operator=(CallstackItem&& src)  noexcept = default;
        ~CallstackItem() = default;

        Glib::ustring callPoint;
        Glib::ustring stackBase;
        Glib::ustring symbol;
        Glib::ustring module;
        Glib::ustring depth;
        std::vector<CallstackItem> m_children;
    }; // CallstackItem

    CallstackItem::CallstackItem(Glib::ustring callPoint, Glib::ustring stackBase, Glib::ustring symbol, Glib::ustring module, Glib::ustring depth)
            : callPoint(std::move(callPoint)), stackBase(std::move(stackBase)), symbol(std::move(symbol)), module(std::move(module)), depth(std::move(depth))
    { }

    CallstackItem::CallstackItem(Glib::ustring callPoint,
                                       const std::vector<CallstackItem>& children)
            : callPoint(std::move(callPoint)), m_children(children)
    { }
}

class CallstackView : public Gtk::ColumnView
{
protected:
    class ModelColumns : public Glib::Object
    {
    public:
        std::vector<CallstackItem> m_children;
        Glib::ustring callPoint;
        Glib::ustring stackBase;
        Glib::ustring symbol;
        Glib::ustring module;
        Glib::ustring depth;

        static Glib::RefPtr<ModelColumns> create(const CallstackItem& item)
        {

            return Glib::make_refptr_for_instance<ModelColumns>(new ModelColumns(item));
        }

    protected:
        explicit ModelColumns(const CallstackItem& item)
                : m_children(item.m_children), callPoint(item.callPoint),
                stackBase(item.stackBase), symbol(item.symbol),
                module(item.module), depth(item.depth)
        { }
    }; // ModelColumns

protected:
    static Glib::RefPtr<Gio::ListModel> create_model(
            const Glib::RefPtr<Glib::ObjectBase>& item)
    {
        auto col = std::dynamic_pointer_cast<ModelColumns>(item);
        if (col && col->m_children.empty())
            return {};

        auto result = Gio::ListStore<ModelColumns>::create();
        const std::vector<CallstackItem>& children = col ? col->m_children : std::vector<CallstackItem>();
        for (const auto& child : children)
            result->append(ModelColumns::create(child));
        return result;
    }

    Glib::RefPtr<Gtk::TreeListModel> m_TreeListModel;
    Glib::RefPtr<Gtk::MultiSelection> m_TreeSelection;
    Glib::RefPtr<Gio::ListStore<ModelColumns>> _store;

public:
    void append_group(const std::string &name, const std::vector<CallstackItem> &g)
    {
        CallstackItem k(name, g);
        if(_store) _store->append(ModelColumns::create(k));
    }

    void clear()
    {
        _store->remove_all();
    }

    CallstackView (BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder) : Gtk::ColumnView(cobject)
    {
        auto root = create_model({});

        m_TreeListModel = Gtk::TreeListModel::create(root,
                                                     sigc::ptr_fun(&CallstackView::create_model), false, true);
        m_TreeSelection = Gtk::MultiSelection::create(m_TreeListModel);
        set_model(m_TreeSelection);
        {
            auto factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(
                    sigc::mem_fun(*this, &CallstackView::on_setup_keylabel));
            factory->signal_bind().connect(
                    sigc::mem_fun(*this, &CallstackView::on_bind_callPoint));
            auto column = Gtk::ColumnViewColumn::create("Call Point", factory);
            column->set_fixed_width(200);
            append_column(column);

            factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(
                    sigc::mem_fun(*this, &CallstackView::on_setup_label));
            factory->signal_bind().connect(
                    sigc::mem_fun(*this, &CallstackView::on_bind_stackBase));

            column = Gtk::ColumnViewColumn::create("Stack Base", factory);
            column->set_expand();
            append_column(column);

            factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(
                    sigc::mem_fun(*this, &CallstackView::on_setup_label));
            factory->signal_bind().connect(
                    sigc::mem_fun(*this, &CallstackView::on_bind_symbol));

            column = Gtk::ColumnViewColumn::create("Symbol", factory);
            column->set_expand();
            append_column(column);

            factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(
                    sigc::mem_fun(*this, &CallstackView::on_setup_label));
            factory->signal_bind().connect(
                    sigc::mem_fun(*this, &CallstackView::on_bind_module));

            column = Gtk::ColumnViewColumn::create("Module", factory);
            column->set_expand();
            append_column(column);

            factory = Gtk::SignalListItemFactory::create();
            factory->signal_setup().connect(
                    sigc::mem_fun(*this, &CallstackView::on_setup_label));
            factory->signal_bind().connect(
                    sigc::mem_fun(*this, &CallstackView::on_bind_depth));

            column = Gtk::ColumnViewColumn::create("Depth", factory);
            column->set_expand();
            append_column(column);
        }

        _store = std::dynamic_pointer_cast<Gio::ListStore<ModelColumns>>(root);
    }

    void on_setup_keylabel(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        // Each ListItem contains a TreeExpander, which contains a Label.
        // The Label shows the ModelColumns::m_holiday_name. That's done in on_bind_holiday().
        auto expander = Gtk::make_managed<Gtk::TreeExpander>();
        auto label = Gtk::make_managed<Gtk::Label>();
        label->set_halign(Gtk::Align::START);
        expander->set_child(*label);
        list_item->set_child(*expander);
    }

    void on_setup_label(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        // Each ListItem contains a TreeExpander, which contains a Label.
        // The Label shows the ModelColumns::m_holiday_name. That's done in on_bind_holiday().
        auto label = Gtk::make_managed<Gtk::Label>();
        label->set_halign(Gtk::Align::START);
        list_item->set_child(*label);
    }

    void on_bind_callPoint(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto row = std::dynamic_pointer_cast<Gtk::TreeListRow>(list_item->get_item());
        if (!row)
            return;
        auto col = std::dynamic_pointer_cast<ModelColumns>(row->get_item());
        if (!col)
            return;
        auto expander = dynamic_cast<Gtk::TreeExpander*>(list_item->get_child());
        if (!expander)
            return;
        expander->set_list_row(row);
        auto label = dynamic_cast<Gtk::Label*>(expander->get_child());
        if (!label)
            return;
        label->set_text(col->callPoint);
    }

    void on_bind_stackBase(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto row = std::dynamic_pointer_cast<Gtk::TreeListRow>(list_item->get_item());
        if (!row)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_visible(!row->is_expandable());
        if (row->is_expandable())
            return;

        auto col = std::dynamic_pointer_cast<ModelColumns>(row->get_item());
        if (!col)
            return;
        label->set_text(col->stackBase);
    }

    void on_bind_symbol(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto row = std::dynamic_pointer_cast<Gtk::TreeListRow>(list_item->get_item());
        if (!row)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_visible(!row->is_expandable());
        if (row->is_expandable())
            return;

        auto col = std::dynamic_pointer_cast<ModelColumns>(row->get_item());
        if (!col)
            return;
        label->set_text(col->symbol);
    }

    void on_bind_module(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto row = std::dynamic_pointer_cast<Gtk::TreeListRow>(list_item->get_item());
        if (!row)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_visible(!row->is_expandable());
        if (row->is_expandable())
            return;

        auto col = std::dynamic_pointer_cast<ModelColumns>(row->get_item());
        if (!col)
            return;
        label->set_text(col->module);
    }

    void on_bind_depth(
            const Glib::RefPtr<Gtk::ListItem>& list_item)
    {
        auto row = std::dynamic_pointer_cast<Gtk::TreeListRow>(list_item->get_item());
        if (!row)
            return;
        auto label = dynamic_cast<Gtk::Label*>(list_item->get_child());
        if (!label)
            return;
        label->set_visible(!row->is_expandable());
        if (row->is_expandable())
            return;

        auto col = std::dynamic_pointer_cast<ModelColumns>(row->get_item());
        if (!col)
            return;
        label->set_text(col->depth);
    }
};
