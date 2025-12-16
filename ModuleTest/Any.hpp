#include <typeinfo>
#include <algorithm>
#include <cassert>

class Any
{
private:
    class holder
    {
    public:
        virtual ~holder() {}
        virtual const std::type_info& type() = 0;
        virtual holder *clone() = 0;
    };
    template <class T>
    class placeholder : public holder
    {
    public:
        placeholder(const T &val) : _val(val) {}
        // 获取子类对象保存的数据类型
        virtual const std::type_info& type() { return typeid(T); }
        // 针对当前的对象自身，克隆出一个新的子类对象
        virtual holder *clone() { return new placeholder(_val); }

    public:
        T _val;
    };

    holder *_content; // 父类指针，可以指向子类的对象（多态）
public:
    Any() : _content(nullptr) {}
    ~Any() { if (_content) delete _content; }
    template <class T>
    Any(const T &val)
    {
        _content = new placeholder<T>(val);
    }
    Any(const Any& other)
    {
        _content = (other._content ? other._content->clone() : nullptr);
    }
    Any& swap(Any& other)
    {
        std::swap(_content, other._content);
        return *this;
    }
    //返回子类对象保存数据的指针
    template <class T>
    T*get()
    {
        //目的数据类型必须与保存数据的类型一致
        assert(typeid(T) == _content->type());
        return &(static_cast<placeholder<T>*>(_content)->_val);
    }
    //=运算符重载
    template <class T>
    Any& operator=(const T &val)
    {
        //为val构造一个临时对象，然后与当前对象进行交换，当临时对象析构的时候，释放当前对象原有的内容
        Any(val).swap(*this);
        return *this;
    }
    Any& operator=(const Any& other)
    {
        Any(other).swap(*this);
        return *this;
    }
};
