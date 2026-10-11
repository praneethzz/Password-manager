#include <iostream>
#include <memory>
#include <string>

class DemoBase {
protected:
    int value_;

public:
    DemoBase() : value_(0) {}
    explicit DemoBase(int value) : value_(value) {}
    DemoBase(const DemoBase& other) : value_(other.value_) {}
    virtual ~DemoBase() = default;

    virtual std::string name() const { return "DemoBase"; }
    inline int value() const { return value_; }
};

class DemoDerived : public DemoBase {
public:
    using DemoBase::DemoBase;
    std::string name() const override { return "DemoDerived"; }
};

template <typename T>
T add(T a, T b) {
    return a + b;
}

int factorial(int n) {
    return n <= 1 ? 1 : n * factorial(n - 1);
}

void pointerAndReferenceDemo(DemoBase* ptr, DemoBase& ref) {
    std::cout << ptr->name() << " " << ref.name() << "\n";
}

int main() {
    static int staticStorage = 7;
    thread_local int threadLocalStorage = 3;
    DemoBase* raw = new DemoDerived(42);
    std::unique_ptr<DemoBase> owned = std::make_unique<DemoDerived>(10);
    pointerAndReferenceDemo(raw, *owned);
    std::cout << "template add: " << add(2, 3) << "\n";
    std::cout << "factorial recursion: " << factorial(5) << "\n";
    std::cout << "storage values: " << staticStorage << " " << threadLocalStorage << "\n";
    delete raw;
    return 0;
}
