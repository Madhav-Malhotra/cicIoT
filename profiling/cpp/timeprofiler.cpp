#include <chrono>       // timing library
#include <iostream>     // just for displaying function time execution
    
void long_operation() {
    for (std::size_t i = 0; i != 0; ++i) {}
}

double func_timer() {
    // Get time before and after function
    auto t1 = std::chrono::high_resolution_clock::now();
    long_operation();
    auto t2 = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::micro> us = t2 - t1;
    return us.count();
}

int main() {
    // Get time before and after function
    auto t1 = std::chrono::high_resolution_clock::now();
    long_operation();
    auto t2 = std::chrono::high_resolution_clock::now();

    // Get integer number of microseconds (truncated)
    auto ms_int = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);

    // Get floating-point microseconds
    std::chrono::duration<double, std::micro> ms_double = t2 - t1;

    std::cout << ms_int.count() << "us\n";
    std::cout << ms_double.count() << "us\n";
    return 0;
}