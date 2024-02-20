#include <iostream>
#include <unistd.h> // IMPORT THESE TWO HEADERS
#include <fstream>  // 

int main() {
    // JUST ADD THESE FOUR LINES TO THE START OF YOUR MAIN FUNCTION
    pid_t process{ getpid() };
    std::ofstream out_file("pid.txt");
    out_file << process;
    out_file.close();

    // the rest of your code here
    while (true) {
        process = getpid();
        sleep(1);
    }
    
    return 0;
}