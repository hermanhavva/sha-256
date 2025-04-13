#include <iostream>
#include <bitset>
#include <string>
#include <iomanip>
#include "sha256.h"

using namespace std;

int main()
{

    string s1, s2;
    std::vector<uint8_t> test1 = { 'a', 'b', 'c'};

    
    auto vec = sha256::compute(test1);

    if (!sha256::runTests())
    {
        cout << "NOO way bro, tests failed" << endl;
        return 1;
    }


    for (auto& item : vec)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)item << endl;
    }


}