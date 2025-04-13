#include <iostream>
#include <bitset>
#include <string>
#include <iomanip>
#include "sha256.h"

using namespace std;

int main()
{

    string s1, s2;
    std::vector<uint8_t> test1 = { 0x61, 0x62, 0x63 };

    
    auto vec = sha256::compute(test1);
    
    for (auto& item : vec)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)item << endl;
    }
	


    /*
    auto vec = sha256::bytesToWords(test1);
    
    for (auto& item : vec)
    {
        s2 += std::bitset<32>(item).to_string();
    }

    cout << (s1 == s2);
    */

}