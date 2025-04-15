#include <iostream>
#include <bitset>
#include <string>
#include <iomanip>
#include <fstream>
#include "sha256.h"
#include "fingerprint_verification.h"

using namespace std;

int main()
{
    if (!sha256::runTests())
    {
        cout << "NOO way bro, tests failed" << endl;
        return 1;
    }


    // ###############
    // Usage example
    // ###############
    /*
    vector<uint8_t> test1 = { 'a', 'b', 'c'};
    auto vec = sha256::compute(test1);
    
    for (auto& item : vec)
    {
        cout << std::hex << std::setw(2) << std::setfill('0') << (int)item << " ";
    }
    cout << endl;
    */ 

    computeFingerprint("..//cert_files//kseua.der");
    
}