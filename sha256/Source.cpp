#include <iostream>
#include <bitset>
#include <string>
#include <iomanip>
#include <random>
#include <thread>
#include <fstream>
#include <mutex>
#include "find_padding.h"
#include "sha256.h"

using namespace std;


mutex fileMtx;
ofstream file("prefixes.txt", ios::app);


int main()
{
    // run test
    if (!sha256::runTests())
    {
        cout << "NOO way bro, tests failed" << endl;
        return 1;
    }

    // #########################
    // Lets have some decent mining!
    // #########################
    string phrase = "give my friend 2 bitcoins for pizza";

    tryFindPrefixesParrallel(phrase, file, fileMtx);
}