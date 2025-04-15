#pragma once
#include <iostream>
#include <iomanip>
#include <fstream>
#include "sha256.h"


// ##########################
// verifying the kse.ua certificate fingerprint
// ##########################
void computeFingerprint(const string& filePath)
{
    ifstream file(filePath, ios::binary | ios::ate);
    if (!file.is_open()) 
    {
        cerr << "Failed to open file" << endl;
        return;
    }

    streamsize size = file.tellg();
    if (size <= 0) 
    {
        cerr << "Invalid file size: " << size << endl;
        return;
    }

    file.seekg(0, ios::beg);
    vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size))
    {
        cerr << "Failed to read file content" << endl;
        return;
    }

    auto result = sha256::compute(data);

    for (auto& item : result)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)item << " ";
    }
}


