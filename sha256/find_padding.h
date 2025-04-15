#pragma once

#include <iomanip>
#include <random>
#include <thread>
#include <fstream>
#include <mutex>
#include "sha256.h"

using namespace std;


vector<uint8_t> generateRandomPrefix(mt19937& gen, const size_t prefixLenBytes)
{
    uniform_int_distribution<unsigned short> dist{ 0x00, 0xFF };

    vector<uint8_t> result;
    for (size_t index = 0; index < prefixLenBytes; index++)
    {
        result.emplace_back(static_cast<uint8_t>(dist(gen)));
    }

    return result;
}

template<typename T>
vector<T> concatVectors(vector<T> vec1, const vector<T>& vec2)
{
    vec1.insert(vec1.end(), vec2.begin(), vec2.end());
    return vec1;
}

void printVec(std::ostream& out, const std::vector<uint8_t>& vec, mutex& mtx)
{
    lock_guard<mutex> lock(mtx);

    for (auto& item : vec)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (int)item << " ";
    }
    out << std::endl;
}

vector<uint8_t> tryFindPrefix(vector<uint8_t> phrase, size_t prefixLenByte, const vector<uint8_t> wantedPrefix, mt19937& gen)
{
    while (true)
    {
        vector<uint8_t> prefix = generateRandomPrefix(gen, prefixLenByte);

        vector<uint8_t> concated = concatVectors(prefix, phrase);

        vector<uint8_t> hash = sha256::compute(concated);

        for (size_t index = 0; index < wantedPrefix.size(); index++)
        {
            if (hash[index] != wantedPrefix[index])
            {
                break;
            }
            else if (hash[index] == wantedPrefix[index] && index == wantedPrefix.size() - 1)
            {
                return prefix;
            }
        }
    }
}

void tryFindPrefixesParrallel(const string phrase, ofstream& outStream, mutex& streamOutMtx)
{

    vector<uint8_t> phraseVec = { phrase.begin(), phrase.end() };

    vector<thread> thVec;

    // launch threads

    for (size_t index = 0; index < 8; index++)
    {
        thVec.emplace_back([phraseVec, &outStream, &streamOutMtx]()
            {
                random_device rd;
                mt19937 gen(rd());

                vector<uint8_t> prefix = tryFindPrefix(phraseVec, 20, vector<uint8_t>(4, 0x00), gen);

                printVec(outStream, prefix, streamOutMtx);
            });
    }


    // join the threads
    for (auto& th : thVec)
    {
        if (th.joinable())
        {
            th.join();
        }
    }

    outStream.close();

}