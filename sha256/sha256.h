#pragma once
#include <vector>
#include <iostream>
#include <format>
 
using namespace std;

static class sha256
{
public: 
	sha256() = delete;
    
    // #####################
    // The API exposed is:  
    // compute(msg: const vector<uint8_t>&): vector<uint8_t> 
    // runTests(): bool
    // #####################

    static vector<uint8_t> compute(const vector<uint8_t>& msg);
    
    static bool runTests();

private:
    
    static const int kBitsInBlock = 512;
    static const int kBitsInWord = 32;
    static const int kWordsInBlock = kBitsInBlock / kBitsInWord;
    static const vector<uint32_t> K;
    static const vector<uint32_t> H;

    static vector<uint8_t> addPadding(const vector<uint8_t>& input);
    
    static vector<uint8_t> wordsToBytes(const vector<uint32_t>& input);
    
    static vector<uint32_t> bytesToWords(const std::vector<uint8_t>& bytes);

    static uint32_t Ch(const uint32_t x, const uint32_t y, const uint32_t z);

    static uint32_t Maj(const uint32_t x, const uint32_t y, const uint32_t z);

    static uint32_t SHR(const uint32_t x, const uint32_t n);

    static uint32_t ROTR(const uint32_t x, const uint32_t n);

    // ########################
    // Capital Sigma
    // ########################
    static uint32_t Sigma0(uint32_t x);

    static uint32_t Sigma1(uint32_t x);

    // ########################
    // small sigma
    // ########################
    static uint32_t sigma0(uint32_t x);

    static uint32_t sigma1(uint32_t x);

};