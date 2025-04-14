#include "sha256.h"


vector<uint8_t> sha256::compute(const vector<uint8_t>& msg)
{
    // preprocessing
    vector<uint32_t> msgWithPadding = bytesToWords(addPadding(msg));
    vector<uint32_t> hashVec = H; 
    vector<uint32_t> W;
    
    size_t totalBlocks = msgWithPadding.size() * sizeof(uint32_t) * CHAR_BIT / kBitsInBlock;

    uint32_t a, b, c, d, e, f, g, h;
    

    for (size_t i = 0; i < totalBlocks; i++)
    {
        W.clear();

        // obtain the first block 
        vector<uint32_t> curBlock = vector<uint32_t>(msgWithPadding.begin() + i * kWordsInBlock, msgWithPadding.begin() + (i + 1) * kWordsInBlock);

        // fill the W_0 - W_15 (msg schedules)
        for (size_t t = 0; t <= 63; t++)
        {
            if (t <= 15)
            {
                W.emplace_back(curBlock[t]);
            }
            else
            {
                W.emplace_back(sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]);
            }
        }

        // init working variables with previous hash values
        a = hashVec[0]; 
        b = hashVec[1]; 
        c = hashVec[2]; 
        d = hashVec[3]; 
        e = hashVec[4]; 
        f = hashVec[5]; 
        g = hashVec[6]; 
        h = hashVec[7];

        for (size_t t = 0; t <= 63; t++)
        {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h = g; 
            g = f; 
            f = e; 
            e = d + T1; 
            d = c; 
            c = b; 
            b = a;
            a = T1 + T2;
        }

        hashVec[0] = a + hashVec[0];
        hashVec[1] = b + hashVec[1];
        hashVec[2] = c + hashVec[2];
        hashVec[3] = d + hashVec[3];
        hashVec[4] = e + hashVec[4];
        hashVec[5] = f + hashVec[5];
        hashVec[6] = g + hashVec[6];
        hashVec[7] = h + hashVec[7];
    }    

    return wordsToBytes(hashVec);
}

bool sha256::runTests()
{
    vector<uint8_t> test1{ }, test2{ 'a', 'b', 'c' }, test3(1000000, 'a');

    vector<uint8_t> result1 = 
    {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    vector<uint8_t> result2 =
    {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    }; 

    vector<uint8_t> result3 = 
    {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
    };

    return sha256::compute(test1) == result1 && sha256::compute(test2) == result2 && sha256::compute(test3) == result3;
}

vector<uint8_t> sha256::wordsToBytes(const vector<uint32_t>& input)
{
    vector<uint8_t> result;
    result.reserve(input.size() * 4);

    for (uint32_t value : input) 
    {
        result.emplace_back((value >> 24) & 0xFF); 
        result.emplace_back((value >> 16) & 0xFF);
        result.emplace_back((value >> 8) & 0xFF);
        result.emplace_back(value & 0xFF);
    }

    return result;
}

vector<uint32_t> sha256::bytesToWords(const std::vector<uint8_t>& bytes)
{
    std::vector<uint32_t> words;

    for (size_t i = 0; i < bytes.size(); i += 4)
    {
        uint32_t word = 0;

        for (size_t j = 0; j < 4; ++j)
        {
            word <<= 8;
            if (i + j < bytes.size())
            {
                word |= bytes[i + j];
            }
        }

        words.push_back(word);
    }
    return words;
}

vector<uint8_t> sha256::addPadding(const std::vector<uint8_t>& input)
 {
     std::vector<uint8_t> padded = input;

     uint64_t bitLen = static_cast<uint64_t>(padded.size()) * 8;

     padded.push_back(0x80);

     while ((padded.size() % 64) != 56)
     {
         padded.push_back(0x00);
     }

     for (int i = 7; i >= 0; --i)
     {
         padded.push_back(static_cast<uint8_t>((bitLen >> (8 * i)) & 0xFF));
     }

     return padded;
 }

uint32_t sha256::SHR(const uint32_t x, const uint32_t n)
{
    return x >> n;
}

uint32_t sha256::ROTR(const uint32_t x, const uint32_t n)
{
    if (n > 32 || n < 0)
    {
        cerr << format("Erorr at {}, n = {}", __func__, n);
        return 0;
    }

    return (x >> n) | (x << (32 - n));
}

uint32_t sha256::Ch(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t sha256::Maj(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sha256::Sigma0(const uint32_t x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

uint32_t sha256::Sigma1(const uint32_t x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

uint32_t sha256::sigma0(const uint32_t x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

uint32_t sha256::sigma1(const uint32_t x) 
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

const vector<uint32_t> sha256::K
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const vector<uint32_t> sha256::H =
{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};