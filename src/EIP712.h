#pragma once
#include <string>
#include <vector>
#include <map>
#include "cJSON/cJSON.h"
#include <iostream>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <Crypto.h>
#include "EthABI.h"
#include <algorithm>

#define ETHERS_KECCAK256_LENGTH 32

using namespace std;

struct Type
{
    string name;
    string type;
};

struct StructuredTypedData
{
    string primaryType;
    vector<Type> types;
};

struct MetaTxTypedData
{
    std::map<string, vector<Type>> types;
    std::map<string, string> domain;
    string primaryType;
    std::map<string, string> message;
};

class EIP712
{
public:
    static vector<string> dependencies(string primaryType, cJSON *types, vector<string> found = vector<string>{});
    static vector<uint8_t> encodeType(string primaryType, cJSON *types);
    static void typeHash(string primaryType, cJSON *types, uint8_t *digest);
    static vector<uint8_t> encodeData(string primaryType, cJSON *data, cJSON *types);
    static void hashStruct(string primaryType, cJSON *data, cJSON *types, uint8_t *result);
    static void EIP712Hash(string primaryType, cJSON *data, cJSON *types, cJSON *domain, uint8_t *result);
    static string encodeField(string type, string value);
};
