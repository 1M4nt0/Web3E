#pragma once
#include <stdint.h>
#include <string>

using namespace std;

class ABI
{
public:
    static string encodeArg(string type, string value);

private:
    static string encodeAddress(const string *address);
    static string encodeBytes(const string *bytes);
    static string encodeBytes32(const string *bytes);
    static string encodeString(const string *str);
    static string encodeBool(const bool b);
    static string encodeUint256(const string n);
};
