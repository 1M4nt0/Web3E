#include "EthABI.h"
#include <Crypto.h>
#include <vector>
#include <iostream>

/**
 * @brief Encode field given type and value
 *
 * @param {string} type - type of argument
 * @param {string} value - value of field
 * @return string - ABI Encoded rappresentation of the field
 */

string ABI::encodeArg(const string type, const string value)
{
    if (type == "uint256" || type == "uint")
    {
        return encodeUint256(value);
    }
    else if (type == "bool")
    {
        return encodeBool(value == "true" ? true : false);
    }
    else if (type == "address")
    {
        return encodeAddress(&value);
    }
    else if (type == "string")
    {
        return encodeString(&value);
    }
    else if (type == "bytes")
    {
        return encodeBytes32(&value);
    }
    return "";
}

string ABI::encodeAddress(const string *address)
{
    string cleaned = *address;
    if (address->at(0) == 'x')
        cleaned = address->substr(1);
    else if (address->at(1) == 'x')
        cleaned = address->substr(2);
    size_t digits = cleaned.length();
    return string(64 - digits, '0') + cleaned;
}

string ABI::encodeBytes(const string *bytes)
{
    vector<uint8_t> stringBuffer;
    vector<uint8_t> bytesVector(bytes->begin(), bytes->end());
    string encodedString = encodeUint256(to_string(bytesVector.size()));
    stringBuffer.insert(stringBuffer.begin(), bytesVector.begin(), bytesVector.end());
    stringBuffer.insert(stringBuffer.end(), encodedString.begin(), encodedString.end());
    if (bytesVector.size() % 32 != 0)
    {
        string zeroPadding = string(64 - bytesVector.size() % 32, '0');
        stringBuffer.insert(stringBuffer.end(), zeroPadding.begin(), zeroPadding.end());
    }
    return Util::VectorToString(&stringBuffer);
}

string ABI::encodeString(const string *str)
{
    vector<uint8_t> stringVector(str->begin(), str->end());
    return Crypto::Keccak256(&stringVector).erase(0, 2);
}

string ABI::encodeBytes32(const string *bytes)
{
    vector<uint8_t> bytesVector = Util::ConvertHexToVector(bytes);
    return Crypto::Keccak256(&bytesVector).erase(0, 2);
}

string ABI::encodeBool(const bool b)
{
    vector<uint8_t> encodedValuedBuffer;
    if (b)
    {
        std::fill_n(encodedValuedBuffer.begin(), 31, 0);
        encodedValuedBuffer.push_back(1);
    }
    else
    {
        std::fill_n(encodedValuedBuffer.begin(), 32, 0);
    }
    return reinterpret_cast<char *>(encodedValuedBuffer.data());
}

string ABI::encodeUint256(const string n)
{
    int number = stoi(n);
    const vector<uint8_t> numberVector = Util::ConvertNumberToVector((uint32_t)number);
    const string numberHex = Util::VectorToString(&numberVector).erase(0, 2);
    return string(64 - numberHex.length(), '0') + numberHex;
}