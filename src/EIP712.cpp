#include <EIP712.h>

using namespace std;

/**
 * Finds all types within a type definition object
 *
 * @param {string} primaryType - Root type
 * @param {cJSON} types - Type definitions
 * @param {vector<string>} results - current vector of accumulated types
 * @returns {vector<string>} - Vector of all types found in the type definition
 */

vector<string> EIP712::dependencies(string primaryType, cJSON *types, vector<string> found)
{
    const cJSON *field = NULL;
    const cJSON *primaryTypeData = cJSON_GetObjectItem(types, primaryType.c_str());

    if (std::find(found.begin(), found.end(), primaryType) != found.end())
    {
        return found;
    }

    if (!primaryTypeData)
    {
        return found;
    }
    found.push_back(primaryType);
    cJSON_ArrayForEach(field, primaryTypeData)
    {
        cJSON *fieldType = cJSON_GetObjectItemCaseSensitive(field, "type");
        for (auto dep : dependencies(fieldType->valuestring, types, found))
        {
            if (std::find(found.begin(), found.end(), dep) == found.end())
            {
                found.push_back(dep);
            }
        }
    }
    return found;
}

/*
 *
 * Encodes the type of an object by encoding a comma delimited list of its members
 *
 * @param {string} primaryType - Root type to encode
 * @param {cJSON} types - Type definitions
 * @returns {vector<uint8_t>} - Encoded bytes representation of the type of an object
 *
 */

vector<uint8_t> EIP712::encodeType(string primaryType, cJSON *types)
{
    const cJSON *field = NULL;
    cJSON *dependecyData = NULL;
    vector<string> deps = dependencies(primaryType, types);
    vector<string> depsNoPrimaryType(deps.begin() + 1, deps.end());
    vector<string> sortedDeps;
    sort(depsNoPrimaryType.begin(), depsNoPrimaryType.end());
    sortedDeps.push_back(primaryType);
    sortedDeps.insert(sortedDeps.end(), depsNoPrimaryType.begin(), depsNoPrimaryType.end());
    string result = "";
    for (auto dep : sortedDeps)
    {
        dependecyData = cJSON_GetObjectItem(types, dep.c_str());
        result += dep + "(";
        cJSON_ArrayForEach(field, dependecyData)
        {
            cJSON *type = cJSON_GetObjectItemCaseSensitive(field, "type");
            cJSON *name = cJSON_GetObjectItemCaseSensitive(field, "name");
            result += string(type->valuestring) + " " + string(name->valuestring) + ",";
        }
        result.pop_back();
        result += ")";
    }
    std::vector<uint8_t> stringVector(result.begin(), result.end());
    return stringVector;
}

/**
 *
 * Hashes the type of an object
 *
 * @param {string} primaryType - Root type to hash
 * @param {cJSON} types - Type definitions
 * @param {uint8_t *} digest - Hash of an object
 *
 */

void EIP712::typeHash(string primaryType, cJSON *types, uint8_t *digest)
{
    vector<uint8_t> encodedTypeVector = encodeType(primaryType, types);
    Crypto::Keccak256(encodedTypeVector.data(), encodedTypeVector.size(), digest);
}

/**
 * Encodes a field of an object by encoding given type and name
 *
 * @param {string} type - The type of the field
 * @param {string} data - The value of the field
 * @returns {string} - Encoded hex representation of an object (without 0x)
 */

string EIP712::encodeField(string type, string value)
{
    return ABI::encodeArg(type, value);
}

/**
 * Encodes an object by encoding and concatenating each of its members
 *
 * @param {string} primaryType - Root type
 * @param {cJSON} data - Object to encode
 * @param {cJSON} types - Type definitions
 * @returns {vector<uint8_t>} - Encoded bytes representation of an object
 */

vector<uint8_t> EIP712::encodeData(string primaryType, cJSON *data, cJSON *types)
{
    cJSON *value = NULL;
    const cJSON *field = NULL;
    const cJSON *primaryTypeData = cJSON_GetObjectItem(types, primaryType.c_str());

    vector<uint8_t> encValues = {};
    uint8_t encPrimaryHash[ETHERS_KECCAK256_LENGTH] = {};
    typeHash(primaryType, types, encPrimaryHash);
    encValues.insert(encValues.begin(), encPrimaryHash, encPrimaryHash + ETHERS_KECCAK256_LENGTH);
    cJSON_ArrayForEach(field, primaryTypeData)
    {
        cJSON *fieldName = cJSON_GetObjectItemCaseSensitive(field, "name");
        cJSON *fieldType = cJSON_GetObjectItemCaseSensitive(field, "type");
        cJSON *fieldvalue = cJSON_GetObjectItemCaseSensitive(data, fieldName->valuestring);
        if (cJSON_GetObjectItemCaseSensitive(types, fieldType->valuestring))
        {
            uint8_t encValue[ETHERS_KECCAK256_LENGTH] = {};
            vector<uint8_t> customTypeEncoded = encodeData(fieldType->valuestring, fieldvalue, types);
            Crypto::Keccak256(customTypeEncoded.data(), customTypeEncoded.size(), encValue);
            encValues.insert(encValues.end(), encValue, encValue + ETHERS_KECCAK256_LENGTH);
        }
        else
        {
            string encodedField = encodeField(fieldType->valuestring, fieldvalue->valuestring);
            vector<uint8_t> encodedFieldBytes = Util::ConvertHexToVector(&encodedField);
            encValues.insert(encValues.end(), encodedFieldBytes.begin(), encodedFieldBytes.end());
        }
    }
    return encValues;
}

/*
 *
 * Hashes an object
 *
 * @param {string} primaryType - Root type
 * @param {cJSON} data - Object to hash
 * @param {cJSON} types - Type definitions
 * @param {uint8_t*} result - Hash of an object
 *
 */

void EIP712::hashStruct(string primaryType, cJSON *data, cJSON *types, uint8_t *result)
{
    vector<uint8_t> encodedData = encodeData(primaryType, data, types);
    Crypto::Keccak256(encodedData.data(), encodedData.size(), result);
}

/**
 * Signs a typed message as per EIP-712 and returns its keccak hash
 *
 * @param {Object} typedData - Types message data to sign
 * @param {cJSON} data - Object to hash
 * @param {cJSON} types - Type definitions
 * @param {cJSON} domain - Domain definition
 * @param {uint8_t*} result - Hash of an object
 */

void EIP712::EIP712Hash(string primaryType, cJSON *data, cJSON *types, cJSON *domain, uint8_t *result)
{
    uint8_t EIP712DomainHash[ETHERS_KECCAK256_LENGTH] = {};
    uint8_t primaryTypeHash[ETHERS_KECCAK256_LENGTH] = {};
    vector<uint8_t> parts;
    parts.push_back(25); // \x19
    parts.push_back(1);  // \x01
    hashStruct("EIP712Domain", domain, types, EIP712DomainHash);
    hashStruct(primaryType, data, types, primaryTypeHash);
    parts.insert(parts.end(), EIP712DomainHash, EIP712DomainHash + ETHERS_KECCAK256_LENGTH);
    parts.insert(parts.end(), primaryTypeHash, primaryTypeHash + ETHERS_KECCAK256_LENGTH);
    Crypto::Keccak256(parts.data(), parts.size(), result);
}