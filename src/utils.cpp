#include <string>
#include <sstream>
#include <codecvt>
#include <locale>
#include "wchar.h"
#include "uchar.h"
#include <iomanip>
#include <unicorn/unicorn.h>
#include "common.h"

template <typename T>
std::string int_to_hex(T i)
{
    std::stringstream stream;
    stream << "0x"
           << std::setfill('0') << std::setw(sizeof(T) * 2)
           << std::hex << i;
    return stream.str();
}

std::pair<std::string, std::string> split_unix_path(std::string const &u)
{
    unsigned int indexof = 0;
    for (unsigned int i = 0; i < u.size(); i++)
    {
        if (u[i] == u'/')
            indexof = i;
    }

    if (indexof == 0 || indexof >= (u.size() - 1))
    {
        return {u, ""};
    }
    else
    {
        indexof++;
        return {u.substr(0, indexof), u.substr(indexof)};
    }
}

std::string to_unix_path(std::u16string const &u)
{
    std::u16string copy(u);

    for (auto &c : copy)
    {
        if (c == '\\')
            c = '/';
    }

    return to_utf8string(copy);
}

std::u16string to_upper(std::u16string const &u)
{
    std::u16string out(u);

    for (auto &c : out)
    {
        c = towupper(c);
    }

    return out;
}

std::u16string to_lower(std::u16string const &u)
{
    std::u16string out(u);

    for (auto &c : out)
    {
        c = towlower(c);
    }

    return out;
}

std::string to_utf8string(std::u16string const &u)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    return convert.to_bytes(u);
}

std::u16string to_u16string(std::string const &u)
{
    std::u16string out;
    mbstate_t state = {};
    char16_t c = 0;
    const char *p = u.data();
    const char *end = &*u.end();
    size_t rc = 0;

    while ((rc = mbrtoc16(&c, p, end - p, &state)) != 0)
    {
        if (*p == 0) break;

        if (rc == size_t(-1) || rc == size_t(-2))
        {
            break;
        }
        else if (rc == size_t(-3))
        {
            out.push_back(c);
        }
        else
        {
            p += rc;
            out.push_back(c);
        }
    }

    return out;
}

std::u16string read_u16string(uc_engine *uc, uint32_t address)
{
    std::u16string s;
    char16_t chr;

    for (;;)
    {
        uc_assert(uc_mem_read(uc, address, &chr, 2));
        if (chr == 0)
            break;
        address += 2;
        s += chr;
    }
    s.reserve(2);
    s.data()[s.size()] = 0;

    return s;
}

std::string read_string(uc_engine *uc, uint32_t address)
{
    std::string s;
    char chr;

    for (;;)
    {
        uc_assert(uc_mem_read(uc, address, &chr, 1));
        if (chr == 0)
            break;
        s += chr;
        address += 1;
    }
    s.reserve(2);
    s.data()[s.size()] = 0;

    return s;
}