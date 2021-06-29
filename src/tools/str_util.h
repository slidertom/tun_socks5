#ifndef __STR_UTIL_H__
#define __STR_UTIL_H__
#pragma once

#include "vector"

#ifndef _INC_MATH
    #include <math.h>
#endif

#include "string"
#include "locale"
#include "algorithm"

// C:\Program Files (x86)\Windows Kits\10\Include\10.0.17134.0\shared\minwindef.h
// https://stackoverflow.com/questions/6884093/warning-c4003-not-enough-actual-parameters-for-macro-max-visual-studio-2010
#ifdef max
    #undef max
#endif
#ifdef min
    #undef min
#endif

#define FMT_HEADER_ONLY
#ifndef FMT_FORMAT_H_
    #include "fmt/format.h"
#endif

#ifndef FMT_PRINTF_H_
    #include "fmt/printf.h"
#endif

template <typename... T>
inline std::wstring FormatStr(const wchar_t *pszFormat, const T & ... args) {
    const std::wstring str = fmt::sprintf(pszFormat, args...);
    return str;
}

template <typename... T>
inline std::string FormatStr(const char *pszFormat, const T & ... args) {
    const std::string str = fmt::sprintf(pszFormat, args...);
    return str;
}

template <class TDouble>
inline std::wstring FormatStrWithE(int width, int precision, int exponent, TDouble value)
{
    double y = 0; // integer part
    double l = 0; // fraction part

    if (value != 0)	{				// value = y + l
        l = ::modf(::log10(::fabs(value)), &y); // Splits a value into fractional and integer parts
    }

    if (l < 0) {
        y -= 1.0;
    }

    y -= (width - 1);
    return fmt::sprintf(L"%.*fe%+0*.0f", precision, value * pow(10.0, -y), exponent + 1, y);
}

template <class TDouble>
inline std::wstring FormatStrM4(TDouble value) {
    return FormatStrWithE(1, 4, 2, value);
}

template <class TString>
inline void MakeLower(TString &str) {
    const std::locale &loc = std::locale();
    std::transform(str.begin(), str.end(), str.begin(),
            [&loc](int c) { return std::tolower(c, loc); });
}

template <class TString>
inline void MakeUpper(TString &str) {
    const std::locale &loc = std::locale();
    std::transform(str.begin(), str.end(), str.begin(),
            [&loc](int c) { return std::toupper(c, loc); });
}

#ifndef SS_USE_FACET
// STLPort #defines a macro (__STL_NO_EXPLICIT_FUNCTION_TMPL_ARGS) for
// all MSVC builds, erroneously in my opinion.  It causes problems for
// my SS_ANSI builds.  In my code, I always comment out that line.  You'll
// find it in   \stlport\config\stl_msvc.h

#if defined(__SGI_STL_PORT) && (__SGI_STL_PORT >= 0x400 )

    #if defined(__STL_NO_EXPLICIT_FUNCTION_TMPL_ARGS) && defined(_MSC_VER)
        #ifdef SS_ANSI
            #pragma schMSG(__STL_NO_EXPLICIT_FUNCTION_TMPL_ARGS defined!!)
        #endif
    #endif
    #define SS_USE_FACET(loc, fac) std::use_facet<fac >(loc)

#elif defined(_MSC_VER )

    #define SS_USE_FACET(loc, fac) std::use_facet<fac >(loc)

// ...and
#elif defined(_RWSTD_NO_TEMPLATE_ON_RETURN_TYPE)

    #define SS_USE_FACET(loc, fac) std::use_facet(loc, (fac*)0)

#else

    #define SS_USE_FACET(loc, fac) std::use_facet<fac >(loc)

#endif
#endif

// comparison (case Insensitive, not affected by locale)
template <typename CT>
inline int32_t str_cmpnocase(const CT *pA1, const CT *pA2)
{
    // SS_USE_FACET  -> std::_USE(loc, fac) -> std::use_facet<fac>(loc)
    std::locale loc = std::locale::classic();
    const std::ctype<CT>& ct = SS_USE_FACET(loc, std::ctype<CT>);
    CT f;
    CT l;

    do
    {
        f = ct.tolower(*(pA1++));
        l = ct.tolower(*(pA2++));
    } while ( (f) && (f == l) );

    return (int32_t)(f - l);
}

inline int32_t str_cmpnocase(const wchar_t *str1, const wchar_t *str2) {
    return ::str_cmpnocase<wchar_t>(str1, str2);
}
inline int32_t str_cmpnocase(const std::wstring &str1, const std::wstring &str2) {
    return ::str_cmpnocase(str1.c_str(), str2.c_str());
}
inline int32_t str_cmpnocase(const char *str1, const char *str2) {
    return ::str_cmpnocase<char>(str1, str2);
}

// trim from start
template <typename TString>
inline void str_ltrim(TString &s) {
    typedef typename TString::value_type char_type;
    const std::locale &loc = std::locale();
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            [&loc](char_type c) { return !std::isspace(c, loc); }));
}
// trim from end
template <typename TString>
inline void str_rtrim(TString &s) {
    typedef typename TString::value_type char_type;
    const std::locale &loc = std::locale();
    s.erase(std::find_if(s.rbegin(), s.rend(),
        [&loc](char_type c) {
            return !std::isspace(c, loc);
        }).base(), s.end());
}
// trim from both ends
template <typename TString>
inline void str_trim(TString &s) {
    str_rtrim(s);
    str_ltrim(s);
}

inline size_t str_count_lines(const wchar_t *str)
{
    size_t nRet(1);//, nPos(0);
    size_t nLen = ::wcslen(str);
    if (0 == nLen) {
        return 0;
    }

    for (size_t i1 = 0; i1 < nLen; ++i1) {
        if (str[i1] == L'\n')
            ++nRet;
    }

    return nRet;
}

// http://www.codeproject.com/KB/string/stringsplit.aspx
//-----------------------------------------------------------
// StrT:    Type of string to be constructed
//          Must have char* ctor.
// str:     String to be parsed.
// delim:   Pointer to delimiter.
// results: Vector of StrT for strings between delimiter.
// empties: Include empty strings in the results.
//-----------------------------------------------------------
template <typename StrT>
inline size_t str_split_string(const wchar_t *str, const wchar_t *delim, std::vector<StrT> &results, bool empties = true)
{
    wchar_t *pstr = const_cast<wchar_t *>(str);
    wchar_t *r = ::wcsstr(pstr, delim); // Returns a pointer to the first occurrence of str2 in str1, or a null pointer if str2 is not part of str1.
                                         // A pointer to the first occurrence in str1 of the entire sequence of characters specified in str2,
                                         // or a null pointer if the sequence is not present in str1.
    size_t dlen = ::wcslen(delim);

    while (r != NULL)
    {
        wchar_t *cp = new wchar_t[(r-pstr)+1];
        ::memcpy(cp, pstr, sizeof(wchar_t)*(r-pstr));
        cp[(r-pstr)] = '\0';
        if ( ::wcslen(cp) > 0 || empties ) {
            StrT s(cp);
            results.push_back(s);
        }
        delete[] cp;

        pstr = r + dlen;
        r = ::wcsstr(pstr, delim);
    }

    if ( ::wcslen(pstr) > 0 || empties ) {
        results.push_back(StrT(pstr));
    }

    return results.size();
}

template <typename StrT>
inline size_t str_split_string(const char *str, const char *delim,
                               std::vector<StrT> &results, bool empties = true)
{
    char *pstr = const_cast<char *>(str);
    char *r = ::strstr(pstr, delim); // Returns a pointer to the first occurrence of str2 in str1, or a null pointer if str2 is not part of str1.
                                     // A pointer to the first occurrence in str1 of the entire sequence of characters specified in str2,
                                     // or a null pointer if the sequence is not present in str1.
    size_t dlen = ::strlen(delim);

    while( r != NULL )
    {
        char *cp = new char[(r-pstr)+1];
        ::memcpy(cp, pstr, (r-pstr));
        cp[(r-pstr)] = '\0';
        if ( ::strlen(cp) > 0 || empties ) {
            StrT s(cp);
            results.push_back(s);
        }
        delete[] cp;

        pstr = r + dlen;
        r = ::strstr(pstr, delim);
    }

    if ( ::strlen(pstr) > 0 || empties ) {
        results.push_back(StrT(pstr));
    }

    return results.size();
}

template <typename StrT, typename value_type>
inline StrT str_join_post_delim(const std::vector<StrT> &strs, const value_type *delim) {
    StrT result;
    for (const StrT &str : strs) {
        result += str;
        result += delim;
    }
    return result;
}

inline std::wstring str_format_sorted_sel_string(std::vector<std::wstring> &arr) {
    std::sort(arr.begin(), arr.end());
    return ::str_join_post_delim(arr, L"\n");
}

inline std::string str_format_sorted_sel_string(std::vector<std::string> &arr) {
    std::sort(arr.begin(), arr.end());
    return ::str_join_post_delim(arr, "\n");
}

template <typename StrT, typename value_type>
inline std::wstring str_join_pre_delim(const std::vector<StrT> &text_array, const value_type *delim) {
    StrT sResult;
    auto end_it = text_array.end();
    for (auto it = text_array.begin(); it != end_it; ++it) {
        sResult += *it;
        if (it != end_it - 1) {
            sResult += delim;
        }
    }
    return sResult;
}

template <typename StrT, typename value_type>
inline std::wstring str_join_sorted_unique_pre_delim(std::vector<StrT> &text_array, const value_type *delim) {
    std::sort(text_array.begin(), text_array.end(), [](const StrT &sPrev, const StrT &sNext) {
                    return ::str_cmpnocase(sNext, sPrev) > 0;
                  }
    );
    text_array.erase(std::unique(text_array.begin(), text_array.end()), text_array.end());
    return ::str_join_pre_delim(text_array, delim);
}

// Converts nNr from A to Z and formats label string
inline void str_make_default_label(int32_t nNr, std::wstring &label)
{
    if (nNr <= L'Z' - L'A') {
        label = std::to_wstring(nNr);
        label += L'A';
    }
    else {
        label = (char) (nNr  % (L'Z' - L'A' + 1) + L'A');
        label += std::to_wstring(nNr  / (L'Z' - L'A' + 1));
    }
}

// Remove dangerous characters from text
inline void str_sanitize(std::wstring &txt)
{
    for (auto &char_value : txt) {
        if (char_value < L' ')
            char_value = L' ';
    }
}

// This function compares text strings, one of which can have wildcards ('*').
inline bool str_wild_match(const wchar_t *pWildText,				  // A (potentially) corresponding string with wildcards
                           const wchar_t *pTameText,				  // A string without wildcards
                           bool bCaseSensitive = false,       // By default, match on 'X' vs 'x'
                           wchar_t cAltTerminator = L'\0')    // For function names, for example, you can stop at the first '('
{
    bool bMatch = true;
    const wchar_t * pAfterLastWild = nullptr; // The location after the last '*', if we’ve encountered one
    const wchar_t * pAfterLastTame = nullptr; // The location in the tame string, from which we started after last wildcard
    wchar_t  t, w;

    // Walk the text strings one character at a time.
    while (1)
    {
        t = *pTameText;
        w = *pWildText;

        // How do you match a unique text string?
        if (!t || t == cAltTerminator) {
            // Easy: unique up on it!
            if (!w || w == cAltTerminator) {
                break; // "x" matches "x"
            }
            else if (w == L'*') {
                pWildText++;
                continue; // "x*" matches "x" or "xy"
            }
            else if (pAfterLastTame) {
                if (!(*pAfterLastTame) || *pAfterLastTame == cAltTerminator) {
                    bMatch = false;
                    break;
                }
                pTameText = pAfterLastTame++;
                pWildText = pAfterLastWild;
                continue;
            }

            bMatch = false;
            break; // "x" doesn't match "xy"
        }
        else
        {
            if (!bCaseSensitive)
            {   // Lowercase the characters to be compared.
                if (t >= L'A' && t <= L'Z') {
                    t += (L'a' - L'A');
                }

                if (w >= L'A' && w <= L'Z') {
                    w += (L'a' - L'A');
                }
            }

            // How do you match a tame text string?
            if (t != w) {
                if (w == L'*') // The tame way: unique up on it!
                {
                    pAfterLastWild = ++pWildText;
                    pAfterLastTame = pTameText;
                    w = *pWildText;

                    if (!w || w == cAltTerminator) {
                        break; // "*" matches "x"
                    }
                    continue; // "*y" matches "xy"
                }
                else if (pAfterLastWild)
                {
                    if (pAfterLastWild != pWildText)
                    {
                        pWildText = pAfterLastWild;
                        w = *pWildText;

                        if (!bCaseSensitive && w >= L'A' && w <= L'Z') {
                            w += (L'a' - L'A');
                        }

                        if (t == w) {
                            pWildText++;
                        }
                    }
                    pTameText++;
                    continue;  // "*sip*" matches "mississippi"
                }
                else {
                    bMatch = false;
                    break; // "x" doesn't match "y"
                }
            }
        }

        pTameText++;
        pWildText++;
    }

    return bMatch;
}

class CSelectionParser
{
// Static operations
public:
    // Type elements numbers and/or -ranges separated by commas, example 1,3,5-12,4
    static bool ParseString(const wchar_t *selection, std::vector<int> &brandIds) {
        const wchar_t *pCh = selection;
        return ParseSelectionRange(&pCh, brandIds);
    }

private:
    static void SkipSpace(const wchar_t **pCh) {
        while (isspace(**pCh) ) {
            (*pCh)++;
        }
    }

    static int32_t ParseBrandID(const wchar_t **pCh) {
        int32_t nNumber = 0;
        SkipSpace(pCh);
        while (isdigit(**pCh)) {
            nNumber = nNumber * 10 + **pCh - L'0';
            (*pCh)++;
        }
        return nNumber;
    }

    static void SelectItems(int32_t nFirst, int32_t nLast, std::vector<int32_t> &brandIds)
    {
        if (nFirst > nLast) {
            std::swap(nFirst, nLast);
        }

        for (int32_t n = nFirst; n <= nLast; ++n) {
            brandIds.push_back(n);
        }
    }

    static bool ParseItemsRange(const wchar_t **pCh, std::vector<int32_t> &brandIds)
    {
        SkipSpace(pCh);
        const int32_t nFirst = ParseBrandID(pCh); // first number of interval
        if (nFirst == 0) {
            return false;
        }
        SkipSpace(pCh);
        if (**pCh != L'-') {
            brandIds.push_back(nFirst);
        }
        else {
           (*pCh)++;
            int32_t nLast = ParseBrandID(pCh); // last number of interval
            if (nLast == 0) {
                return false;
            }
            SelectItems(nFirst, nLast, brandIds);
        }
        return true;
    }

    static bool ParseSelectionRange(const wchar_t **pCh, std::vector<int> &brandIds) {
        while (true) {
            if (!ParseItemsRange(pCh, brandIds)) {
                return false;
            }
            SkipSpace(pCh);
            if (**pCh != L',') {
                break;
            }

            (*pCh)++;
        }
        return (**pCh == L'\0');
    }
};

template <typename size_type, typename char_type>
inline void str_bool_to_string(const bool bStream[], size_type nSize, char_type *&str) {
    str = new char_type[nSize + 1];
    size_type i = 0;
    for (; i < nSize ; ++i) {
        str[i] = (char_type)(bStream[i] + '0');
    }
    str[i] = 0;
}

template <typename size_type, typename char_type>
inline bool str_string_to_bool(const char_type *str, bool bStream[], size_type nSize) {
    const size_type nStrLen = (size_type)std::char_traits<char_type>::length(str);
    const size_type nCnt = nStrLen < nSize ? nStrLen : nSize; // we will try to fill bStream in any case

    for (size_type i = 0; i < nCnt; ++i) {
        char_type ch = str[i];
        bStream[i] = ( (int(ch) - '0') == 1);
    }
    return true;
}

template <typename size_type, typename char_type>
inline void str_int32_to_string(const int32_t bStream[], size_type nSize, char_type *&str) {
    str = new char_type[nSize + 1];
    size_type i = 0;
    for (; i < nSize ; ++i) {
        str[i] = (char_type)(bStream[i] + '0');
    }
    str[i] = 0;
}

template <typename size_type, typename char_type>
inline bool str_string_to_int32(const char_type *str, int32_t bStream[], size_type nSize) {
    const size_type nStrLen = (size_type)std::char_traits<char_type>::length(str);
    const size_type nCnt = nStrLen < nSize ? nStrLen : nSize; // we will try to fill bStream in any case
    for (size_type i = 0; i < nCnt; ++i) {
        char_type ch = str[i];
        bStream[i] = (int32_t(ch) - '0');
    }
    return true;
}

#endif
