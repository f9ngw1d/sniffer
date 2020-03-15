#ifndef SNIFFER_UTIL_H
#define SNIFFER_UTIL_H

#include <map>
#include <string>

inline bool isLegal(char s) {
    if (s == ':' || s == '\r' || s == '\n') {
        return false;
    }
    return true;
};

inline std::map<std::string, std::string> ParseHttpHeader(std::string raw) {
    enum class ParseMetaStatus {
        NONE,
        KEY,
        VALUE,
        BETWEEN
    };
    std::string tmp_key;
    std::string tmp_value;
    std::string raw_header;
    std::string raw_meta;

    ParseMetaStatus status = ParseMetaStatus::NONE;
    unsigned long pos=raw.find("\r\n\r\n");
    if (pos != std::string::npos) {
        std::string body = raw.substr(pos+4);
    }
    unsigned long pos_header=raw.find("\r\n");
    if (pos != std::string::npos) {
        raw_header = raw.substr(pos_header + 2, pos - pos_header);
        raw_meta = raw.substr(0, pos_header);
    }

    std::map<std::string, std::string> m = std::map<std::string, std::string>();

    for (int i =0; i<raw_header.size(); i++){
        char item = raw_header[i];
        if (status == ParseMetaStatus::NONE && isalpha(item)) {
            status = ParseMetaStatus::KEY;
            tmp_key.push_back(item);
        } else if (status == ParseMetaStatus::KEY && item == ':') {
            status = ParseMetaStatus::BETWEEN;
        } else if (status == ParseMetaStatus::KEY) {
            tmp_key.push_back(item);
        } else if (status == ParseMetaStatus::BETWEEN && isLegal(item)) {
            status = ParseMetaStatus::VALUE;
            tmp_value.push_back(item);
        } else if (status == ParseMetaStatus::VALUE && item == '\r') {
            status = ParseMetaStatus::NONE;
            m.insert(std::pair<std::string, std::string>(tmp_key, tmp_value));
            tmp_key.clear();
            tmp_value.clear();
        } else if (status == ParseMetaStatus::VALUE) {
            tmp_value.push_back(item);
        }
    }
    return m;
}
#endif //SNIFFER_UTIL_H