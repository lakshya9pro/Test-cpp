#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <regex>
#include <unordered_map>
#include <cctype>
#include <chrono>
#include <android/log.h>

#define LOG_TAG "NativeProxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#if __has_include(<openssl/ssl.h>)
#include <openssl/ssl.h>
#include <openssl/err.h>
#define HAS_OPENSSL 1
#endif

namespace native_proxy {

const char* DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const char* DEFAULT_REFERER = "https://nextgencloudfabric.com/";
const char* DEFAULT_ORIGIN = "https://nextgencloudfabric.com";

static std::atomic<bool> g_running(false);
static std::atomic<int> g_server_fd(-1);
static std::atomic<int> g_server_port(0);
static std::thread g_server_thread;

#ifdef HAS_OPENSSL
static SSL_CTX* g_ssl_ctx = nullptr;

void init_ssl() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (g_ssl_ctx) {
            SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, nullptr);
        } else {
            LOGE("Failed to create OpenSSL context");
        }
    });
}
#endif

std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%') {
            if (i + 2 < in.size()) {
                int hex_val = 0;
                sscanf(in.substr(i + 1, 2).c_str(), "%x", &hex_val);
                out += static_cast<char>(hex_val);
                i += 2;
            } else {
                out += in[i];
            }
        } else if (in[i] == '+') {
            out += ' ';
        } else {
            out += in[i];
        }
    }
    return out;
}

std::string url_encode(const std::string& in) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);

    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[(c >> 4) & 0x0F];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

struct ParsedUrl {
    std::string scheme;
    std::string host;
    int port = 80;
    std::string path;
};

bool parse_url(const std::string& url_str, ParsedUrl& out) {
    std::string s = url_str;
    size_t scheme_pos = s.find("://");
    if (scheme_pos == std::string::npos) return false;

    out = ParsedUrl{};
    out.scheme = s.substr(0, scheme_pos);
    std::transform(out.scheme.begin(), out.scheme.end(), out.scheme.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (out.scheme != "http" && out.scheme != "https") return false;

    std::string rest = s.substr(scheme_pos + 3);

    size_t authority_end = rest.find_first_of("/?#");
    std::string host_port = (authority_end == std::string::npos)
                            ? rest : rest.substr(0, authority_end);

    if (host_port.empty()) return false;

    if (authority_end == std::string::npos) {
        out.path = "/";
    } else {
        out.path = rest.substr(authority_end);
        if (out.path.empty() || out.path[0] == '?' || out.path[0] == '#') {
            out.path = "/" + out.path;
        }
    }

    // IPv6 literal: [::1]:8080
    if (!host_port.empty() && host_port[0] == '[') {
        size_t rb = host_port.find(']');
        if (rb == std::string::npos) return false;
        out.host = host_port.substr(0, rb + 1);
        if (rb + 1 < host_port.size() && host_port[rb + 1] == ':') {
            out.port = std::atoi(host_port.substr(rb + 2).c_str());
        } else {
            out.port = (out.scheme == "https") ? 443 : 80;
        }
    } else {
        size_t colon_pos = host_port.rfind(':');
        if (colon_pos != std::string::npos &&
            host_port.find(':') == colon_pos) {
            out.host = host_port.substr(0, colon_pos);
            out.port = std::atoi(host_port.substr(colon_pos + 1).c_str());
        } else {
            out.host = host_port;
            out.port = (out.scheme == "https") ? 443 : 80;
        }
    }

    if (out.host.empty() || out.port <= 0 || out.port > 65535) return false;
    return true;
}

std::string resolve_url(const std::string& base_str, const std::string& ref_str) {
    if (ref_str.empty()) return base_str;
    if (ref_str.find("://") != std::string::npos) return ref_str;

    ParsedUrl base;
    if (!parse_url(base_str, base)) return ref_str;

    std::string host_part = base.scheme + "://" + base.host;
    if ((base.scheme == "http" && base.port != 80) ||
        (base.scheme == "https" && base.port != 443)) {
        host_part += ":" + std::to_string(base.port);
    }

    if (ref_str.size() >= 2 && ref_str[0] == '/' && ref_str[1] == '/') {
        return base.scheme + ":" + ref_str;
    }

    // Query-only / fragment-only reference.
    if (ref_str[0] == '?' || ref_str[0] == '#') {
        std::string base_no_fragment = base_str;
        size_t hash = base_no_fragment.find('#');
        if (hash != std::string::npos) base_no_fragment.resize(hash);
        if (ref_str[0] == '?') {
            size_t q = base_no_fragment.find('?');
            if (q != std::string::npos) base_no_fragment.resize(q);
        }
        return base_no_fragment + ref_str;
    }

    if (ref_str[0] == '/') {
        return host_part + ref_str;
    }

    std::string base_path = base.path;
    size_t qmark = base_path.find('?');
    if (qmark != std::string::npos) base_path.resize(qmark);
    size_t hash = base_path.find('#');
    if (hash != std::string::npos) base_path.resize(hash);

    size_t last_slash = base_path.find_last_of('/');
    std::string base_path_dir =
        (last_slash != std::string::npos) ? base_path.substr(0, last_slash + 1) : "/";

    return host_part + base_path_dir + ref_str;
}

std::string rewrite_m3u8(const std::string& content, const std::string& base_url, const std::string& proxy_host) {
    std::istringstream stream(content);
    std::string line;
    std::ostringstream result;

    static const std::regex uri_regex("URI=\"([^\"]+)\"");

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) {
            result << "\n";
            continue;
        }

        if (line[0] == '#') {
            std::string accum;
            auto words_begin = std::sregex_iterator(line.begin(), line.end(), uri_regex);
            auto words_end = std::sregex_iterator();

            size_t last_pos = 0;
            for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                std::smatch m = *i;
                accum += line.substr(last_pos, m.position() - last_pos);
                std::string sub = m[1].str();
                std::string resolved = resolve_url(base_url, sub);
                std::string proxied = "http://" + proxy_host + "/proxy?url=" + url_encode(resolved);
                accum += "URI=\"" + proxied + "\"";
                last_pos = m.position() + m.length();
            }
            accum += line.substr(last_pos);
            result << accum << "\n";
        } else {
            std::string resolved = resolve_url(base_url, line);
            std::string proxied = "http://" + proxy_host + "/proxy?url=" + url_encode(resolved);
            result << proxied << "\n";
        }
    }

    return result.str();
}

class SocketStream {
public:
    int fd = -1;
#ifdef HAS_OPENSSL
    SSL* ssl = nullptr;
#endif
    bool is_ssl = false;

    SocketStream() = default;
    ~SocketStream() { close_stream(); }

    void close_stream() {
#ifdef HAS_OPENSSL
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
#endif
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }

    ssize_t read_bytes(void* buf, size_t count) {
#ifdef HAS_OPENSSL
        if (is_ssl && ssl) {
            int ret = SSL_read(ssl, buf, count);
            return ret > 0 ? ret : 0;
        }
#endif
        return recv(fd, buf, count, 0);
    }

    ssize_t write_bytes(const void* buf, size_t count) {
#ifdef HAS_OPENSSL
        if (is_ssl && ssl) {
            int ret = SSL_write(ssl, buf, count);
            return ret > 0 ? ret : 0;
        }
#endif
        return send(fd, buf, count, 0);
    }
};

bool connect_remote(const ParsedUrl& target, SocketStream& stream) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(target.port);
    if (getaddrinfo(target.host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        LOGE("getaddrinfo failed for %s:%d", target.host.c_str(), target.port);
        return false;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        LOGE("connect failed to %s:%d (errno: %d)", target.host.c_str(), target.port, errno);
        close(fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);

    stream.fd = fd;
    if (target.scheme == "https") {
        stream.is_ssl = true;
#ifdef HAS_OPENSSL
        init_ssl();
        if (!g_ssl_ctx) return false;
        stream.ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(stream.ssl, fd);
        SSL_set_tlsext_host_name(stream.ssl, target.host.c_str());
        if (SSL_connect(stream.ssl) <= 0) {
            LOGE("SSL_connect failed for %s", target.host.c_str());
            stream.close_stream();
            return false;
        }
#else
        LOGE("HTTPS requested but OpenSSL is not enabled in build");
        stream.close_stream();
        return false;
#endif
    }

    return true;
}

void send_simple_response(int fd, const std::string& status,
                           const std::string& content_type,
                           const std::string& body) {
    std::ostringstream out;
    out << "HTTP/1.1 " << status << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n"
        << "Access-Control-Allow-Headers: *\r\n"
        << "Access-Control-Expose-Headers: *\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    std::string data = out.str();
    send(fd, data.data(), data.size(), 0);
}

void handle_client_connection(int client_fd) {
    struct timeval tv;
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char req_buf[8192];
    ssize_t bytes_read = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
    if (bytes_read <= 0) {
        close(client_fd);
        return;
    }
    req_buf[bytes_read] = '\0';
    std::string request_data(req_buf, bytes_read);

    std::istringstream req_stream(request_data);
    std::string method, path_uri, version;
    req_stream >> method >> path_uri >> version;

    if (method.empty() || path_uri.empty()) {
        send_simple_response(client_fd, "400 Bad Request", "text/plain", "Bad Request");
        close(client_fd);
        return;
    }

    // Local diagnostics. Opening http://127.0.0.1:<port>/ must prove
    // that the native server is actually listening.
    if (path_uri == "/" || path_uri == "/health") {
        send_simple_response(client_fd, "200 OK", "application/json",
                             R"({"ok":true,"server":"native_proxy"})");
        close(client_fd);
        return;
    }

    std::unordered_map<std::string, std::string> headers;
    std::string header_line;
    std::string host_header = "127.0.0.1:" + std::to_string(g_server_port.load());
    
    while (std::getline(req_stream, header_line) && header_line != "\r" && !header_line.empty()) {
        if (!header_line.empty() && header_line.back() == '\r') header_line.pop_back();
        size_t colon = header_line.find(':');
        if (colon != std::string::npos) {
            std::string key = header_line.substr(0, colon);
            std::string val = header_line.substr(colon + 1);
            while (!val.empty() && val[0] == ' ') val.erase(0, 1);
            std::string lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
            headers[lower_key] = val;
            if (lower_key == "host") host_header = val;
        }
    }

    if (method == "OPTIONS") {
        const char* cors_resp = 
            "HTTP/1.1 204 No Content\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n"
            "Access-Control-Allow-Headers: *\r\n"
            "Access-Control-Expose-Headers: *\r\n"
            "Content-Length: 0\r\n\r\n";
        send(client_fd, cors_resp, strlen(cors_resp), 0);
        close(client_fd);
        return;
    }

    if (path_uri.rfind("/proxy", 0) != 0) {
        send_simple_response(client_fd, "404 Not Found", "application/json",
                             R"({"error":"Use /proxy?url=<encoded-url>"})");
        close(client_fd);
        return;
    }

    std::string target_url_encoded;
    size_t query_pos = path_uri.find('?');
    if (query_pos != std::string::npos) {
        std::string query = path_uri.substr(query_pos + 1);
        size_t p = query.find("url=");
        if (p != std::string::npos) {
            target_url_encoded = query.substr(p + 4);
            size_t amp = target_url_encoded.find('&');
            if (amp != std::string::npos) target_url_encoded.resize(amp);
        }
    }

    if (target_url_encoded.empty()) {
        const char* err_resp = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n\r\n"
            "{\"error\":\"Missing 'url' query parameter\"}";
        send(client_fd, err_resp, strlen(err_resp), 0);
        close(client_fd);
        return;
    }

    std::string target_url = url_decode(target_url_encoded);
    ParsedUrl target;
    if (!parse_url(target_url, target)) {
        const char* err_resp = 
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n\r\n"
            "{\"error\":\"Invalid target URL\"}";
        send(client_fd, err_resp, strlen(err_resp), 0);
        close(client_fd);
        return;
    }

    SocketStream remote_stream;
    if (!connect_remote(target, remote_stream)) {
        const char* err_resp = 
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n\r\n"
            "{\"error\":\"Failed to connect to remote server\"}";
        send(client_fd, err_resp, strlen(err_resp), 0);
        close(client_fd);
        return;
    }

    std::ostringstream remote_req;
    remote_req << method << " " << target.path << " HTTP/1.1\r\n";
    remote_req << "Host: " << target.host << "\r\n";

    if (target.host.find("turboviplay") != std::string::npos || target.host.find("turbovid") != std::string::npos || target.host.find("turbosplayer") != std::string::npos || target_url.find("turbovid") != std::string::npos || target_url.find("turbosplayer") != std::string::npos) {
        remote_req << "Referer: https://turbovidhls.com/\r\n";
        remote_req << "Origin: https://turbovidhls.com\r\n";
    } else {
        remote_req << "Referer: " << DEFAULT_REFERER << "\r\n";
        remote_req << "Origin: " << DEFAULT_ORIGIN << "\r\n";
    }

    auto ua_it = headers.find("user-agent");
    if (ua_it != headers.end()) {
        remote_req << "User-Agent: " << ua_it->second << "\r\n";
    } else {
        remote_req << "User-Agent: " << DEFAULT_USER_AGENT << "\r\n";
    }

    auto range_it = headers.find("range");
    if (range_it != headers.end()) {
        remote_req << "Range: " << range_it->second << "\r\n";
    }

    remote_req << "Accept: */*\r\n";
    remote_req << "Connection: close\r\n\r\n";

    std::string out_req_str = remote_req.str();
    remote_stream.write_bytes(out_req_str.data(), out_req_str.size());

    std::vector<char> resp_header_buf;
    char chunk[4096];
    bool header_complete = false;
    size_t header_end_pos = 0;

    while (!header_complete) {
        ssize_t n = remote_stream.read_bytes(chunk, sizeof(chunk));
        if (n <= 0) break;
        resp_header_buf.insert(resp_header_buf.end(), chunk, chunk + n);

        std::string buf_str(resp_header_buf.data(), resp_header_buf.size());
        size_t pos = buf_str.find("\r\n\r\n");
        if (pos != std::string::npos) {
            header_complete = true;
            header_end_pos = pos + 4;
        }
    }

    if (!header_complete) {
        close(client_fd);
        return;
    }

    std::string raw_header_str(resp_header_buf.data(), header_end_pos);
    std::istringstream resp_header_stream(raw_header_str);
    std::string status_line;
    std::getline(resp_header_stream, status_line);
    if (!status_line.empty() && status_line.back() == '\r') status_line.pop_back();

    std::string content_type;
    long long content_length = -1;

    std::string hline;
    while (std::getline(resp_header_stream, hline) && hline != "\r" && !hline.empty()) {
        if (!hline.empty() && hline.back() == '\r') hline.pop_back();
        size_t colon = hline.find(':');
        if (colon != std::string::npos) {
            std::string k = hline.substr(0, colon);
            std::string v = hline.substr(colon + 1);
            while (!v.empty() && v[0] == ' ') v.erase(0, 1);
            std::string lk = k;
            std::transform(lk.begin(), lk.end(), lk.begin(), ::tolower);
            if (lk == "content-type") content_type = v;
            if (lk == "content-length") content_length = atoll(v.c_str());
        }
    }

    bool is_m3u8 = (target.path.find(".m3u8") != std::string::npos) ||
                   (content_type.find("mpegurl") != std::string::npos) ||
                   (content_type.find("m3u8") != std::string::npos);

    if (is_m3u8 && status_line.find("200") != std::string::npos) {
        std::vector<char> body_data;
        if (resp_header_buf.size() > header_end_pos) {
            body_data.insert(body_data.end(), resp_header_buf.begin() + header_end_pos, resp_header_buf.end());
        }

        while (true) {
            ssize_t n = remote_stream.read_bytes(chunk, sizeof(chunk));
            if (n <= 0) break;
            body_data.insert(body_data.end(), chunk, chunk + n);
        }

        std::string raw_m3u8(body_data.data(), body_data.size());
        std::string rewritten = rewrite_m3u8(raw_m3u8, target_url, host_header);

        std::ostringstream client_resp;
        client_resp << "HTTP/1.1 200 OK\r\n";
        client_resp << "Content-Type: application/vnd.apple.mpegurl\r\n";
        client_resp << "Content-Length: " << rewritten.size() << "\r\n";
        client_resp << "Access-Control-Allow-Origin: *\r\n";
        client_resp << "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n";
        client_resp << "Access-Control-Allow-Headers: *\r\n";
        client_resp << "Access-Control-Expose-Headers: *\r\n";
        client_resp << "Connection: close\r\n\r\n";
        client_resp << rewritten;

        std::string final_out = client_resp.str();
        send(client_fd, final_out.data(), final_out.size(), 0);
    } else {
        std::ostringstream client_resp_hdr;
        client_resp_hdr << status_line << "\r\n";
        client_resp_hdr << "Access-Control-Allow-Origin: *\r\n";
        client_resp_hdr << "Access-Control-Allow-Methods: GET, POST, OPTIONS, HEAD\r\n";
        client_resp_hdr << "Access-Control-Allow-Headers: *\r\n";
        client_resp_hdr << "Access-Control-Expose-Headers: *\r\n";

        std::istringstream rh_stream(raw_header_str);
        std::string line_hdr;
        std::getline(rh_stream, line_hdr);
        while (std::getline(rh_stream, line_hdr) && line_hdr != "\r" && !line_hdr.empty()) {
            if (!line_hdr.empty() && line_hdr.back() == '\r') line_hdr.pop_back();
            size_t colon = line_hdr.find(':');
            if (colon != std::string::npos) {
                std::string k = line_hdr.substr(0, colon);
                std::string lk = k;
                std::transform(lk.begin(), lk.end(), lk.begin(), ::tolower);
                if (lk != "transfer-encoding" && lk != "connection") {
                    client_resp_hdr << line_hdr << "\r\n";
                }
            }
        }
        client_resp_hdr << "Connection: close\r\n\r\n";
        std::string out_hdr = client_resp_hdr.str();
        send(client_fd, out_hdr.data(), out_hdr.size(), 0);

        if (resp_header_buf.size() > header_end_pos) {
            send(client_fd, resp_header_buf.data() + header_end_pos, resp_header_buf.size() - header_end_pos, 0);
        }

        char pass_buf[32768];
        while (true) {
            ssize_t n = remote_stream.read_bytes(pass_buf, sizeof(pass_buf));
            if (n <= 0) break;
            ssize_t sent = send(client_fd, pass_buf, n, 0);
            if (sent <= 0) break;
        }
    }

    close(client_fd);
}

void server_loop(int port) {
    if (port < 1024 || port > 65535) {
        LOGE("Invalid server port: %d", port);
        g_running = false;
        return;
    }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        LOGE("Failed to create server socket: errno=%d", errno);
        g_running = false;
        return;
    }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(sfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        LOGE("Failed to bind 127.0.0.1:%d: errno=%d (%s)",
             port, errno, strerror(errno));
        close(sfd);
        g_running = false;
        return;
    }

    if (listen(sfd, 128) != 0) {
        LOGE("Failed to listen on 127.0.0.1:%d: errno=%d (%s)",
             port, errno, strerror(errno));
        close(sfd);
        g_running = false;
        return;
    }

    g_server_fd = sfd;
    g_server_port = port;
    g_running = true;
    LOGI("C++ Native Proxy Server started on http://127.0.0.1:%d", port);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(sfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_running) break;
            continue;
        }

        std::thread([client_fd]() {
            handle_client_connection(client_fd);
        }).detach();
    }

    close(sfd);
    g_server_fd = -1;
    LOGI("C++ Native Proxy Server stopped");
}

int start_proxy(int port) {
    if (g_running) return g_server_port.load();
    int target_port = (port > 0) ? port : 1658;
    g_server_thread = std::thread(server_loop, target_port);
    
    int wait_counter = 0;
    while (!g_running && wait_counter < 50) {
        usleep(10000);
        wait_counter++;
    }

    return g_running ? g_server_port.load() : -1;
}

void stop_proxy() {
    g_running = false;

    int sfd = g_server_fd.exchange(-1);
    if (sfd >= 0) {
        shutdown(sfd, SHUT_RDWR);
        close(sfd);
    }

    if (g_server_thread.joinable()) {
        g_server_thread.join();
    }

    g_server_port = 0;
    LOGI("Native proxy stopped");
}

} // namespace native_proxy

// ─── JNI Exports ─────────────────────────────────────────────────────────────

extern "C" {

// Package: com.batz.tvlauncher.proxy
JNIEXPORT jint JNICALL
Java_com_batz_tvlauncher_proxy_ProxyHandler_nativeStartProxy(JNIEnv* env, jobject thiz, jint port) {
    return native_proxy::start_proxy(port);
}

JNIEXPORT void JNICALL
Java_com_batz_tvlauncher_proxy_ProxyHandler_nativeStopProxy(JNIEnv* env, jobject thiz) {
    native_proxy::stop_proxy();
}

JNIEXPORT jboolean JNICALL
Java_com_batz_tvlauncher_proxy_ProxyHandler_nativeIsRunning(JNIEnv* env, jobject thiz) {
    return native_proxy::g_running.load() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_batz_tvlauncher_proxy_ProxyHandler_nativeGetPort(JNIEnv* env, jobject thiz) {
    return native_proxy::g_server_port.load();
}

JNIEXPORT jstring JNICALL
Java_com_batz_tvlauncher_proxy_ProxyHandler_nativeRewriteM3U8(
        JNIEnv* env, jobject thiz,
        jstring content_, jstring baseUrl_, jstring proxyHost_) {
    if (!content_ || !baseUrl_ || !proxyHost_) return env->NewStringUTF("");

    const char* content = env->GetStringUTFChars(content_, nullptr);
    const char* baseUrl = env->GetStringUTFChars(baseUrl_, nullptr);
    const char* proxyHost = env->GetStringUTFChars(proxyHost_, nullptr);

    std::string rewritten = native_proxy::rewrite_m3u8(content, baseUrl, proxyHost);

    env->ReleaseStringUTFChars(content_, content);
    env->ReleaseStringUTFChars(baseUrl_, baseUrl);
    env->ReleaseStringUTFChars(proxyHost_, proxyHost);

    return env->NewStringUTF(rewritten.c_str());
}

}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    LOGI("libnative_proxy.so loaded");
    return JNI_VERSION_1_6;
}
