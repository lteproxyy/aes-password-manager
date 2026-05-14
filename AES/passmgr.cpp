#include "vendor/botan/botan_all.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#else
#include <conio.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::array<std::uint8_t, 5> kMagic{'C', 'P', 'M', 'V', '1'};
constexpr std::uint32_t kIterations = 600000;
constexpr std::size_t kSaltSize = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kKeySize = 32;
constexpr std::size_t kMaxStringSize = 1024 * 1024;
constexpr std::size_t kMaxEntries = 100000;

struct Entry {
    std::string name;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    std::string created_at;
    std::string updated_at;
};

struct Vault {
    std::map<std::string, Entry> entries;
};

struct Options {
    std::vector<std::string> positional;
    std::unordered_map<std::string, std::string> values;
    std::set<std::string> flags;
};

struct EncryptedVault {
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> tag;
    std::uint32_t iterations = kIterations;
};

void cleanse(std::string& value) {
    if (!value.empty()) {
        Botan::secure_scrub_memory(value.data(), value.size());
    }
    value.clear();
}

void cleanse(std::vector<std::uint8_t>& value) {
    if (!value.empty()) {
        Botan::secure_scrub_memory(value.data(), value.size());
    }
    value.clear();
}

void cleanse(Botan::secure_vector<std::uint8_t>& value) {
    if (!value.empty()) {
        Botan::secure_scrub_memory(value);
    }
    value.clear();
}

std::string now_utc() {
    const auto now = std::chrono::system_clock::now();
    const auto raw = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &raw);
#else
    gmtime_r(&raw, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string read_line(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string line;
    if (!std::getline(std::cin, line)) {
        throw std::runtime_error("Eingabe konnte nicht gelesen werden");
    }
    return line;
}

std::string read_hidden(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string value;
#ifdef _WIN32
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            std::cout << '\n';
            break;
        }
        if (ch == '\b') {
            if (!value.empty()) {
                value.pop_back();
            }
            continue;
        }
        if (ch == 3) {
            throw std::runtime_error("Abgebrochen");
        }
        value.push_back(static_cast<char>(ch));
    }
#else
    if (!isatty(STDIN_FILENO)) {
        if (!std::getline(std::cin, value)) {
            throw std::runtime_error("Eingabe konnte nicht gelesen werden");
        }
        return value;
    }
    termios old_state{};
    if (tcgetattr(STDIN_FILENO, &old_state) != 0) {
        throw std::runtime_error("Terminal-Modus konnte nicht gelesen werden");
    }
    termios new_state = old_state;
    new_state.c_lflag &= static_cast<unsigned int>(~ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_state) != 0) {
        throw std::runtime_error("Terminal-Modus konnte nicht gesetzt werden");
    }
    try {
        if (!std::getline(std::cin, value)) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
            throw std::runtime_error("Eingabe konnte nicht gelesen werden");
        }
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
        std::cout << '\n';
    } catch (...) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
        std::cout << '\n';
        throw;
    }
#endif
    return value;
}

bool strong_master_password(const std::string& password) {
    if (password.size() < 12) {
        return false;
    }
    int classes = 0;
    bool lower = false;
    bool upper = false;
    bool digit = false;
    bool other = false;
    for (std::uint8_t ch : password) {
        lower = lower || std::islower(ch);
        upper = upper || std::isupper(ch);
        digit = digit || std::isdigit(ch);
        other = other || (!std::isalnum(ch) && !std::isspace(ch));
    }
    classes += lower ? 1 : 0;
    classes += upper ? 1 : 0;
    classes += digit ? 1 : 0;
    classes += other ? 1 : 0;
    return classes >= 3;
}

std::vector<std::uint8_t> random_bytes(std::size_t size) {
    return Botan::system_rng().random_vec<std::vector<std::uint8_t>>(size);
}

std::size_t random_below(std::size_t upper) {
    if (upper == 0 || upper > 256) {
        throw std::runtime_error("Ungültiger Zufallsbereich");
    }
    const auto limit = (256 / upper) * upper;
    for (;;) {
        auto b = random_bytes(1)[0];
        if (static_cast<std::size_t>(b) < limit) {
            return b % upper;
        }
    }
}

char random_char(const std::string& chars) {
    return chars[random_below(chars.size())];
}

std::string generate_password(std::size_t length, bool symbols) {
    if (length < 8 || length > 256) {
        throw std::runtime_error("Passwortlänge muss zwischen 8 und 256 liegen");
    }

    const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string special = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
    std::vector<std::string> groups{lower, upper, digits};
    if (symbols) {
        groups.push_back(special);
    }

    std::string all;
    for (const auto& group : groups) {
        all += group;
    }

    std::string out;
    out.reserve(length);
    if (length >= groups.size()) {
        for (const auto& group : groups) {
            out.push_back(random_char(group));
        }
    }
    while (out.size() < length) {
        out.push_back(random_char(all));
    }
    for (std::size_t i = out.size() - 1; i > 0; --i) {
        std::swap(out[i], out[random_below(i + 1)]);
    }
    return out;
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset > data.size() || data.size() - offset < 4) {
        throw std::runtime_error("Vault-Daten sind beschädigt");
    }
    std::uint32_t value = 0;
    value |= static_cast<std::uint32_t>(data[offset]) << 24;
    value |= static_cast<std::uint32_t>(data[offset + 1]) << 16;
    value |= static_cast<std::uint32_t>(data[offset + 2]) << 8;
    value |= static_cast<std::uint32_t>(data[offset + 3]);
    offset += 4;
    return value;
}

void put_string(std::vector<std::uint8_t>& out, std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("Text ist zu groß");
    }
    put_u32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::string get_string(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    const auto size = get_u32(data, offset);
    if (offset > data.size() || size > kMaxStringSize || data.size() - offset < size) {
        throw std::runtime_error("Vault-Daten sind beschädigt");
    }
    std::string value(reinterpret_cast<const char*>(data.data() + offset), size);
    offset += size;
    return value;
}

std::vector<std::uint8_t> serialize(const Vault& vault) {
    if (vault.entries.size() > kMaxEntries) {
        throw std::runtime_error("Zu viele Einträge");
    }
    std::vector<std::uint8_t> out;
    put_u32(out, static_cast<std::uint32_t>(vault.entries.size()));
    for (const auto& [name, entry] : vault.entries) {
        put_string(out, name);
        put_string(out, entry.username);
        put_string(out, entry.password);
        put_string(out, entry.url);
        put_string(out, entry.notes);
        put_string(out, entry.created_at);
        put_string(out, entry.updated_at);
    }
    return out;
}

Vault deserialize(const std::vector<std::uint8_t>& data) {
    std::size_t offset = 0;
    Vault vault;
    const auto count = get_u32(data, offset);
    if (count > kMaxEntries) {
        throw std::runtime_error("Vault enthält zu viele Einträge");
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        Entry entry;
        entry.name = get_string(data, offset);
        entry.username = get_string(data, offset);
        entry.password = get_string(data, offset);
        entry.url = get_string(data, offset);
        entry.notes = get_string(data, offset);
        entry.created_at = get_string(data, offset);
        entry.updated_at = get_string(data, offset);
        if (entry.name.empty() || vault.entries.count(entry.name) != 0) {
            throw std::runtime_error("Vault-Daten sind beschädigt");
        }
        vault.entries.emplace(entry.name, std::move(entry));
    }
    if (offset != data.size()) {
        throw std::runtime_error("Vault-Daten sind beschädigt");
    }
    return vault;
}

std::vector<std::uint8_t> build_header(std::uint32_t iterations, const std::vector<std::uint8_t>& salt, const std::vector<std::uint8_t>& nonce) {
    if (salt.size() != kSaltSize || nonce.size() != kNonceSize) {
        throw std::runtime_error("Ungültige Kryptoparameter");
    }
    std::vector<std::uint8_t> header;
    header.insert(header.end(), kMagic.begin(), kMagic.end());
    put_u32(header, iterations);
    header.insert(header.end(), salt.begin(), salt.end());
    header.insert(header.end(), nonce.begin(), nonce.end());
    return header;
}

Botan::secure_vector<std::uint8_t> derive_key(const std::string& master, const std::vector<std::uint8_t>& salt, std::uint32_t iterations) {
    if (master.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("Master-Passwort ist zu lang");
    }
    if (salt.size() != kSaltSize || iterations < 100000 || iterations > 5000000) {
        throw std::runtime_error("Ungültige KDF-Parameter");
    }
    auto pbkdf = Botan::PBKDF::create_or_throw("PBKDF2(SHA-256)");
    return pbkdf->pbkdf_iterations(kKeySize, master, salt.data(), salt.size(), iterations);
}

EncryptedVault encrypt_payload(const std::vector<std::uint8_t>& plaintext, const std::string& master) {
    EncryptedVault vault;
    vault.salt = random_bytes(kSaltSize);
    vault.nonce = random_bytes(kNonceSize);
    vault.iterations = kIterations;

    auto key = derive_key(master, vault.salt, vault.iterations);
    const auto header = build_header(vault.iterations, vault.salt, vault.nonce);

    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    if (aead->tag_size() != kTagSize || aead->default_nonce_length() != kNonceSize) {
        throw std::runtime_error("AES-GCM Parameter passen nicht zum Vault-Format");
    }

    aead->set_key(key);
    aead->set_associated_data(header);
    aead->start(vault.nonce);

    Botan::secure_vector<std::uint8_t> sealed(plaintext.begin(), plaintext.end());
    aead->finish(sealed);
    if (sealed.size() < kTagSize) {
        cleanse(key);
        cleanse(sealed);
        throw std::runtime_error("Vault konnte nicht verschlüsselt werden");
    }

    const auto tag_start = sealed.end() - static_cast<std::ptrdiff_t>(kTagSize);
    vault.ciphertext.assign(sealed.begin(), tag_start);
    vault.tag.assign(tag_start, sealed.end());

    cleanse(key);
    cleanse(sealed);
    return vault;
}

std::vector<std::uint8_t> decrypt_payload(const EncryptedVault& vault, const std::string& master) {
    auto key = derive_key(master, vault.salt, vault.iterations);
    const auto header = build_header(vault.iterations, vault.salt, vault.nonce);

    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    if (aead->tag_size() != kTagSize || aead->default_nonce_length() != kNonceSize || vault.tag.size() != kTagSize) {
        cleanse(key);
        throw std::runtime_error("AES-GCM Parameter passen nicht zum Vault-Format");
    }

    aead->set_key(key);
    aead->set_associated_data(header);
    aead->start(vault.nonce);

    Botan::secure_vector<std::uint8_t> sealed(vault.ciphertext.begin(), vault.ciphertext.end());
    sealed.insert(sealed.end(), vault.tag.begin(), vault.tag.end());

    try {
        aead->finish(sealed);
    } catch (const Botan::Invalid_Authentication_Tag&) {
        cleanse(key);
        cleanse(sealed);
        throw std::runtime_error("Falsches Master-Passwort oder beschädigte Vault-Datei");
    }

    std::vector<std::uint8_t> plaintext(sealed.begin(), sealed.end());
    cleanse(key);
    cleanse(sealed);
    return plaintext;
}

std::vector<std::uint8_t> pack_encrypted(const EncryptedVault& vault) {
    auto out = build_header(vault.iterations, vault.salt, vault.nonce);
    out.insert(out.end(), vault.ciphertext.begin(), vault.ciphertext.end());
    out.insert(out.end(), vault.tag.begin(), vault.tag.end());
    return out;
}

EncryptedVault unpack_encrypted(const std::vector<std::uint8_t>& data) {
    const auto min_size = kMagic.size() + 4 + kSaltSize + kNonceSize + kTagSize;
    if (data.size() < min_size) {
        throw std::runtime_error("Vault-Datei ist zu klein oder beschädigt");
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), data.begin())) {
        throw std::runtime_error("Unbekanntes Vault-Format");
    }

    std::size_t offset = kMagic.size();
    EncryptedVault vault;
    vault.iterations = get_u32(data, offset);
    vault.salt.assign(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + kSaltSize));
    offset += kSaltSize;
    vault.nonce.assign(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + kNonceSize));
    offset += kNonceSize;
    const auto cipher_end = data.size() - kTagSize;
    vault.ciphertext.assign(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(cipher_end));
    vault.tag.assign(data.begin() + static_cast<std::ptrdiff_t>(cipher_end), data.end());
    return vault;
}

std::vector<std::uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Vault-Datei konnte nicht geöffnet werden: " + path.string());
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_file_atomic(const fs::path& path, const std::vector<std::uint8_t>& data) {
#ifdef _WIN32
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("Temporäre Vault-Datei konnte nicht geschrieben werden");
        }
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) {
            throw std::runtime_error("Vault-Datei konnte nicht vollständig geschrieben werden");
        }
    }
    fs::rename(tmp, path);
#else
    const auto tmp = path.string() + ".tmp." + std::to_string(static_cast<long long>(getpid()));
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        throw std::runtime_error("Temporäre Vault-Datei konnte nicht geöffnet werden");
    }
    std::size_t written = 0;
    while (written < data.size()) {
        const auto result = ::write(fd, data.data() + written, data.size() - written);
        if (result < 0) {
            const auto saved = errno;
            ::close(fd);
            ::unlink(tmp.c_str());
            throw std::runtime_error("Vault-Datei konnte nicht geschrieben werden: " + std::string(std::strerror(saved)));
        }
        written += static_cast<std::size_t>(result);
    }
    if (::fsync(fd) != 0) {
        const auto saved = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        throw std::runtime_error("Vault-Datei konnte nicht synchronisiert werden: " + std::string(std::strerror(saved)));
    }
    if (::close(fd) != 0) {
        const auto saved = errno;
        ::unlink(tmp.c_str());
        throw std::runtime_error("Vault-Datei konnte nicht geschlossen werden: " + std::string(std::strerror(saved)));
    }
    if (::rename(tmp.c_str(), path.string().c_str()) != 0) {
        const auto saved = errno;
        ::unlink(tmp.c_str());
        throw std::runtime_error("Vault-Datei konnte nicht ersetzt werden: " + std::string(std::strerror(saved)));
    }
    ::chmod(path.string().c_str(), S_IRUSR | S_IWUSR);
#endif
}

Vault load_vault(const fs::path& path, const std::string& master) {
    auto raw = read_file(path);
    auto encrypted = unpack_encrypted(raw);
    auto plain = decrypt_payload(encrypted, master);
    auto vault = deserialize(plain);
    cleanse(raw);
    cleanse(encrypted.salt);
    cleanse(encrypted.nonce);
    cleanse(encrypted.ciphertext);
    cleanse(encrypted.tag);
    cleanse(plain);
    return vault;
}

void save_vault(const fs::path& path, const Vault& vault, const std::string& master) {
    auto plain = serialize(vault);
    auto encrypted = encrypt_payload(plain, master);
    auto raw = pack_encrypted(encrypted);
    write_file_atomic(path, raw);
    cleanse(plain);
    cleanse(encrypted.salt);
    cleanse(encrypted.nonce);
    cleanse(encrypted.ciphertext);
    cleanse(encrypted.tag);
    cleanse(raw);
}

Options parse_args(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need_value = [&](const std::string& key) {
            if (i + 1 >= argc) {
                throw std::runtime_error("Option braucht einen Wert: " + arg);
            }
            options.values[key] = argv[++i];
        };

        if (arg == "-f" || arg == "--file") {
            need_value("file");
        } else if (arg == "-u" || arg == "--username") {
            need_value("username");
        } else if (arg == "-p" || arg == "--password") {
            need_value("password");
        } else if (arg == "-n" || arg == "--notes") {
            need_value("notes");
        } else if (arg == "--url") {
            need_value("url");
        } else if (arg == "-l" || arg == "--length") {
            need_value("length");
        } else if (arg == "--show" || arg == "--force" || arg == "--update" || arg == "--generate" || arg == "--no-symbols" || arg == "-h" || arg == "--help") {
            options.flags.insert(arg);
        } else if (!arg.empty() && arg[0] == '-') {
            throw std::runtime_error("Unbekannte Option: " + arg);
        } else {
            options.positional.push_back(arg);
        }
    }
    return options;
}

fs::path vault_path(const Options& options) {
    const auto found = options.values.find("file");
    if (found != options.values.end()) {
        return found->second;
    }
    return "vault.cpm";
}

bool has_flag(const Options& options, const std::string& flag) {
    return options.flags.count(flag) != 0;
}

std::optional<std::string> option_value(const Options& options, const std::string& key) {
    const auto found = options.values.find(key);
    if (found == options.values.end()) {
        return std::nullopt;
    }
    return found->second;
}

std::size_t parse_length(const std::string& value) {
    std::size_t consumed = 0;
    const auto length = std::stoul(value, &consumed);
    if (consumed != value.size()) {
        throw std::runtime_error("Ungültige Länge");
    }
    return length;
}

std::string request_master() {
    auto master = read_hidden("Master-Passwort: ");
    if (master.empty()) {
        throw std::runtime_error("Master-Passwort darf nicht leer sein");
    }
    return master;
}

void print_usage(const char* exe) {
    std::cout
        << "Nutzung:\n"
        << "  " << exe << " init [--file vault.cpm] [--force]\n"
        << "  " << exe << " add <name> [-u user] [--url url] [-p pass] [-n notes] [--generate] [--update] [--file vault.cpm]\n"
        << "  " << exe << " get <name> [--show] [--file vault.cpm]\n"
        << "  " << exe << " list [--file vault.cpm]\n"
        << "  " << exe << " remove <name> [--force] [--file vault.cpm]\n"
        << "  " << exe << " gen [length] [--no-symbols]\n"
        << "  " << exe << " change-master [--file vault.cpm]\n";
}

void command_init(const Options& options) {
    const auto path = vault_path(options);
    if (fs::exists(path) && !has_flag(options, "--force")) {
        throw std::runtime_error("Vault existiert bereits. Nutze --force zum Überschreiben");
    }

    auto first = read_hidden("Neues Master-Passwort: ");
    auto second = read_hidden("Master-Passwort wiederholen: ");
    if (first != second) {
        cleanse(first);
        cleanse(second);
        throw std::runtime_error("Master-Passwörter stimmen nicht überein");
    }
    if (!strong_master_password(first)) {
        cleanse(first);
        cleanse(second);
        throw std::runtime_error("Master-Passwort zu schwach: mindestens 12 Zeichen und 3 Zeichentypen");
    }

    Vault vault;
    save_vault(path, vault, first);
    cleanse(first);
    cleanse(second);
    std::cout << "Vault erstellt: " << path.string() << '\n';
}

void command_gen(const Options& options) {
    std::size_t length = 24;
    if (const auto value = option_value(options, "length")) {
        length = parse_length(*value);
    } else if (options.positional.size() >= 2) {
        length = parse_length(options.positional[1]);
    }
    std::cout << generate_password(length, !has_flag(options, "--no-symbols")) << '\n';
}

void command_add(const Options& options) {
    if (options.positional.size() < 2) {
        throw std::runtime_error("Eintragsname fehlt");
    }
    const auto path = vault_path(options);
    const auto name = options.positional[1];
    if (name.empty()) {
        throw std::runtime_error("Eintragsname darf nicht leer sein");
    }

    auto master = request_master();
    auto vault = load_vault(path, master);
    const bool updating = vault.entries.count(name) != 0;
    if (updating && !has_flag(options, "--update")) {
        cleanse(master);
        throw std::runtime_error("Eintrag existiert bereits. Nutze --update zum Ändern");
    }

    Entry entry;
    if (updating) {
        entry = vault.entries.at(name);
    } else {
        entry.name = name;
        entry.created_at = now_utc();
    }

    if (const auto value = option_value(options, "username")) {
        entry.username = *value;
    } else if (!updating) {
        entry.username = read_line("Benutzername (optional): ");
    }

    if (const auto value = option_value(options, "url")) {
        entry.url = *value;
    } else if (!updating) {
        entry.url = read_line("URL (optional): ");
    }

    if (const auto value = option_value(options, "notes")) {
        entry.notes = *value;
    } else if (!updating) {
        entry.notes = read_line("Notizen (optional): ");
    }

    bool generated = false;
    if (has_flag(options, "--generate")) {
        entry.password = generate_password(24, true);
        generated = true;
    } else if (const auto value = option_value(options, "password")) {
        entry.password = *value;
    } else if (!updating) {
        entry.password = read_hidden("Passwort (leer = generieren): ");
        if (entry.password.empty()) {
            entry.password = generate_password(24, true);
            generated = true;
        }
    }

    if (entry.password.empty()) {
        cleanse(master);
        throw std::runtime_error("Passwort darf nicht leer sein");
    }

    entry.updated_at = now_utc();
    vault.entries[name] = entry;
    save_vault(path, vault, master);
    cleanse(master);

    std::cout << (updating ? "Eintrag aktualisiert" : "Eintrag gespeichert") << ": " << name << '\n';
    if (generated) {
        std::cout << "Generiertes Passwort: " << entry.password << '\n';
    }
}

void command_list(const Options& options) {
    auto master = request_master();
    auto vault = load_vault(vault_path(options), master);
    cleanse(master);

    if (vault.entries.empty()) {
        std::cout << "Keine Einträge vorhanden\n";
        return;
    }

    for (const auto& [name, entry] : vault.entries) {
        std::cout << name;
        if (!entry.username.empty()) {
            std::cout << " | " << entry.username;
        }
        if (!entry.url.empty()) {
            std::cout << " | " << entry.url;
        }
        std::cout << '\n';
    }
}

void command_get(const Options& options) {
    if (options.positional.size() < 2) {
        throw std::runtime_error("Eintragsname fehlt");
    }

    auto master = request_master();
    auto vault = load_vault(vault_path(options), master);
    cleanse(master);

    const auto found = vault.entries.find(options.positional[1]);
    if (found == vault.entries.end()) {
        throw std::runtime_error("Eintrag nicht gefunden");
    }

    const auto& entry = found->second;
    std::cout << "Name: " << entry.name << '\n';
    if (!entry.username.empty()) {
        std::cout << "Benutzername: " << entry.username << '\n';
    }
    if (!entry.url.empty()) {
        std::cout << "URL: " << entry.url << '\n';
    }
    if (!entry.notes.empty()) {
        std::cout << "Notizen: " << entry.notes << '\n';
    }
    std::cout << "Erstellt: " << entry.created_at << '\n';
    std::cout << "Geändert: " << entry.updated_at << '\n';
    if (has_flag(options, "--show")) {
        std::cout << "Passwort: " << entry.password << '\n';
    } else {
        std::cout << "Passwort: verborgen, nutze --show zum Anzeigen\n";
    }
}

void command_remove(const Options& options) {
    if (options.positional.size() < 2) {
        throw std::runtime_error("Eintragsname fehlt");
    }

    const auto name = options.positional[1];
    auto master = request_master();
    auto vault = load_vault(vault_path(options), master);
    const auto found = vault.entries.find(name);
    if (found == vault.entries.end()) {
        cleanse(master);
        throw std::runtime_error("Eintrag nicht gefunden");
    }

    if (!has_flag(options, "--force")) {
        auto answer = read_line("Eintrag wirklich löschen? Tippe yes: ");
        if (answer != "yes") {
            cleanse(master);
            std::cout << "Abgebrochen\n";
            return;
        }
    }

    vault.entries.erase(found);
    save_vault(vault_path(options), vault, master);
    cleanse(master);
    std::cout << "Eintrag gelöscht: " << name << '\n';
}

void command_change_master(const Options& options) {
    const auto path = vault_path(options);
    auto old_master = request_master();
    auto vault = load_vault(path, old_master);

    auto first = read_hidden("Neues Master-Passwort: ");
    auto second = read_hidden("Master-Passwort wiederholen: ");
    if (first != second) {
        cleanse(old_master);
        cleanse(first);
        cleanse(second);
        throw std::runtime_error("Master-Passwörter stimmen nicht überein");
    }
    if (!strong_master_password(first)) {
        cleanse(old_master);
        cleanse(first);
        cleanse(second);
        throw std::runtime_error("Master-Passwort zu schwach: mindestens 12 Zeichen und 3 Zeichentypen");
    }

    save_vault(path, vault, first);
    cleanse(old_master);
    cleanse(first);
    cleanse(second);
    std::cout << "Master-Passwort geändert\n";
}

int run(int argc, char** argv) {
    auto options = parse_args(argc, argv);
    if (options.positional.empty() || has_flag(options, "-h") || has_flag(options, "--help")) {
        print_usage(argv[0]);
        return has_flag(options, "-h") || has_flag(options, "--help") ? 0 : 1;
    }

    const auto& command = options.positional[0];
    if (command == "init") {
        command_init(options);
    } else if (command == "add") {
        command_add(options);
    } else if (command == "get") {
        command_get(options);
    } else if (command == "list") {
        command_list(options);
    } else if (command == "remove") {
        command_remove(options);
    } else if (command == "gen") {
        command_gen(options);
    } else if (command == "change-master") {
        command_change_master(options);
    } else {
        throw std::runtime_error("Unbekannter Befehl: " + command);
    }

    return 0;
}

} 

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "Fehler: " << ex.what() << '\n';
        return 1;
    }
}
