#include <switch.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <memory>
#include <bit>
#include <experimental/scope>

namespace {

#define R_SUCCEED() return 0
#define R_THROW(_rc) return _rc
#define R_UNLESS(_rc, _msg) { \
    if (!(_rc)) { \
        std::printf("failed: %s %s:%d %s\n", #_rc, __FILE__, __LINE__, _msg); \
        R_THROW(0x1); \
    } \
}
#define R_TRY(r) { \
    if (const auto _rc = (r); R_FAILED(_rc)) { \
        std::printf("failed: %s %s:%d 0x%X\n", #r, __FILE__, __LINE__, _rc); \
        R_THROW(_rc); \
    } \
}

#define CONCATENATE_IMPL(s1, s2) s1##s2
#define CONCATENATE(s1, s2) CONCATENATE_IMPL(s1, s2)

#ifdef __COUNTER__
    #define ANONYMOUS_VARIABLE(pref) CONCATENATE(pref, __COUNTER__)
#else
    #define ANONYMOUS_VARIABLE(pref) CONCATENATE(pref, __LINE__)
#endif

#define ON_SCOPE_EXIT(_f) std::experimental::scope_exit ANONYMOUS_VARIABLE(SCOPE_EXIT_STATE_){[&] { _f; }};

constexpr u64 BUFFER_SIZE = 1024*1024*4;
constexpr double _1MiB = 1024*1024;

constexpr u32 KEYGEN_LIMIT = 0x20;

constexpr u8 HEADER_KEK_SRC[0x10] = { 0x1F, 0x12, 0x91, 0x3A, 0x4A, 0xCB, 0xF0, 0x0D, 0x4C, 0xDE, 0x3A, 0xF6, 0xD5, 0x23, 0x88, 0x2A };
constexpr u8 HEADER_KEY_SRC[0x20] = { 0x5A, 0x3E, 0xD8, 0x4F, 0xDE, 0xC0, 0xD8, 0x26, 0x31, 0xF7, 0xE2, 0x5D, 0x19, 0x7B, 0xF5, 0xD0, 0x1C, 0x9B, 0x7B, 0xFA, 0xF6, 0x28, 0x18, 0x3D, 0x71, 0xF6, 0x4D, 0x73, 0xF1, 0x50, 0xB9, 0xD2 };

constexpr u8 g_key_area_key_application_source[0x10] = { 0x7F, 0x59, 0x97, 0x1E, 0x62, 0x9F, 0x36, 0xA1, 0x30, 0x98, 0x06, 0x6F, 0x21, 0x44, 0xC3, 0x0D };
constexpr u8 g_key_area_key_ocean_source[0x10] = { 0x32, 0x7D, 0x36, 0x08, 0x5A, 0xD1, 0x75, 0x8D, 0xAB, 0x4E, 0x6F, 0xBA, 0xA5, 0x55, 0xD8, 0x82 };
constexpr u8 g_key_area_key_system_source[0x10] = { 0x87, 0x45, 0xF1, 0xBB, 0xA6, 0xBE, 0x79, 0x64, 0x7D, 0x04, 0x8B, 0xA6, 0x7B, 0x5F, 0xDA, 0x4A };

constexpr const u8* g_key_area_key[] = {
    g_key_area_key_application_source,
    g_key_area_key_ocean_source,
    g_key_area_key_system_source
};

// changes distribution bit in nca header to 0.
bool FIX_DISTRIBUTION_BIT{false};

// converts titlekey to standard crypto, also known as "ticketless".
// this will not work with addon, so, addon tickets will be installed.
bool CONVERT_TO_STANDARD_CRYPTO{false};

// encrypts the keak with master key 0, this allows the game to be launched
// on every fw. Also implicitly does standard crypto.
bool LOWER_MASTER_KEY{false};

// sets the system_firmware field in the cnmt extended header.
// if mkey is higher than fw version, the game still won't launch
// as the fw won't have the key to decrypt keak.
bool LOWER_SYSTEM_VERSION{false};

// per-type overrides, for testing patches.
bool CONVERT_BASE_TO_STANDARD_CRYTPO{false};
bool CONVERT_UPDATE_TO_STANDARD_CRYTPO{true};
bool CONVERT_DLC_TO_STANDARD_CRYTPO{true};

enum NsApplicationRecordType {
    // installed
    NsApplicationRecordType_Installed       = 0x3,
    // application is gamecard, but gamecard isn't insterted
    NsApplicationRecordType_GamecardMissing = 0x5,
    // archived
    NsApplicationRecordType_Archived        = 0xB,
};

struct NcmContentStorageRecord {
    NcmContentMetaKey key;
    u8 storage_id;
    u8 padding[0x7];
};

enum NcaOldKeyGeneration {
    NcaOldKeyGeneration_100    = 0x0,
    NcaOldKeyGeneration_Unused = 0x1,
    NcaOldKeyGeneration_300    = 0x2,
};

enum NcaKeyGeneration {
    NcaKeyGeneration_301     = 0x3,
    NcaKeyGeneration_400     = 0x4,
    NcaKeyGeneration_500     = 0x5,
    NcaKeyGeneration_600     = 0x6,
    NcaKeyGeneration_620     = 0x7,
    NcaKeyGeneration_700     = 0x8,
    NcaKeyGeneration_810     = 0x9,
    NcaKeyGeneration_900     = 0x0A,
    NcaKeyGeneration_910     = 0x0B,
    NcaKeyGeneration_1210    = 0x0C,
    NcaKeyGeneration_1300    = 0x0D,
    NcaKeyGeneration_1400    = 0x0E,
    NcaKeyGeneration_1500    = 0x0F,
    NcaKeyGeneration_1600    = 0x10,
    NcaKeyGeneration_1700    = 0x11,
    NcaKeyGeneration_Invalid = 0xFF
};

enum NcaKeyAreaEncryptionKeyIndex {
    NcaKeyAreaEncryptionKeyIndex_Application = 0x0,
    NcaKeyAreaEncryptionKeyIndex_Ocean       = 0x1,
    NcaKeyAreaEncryptionKeyIndex_System      = 0x2
};

enum NcaDistributionType {
    NcaDistributionType_System   = 0x0,
    NcaDistributionType_GameCard = 0x1
};

enum NcaContentType {
    NcaContentType_Program    = 0x0,
    NcaContentType_Meta       = 0x1,
    NcaContentType_Control    = 0x2,
    NcaContentType_Manual     = 0x3,
    NcaContentType_Data       = 0x4,
    NcaContentType_PublicData = 0x5,
};

struct NcaSectionTableEntry {
    u32 media_start_offset; // divided by 0x200.
    u32 media_end_offset;   // divided by 0x200.
    u8 _0x8[0x4];           // unknown.
    u8 _0xC[0x4];           // unknown.
};

struct LayerRegion {
    u64 offset;
    u64 size;
};

struct HierarchicalSha256Data {
    u8 master_hash[0x20];
    u32 block_size;
    u32 layer_count;
    LayerRegion hash_layer;
    LayerRegion pfs0_layer;
    LayerRegion unused_layers[3];
    u8 _0x78[0x80];
};

#pragma pack(push, 1)
struct HierarchicalIntegrityVerificationLevelInformation {
    u64 logical_offset;
    u64 hash_data_size;
    u32 block_size; // log2
    u32 _0x14; // reserved
};
#pragma pack(pop)

struct InfoLevelHash {
    u32 max_layers;
    HierarchicalIntegrityVerificationLevelInformation levels[6];
    u8 signature_salt[0x20];
};

struct IntegrityMetaInfo {
    u32 magic; // IVFC
    u32 version;
    u32 master_hash_size;
    InfoLevelHash info_level_hash;
    u8 master_hash[0x20];
    u8 _0xE0[0x18];
};

struct NcaFsHeader {
    u16 version;           // always 2.
    u8 fs_type;            // see NcaFileSystemType.
    u8 hash_type;          // see NcaHashType.
    u8 encryption_type;    // see NcaEncryptionType.
    u8 metadata_hash_type;
    u8 _0x6[0x2];          // empty.
    union {
        HierarchicalSha256Data hierarchical_sha256_data;
        IntegrityMetaInfo integrity_meta_info; // used for romfs
    } hash_data;
    u8 patch_info[0x40];
    u64 section_ctr;
    u8 spares_info[0x30];
    u8 compression_info[0x28];
    u8 meta_data_hash_data_info[0x30];
    u8 reserved[0x30];
};

struct NcaSectionHeaderHash {
    u8 sha256[0x20];
};

struct NcaKeyArea {
    u8 area[0x10];
};

struct NcaHeader {
    u8 rsa_fixed_key[0x100];
    u8 rsa_npdm[0x100];        // key from npdm.
    u32 magic;
    u8 distribution_type;      // NcaDistributionType.
    u8 content_type;           // NcaContentType.
    u8 old_key_gen;            // NcaOldKeyGeneration.
    u8 kaek_index;             // NcaKeyAreaEncryptionKeyIndex.
    u64 size;
    u64 title_id;
    u32 context_id;
    u32 sdk_version;
    u8 key_gen;                // NcaKeyGeneration.
    u8 header_1_sig_key_gen;
    u8 _0x222[0xE];            // empty.
    FsRightsId rights_id;
    NcaSectionTableEntry fs_table[0x4];
    NcaSectionHeaderHash fs_header_hash[0x4];
    NcaKeyArea key_area[0x4];
    u8 _0x340[0xC0];           // empty.
    NcaFsHeader fs_header[0x4];

    auto GetKeyGeneration() const -> u8 {
        if (old_key_gen < key_gen) {
            return key_gen;
        } else {
            return old_key_gen;
        }
    }

    void SetKeyGeneration(u8 key_generation) {
        if (key_generation <= 0x2) {
            old_key_gen = key_generation;
            key_gen = 0;
        } else {
            old_key_gen = 0x2;
            key_gen = key_generation;
        }
    }
};

union NcmExtendedHeader {
    NcmApplicationMetaExtendedHeader application;
    NcmPatchMetaExtendedHeader patch;
    NcmAddOnContentMetaExtendedHeader addon;
    NcmLegacyAddOnContentMetaExtendedHeader addon_legacy;
    NcmDataPatchMetaExtendedHeader data_patch;
};

struct NcaCollection {
    NcmContentId content_id{};
    NcmPlaceHolderId placeholder_id{};
    u8 content_type{};
    u64 size{};
    u8 hash[SHA256_HASH_SIZE]{};
    bool modified{};
};

struct GciEntry {
    NcmContentMetaKey key;
    NcmContentMetaHeader content_meta_header;
    NcmExtendedHeader extended_header;
    std::vector<NcmContentInfo> content_infos;
    std::vector<NcaCollection> ncas;
    NcmRightsId ncm_rights_id;

    auto GetType() const {
        return static_cast<NcmContentMetaType>(key.type);
    }

    auto IsRightsIdValid() const -> bool {
        FsRightsId id{};
        return 0 != std::memcmp(std::addressof(ncm_rights_id.rights_id), std::addressof(id), sizeof(id));
    }

    auto GetAppId() const -> u64 {
        if (key.type == NcmContentMetaType_Patch) {
            return key.id ^ 0x800;
        } else if (key.type == NcmContentMetaType_AddOnContent) {
            return (key.id ^ 0x1000) & ~0xFFF;
        } else {
            return key.id;
        }
    }
};

using GciEntries = std::vector<GciEntry>;

// stdio-like wrapper for std::vector
struct BufHelper {
    void write(const void* data, u64 size) {
        if (offset + size >= buf.size()) {
            buf.resize(offset + size);
        }
        std::memcpy(buf.data() + offset, data, size);
        offset += size;
    }

    void seek(u64 where_to) {
        offset = where_to;
    }

    [[nodiscard]]
    auto tell() const {
        return offset;
    }

    std::vector<u8> buf;
    u64 offset{};
};

struct TimeStamp {
    TimeStamp() {
        Reset();
    }

    void Reset() {
        start = armGetSystemTick();
    }

    auto GetNs() const -> u64 {
        auto end_ticks = armGetSystemTick();
        return armTicksToNs(end_ticks) - armTicksToNs(start);
    }

    auto GetSeconds() const -> double {
        const double ns = GetNs();
        return ns/1000.0/1000.0/1000.0;
    }

    u64 start;
};

struct ThreadData {
    ThreadData(FsFile _nca_file, NcmContentStorage _cs, NcmPlaceHolderId _placeholder_id, u64 _total_size)
    : nca_file{_nca_file}, cs{_cs}, placeholder_id{_placeholder_id}, total_size{_total_size} {
        buf.resize(BUFFER_SIZE);
        mutexInit(std::addressof(mutex));
        condvarInit(std::addressof(can_read));
        condvarInit(std::addressof(can_write));
    }

    // these need to be created
    std::vector<u8> buf;
    Mutex mutex;
    CondVar can_read;
    CondVar can_write;

    // these need to be copied
    FsFile nca_file;
    NcmContentStorage cs;
    const NcmPlaceHolderId placeholder_id;
    const u64 total_size;

    // these are shared between threads
    volatile u64 write_offset{};
    volatile u64 data_size{};
    volatile Result read_result{};
    volatile Result write_result{};
};

struct HashStr {
    char str[0x21];
};

using KeySection = std::vector<NcaKeyArea>;
struct Keys {
    KeySection keak[0x3]; // index
    KeySection title_kek;
    KeySection mkey;
    u8 header_key[0x20];

    static auto FixKey(u8 key) -> u8 {
        if (key) {
            return key - 1;
        }
        return key;
    }

    auto HasNcaKeyArea(u8 key, u8 index) const {
        return FixKey(key) <= keak[index].size();
    }

    auto HasTitleKek(u8 key) const {
        return FixKey(key) <= title_kek.size();
    }

    auto HasMasterKey(u8 key) const {
        return FixKey(key) <= mkey.size();
    }

    auto GetNcaKeyArea(NcaKeyArea* out, u8 key, u8 index) const -> Result {
        R_UNLESS(HasNcaKeyArea(key, index), "Missing Key!");
        *out = keak[index][FixKey(key)];
        R_SUCCEED();
    }

    auto GetTitleKek(NcaKeyArea* out, u8 key) const -> Result {
        R_UNLESS(HasTitleKek(key), "Missing Key!");
        *out = title_kek[FixKey(key)];
        R_SUCCEED();
    }

    auto GetMasterKey(NcaKeyArea* out, u8 key) const -> Result {
        R_UNLESS(HasMasterKey(key), "Missing Key!");
        *out = mkey[FixKey(key)];
        R_SUCCEED();
    }
};

HashStr hexIdToStr(auto id) {
    HashStr str{};
    const auto id_lower = std::byteswap(*(u64*)id.c);
    const auto id_upper = std::byteswap(*(u64*)(id.c + 0x8));
    std::snprintf(str.str, 0x21, "%016lx%016lx", id_lower, id_upper);
    return str;
}

auto isRightsIdValid(FsRightsId id) -> bool {
    FsRightsId empty_id{};
    return 0 != std::memcmp(std::addressof(id), std::addressof(empty_id), sizeof(id));
}

auto getKeyGenFromRightsId(FsRightsId id) -> u8 {
    return id.c[sizeof(id) - 1];
}

void parse_hex_key(NcaKeyArea* keak, const char* hex) {
    char low[0x11]{};
    char upp[0x11]{};
    std::memcpy(low, hex, 0x10);
    std::memcpy(upp, hex + 0x10, 0x10);
    *(u64*)keak->area = std::byteswap<u64>(std::strtoul(low, nullptr, 0x10));
    *(u64*)(keak->area + 8) = std::byteswap<u64>(std::strtoul(upp, nullptr, 0x10));
}

void find_keys_in_file(const char* loaded_file, const char* search_key, KeySection& key_section) {
    auto ed = loaded_file;
    char parse_string[0x100] = {0};
    const auto skip = std::strlen(search_key) + 2 + 3;  // two extra hex + 2 spaces and =.

    for (u8 i = 0; i < KEYGEN_LIMIT; i++) {
        std::sprintf(parse_string, "%s%02x", search_key, i);
        if (!(ed = std::strstr(ed, parse_string)))
            break;
        ed += skip;
        #if 0
        consolePrint("found %s: %.32s\n", parse_string, ed);
        #endif

        NcaKeyArea keak;
        parse_hex_key(&keak, ed);
        key_section.emplace_back(keak);
        ed += (sizeof(keak) * 2) + 1;
    }
}

Result readKeyFile(std::vector<char>& out) {
    FsFileSystem fs;
    R_TRY(fsOpenSdCardFileSystem(std::addressof(fs)));
    ON_SCOPE_EXIT(fsFsClose(std::addressof(fs)));

    FsFile file;
    const char keys_path[FS_MAX_PATH]{"/switch/prod.keys"};
    R_TRY(fsFsOpenFile(std::addressof(fs), keys_path, FsOpenMode_Read, std::addressof(file)));
    ON_SCOPE_EXIT(fsFileClose(std::addressof(file)));

    s64 size;
    R_TRY(fsFileGetSize(&file, &size));
    R_UNLESS(size > 0, "Empty keys file!");
    R_UNLESS(size < 1024*1024, "Huge keys file!");

    out.resize(size);
    u64 bytes_read;
    R_TRY(fsFileRead(&file, 0, out.data(), out.size(), FsReadOption_None, &bytes_read));
    R_UNLESS(bytes_read == static_cast<u64>(size), "Missmatch");

    R_SUCCEED();
}

Result parse_keys(Keys& out) {
    std::vector<char> buf;
    R_TRY(readKeyFile(buf));

    const char* key_text_keak_app = "key_area_key_application_";
    const char* key_text_keak_oce = "key_area_key_ocean_";
    const char* key_text_keak_sys = "key_area_key_system_";
    const char* key_text_title_kek = "titlekek_";
    const char* key_text_mkey = "master_key_";

    find_keys_in_file(buf.data(), key_text_keak_app, out.keak[NcaKeyAreaEncryptionKeyIndex_Application]);
    find_keys_in_file(buf.data(), key_text_keak_oce, out.keak[NcaKeyAreaEncryptionKeyIndex_Ocean]);
    find_keys_in_file(buf.data(), key_text_keak_sys, out.keak[NcaKeyAreaEncryptionKeyIndex_System]);
    find_keys_in_file(buf.data(), key_text_title_kek, out.title_kek);
    find_keys_in_file(buf.data(), key_text_mkey, out.mkey);

    R_TRY(splCryptoInitialize());
    ON_SCOPE_EXIT(splCryptoExit());

    u8 header_kek[0x20];
    R_TRY(splCryptoGenerateAesKek(HEADER_KEK_SRC, 0, 0, header_kek));
    R_TRY(splCryptoGenerateAesKey(header_kek, HEADER_KEY_SRC, out.header_key));
    R_TRY(splCryptoGenerateAesKey(header_kek, HEADER_KEY_SRC + 0x10, out.header_key + 0x10));

    R_SUCCEED();
}

void readFunc(void* d) {
    auto t = static_cast<ThreadData*>(d);
    std::vector<u8> buf(BUFFER_SIZE);

    u64 done = t->write_offset;
    while (done < t->total_size && R_SUCCEEDED(t->write_result)) {
        u64 bytes_read;
        if (auto rc = fsFileRead(std::addressof(t->nca_file), done, buf.data(), buf.size(), FsReadOption_None, std::addressof(bytes_read)); R_FAILED(rc)) {
            t->read_result = rc;
            return;
        }

        mutexLock(std::addressof(t->mutex));
        if (t->data_size != 0) {
            condvarWait(std::addressof(t->can_read), std::addressof(t->mutex));
        }

        std::memcpy(t->buf.data(), buf.data(), bytes_read);
        t->data_size = bytes_read;
        done += bytes_read;

        mutexUnlock(std::addressof(t->mutex));
        condvarWakeOne(std::addressof(t->can_write));
    }
}

void writeFunc(void* d) {
    auto t = static_cast<ThreadData*>(d);

    while (t->write_offset < t->total_size && R_SUCCEEDED(t->read_result)) {
        mutexLock(std::addressof(t->mutex));
        if (t->data_size == 0) {
            condvarWait(std::addressof(t->can_write), std::addressof(t->mutex));
        }

        if (auto rc = ncmContentStorageWritePlaceHolder(std::addressof(t->cs), std::addressof(t->placeholder_id), t->write_offset, t->buf.data(), t->data_size); R_FAILED(rc)) {
            t->write_result = rc;
            return;
        }

        t->write_offset += t->data_size;
        t->data_size = 0;

        mutexUnlock(std::addressof(t->mutex));
        condvarWakeOne(std::addressof(t->can_read));
    }
}

void cryptoAes128(const void *in, void *out, const void* key, bool is_encryptor) {
    Aes128Context ctx;
    aes128ContextCreate(&ctx, key, is_encryptor);

    if (is_encryptor) {
        aes128EncryptBlock(&ctx, out, in);
    } else {
        aes128DecryptBlock(&ctx, out, in);
    }
}

void cryptoAes128Xts(const void* in, void* out, const void* key, u64 sector, u64 sector_size, u64 data_size, bool is_encryptor) {
    Aes128XtsContext ctx;
    aes128XtsContextCreate(std::addressof(ctx), key, static_cast<const u8*>(key) + 0x10, is_encryptor);

    for (u64 pos = 0; pos < data_size; pos += sector_size) {
        aes128XtsContextResetSector(std::addressof(ctx), sector++, true);
        if (is_encryptor) {
            aes128XtsEncrypt(std::addressof(ctx), static_cast<u8*>(out) + pos, static_cast<const u8*>(in) + pos, sector_size);
        } else {
            aes128XtsDecrypt(std::addressof(ctx), static_cast<u8*>(out) + pos, static_cast<const u8*>(in) + pos, sector_size);
        }
    }
}

Result NcaDecryptKeak(const Keys& keys, NcaHeader& header) {
    const auto key_generation = header.GetKeyGeneration();

    // try with spl
    NcaKeyArea keak;
    if (R_SUCCEEDED(splCryptoGenerateAesKek(g_key_area_key[header.kaek_index], key_generation, 0, &keak))) {
        for (auto& key_area : header.key_area) {
            R_TRY(splCryptoGenerateAesKey(&keak, std::addressof(key_area), std::addressof(key_area)));
        }
    } else {
        // failed with spl, try using keys.
        R_TRY(keys.GetNcaKeyArea(&keak, key_generation, header.kaek_index));
        for (auto& key_area : header.key_area) {
            cryptoAes128(std::addressof(key_area), std::addressof(key_area), std::addressof(keak), false);
        }
    }

    R_SUCCEED();
}

Result NcaEncryptKeak(const Keys& keys, NcaHeader& header, u8 key_generation) {
    header.SetKeyGeneration(key_generation);

    NcaKeyArea keak;
    R_TRY(keys.GetNcaKeyArea(&keak, key_generation, header.kaek_index));
    printf("re-encrypting with: 0x%X\n", key_generation);

    for (auto& key_area : header.key_area) {
        cryptoAes128(std::addressof(key_area), std::addressof(key_area), std::addressof(keak), true);
    }

    std::memset(&header.rights_id, 0, sizeof(header.rights_id));
    R_SUCCEED();
}

Result esImportTicket(Service* srv, const void* tik_buf, u64 tik_size, const void* cert_buf, u64 cert_size) {
    return serviceDispatch(srv, 1,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In, SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { tik_buf, tik_size }, { cert_buf, cert_size } });
}

Result nsPushApplicationRecord(Service* srv, u64 tid, const NcmContentStorageRecord* records, u32 count) {
    const struct {
        u8 last_modified_event;
        u8 padding[0x7];
        u64 tid;
    } in = { NsApplicationRecordType_Installed, {0}, tid };

    return serviceDispatchIn(srv, 16, in,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { records, sizeof(NcmContentStorageRecord) * count } });
}

Result ncmDelete(NcmContentStorage* cs, const NcmContentId *content_id) {
    bool has;
    R_TRY(ncmContentStorageHas(cs, std::addressof(has), content_id));
    if (has) {
        R_TRY(ncmContentStorageDelete(cs, content_id));
    }
    R_SUCCEED();
}

Result ncmRegister(NcmContentStorage* cs, const NcmContentId *content_id, const NcmPlaceHolderId *placeholder_id) {
    R_TRY(ncmDelete(cs, content_id));
    return ncmContentStorageRegister(cs, content_id, placeholder_id);
}

__attribute__((format (printf, 1, 2)))
void consolePrint(const char* f, ...) {
    std::va_list argv;
    va_start(argv, f);
    std::vprintf(f, argv);
    va_end(argv);
    consoleUpdate(nullptr);
}

Result gci_parse(GciEntries& out) {
    R_TRY(ncmInitialize());
    ON_SCOPE_EXIT(ncmExit());

    NcmContentMetaDatabase db;
    R_TRY(ncmOpenContentMetaDatabase(std::addressof(db), NcmStorageId_GameCard));
    ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(std::addressof(db)));

    s32 meta_total;
    s32 meta_entries_written;
    std::vector<NcmContentMetaKey> keys(1);
    R_TRY(ncmContentMetaDatabaseList(std::addressof(db), std::addressof(meta_total), std::addressof(meta_entries_written), keys.data(), keys.size(), NcmContentMetaType_Unknown, 0, 0, UINT64_MAX, NcmContentInstallType_Full));
    R_UNLESS(static_cast<u64>(meta_entries_written) == keys.size(), "Missmatch");

    if (static_cast<u64>(meta_total) > keys.size()) {
        keys.resize(meta_total);
        R_TRY(ncmContentMetaDatabaseList(std::addressof(db), std::addressof(meta_total), std::addressof(meta_entries_written), keys.data(), keys.size(), NcmContentMetaType_Unknown, 0, 0, UINT64_MAX, NcmContentInstallType_Full));
        R_UNLESS(static_cast<u64>(meta_entries_written) == keys.size(), "Missmatch");
    }

    NcmContentStorage cs;
    R_TRY(ncmOpenContentStorage(std::addressof(cs), NcmStorageId_GameCard));
    ON_SCOPE_EXIT(ncmContentStorageClose(std::addressof(cs)));

    for (const auto& key : keys) {
        struct {
            NcmContentMetaHeader header;
            NcmExtendedHeader extended;
        } content_meta;
        u64 out_size;
        R_TRY(ncmContentMetaDatabaseGet(std::addressof(db), std::addressof(key), std::addressof(out_size), std::addressof(content_meta), sizeof(content_meta)));
        R_UNLESS(out_size == sizeof(content_meta), "Bad Size");

        std::vector<NcmContentInfo> content_infos(content_meta.header.content_count);
        s32 content_info_out;
        R_TRY(ncmContentMetaDatabaseListContentInfo(std::addressof(db), std::addressof(content_info_out), content_infos.data(), content_infos.size(), std::addressof(key), 0));
        R_UNLESS(static_cast<u64>(content_info_out) == content_infos.size(), "Missmatch");

        NcmContentId program_content_id;
        R_TRY(ncmContentMetaDatabaseGetContentIdByType(std::addressof(db), std::addressof(program_content_id), std::addressof(key), NcmContentType_Program));

        NcmRightsId rights_id;
        R_TRY(ncmContentStorageGetRightsIdFromContentId(std::addressof(cs), std::addressof(rights_id), std::addressof(program_content_id), FsContentAttributes_All));

        GciEntry entry;
        entry.key = key;
        entry.content_meta_header = content_meta.header;
        entry.extended_header = content_meta.extended;
        entry.ncm_rights_id = rights_id;
        entry.content_infos = content_infos;
        for (auto& info : content_infos) {
            NcaCollection nca{};
            nca.content_id = info.content_id;
            nca.content_type = info.content_type;
            ncmContentInfoSizeToU64(std::addressof(info), std::addressof(nca.size));
            R_UNLESS(nca.size > 0, "Size is zero!");
            entry.ncas.emplace_back(nca);
        }

        out.emplace_back(entry);
        #if 1
        consolePrint("\textended_header_size: %u\n", content_meta.header.extended_header_size);
        consolePrint("\tcontent_count: %u\n", content_meta.header.content_count);
        consolePrint("\tcontent_meta_count: %u\n", content_meta.header.content_meta_count);
        consolePrint("\tread_size: %zu\n", out_size);
        if (entry.IsRightsIdValid()) {
            consolePrint("\t\trights_id: %s.tik\n", hexIdToStr(rights_id.rights_id).str);
            consolePrint("\t\tkey_generation: 0x%X\n", rights_id.key_generation);
        }
        consolePrint("\n");

        for (auto& info: content_infos) {
            consolePrint("\t\tcontent_id: %s%s.nca\n", hexIdToStr(info.content_id).str, info.content_type == NcmContentType_Meta ? ".cnmt.nca" : ".nca");
            consolePrint("\t\tcontent_type: %X\n", info.content_type);
        }
        consolePrint("\n");
        #endif
    }

    R_SUCCEED();
};

Result gci_install(NcmStorageId storage_id) {
    FsDeviceOperator dev_op;
    R_TRY(fsOpenDeviceOperator(std::addressof(dev_op)));
    ON_SCOPE_EXIT(fsDeviceOperatorClose(std::addressof(dev_op)));

    bool gc_inserted;
    R_TRY(fsDeviceOperatorIsGameCardInserted(std::addressof(dev_op), std::addressof(gc_inserted)));
    R_UNLESS(gc_inserted, "No GameCard Inserted!");

    GciEntries entries;
    R_TRY(gci_parse(entries));

    Keys keys;
    R_TRY(parse_keys(keys));

    #if 1
    FsGameCardHandle gc_handle;
    R_TRY(fsDeviceOperatorGetGameCardHandle(std::addressof(dev_op), std::addressof(gc_handle)));
    // ON_SCOPE_EXIT(svcCloseHandle(gc_handle.value)); // todo: is this needed?

    FsFileSystem fs;
    R_TRY(fsOpenGameCardFileSystem(std::addressof(fs), std::addressof(gc_handle), FsGameCardPartition_Secure));
    ON_SCOPE_EXIT(fsFsClose(std::addressof(fs)));

    // will install in this order
    const NcmContentMetaType meta_types[] = {
        NcmContentMetaType_Application,
        NcmContentMetaType_Patch,
        NcmContentMetaType_AddOnContent,
    };

    R_TRY(nsInitialize());
    ON_SCOPE_EXIT(nsExit());

    R_TRY(ncmInitialize());
    ON_SCOPE_EXIT(ncmExit());

    NcmContentStorage cs;
    R_TRY(ncmOpenContentStorage(std::addressof(cs), storage_id));
    ON_SCOPE_EXIT(ncmContentStorageClose(std::addressof(cs)));

    NcmContentMetaDatabase db;
    R_TRY(ncmOpenContentMetaDatabase(std::addressof(db), storage_id));
    ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(std::addressof(db)));

    Service es;
    R_TRY(smGetService(std::addressof(es), "es"));
    ON_SCOPE_EXIT(serviceClose(std::addressof(es)));

    R_TRY(splCryptoInitialize());
    ON_SCOPE_EXIT(splCryptoExit());

    for (const auto meta_type : meta_types) {
        for (auto& entry : entries) {
            if (entry.GetType() != meta_type) {
                continue;
            }

            bool convert_to_standard_crypto = CONVERT_TO_STANDARD_CRYPTO;
            if (CONVERT_BASE_TO_STANDARD_CRYTPO && entry.GetType() == NcmContentMetaType_Application) {
                convert_to_standard_crypto = CONVERT_BASE_TO_STANDARD_CRYTPO;
            } else if (CONVERT_UPDATE_TO_STANDARD_CRYTPO && entry.GetType() == NcmContentMetaType_Patch) {
                convert_to_standard_crypto = CONVERT_UPDATE_TO_STANDARD_CRYTPO;
            } else if (CONVERT_DLC_TO_STANDARD_CRYTPO && entry.GetType() == NcmContentMetaType_AddOnContent) {
                convert_to_standard_crypto = CONVERT_DLC_TO_STANDARD_CRYTPO;
            }

            consolePrint("Installing Type: 0x%X\n", entry.GetType());

            // cleanup all placeholders on error.
            ON_SCOPE_EXIT(
                for (auto& nca : entry.ncas) {
                    ncmContentStorageDeletePlaceHolder(std::addressof(cs), std::addressof(nca.placeholder_id));
                }
            );

            // install all ncas
            for (auto& nca : entry.ncas) {
                R_TRY(ncmContentStorageGeneratePlaceHolderId(std::addressof(cs), std::addressof(nca.placeholder_id)));
                R_TRY(ncmContentStorageCreatePlaceHolder(std::addressof(cs), std::addressof(nca.content_id), std::addressof(nca.placeholder_id), nca.size));

                char safe_buf[FS_MAX_PATH];
                std::sprintf(safe_buf, "/%s%s", hexIdToStr(nca.content_id).str, nca.content_type == NcmContentType_Meta ? ".cnmt.nca" : ".nca");
                consolePrint("\nInstalling NCA: %s\n\n", safe_buf);

                FsFile nca_file;
                R_TRY(fsFsOpenFile(std::addressof(fs), safe_buf, FsOpenMode_Read, std::addressof(nca_file)));
                ON_SCOPE_EXIT(fsFileClose(std::addressof(nca_file)));

                NcaHeader nca_header;
                u64 bytes_read;
                R_TRY(fsFileRead(std::addressof(nca_file), 0, std::addressof(nca_header), sizeof(nca_header), 0, std::addressof(bytes_read)));
                R_UNLESS(bytes_read > 0, "Size is empty!");

                cryptoAes128Xts(std::addressof(nca_header), std::addressof(nca_header), keys.header_key, 0, 0x200, sizeof(nca_header), false);
                R_UNLESS(nca_header.magic == 0x3341434E, "Wrong NCA magic!");

                if (FIX_DISTRIBUTION_BIT) {
                    nca_header.distribution_type = NcaDistributionType_System;
                }

                if ((convert_to_standard_crypto && isRightsIdValid(nca_header.rights_id)) || LOWER_MASTER_KEY) {
                    u8 keak_generation;

                    if (isRightsIdValid(nca_header.rights_id)) {
                        const auto key_gen = getKeyGenFromRightsId(nca_header.rights_id);
                        consolePrint("converting to standard crypto: 0x%X 0x%X\n", key_gen, nca_header.key_gen);

                        char tik_name[FS_MAX_PATH];
                        std::sprintf(tik_name, "/%s.tik", hexIdToStr(nca_header.rights_id).str);

                        FsFile tik_file;
                        R_TRY(fsFsOpenFile(std::addressof(fs), tik_name, FsOpenMode_Read, std::addressof(tik_file)));
                        ON_SCOPE_EXIT(fsFileClose(std::addressof(tik_file)));

                        NcaKeyArea title_key;
                        u64 tik_read_bytes;
                        R_TRY(fsFileRead(std::addressof(tik_file), 0x180, &title_key, sizeof(title_key), FsReadOption_None, std::addressof(tik_read_bytes)));
                        R_UNLESS(tik_read_bytes == sizeof(title_key), "Missmatch!");

                        NcaKeyArea title_kek;
                        R_TRY(keys.GetTitleKek(&title_kek, key_gen));
                        cryptoAes128(&title_key, &title_key, &title_kek, false);

                        std::memset(nca_header.key_area, 0, sizeof(nca_header.key_area));
                        nca_header.key_area[0x2] = title_key;

                        keak_generation = key_gen;
                    } else /*if (LOWER_MASTER_KEY)*/ {
                        keak_generation = nca_header.GetKeyGeneration();
                        R_TRY(NcaDecryptKeak(keys, nca_header));
                    }

                    if (LOWER_MASTER_KEY) {
                        keak_generation = 0;
                    }

                    // re-encrypt keak with new keak_generation
                    R_TRY(NcaEncryptKeak(keys, nca_header, keak_generation));
                }

                cryptoAes128Xts(std::addressof(nca_header), std::addressof(nca_header), keys.header_key, 0, 0x200, sizeof(nca_header), true);
                R_UNLESS(nca_header.magic != 0x3341434E, "NCA magic after encryption!");
                R_TRY(ncmContentStorageWritePlaceHolder(std::addressof(cs), std::addressof(nca.placeholder_id), 0, std::addressof(nca_header), sizeof(nca_header)));

                ThreadData t_data{nca_file, cs, nca.placeholder_id, nca.size};
                t_data.write_offset += sizeof(nca_header);

                Thread t_read, t_write;
                R_TRY(threadCreate(std::addressof(t_read), readFunc, std::addressof(t_data), nullptr, 1024*32, 0x2C, -2));
                R_TRY(threadCreate(std::addressof(t_write), writeFunc, std::addressof(t_data), nullptr, 1024*32, 0x2C, -2));
                R_TRY(threadStart(std::addressof(t_read)));
                R_TRY(threadStart(std::addressof(t_write)));

                TimeStamp clock{};
                double speed{};
                double written{};
                while (t_data.write_offset != t_data.total_size && R_SUCCEEDED(t_data.read_result) && R_SUCCEEDED(t_data.write_result)) {
                    if (clock.GetSeconds() >= 1.0) {
                        const double new_written = t_data.write_offset;
                        speed = (new_written - written) / _1MiB;
                        written = new_written;
                        clock.Reset();
                    }
                    consolePrint("* INSTALLING: %.2fMB of %.2fMB %.2fMB/s *\r", static_cast<double>(t_data.write_offset) / _1MiB, static_cast<double>(nca.size) / _1MiB, speed);
                    svcSleepThread(33'333'333);
                }
                consolePrint("\n");

                R_TRY(threadWaitForExit(std::addressof(t_read)));
                R_TRY(threadWaitForExit(std::addressof(t_write)));
                R_TRY(threadClose(std::addressof(t_read)));
                R_TRY(threadClose(std::addressof(t_write)));

                R_UNLESS(R_SUCCEEDED(t_data.read_result), "readThread");
                R_UNLESS(R_SUCCEEDED(t_data.write_result), "writeThread");
            }

            // remove current entries (if any).
            const auto app_id = entry.GetAppId();
            s32 db_list_total;
            s32 db_list_count;
            u64 id_min = entry.key.id;
            u64 id_max = entry.key.id;
            std::vector<NcmContentMetaKey> keys(1);

            // if installing a patch, remove all previously installed patches.
            if (entry.key.type == NcmContentMetaType_Patch) {
                id_min = 0;
                id_max = UINT64_MAX;
            }

            R_TRY(ncmContentMetaDatabaseList(std::addressof(db), std::addressof(db_list_total), std::addressof(db_list_count), keys.data(), keys.size(), static_cast<NcmContentMetaType>(entry.key.type), app_id, id_min, id_max, NcmContentInstallType_Full));

            if ((u64)db_list_total != keys.size()) {
                keys.resize(db_list_total);
                if (keys.size()) {
                    R_TRY(ncmContentMetaDatabaseList(std::addressof(db), std::addressof(db_list_total), std::addressof(db_list_count), keys.data(), keys.size(), static_cast<NcmContentMetaType>(entry.key.type), app_id, id_min, id_max, NcmContentInstallType_Full));
                }
            }

            for (auto& key : keys) {
                consolePrint("found key: 0x%016lX type: %u version: %u\n", key.id, key.type, key.version);
                NcmContentMetaHeader header;
                u64 out_size;
                consolePrint("trying to get from db\n");
                R_TRY(ncmContentMetaDatabaseGet(std::addressof(db), std::addressof(key), std::addressof(out_size), std::addressof(header), sizeof(header)));
                R_UNLESS(out_size == sizeof(header), "Missmatch!");
                consolePrint("trying to list infos\n");

                std::vector<NcmContentInfo> infos(header.content_count);
                s32 content_info_out;
                R_TRY(ncmContentMetaDatabaseListContentInfo(std::addressof(db), std::addressof(content_info_out), infos.data(), infos.size(), std::addressof(key), 0));
                R_UNLESS((u64)content_info_out == infos.size(), "Missmatch!");
                consolePrint("size matches\n");

                for (auto& info : infos) {
                    R_TRY(ncmDelete(std::addressof(cs), std::addressof(info.content_id)));
                }

                consolePrint("trying to remove it\n");
                R_TRY(ncmContentMetaDatabaseRemove(std::addressof(db), std::addressof(key)));
                R_TRY(ncmContentMetaDatabaseCommit(std::addressof(db)));
                consolePrint("all done with this key\n\n");
            }

            for (auto& nca : entry.ncas) {
                consolePrint("registering nca: %s\n", hexIdToStr(nca.content_id).str);
                R_TRY(ncmRegister(std::addressof(cs), std::addressof(nca.content_id), std::addressof(nca.placeholder_id)));
                consolePrint("registered nca: %s\n", hexIdToStr(nca.content_id).str);
            }


            // set the database
            {
                auto& extended_header = entry.extended_header;
                if (LOWER_SYSTEM_VERSION) {
                    if (entry.key.type == NcmContentMetaType_Application) {
                        extended_header.application.required_system_version = 0;
                    } else if (entry.key.type == NcmContentMetaType_Patch) {
                        extended_header.patch.required_system_version = 0;
                    }

                    R_UNLESS(entry.GetType() != NcmContentMetaType_DataPatch, "Not yet handled");
                }

                BufHelper content_meta_data;
                content_meta_data.write(std::addressof(entry.content_meta_header), sizeof(entry.content_meta_header));
                content_meta_data.write(std::addressof(extended_header), entry.content_meta_header.extended_header_size);
                content_meta_data.write(entry.content_infos.data(), sizeof(NcmContentInfo) * entry.content_infos.size());

                R_TRY(ncmContentMetaDatabaseSet(std::addressof(db), std::addressof(entry.key), content_meta_data.buf.data(), content_meta_data.tell()));
                R_TRY(ncmContentMetaDatabaseCommit(std::addressof(db)));
            }

            // push app record
            {
                Service ns_srv;
                R_TRY(nsGetApplicationManagerInterface(std::addressof(ns_srv)));

                NcmContentStorageRecord storage_record{};
                storage_record.key = entry.key;
                storage_record.storage_id = storage_id;
                R_TRY(nsPushApplicationRecord(std::addressof(ns_srv), app_id, std::addressof(storage_record), 1));

                if (hosversionAtLeast(6,0,0)) {
                    R_TRY(avmInitialize());
                    ON_SCOPE_EXIT(avmExit());

                    if (storage_record.key.type == NcmContentMetaType_Patch) {
                        R_TRY(avmPushLaunchVersion(app_id, storage_record.key.version));
                    }
                }
            }

            // install ticket if titlekey crypto
            if (entry.IsRightsIdValid() && !convert_to_standard_crypto && !LOWER_MASTER_KEY) {
                char tik_name[FS_MAX_PATH], cert_name[FS_MAX_PATH];
                std::sprintf(tik_name, "/%s.tik", hexIdToStr(entry.ncm_rights_id.rights_id).str);
                std::sprintf(cert_name, "/%s.cert", hexIdToStr(entry.ncm_rights_id.rights_id).str);

                FsFile tik_file, cert_file;
                R_TRY(fsFsOpenFile(std::addressof(fs), tik_name, FsOpenMode_Read, std::addressof(tik_file)));
                ON_SCOPE_EXIT(fsFileClose(std::addressof(tik_file)));
                R_TRY(fsFsOpenFile(std::addressof(fs), cert_name, FsOpenMode_Read, std::addressof(cert_file)));
                ON_SCOPE_EXIT(fsFileClose(std::addressof(cert_file)));

                s64 tik_size, cert_size;
                R_TRY(fsFileGetSize(std::addressof(tik_file), std::addressof(tik_size)));
                R_TRY(fsFileGetSize(std::addressof(cert_file), std::addressof(cert_size)));
                R_UNLESS(tik_size > 0, "Size is zero!");
                R_UNLESS(cert_size > 0, "Size is zero!");

                std::vector<u8> tik_buf(tik_size), cert_buf(cert_size);
                u64 tik_read_bytes, cert_read_bytes;
                R_TRY(fsFileRead(std::addressof(tik_file), 0, tik_buf.data(), tik_buf.size(), 0, std::addressof(tik_read_bytes)));
                R_TRY(fsFileRead(std::addressof(cert_file), 0, cert_buf.data(), cert_buf.size(), 0, std::addressof(cert_read_bytes)));
                R_UNLESS(tik_read_bytes == tik_buf.size(), "Missmatch!");
                R_UNLESS(cert_read_bytes == cert_buf.size(), "Missmatch!");

                consolePrint("\tInstalling tik: %s\n", tik_name);
                R_TRY(esImportTicket(std::addressof(es), tik_buf.data(), tik_buf.size(), cert_buf.data(), cert_buf.size()));
            }
        }
    }

    #endif
    consolePrint("all good :)!\n");
    R_SUCCEED();
}

} // namespace

extern "C" void userAppInit(void) {
    appletLockExit();
}

extern "C" void userAppExit(void) {
    appletUnlockExit();
}

int main(void) {
    consoleInit(nullptr);
    ON_SCOPE_EXIT(consoleExit(nullptr));

    TimeStamp ts;
    appletSetCpuBoostMode(ApmCpuBoostMode_FastLoad);
        gci_install(NcmStorageId_SdCard);
    appletSetCpuBoostMode(ApmCpuBoostMode_Normal);

    consolePrint("Press (+) to exit, time taken: %.2fs\n\n", ts.GetSeconds());

    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(std::addressof(pad));

    while (appletMainLoop()) {
        padUpdate(std::addressof(pad));

        const u64 kDown = padGetButtonsDown(std::addressof(pad));
        if (kDown & HidNpadButton_Plus)
            break; // break in order to return to hbmenu

        svcSleepThread(33'333'333);
    }
}
