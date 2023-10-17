#include <switch.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <string_view>
#include <bit>
#include <experimental/scope>

namespace {

#define R_SUCCEED() return 0
#define R_THROW(_rc) return _rc
#define R_TRY(r) { \
    if (const auto _rc = (r); R_FAILED(_rc)) { \
        std::printf("failed: %s 0x%X\n", #r, _rc); \
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

enum NsApplicationRecordType {
    // installed
    NsApplicationRecordType_Installed       = 0x3,
    // application is gamecard, but gamecard isn't insterted
    NsApplicationRecordType_GamecardMissing = 0x5,
    // archived
    NsApplicationRecordType_Archived        = 0xB,
};

struct CnmtHeader {
    u64 title_id;
    u32 title_version;
    u8 meta_type; // NcmContentMetaType
    u8 _0xD;
    NcmContentMetaHeader meta_header;
    u8 install_type; // NcmContentInstallType
    u8 _0x17;
    u32 required_sys_version;
    u8 _0x1C[0x4];
};
static_assert(sizeof(CnmtHeader) == 0x20);

struct NcmContentStorageRecord {
    NcmContentMetaKey key;
    u8 storage_id; //
    u8 padding[0x7];
};

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

const NcmContentId nca_get_id_from_string(const char *nca_in_string) {
    NcmContentId nca_id{};
    char lowerU64[0x11]{};
    char upperU64[0x11]{};
    std::memcpy(lowerU64, nca_in_string, 0x10);
    std::memcpy(upperU64, nca_in_string + 0x10, 0x10);
    *(u64*)nca_id.c = std::byteswap(strtoul(lowerU64, nullptr, 0x10));
    *(u64*)(nca_id.c + 8) = std::byteswap(strtoul(upperU64, nullptr, 0x10));
    return nca_id;
}

Result nsDeleteApplicationRecord(Service* srv, u64 tid) {
    return serviceDispatchIn(srv, 27, tid);
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

Result nsInvalidateApplicationControlCache(Service* srv, u64 tid) {
    return serviceDispatchIn(srv, 404, tid);
}

void consolePrint(const char* f, ...) {
    std::va_list argv;
    va_start(argv, f);
    std::vprintf(f, argv);
    va_end(argv);
    consoleUpdate(nullptr);
}

Result dumb_installer(NcmStorageId storage_id) {
    FsDeviceOperator dev_op{};
    R_TRY(fsOpenDeviceOperator(&dev_op));
    ON_SCOPE_EXIT(fsDeviceOperatorClose(&dev_op));

    bool gc_inserted{};
    R_TRY(fsDeviceOperatorIsGameCardInserted(&dev_op, &gc_inserted));
    if (!gc_inserted) {
        consolePrint("No GameCard Inserted!\n");
        R_THROW(0x1);
    }

    FsGameCardHandle gc_handle{};
    R_TRY(fsDeviceOperatorGetGameCardHandle(&dev_op, &gc_handle));
    ON_SCOPE_EXIT(svcCloseHandle(gc_handle.value));

    FsFileSystem gc_fs{};
    R_TRY(fsOpenGameCardFileSystem(&gc_fs, &gc_handle, FsGameCardPartition_Secure));
    ON_SCOPE_EXIT(fsFsClose(&gc_fs));

    FsDir gc_dir{};
    char safe_buf[FS_MAX_PATH];
    std::strcpy(safe_buf, "/");
    R_TRY(fsFsOpenDirectory(&gc_fs, safe_buf, FsDirOpenMode_ReadDirs | FsDirOpenMode_ReadFiles, &gc_dir));
    ON_SCOPE_EXIT(fsDirClose(&gc_dir));

    s64 gc_count{};
    R_TRY(fsDirGetEntryCount(&gc_dir, &gc_count));
    consolePrint("entry count: %zd\n", gc_count);

    std::vector<FsDirectoryEntry> gc_entries(gc_count);
    s64 total_entries{};
    R_TRY(fsDirRead(&gc_dir, &total_entries, gc_entries.size(), gc_entries.data()));

    for (auto&e : gc_entries) {
        consolePrint("\tfound entry: %s size: %zd\n", e.name, e.file_size);
    }

    R_TRY(ncmInitialize());
    ON_SCOPE_EXIT(ncmExit());

    NcmContentStorage cs;
    R_TRY(ncmOpenContentStorage(&cs, storage_id));
    ON_SCOPE_EXIT(ncmContentStorageClose(&cs));

    for (const auto& nca : gc_entries) {
        NcmPlaceHolderId placeholder_id;
        NcmContentId content_id = nca_get_id_from_string(nca.name);
        R_TRY(ncmContentStorageGeneratePlaceHolderId(&cs, &placeholder_id));
        ncmContentStorageDeletePlaceHolder(&cs, &placeholder_id);
        R_TRY(ncmContentStorageCreatePlaceHolder(&cs, &content_id, &placeholder_id, nca.file_size));

        FsFile nca_file;
        std::strcpy(safe_buf, "/");
        std::strcat(safe_buf, nca.name);
        R_TRY(fsFsOpenFile(&gc_fs, safe_buf, FsOpenMode_Read, &nca_file));
        ON_SCOPE_EXIT(fsFileClose(&nca_file));

        consolePrint("\nwriting placeholder: %s\n\n", nca.name);
        std::vector<u8> buf(1024*1024);
        s64 offset{};
        while (offset < nca.file_size) {
            u64 bytes_read{};
            R_TRY(fsFileRead(&nca_file, offset, buf.data(), buf.size(), 0, &bytes_read));
            R_TRY(ncmContentStorageWritePlaceHolder(&cs, &placeholder_id, offset, buf.data(), bytes_read));
            constexpr float _1MiB = 1024*1024;
            consolePrint("* INSTALLING: %.2fMB of %.2fMB *\r", static_cast<float>(offset) / _1MiB, static_cast<float>(nca.file_size) / _1MiB);
            offset += bytes_read;
        }

        ncmContentStorageDelete(&cs, &content_id);
        R_TRY(ncmContentStorageRegister(&cs, &content_id, &placeholder_id));

        if (std::string_view(nca.name).ends_with(".cnmt.nca")) {
            R_TRY(ncmContentStorageGetPath(&cs, safe_buf, sizeof(safe_buf), &content_id));

            FsFileSystem cnmt_fs;
            R_TRY(fsOpenFileSystem(&cnmt_fs, FsFileSystemType_ContentMeta, safe_buf))
            ON_SCOPE_EXIT(fsFsClose(&cnmt_fs));

            FsDir cnmt_dir{};
            std::strcpy(safe_buf, "/");
            R_TRY(fsFsOpenDirectory(&cnmt_fs, safe_buf, FsDirOpenMode_ReadDirs|FsDirOpenMode_ReadFiles, &cnmt_dir));
            ON_SCOPE_EXIT(fsDirClose(&cnmt_dir));

            s64 cnmt_count{};
            R_TRY(fsDirGetEntryCount(&cnmt_dir, &cnmt_count));
            if (cnmt_count != 1) {
                consolePrint("cnmt dir missmatch! expected 1 file, found: %zd\n", cnmt_count);
                R_THROW(0x1);
            }

            std::vector<FsDirectoryEntry> cnmt_entries(cnmt_count);
            s64 cnmt_total_entries{};
            R_TRY(fsDirRead(&cnmt_dir, &cnmt_total_entries, cnmt_entries.size(), cnmt_entries.data()));

            FsFile cnmt_file;
            std::strcpy(safe_buf, "/");
            std::strcat(safe_buf, cnmt_entries[0].name);
            R_TRY(fsFsOpenFile(&cnmt_fs, safe_buf, FsOpenMode_Read, &cnmt_file));
            ON_SCOPE_EXIT(fsFileClose(&cnmt_file));

            for (auto&e : cnmt_entries) {
                consolePrint("\tfound entry: %s size: %zd\n", e.name, e.file_size);
            }

            CnmtHeader cnmt_header{};
            u64 bytes_read{};
            u64 cnmt_offset{};
            R_TRY(fsFileRead(&cnmt_file, cnmt_offset, &cnmt_header, sizeof(cnmt_header), cnmt_offset, &bytes_read));
            cnmt_offset += bytes_read;

            std::vector<u8> extended_header(cnmt_header.meta_header.extended_header_size);
            R_TRY(fsFileRead(&cnmt_file, cnmt_offset, extended_header.data(), extended_header.size(), cnmt_offset, &bytes_read));
            cnmt_offset += bytes_read;

            NcmContentInfo cnmt_content_info{};
            cnmt_content_info.content_id = content_id;
            cnmt_content_info.content_type = NcmContentType_Meta;
            ncmU64ToContentInfoSize(nca.file_size, &cnmt_content_info);

            std::vector<NcmContentInfo> content_infos;
            content_infos.push_back(cnmt_content_info);

            for (u16 i = 0; i < cnmt_header.meta_header.content_count; i++) {
                NcmPackagedContentInfo packed_content{};
                R_TRY(fsFileRead(&cnmt_file, cnmt_offset, &packed_content, sizeof(packed_content), cnmt_offset, &bytes_read));
                cnmt_offset += bytes_read;

                if (packed_content.info.content_type == NcmContentType_DeltaFragment) {
                    continue;
                }
                content_infos.push_back(packed_content.info);
            }

            NcmContentMetaKey content_meta_key{};
            content_meta_key.id = cnmt_header.title_id;
            content_meta_key.version = cnmt_header.title_version;
            content_meta_key.type = cnmt_header.meta_type;
            content_meta_key.install_type = NcmContentInstallType_Full;

            NcmContentMetaHeader content_meta_header = cnmt_header.meta_header;
            content_meta_header.content_meta_count = content_infos.size();

            BufHelper content_meta_data;
            content_meta_data.write(&content_meta_header, sizeof(content_meta_header));
            content_meta_data.write(extended_header.data(), extended_header.size());
            content_meta_data.write(content_infos.data(), sizeof(NcmContentInfo) * content_infos.size());

            NcmContentMetaDatabase db;
            R_TRY(ncmOpenContentMetaDatabase(&db, storage_id));
            ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(&db));
            R_TRY(ncmContentMetaDatabaseSet(&db, &content_meta_key, content_meta_data.buf.data(), content_meta_data.tell()));
            R_TRY(ncmContentMetaDatabaseCommit(&db));

            u64 app_id = content_meta_key.id;
            if (content_meta_key.type == NcmContentMetaType_Patch) {
                app_id = app_id ^ 0x800;
            } else if (content_meta_key.type == NcmContentMetaType_AddOnContent) {
                app_id = (app_id ^ 0x1000) & ~0xFFF;
            }

            NcmContentStorageRecord content_storage_record{};
            content_storage_record.key = content_meta_key;
            content_storage_record.storage_id = storage_id;

            R_TRY(nsInitialize());
            ON_SCOPE_EXIT(nsExit());

            Service ns_srv{};
            bool already_installed{};
            R_TRY(nsIsAnyApplicationEntityInstalled(app_id, &already_installed));

            if (hosversionBefore(3,0,0)) {
                ns_srv = *nsGetServiceSession_ApplicationManagerInterface();
            } else {
                R_TRY(nsGetApplicationManagerInterface(&ns_srv));
            }
            ON_SCOPE_EXIT(if (hosversionBefore(3,0,0)) { serviceClose(&ns_srv); });

            if (already_installed) {
                R_TRY(nsDeleteApplicationRecord(&ns_srv, app_id)); // remove previous application record
            }

            R_TRY(nsPushApplicationRecord(&ns_srv, app_id, &content_storage_record, 1));

            if (already_installed) {
                R_TRY(nsInvalidateApplicationControlCache(&ns_srv, app_id)); // force flush
            }
        }
    }

    consolePrint("all good :)!\n");
    R_SUCCEED();
}

} // namespace

// called before main
extern "C" void userAppInit(void) {
    Result rc;
    if (R_FAILED(rc = appletLockExit())) // block exit until everything is cleaned up
        diagAbortWithResult(rc);
    if (R_FAILED(rc = socketInitializeDefault()))
        diagAbortWithResult(rc);
}

// called after main has exit
extern "C" void userAppExit(void) {
    socketExit();
    appletUnlockExit(); // unblocks exit to cleanly exit
}

int main(void) {
    consoleInit(nullptr);
    ON_SCOPE_EXIT(consoleExit(nullptr));

    dumb_installer(NcmStorageId_SdCard);

    consolePrint("Press (+) to exit\n\n");

    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&pad);

    while (appletMainLoop()) {
        padUpdate(&pad);

        const u64 kDown = padGetButtonsDown(&pad);
        if (kDown & HidNpadButton_Plus)
            break; // break in order to return to hbmenu

        svcSleepThread(1000000);
    }
}
