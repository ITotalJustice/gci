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

union NcmExtendedHeader {
    NcmApplicationMetaExtendedHeader application;
    NcmPatchMetaExtendedHeader patch;
    NcmAddOnContentMetaExtendedHeader addon;
    NcmLegacyAddOnContentMetaExtendedHeader addon_legacy;
    NcmDataPatchMetaExtendedHeader data_patch;
};

struct GciEntry {
    NcmContentMetaKey key;
    NcmContentMetaHeader content_meta_header;
    NcmExtendedHeader extended_header;
    std::vector<NcmContentInfo> content_infos;
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
    NcmPlaceHolderId placeholder_id;
    volatile u64 total_size;

    // these are shared between threads
    volatile u64 offset{};
    volatile u64 data_written{};
    volatile u64 data_size{};
    volatile Result read_result{};
    volatile Result write_result{};
};

struct HashStr {
    char str[0x21];
};

HashStr hexIdToStr(auto id) {
    HashStr str{};
    const auto id_lower = std::byteswap(*(u64*)id.c);
    const auto id_upper = std::byteswap(*(u64*)(id.c + 0x8));
    std::snprintf(str.str, 0x21, "%016lx%016lx", id_lower, id_upper);
    return str;
}

void readFunc(void* d) {
    auto t = static_cast<ThreadData*>(d);
    std::vector<u8> buf(BUFFER_SIZE);

    u64 done = t->data_written;
    while (done < t->total_size && R_SUCCEEDED(t->write_result)) {
        u64 bytes_read;
        if (auto rc = fsFileRead(std::addressof(t->nca_file), t->offset, buf.data(), buf.size(), FsReadOption_None, std::addressof(bytes_read)); R_FAILED(rc)) {
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
        t->offset += bytes_read;

        mutexUnlock(std::addressof(t->mutex));
        condvarWakeOne(std::addressof(t->can_write));
    }
}

void writeFunc(void* d) {
    auto t = static_cast<ThreadData*>(d);

    while (t->data_written < t->total_size && R_SUCCEEDED(t->read_result)) {
        mutexLock(std::addressof(t->mutex));
        if (t->data_size == 0) {
            condvarWait(std::addressof(t->can_write), std::addressof(t->mutex));
        }

        if (auto rc = ncmContentStorageWritePlaceHolder(std::addressof(t->cs), std::addressof(t->placeholder_id), t->data_written, t->buf.data(), t->data_size); R_FAILED(rc)) {
            t->write_result = rc;
            return;
        }

        t->data_written += t->data_size;
        t->data_size = 0;

        mutexUnlock(std::addressof(t->mutex));
        condvarWakeOne(std::addressof(t->can_read));
    }
}

Result esImportTicket(Service* srv, const void* tik_buf, u64 tik_size, const void* cert_buf, u64 cert_size) {
    return serviceDispatch(srv, 1,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In, SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = { { tik_buf, tik_size }, { cert_buf, cert_size } });
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

Result nsListApplicationRecordContentMeta(Service* srv, u64 offset, u64 tid, NcmContentStorageRecord* out_records, u32 count, s32* entries_read) {
    struct {
        u64 offset;
        u64 tid;
    } in = { offset, tid };

    return serviceDispatchInOut(srv, 17, in, *entries_read,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { out_records, sizeof(NcmContentStorageRecord) * count } });
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
        entry.content_infos = content_infos;
        entry.ncm_rights_id = rights_id;
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

    R_TRY(ncmInitialize());
    ON_SCOPE_EXIT(ncmExit());

    NcmContentStorage cs;
    R_TRY(ncmOpenContentStorage(std::addressof(cs), storage_id));
    ON_SCOPE_EXIT(ncmContentStorageClose(std::addressof(cs)));

    for (const auto meta_type : meta_types) {
        for (const auto& entry : entries) {
            if (entry.GetType() != meta_type) {
                continue;
            }
            consolePrint("Installing Type: 0x%X\n", entry.GetType());

            // install all ncas
            for (const auto& content_info : entry.content_infos) {
                u64 nca_size;
                ncmContentInfoSizeToU64(std::addressof(content_info), std::addressof(nca_size));
                R_UNLESS(nca_size > 0, "Size is zero!");

                NcmPlaceHolderId placeholder_id;
                R_TRY(ncmContentStorageGeneratePlaceHolderId(std::addressof(cs), std::addressof(placeholder_id)));

                bool has_placeholder;
                R_TRY(ncmContentStorageHasPlaceHolder(std::addressof(cs), std::addressof(has_placeholder), std::addressof(placeholder_id)));
                if (has_placeholder) {
                    R_TRY(ncmContentStorageDeletePlaceHolder(std::addressof(cs), std::addressof(placeholder_id)));
                }
                R_TRY(ncmContentStorageCreatePlaceHolder(std::addressof(cs), std::addressof(content_info.content_id), std::addressof(placeholder_id), nca_size));

                char safe_buf[FS_MAX_PATH];
                std::sprintf(safe_buf, "/%s%s", hexIdToStr(content_info.content_id).str, content_info.content_type == NcmContentType_Meta ? ".cnmt.nca" : ".nca");
                consolePrint("\nInstalling NCA: %s\n\n", safe_buf);

                FsFile nca_file;
                R_TRY(fsFsOpenFile(std::addressof(fs), safe_buf, FsOpenMode_Read, std::addressof(nca_file)));
                ON_SCOPE_EXIT(fsFileClose(std::addressof(nca_file)));

                ThreadData t_data{nca_file, cs, placeholder_id, nca_size};
                Thread t_read, t_write;
                R_TRY(threadCreate(std::addressof(t_read), readFunc, std::addressof(t_data), nullptr, 1024*32, 0x2C, -2));
                R_TRY(threadCreate(std::addressof(t_write), writeFunc, std::addressof(t_data), nullptr, 1024*32, 0x2C, -2));
                R_TRY(threadStart(std::addressof(t_read)));
                R_TRY(threadStart(std::addressof(t_write)));

                // loop until file has finished installing.
                TimeStamp clock{};
                double speed{};
                double written{};
                while (t_data.data_written != t_data.total_size && R_SUCCEEDED(t_data.read_result) && R_SUCCEEDED(t_data.write_result)) {
                    if (clock.GetSeconds() >= 1.0) {
                        const double new_written = t_data.data_written;
                        speed = (new_written - written) / _1MiB;
                        written = new_written;
                        clock.Reset();
                    }
                    consolePrint("* INSTALLING: %.2fMB of %.2fMB %.2fMB/s*\r", static_cast<double>(t_data.data_written) / _1MiB, static_cast<double>(nca_size) / _1MiB, speed);
                    svcSleepThread(33'333'333);
                }
                consolePrint("\n");

                R_TRY(threadWaitForExit(std::addressof(t_read)));
                R_TRY(threadWaitForExit(std::addressof(t_write)));
                R_TRY(threadClose(std::addressof(t_read)));
                R_TRY(threadClose(std::addressof(t_write)));

                R_UNLESS(R_SUCCEEDED(t_data.read_result), "readThread");
                R_UNLESS(R_SUCCEEDED(t_data.write_result), "writeThread");

                bool has_content;
                R_TRY(ncmContentStorageHas(std::addressof(cs), std::addressof(has_content), &content_info.content_id));
                if (has_content) {
                    R_TRY(ncmContentStorageDelete(std::addressof(cs), std::addressof(content_info.content_id)));
                }
                R_TRY(ncmContentStorageRegister(std::addressof(cs), std::addressof(content_info.content_id), std::addressof(placeholder_id)));
            }

            // set the database
            {
                BufHelper content_meta_data;
                content_meta_data.write(std::addressof(entry.content_meta_header), sizeof(entry.content_meta_header));
                content_meta_data.write(std::addressof(entry.extended_header), entry.content_meta_header.extended_header_size);
                content_meta_data.write(entry.content_infos.data(), sizeof(NcmContentInfo) * entry.content_infos.size());

                NcmContentMetaDatabase db;
                R_TRY(ncmOpenContentMetaDatabase(std::addressof(db), storage_id));
                ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(std::addressof(db)));
                R_TRY(ncmContentMetaDatabaseSet(std::addressof(db), std::addressof(entry.key), content_meta_data.buf.data(), content_meta_data.tell()));
                R_TRY(ncmContentMetaDatabaseCommit(std::addressof(db)));
            }

            // push app record
            {
                R_TRY(nsInitialize());
                ON_SCOPE_EXIT(nsExit());

                const auto app_id = entry.GetAppId();
                Service ns_srv;

                if (hosversionBefore(3,0,0)) {
                    ns_srv = *nsGetServiceSession_ApplicationManagerInterface();
                } else {
                    R_TRY(nsGetApplicationManagerInterface(std::addressof(ns_srv)));
                }
                ON_SCOPE_EXIT(if (hosversionBefore(3,0,0)) { serviceClose(std::addressof(ns_srv)); });

                std::vector<NcmContentStorageRecord> content_storage_record;
                #if 1
                s32 content_meta_count;
                R_TRY(nsCountApplicationContentMeta(app_id, std::addressof(content_meta_count)));

                // NOTE: i am not sure if this is correct.
                if (content_meta_count) {
                    std::vector<NcmContentStorageRecord> records(content_meta_count);
                    s32 out_count;
                    R_TRY(nsListApplicationRecordContentMeta(std::addressof(ns_srv), 0, app_id, records.data(), records.size(), std::addressof(out_count)));
                    R_UNLESS(out_count == content_meta_count, "Missmatch");

                    for (const auto& record : records) {
                        if (record.storage_id == NcmStorageId_GameCard) {
                            consolePrint("\tSkipping GameCard Record\n");
                            continue;
                        }
                        consolePrint("\tPushing record: %u\n", record.storage_id);
                        content_storage_record.push_back(record);
                    }
                }
                #endif

                NcmContentStorageRecord storage_record{};
                storage_record.key = entry.key;
                storage_record.storage_id = storage_id;
                content_storage_record.push_back(storage_record);

                // R_TRY(nsDeleteApplicationRecord(std::addressof(ns_srv), app_id)); // remove previous application record
                R_TRY(nsPushApplicationRecord(std::addressof(ns_srv), app_id, content_storage_record.data(), content_storage_record.size()));
                // nsDeleteRedundantApplicationEntity();
            }

            // install tickets
            if (entry.IsRightsIdValid()) {
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
                Service es_srv;
                R_TRY(smGetService(std::addressof(es_srv), "es"));
                ON_SCOPE_EXIT(serviceClose(std::addressof(es_srv)););
                R_TRY(esImportTicket(std::addressof(es_srv), tik_buf.data(), tik_buf.size(), cert_buf.data(), cert_buf.size()));
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
