/*
 * ETS2 Convoy Helper plugin (made for ETS2 1.62.x)
 *
 * Loaded by the game from bin\win_x64\plugins. Changes only the running game's memory.
 *  1. Every mod counts as "optional" for Convoy (skips the game's own re-check).
 *  2. Mod fingerprint cache: Convoy hashes every file of every mod into a 64-bit fingerprint
 *     per mod and keeps it in memory only. This plugin saves the fingerprints after the game
 *     computes them and puts them back before the game decides what to hash, so the wait
 *     only happens for mods that are new or changed (file count/size/time, plus game exe).
 *  3. Fast lookups for loose-folder mods: the game asks every mounted mod for every file it
 *     looks up; for mods stored as loose folders (most Steam Workshop items) each question is a
 *     real file system call. Missing files are answered from an in-memory listing instead.
 *  Diagnostics (off unless a switch file sits next to the DLL): one-shot stack sampler
 *  (ConvoyHelper.sample.on) and file access recorder (ConvoyHelper.iotrace.on).
 *
 * Log:   %LOCALAPPDATA%\ETS2ConvoyHelperData\plugin.log
 * Cache: %LOCALAPPDATA%\ETS2ConvoyHelperData\mod_hash_cache.txt
 *
 * Build: build.cmd  (zig cc -target x86_64-windows-gnu -shared -O2 ... -lshell32 -lwinmm)
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ---------------- SCS SDK (minimal) ---------------- */
typedef void (__stdcall *scs_log_t)(int type, const char *msg);
typedef struct {
    const char *game_name;
    const char *game_id;
    uint32_t game_version;
    uint32_t _pad;
    scs_log_t log;
} scs_common_params_t;

/* ---------------- logging ---------------- */
static wchar_t g_dir[MAX_PATH];
static wchar_t g_logPath[MAX_PATH], g_cachePath[MAX_PATH], g_cacheTmp[MAX_PATH];
static scs_log_t g_gameLog;
static CRITICAL_SECTION g_logLock;

static void logf(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    EnterCriticalSection(&g_logLock);
    FILE *f = _wfopen(g_logPath, L"ab");
    if (f) {
        SYSTEMTIME t; GetLocalTime(&t);
        fprintf(f, "[%02d:%02d:%02d] %s\r\n", t.wHour, t.wMinute, t.wSecond, buf);
        fclose(f);
    }
    LeaveCriticalSection(&g_logLock);
}
static void gamelog(const char *fmt, ...) { /* main thread only */
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    logf("%s", buf);
    if (g_gameLog) { char b2[1100]; snprintf(b2, sizeof b2, "[ConvoyHelper] %s", buf); g_gameLog(0, b2); }
}

/* ---------------- module scan ---------------- */
static uint8_t *g_base; static size_t g_textOff, g_textLen;

static int find_sig(const int16_t *sig, int n, size_t start, size_t *out) {
    const uint8_t *d = g_base + g_textOff;
    for (size_t i = start; i + n <= g_textLen; i++) {
        if (d[i] != (uint8_t)sig[0]) continue;
        int j = 1;
        for (; j < n; j++) if (sig[j] >= 0 && d[i + j] != (uint8_t)sig[j]) break;
        if (j == n) { *out = i; return 1; }
    }
    return 0;
}
/* unique match -> address, else NULL */
static uint8_t *find_unique(const int16_t *sig, int n) {
    size_t a, b;
    if (!find_sig(sig, n, 0, &a)) return NULL;
    if (find_sig(sig, n, a + 1, &b)) return NULL;
    return g_base + g_textOff + a;
}
static uint8_t *rel32(uint8_t *insn, int dispOff, int len) { return insn + len + *(int32_t *)(insn + dispOff); }
#define SIG(...) ((const int16_t[]){__VA_ARGS__}), (int)(sizeof((const int16_t[]){__VA_ARGS__}) / sizeof(int16_t))
#define X -1

static void patch_bytes(uint8_t *at, const void *src, size_t n) {
    DWORD old; VirtualProtect(at, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(at, src, n);
    VirtualProtect(at, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, n);
}
static void put_jmp(uint8_t *at, const void *dst) { /* 14 bytes: jmp [rip+0]; dq dst */
    at[0] = 0xFF; at[1] = 0x25; *(uint32_t *)(at + 2) = 0; *(uint64_t *)(at + 6) = (uint64_t)dst;
}
/* replace the first `stolen` bytes (relocatable instructions only) with a jump to hook */
static void *detour(uint8_t *target, int stolen, void *hook) {
    uint8_t *t = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!t) return NULL;
    memcpy(t, target, stolen); put_jmp(t + stolen, target + stolen);
    uint8_t j[32]; memset(j, 0x90, sizeof j); put_jmp(j, hook);
    patch_bytes(target, j, stolen);
    return t;
}

/* ---------------- part 1: optional patch ---------------- */
static void optional_patch(void) {
    /* movzx r12d,[rbx+0x200]; and al,1; mov [rsp+?],al; test r13b,r13b; je ?; test r12b,r12b; je ? */
    uint8_t *p = find_unique(SIG(0x44,0x0F,0xB6,0xA3,0x00,0x02,0x00,0x00, 0x24,0x01, 0x88,0x44,0x24,X,
                                 0x45,0x84,0xED, 0x0F,0x84,X,X,X,X, 0x45,0x84,0xE4, 0x0F,0x84,X,X,X,X));
    if (!p) { gamelog("optional patch: code not found (different game version?) - skipped"); return; }
    static const uint8_t a[8] = { 0x41,0xBC,0x01,0x00,0x00,0x00,0x66,0x90 };   /* mov r12d,1 */
    uint8_t *je = p + 0x17 + 3;
    uint8_t *target = rel32(je, 2, 6);
    uint8_t b[9] = { 0xE9 };                                                     /* jmp past re-check */
    *(int32_t *)(b + 1) = (int32_t)(target - (p + 0x17 + 5));
    memset(b + 5, 0x90, 4);
    patch_bytes(p, a, 8); patch_bytes(p + 0x17, b, 9);
    gamelog("optional patch: all mods count as optional for Convoy");
}

/* ---------------- part 2: fingerprint cache ---------------- */
typedef int64_t (*lookup_t)(void *hasher, void *key);            /* -> fingerprint or -1 */
typedef char    (*insert_t)(void *table, void *key, uint64_t *v);
typedef uint64_t (*collect_t)(void *mgr, void *list, void *p3, uint64_t p4);
typedef char    (*drive_t)(int64_t *hasher, int64_t *deadline);

static uint8_t **g_mgrGlobal, **g_coreGlobal;
static lookup_t g_lookup;
static collect_t g_collectOrig;
static drive_t g_driveOrig;

#define MAXE 4096
typedef struct { char name[320]; uint64_t hash; char sig[64]; char cur[64]; int curDone; int have; } entry_t;
static entry_t *g_e; static int g_n;
static char g_stamp[64];
static wchar_t g_steamapps[MAX_PATH], g_docsMod[MAX_PATH];
static HANDLE g_sigThread;
static int g_dirty;

static entry_t *entry_get(const char *name, int create) {
    for (int i = 0; i < g_n; i++) if (!strcmp(g_e[i].name, name)) return &g_e[i];
    if (!create || g_n >= MAXE || strlen(name) >= sizeof g_e[0].name) return NULL;
    entry_t *e = &g_e[g_n++]; memset(e, 0, sizeof *e); strcpy(e->name, name); return e;
}

static int path_for(const char *name, wchar_t *out) {
    static const char ws[] = "mod_workshop_package.";
    if (!strncmp(name, ws, sizeof ws - 1)) {
        uint64_t id = _strtoui64(name + sizeof ws - 1, NULL, 16);
        if (!id) return 0;
        swprintf(out, MAX_PATH, L"%ls\\workshop\\content\\227300\\%llu", g_steamapps, (unsigned long long)id);
        DWORD a = GetFileAttributesW(out);
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }
    wchar_t wn[320];
    if (!MultiByteToWideChar(CP_UTF8, 0, name, -1, wn, 320)) return 0;
    static const wchar_t *ext[] = { L".scs", L".zip", L"" };
    for (int i = 0; i < 3; i++) {
        swprintf(out, MAX_PATH, L"%ls\\%ls%ls", g_docsMod, wn, ext[i]);
        DWORD a = GetFileAttributesW(out);
        if (a == INVALID_FILE_ATTRIBUTES) continue;
        if (i < 2 && !(a & FILE_ATTRIBUTE_DIRECTORY)) return 1;
        if (i == 2 && (a & FILE_ATTRIBUTE_DIRECTORY)) return 1;
    }
    return 0;
}

static void walk(const wchar_t *dir, uint64_t *n, uint64_t *size, uint64_t *newest) {
    wchar_t pat[MAX_PATH * 2]; swprintf(pat, MAX_PATH * 2, L"%ls\\*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pat, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' && (!fd.cFileName[1] || (fd.cFileName[1] == L'.' && !fd.cFileName[2]))) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            wchar_t sub[MAX_PATH * 2]; swprintf(sub, MAX_PATH * 2, L"%ls\\%ls", dir, fd.cFileName);
            walk(sub, n, size, newest);
        } else {
            (*n)++;
            *size += ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            uint64_t t = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
            if (t > *newest) *newest = t;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* signature of a mod's files on disk: count:size:newest-write-time */
static void compute_sig(entry_t *e) {
    if (e->curDone) return;
    e->curDone = 1; e->cur[0] = 0;
    wchar_t p[MAX_PATH];
    if (!path_for(e->name, p)) return;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(p, GetFileExInfoStandard, &fa)) return;
    uint64_t n = 0, size = 0, newest = 0;
    if (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) walk(p, &n, &size, &newest);
    else {
        n = 1; size = ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
        newest = ((uint64_t)fa.ftLastWriteTime.dwHighDateTime << 32) | fa.ftLastWriteTime.dwLowDateTime;
    }
    snprintf(e->cur, sizeof e->cur, "%llu:%llu:%llu", (unsigned long long)n, (unsigned long long)size, (unsigned long long)newest);
}

static DWORD WINAPI sig_thread(LPVOID unused) {
    (void)unused;
    DWORD t0 = GetTickCount();
    for (int i = 0; i < g_n; i++) compute_sig(&g_e[i]);
    logf("checked %d cached mods on disk in %lu ms", g_n, GetTickCount() - t0);
    return 0;
}

static wchar_t g_oldCachePath[MAX_PATH];
static void load_cache(void) {
    FILE *f = _wfopen(g_cachePath, L"rb");
    if (!f && g_oldCachePath[0] && (f = _wfopen(g_oldCachePath, L"rb"))) { logf("using the cache from the old folder"); g_dirty = 1; }
    if (!f) { logf("no cache file yet"); return; }
    char line[1024]; int ok = 0, n = 0;
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *tab = strchr(line, '\t');
        ok = !strncmp(line, "ETS2ConvoyHelper 1", 18) && tab && !strcmp(tab + 1, g_stamp);
    }
    if (!ok) { logf("cache made for a different game exe: starting fresh"); fclose(f); return; }
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *t1 = strchr(line, '\t'); if (!t1) continue; *t1++ = 0;
        char *t2 = strchr(t1, '\t'); if (!t2) continue; *t2++ = 0;
        entry_t *e = entry_get(line, 1); if (!e) continue;
        e->hash = _strtoui64(t1, NULL, 16); snprintf(e->sig, sizeof e->sig, "%s", t2); e->have = 1; n++;
    }
    fclose(f);
    logf("loaded %d cached fingerprints", n);
}

static void save_cache(void) {
    FILE *f = _wfopen(g_cacheTmp, L"wb");
    if (!f) { logf("cannot write cache"); return; }
    fprintf(f, "ETS2ConvoyHelper 1\t%s\n", g_stamp);
    int n = 0;
    for (int i = 0; i < g_n; i++) if (g_e[i].have) { fprintf(f, "%s\t%016llX\t%s\n", g_e[i].name, (unsigned long long)g_e[i].hash, g_e[i].sig); n++; }
    fclose(f);
    MoveFileExW(g_cacheTmp, g_cachePath, MOVEFILE_REPLACE_EXISTING);
    g_dirty = 0;
    logf("saved cache (%d fingerprints)", n);
}

/* active packages: [[core]+0x12d0] -> {+0x128 array, +0x130 count}; key = pkg+0x10, name = *(char**)(pkg+0x18) */
static int packages(uint8_t ***arr) {
    uint8_t *core = *g_coreGlobal; if (!core) return 0;
    uint8_t *lst = *(uint8_t **)(core + 0x12d0); if (!lst) return 0;
    *arr = *(uint8_t ***)(lst + 0x128);
    int64_t c = *(int64_t *)(lst + 0x130);
    return (*arr && c > 0 && c < 5000) ? (int)c : 0;
}
static uint8_t *root_hasher(void) {
    uint8_t *m = *g_mgrGlobal; return m ? *(uint8_t **)(m + 0x738) : NULL;
}

/* before the game picks which mods to hash: put back cached fingerprints */
static void restore(void) {
    uint8_t *root = root_hasher(); if (!root) return;
    WaitForSingleObject(g_sigThread, INFINITE);
    uint8_t **arr; int c = packages(&arr);
    void *table = root + 0x88;
    insert_t ins = (insert_t)(*(void ***)table)[0xF8 / 8];
    int restored = 0, stale = 0;
    for (int i = 0; i < c; i++) {
        uint8_t *pkg = arr[i]; if (!pkg) continue;
        const char *name = *(const char **)(pkg + 0x18); if (!name) continue;
        entry_t *e = entry_get(name, 0);
        if (!e || !e->have) continue;
        if (g_lookup(root, pkg + 0x10) != -1) continue;
        compute_sig(e);
        if (!e->cur[0] || strcmp(e->cur, e->sig)) { if (e->have != 2) { stale++; e->have = 2; } continue; }
        uint64_t v = e->hash;
        if (ins(table, pkg + 0x10, &v)) restored++;
    }
    if (restored || stale)
        gamelog("restored %d cached mod fingerprint(s)%s", restored, stale ? " (some mods changed on disk and will be recomputed)" : "");
}

/* after hashing finished: store new fingerprints */
static void save_sweep(void) {
    uint8_t *root = root_hasher(); if (!root) return;
    WaitForSingleObject(g_sigThread, INFINITE);
    uint8_t **arr; int c = packages(&arr), added = 0;
    for (int i = 0; i < c; i++) {
        uint8_t *pkg = arr[i]; if (!pkg) continue;
        const char *name = *(const char **)(pkg + 0x18); if (!name) continue;
        int64_t v = g_lookup(root, pkg + 0x10);
        if (v == -1) continue;
        entry_t *e = entry_get(name, 0);
        if (e && e->have == 1 && e->hash == (uint64_t)v && e->curDone && !strcmp(e->cur, e->sig)) continue;
        wchar_t p[MAX_PATH]; if (!path_for(name, p)) continue;     /* only mods we can check on disk */
        if (!e) e = entry_get(name, 1);
        if (!e) continue;
        compute_sig(e);
        if (!e->cur[0]) continue;
        if (e->have == 1 && e->hash == (uint64_t)v && !strcmp(e->cur, e->sig)) continue;
        e->hash = (uint64_t)v; strcpy(e->sig, e->cur); e->have = 1; added++; g_dirty = 1;
    }
    if (g_dirty) { save_cache(); gamelog("saved %d new mod fingerprint(s) to the cache", added); }
}

static uint64_t hk_collect(void *mgr, void *list, void *p3, uint64_t p4) {
    if (list) restore();
    return g_collectOrig(mgr, list, p3, p4);
}
static char hk_drive(int64_t *h, int64_t *deadline) {
    int busy = (uint64_t)h[0xc] < (uint64_t)h[3];
    char done = g_driveOrig(h, deadline);
    if (busy && done) save_sweep();
    return done;
}

static void hash_cache_init(void) {
    uint8_t *m = find_unique(SIG(0x48,0x8B,0x0D,X,X,X,X, 0xE8,X,X,X,X, 0x48,0x8B,0x8E,0x40,0x07,0x00,0x00,
                                 0x48,0x8D,0x54,0x24,0x20, 0x45,0x33,0xC0, 0xE8));
    uint8_t *c = find_unique(SIG(0x48,0x8B,0x05,X,X,X,X, 0x33,0xDB, 0x4C,0x8B,0xB8,0xD0,0x12,0x00,0x00,
                                 0x4D,0x8B,0xB7,0x30,0x01,0x00,0x00));
    uint8_t *l = find_unique(SIG(0x49,0x8B,0x8D,0x38,0x07,0x00,0x00, 0x48,0x8B,0xD7, 0xE8,X,X,X,X, 0x48,0x83,0xF8,0xFF));
    uint8_t *col = find_unique(SIG(0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x6C,0x24,0x10, 0x48,0x89,0x74,0x24,0x18, 0x57,
                                   0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57, 0x48,0x83,0xEC,0x40, 0x45,0x0F,0xB6,0xE1,
                                   0x48,0x8B,0xEA, 0x4C,0x8B,0xE9, 0x48,0x85,0xD2));
    uint8_t *drv = find_unique(SIG(0x40,0x53,0x55,0x57, 0x48,0x81,0xEC,0x90,0x00,0x00,0x00, 0x48,0x8B,0x59,0x60,
                                   0x48,0x8B,0xEA, 0x48,0x8B,0xF9, 0x48,0x3B,0x59,0x18));
    if (!m || !c || !l || !col || !drv) {
        gamelog("fingerprint cache: game code not found (different game version?) - disabled [%d%d%d%d%d]", !!m, !!c, !!l, !!col, !!drv);
        return;
    }
    g_mgrGlobal = (uint8_t **)rel32(m, 3, 7);
    g_coreGlobal = (uint8_t **)rel32(c, 3, 7);
    g_lookup = (lookup_t)rel32(l + 10, 1, 5);

    /* paths and exe stamp */
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fa; GetFileAttributesExW(exe, GetFileExInfoStandard, &fa);
    snprintf(g_stamp, sizeof g_stamp, "%lu:%llu", fa.nFileSizeLow,
             ((unsigned long long)fa.ftLastWriteTime.dwHighDateTime << 32) | fa.ftLastWriteTime.dwLowDateTime);

    g_e = calloc(MAXE, sizeof(entry_t));
    if (!g_e) return;
    load_cache();
    g_sigThread = CreateThread(NULL, 0, sig_thread, NULL, 0, NULL);

    g_collectOrig = (collect_t)detour(col, 15, (void *)hk_collect);
    g_driveOrig = (drive_t)detour(drv, 15, (void *)hk_drive);
    if (!g_collectOrig || !g_driveOrig) { gamelog("fingerprint cache: hook failed"); return; }
    gamelog("fingerprint cache: on (%d saved fingerprints)", g_n);
}

/* ---------------- one-shot load sampler ----------------
 * Runs only when plugins\ConvoyHelper.sample.on exists next to this DLL (deleted at start).
 * Every 2 ms: suspend the game's main thread, read its registers, walk its call stack with the
 * modules' unwind tables (no locks, no allocation while suspended), resume. 8 minutes max.
 * Output: samples.bin  = records { u32 ms_since_process_start; u32 tid; u32 depth; u64 addr[depth] }
 *         samples_modules.txt = base size path  (for mapping addresses)                       */
#include <tlhelp32.h>
#include <timeapi.h>
typedef struct { uint64_t base, size; RUNTIME_FUNCTION *rf; DWORD nrf; wchar_t path[MAX_PATH]; } smod_t;
static smod_t g_sm[600]; static int g_nsm;
static wchar_t g_samplePath[MAX_PATH], g_sampleMods[MAX_PATH];

static void s_modules(void) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (s == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me; me.dwSize = sizeof me; int n = 0;
    if (Module32FirstW(s, &me)) do {
        if (n >= 600) break;
        smod_t *m = &g_sm[n]; m->base = (uint64_t)me.modBaseAddr; m->size = me.modBaseSize;
        wcsncpy(m->path, me.szExePath, MAX_PATH - 1); m->path[MAX_PATH - 1] = 0;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(me.modBaseAddr + ((IMAGE_DOS_HEADER *)me.modBaseAddr)->e_lfanew);
        IMAGE_DATA_DIRECTORY *d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        m->rf = d->Size ? (RUNTIME_FUNCTION *)(me.modBaseAddr + d->VirtualAddress) : NULL;
        m->nrf = d->Size / sizeof(RUNTIME_FUNCTION);
        n++;
    } while (Module32NextW(s, &me));
    CloseHandle(s);
    g_nsm = n;
    if (g_sampleMods[0]) {
        FILE *mf = _wfopen(g_sampleMods, L"wb");
        if (mf) {
            for (int i = 0; i < g_nsm; i++) {
                char pth[MAX_PATH * 3]; WideCharToMultiByte(CP_UTF8, 0, g_sm[i].path, -1, pth, sizeof pth, NULL, NULL);
                fprintf(mf, "%llx %llx %s\n", (unsigned long long)g_sm[i].base, (unsigned long long)g_sm[i].size, pth);
            }
            fclose(mf);
        }
    }
}
static smod_t *s_mod(uint64_t pc) {
    for (int i = 0; i < g_nsm; i++) if (pc - g_sm[i].base < g_sm[i].size) return &g_sm[i];
    return NULL;
}
static RUNTIME_FUNCTION *s_rf(smod_t *m, uint64_t pc) {
    if (!m->rf) return NULL;
    DWORD rva = (DWORD)(pc - m->base); long lo = 0, hi = (long)m->nrf - 1;
    while (lo <= hi) {
        long mid = (lo + hi) / 2; RUNTIME_FUNCTION *f = &m->rf[mid];
        if (rva < f->BeginAddress) hi = mid - 1; else if (rva >= f->EndAddress) lo = mid + 1; else return f;
    }
    return NULL;
}
#define SMAXD 28
/* read memory without risking an access violation (fails instead) */
static int s_read(uint64_t a, void *out, size_t n) {
    SIZE_T r = 0;
    return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)a, out, n, &r) && r == n;
}
static int s_walk(HANDLE th, uint64_t lo, uint64_t hi, uint64_t *out) {
    CONTEXT c; memset(&c, 0, sizeof c); c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(th, &c)) return 0;
    int d = 0; out[d++] = c.Rip;
    while (d < SMAXD) {
        if (c.Rsp < lo || c.Rsp + 64 > hi) break;
        smod_t *m = s_mod(c.Rip); if (!m) break;
        RUNTIME_FUNCTION *f = s_rf(m, c.Rip);
        if (f) {
            PVOID hd; DWORD64 ef;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, m->base, c.Rip, f, &c, &hd, &ef, NULL);
        } else { if (!s_read(c.Rsp, &c.Rip, 8)) break; c.Rsp += 8; }   /* leaf */
        if (c.Rip < 0x10000) break;
        out[d++] = c.Rip;
    }
    return d;
}
static uint64_t s_now_ms(uint64_t created) {
    FILETIME n; GetSystemTimePreciseAsFileTime(&n);
    return ((((uint64_t)n.dwHighDateTime << 32) | n.dwLowDateTime) - created) / 10000;
}
/* every thread of the process that used CPU since the last tick gets sampled */
typedef LONG (NTAPI *NtQIT_t)(HANDLE, int, PVOID, ULONG, PULONG);
typedef struct { DWORD tid; HANDLE h; uint64_t teb, start, cycles; int alive; } sthr_t;
static sthr_t g_th[1024]; static int g_nth;
static wchar_t g_sampleThreads[MAX_PATH];

static void s_threads(NtQIT_t qit, DWORD self) {
    for (int i = 0; i < g_nth; i++) g_th[i].alive = 0;
    DWORD pid = GetCurrentProcessId();
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof te;
    if (s != INVALID_HANDLE_VALUE && Thread32First(s, &te)) do {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
        int k = -1;
        for (int i = 0; i < g_nth; i++) if (g_th[i].tid == te.th32ThreadID) { k = i; break; }
        if (k < 0) {
            if (g_nth >= 1024) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) continue;
            struct { LONG st; PVOID teb; HANDLE cid_pid, cid_tid; ULONG_PTR aff; LONG pri, bpri; } tbi;
            uint64_t start = 0;
            if (qit(h, 0, &tbi, sizeof tbi, NULL) < 0) { CloseHandle(h); continue; }
            qit(h, 9, &start, sizeof start, NULL);               /* ThreadQuerySetWin32StartAddress */
            k = g_nth++;
            g_th[k].tid = te.th32ThreadID; g_th[k].h = h; g_th[k].teb = (uint64_t)tbi.teb; g_th[k].start = start;
            QueryThreadCycleTime(h, &g_th[k].cycles);
        }
        g_th[k].alive = 1;
    } while (Thread32Next(s, &te));
    if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
    FILE *tf = _wfopen(g_sampleThreads, L"wb");
    if (tf) { for (int i = 0; i < g_nth; i++) fprintf(tf, "%lu %llx\n", g_th[i].tid, (unsigned long long)g_th[i].start); fclose(tf); }
}

static DWORD WINAPI sampler_thread(LPVOID unused) {
    (void)unused;
    NtQIT_t qit = (NtQIT_t)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!qit) { logf("sampler: no NtQueryInformationThread"); return 0; }
    DWORD self = GetCurrentThreadId();
    FILETIME cr, ex, k, u; GetProcessTimes(GetCurrentProcess(), &cr, &ex, &k, &u);
    uint64_t created = ((uint64_t)cr.dwHighDateTime << 32) | cr.dwLowDateTime;

    FILE *f = _wfopen(g_samplePath, L"wb");
    if (!f) { logf("sampler: cannot write output"); return 0; }
    s_modules(); s_threads(qit, self);
    logf("sampler: all busy threads (%d now), recording 8 minutes", g_nth);
    static uint64_t addr[SMAXD];
    uint64_t start = s_now_ms(created), lastRefresh = start, n = 0;
    const uint64_t minCycles = 200000;   /* ~0.05-0.1 ms of CPU since the last tick */
    for (;;) {
        uint64_t t = s_now_ms(created);
        if (t - start > 8 * 60 * 1000) break;
        if (t - lastRefresh > 2000) { s_modules(); s_threads(qit, self); lastRefresh = t; }
        for (int i = 0; i < g_nth; i++) {
            sthr_t *x = &g_th[i]; if (!x->alive) continue;
            uint64_t cyc = 0; if (!QueryThreadCycleTime(x->h, &cyc)) { x->alive = 0; continue; }
            uint64_t dc = cyc - x->cycles; x->cycles = cyc;
            if (dc < minCycles) continue;                       /* idle since last tick */
            /* pause first, then make sure the thread is still alive before touching its TEB:
               a thread that exited since the last refresh has a freed TEB */
            if (SuspendThread(x->h) == (DWORD)-1) { x->alive = 0; continue; }
            DWORD ec = 0; uint64_t tib[3];
            if (!GetExitCodeThread(x->h, &ec) || ec != STILL_ACTIVE || !s_read(x->teb, tib, sizeof tib)) {
                ResumeThread(x->h); x->alive = 0; continue;
            }
            int d = s_walk(x->h, tib[2], tib[1], addr);            /* NT_TIB StackLimit / StackBase */
            ResumeThread(x->h);
            if (d) {
                uint32_t hd[3] = { (uint32_t)t, x->tid, (uint32_t)d };
                fwrite(hd, 4, 3, f); fwrite(addr, 8, d, f); n++;
            }
        }
        Sleep(3);
    }
    fclose(f);
    s_modules();
    for (int i = 0; i < g_nth; i++) CloseHandle(g_th[i].h);
    logf("sampler: done, %llu samples", (unsigned long long)n);
    return 0;
}
static void sampler_maybe_start(void) {
    /* switch file sits next to this DLL: plugins\ConvoyHelper.sample.on */
    wchar_t flag[MAX_PATH]; HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(void *)sampler_maybe_start, &self);
    if (!GetModuleFileNameW(self, flag, MAX_PATH)) return;
    wchar_t *sl = wcsrchr(flag, L'\\'); if (!sl) return;
    wcscpy(sl + 1, L"ConvoyHelper.sample.on");
    if (GetFileAttributesW(flag) == INVALID_FILE_ATTRIBUTES) return;
    if (!DeleteFileW(flag)) { gamelog("load sampler: cannot remove the switch file - not sampling"); return; }
    swprintf(g_samplePath, MAX_PATH, L"%ls\\samples.bin", g_dir);
    swprintf(g_sampleMods, MAX_PATH, L"%ls\\samples_modules.txt", g_dir);
    swprintf(g_sampleThreads, MAX_PATH, L"%ls\\samples_threads.txt", g_dir);
    timeBeginPeriod(1);
    HANDLE t = CreateThread(NULL, 0, sampler_thread, NULL, 0, NULL);
    if (t) { SetThreadPriority(t, THREAD_PRIORITY_TIME_CRITICAL); CloseHandle(t); }
    gamelog("load sampler started (one-shot)");
}

/* ---------------- one-shot file access recorder ----------------
 * Runs only when plugins\ConvoyHelper.iotrace.on exists (deleted at start). For 7 minutes it counts
 * the game's CreateFileW / GetFileAttributesExW calls (through the exe's import table), grouped by
 * folder (first 7 path parts, e.g. ...\workshop\content\227300\<id> or ...\mod\<name>), with time
 * spent and how many found nothing. Writes iotrace.txt every 10 s. Changes no results.          */
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *GetFileAttributesExW_t)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
static CreateFileW_t o_CreateFileW; static GetFileAttributesExW_t o_GFAEx;
static int g_fastOn;
static void **g_slotCF, **g_slotGA;
#define IOB 8192
typedef struct { uint32_t used; wchar_t key[192]; uint64_t cf, cfMiss, ga, gaMiss, ticks; wchar_t ex[2][200]; int nex; } iob_t;
static iob_t *g_iob; static SRWLOCK g_ioLock = SRWLOCK_INIT; static volatile LONG g_ioOn;
static uint64_t g_ioTotal; static wchar_t g_ioPath[MAX_PATH];

static void io_note(LPCWSTR p, int kind, int miss, uint64_t dt) {
    if (!g_ioOn || !p) return;
    wchar_t key[192]; int seps = 0, i = 0; uint32_t h = 2166136261u;
    for (; p[i] && i < 191; i++) {
        wchar_t c = p[i] == L'/' ? L'\\' : p[i];
        if (c == L'\\' && ++seps == 8) break;
        if (c >= L'A' && c <= L'Z') c += 32;
        key[i] = c; h = (h ^ c) * 16777619u;
    }
    key[i] = 0;
    AcquireSRWLockExclusive(&g_ioLock);
    g_ioTotal++;
    for (uint32_t k = 0; k < IOB; k++) {
        iob_t *b = &g_iob[(h + k) & (IOB - 1)];
        if (b->used && wcscmp(b->key, key)) continue;
        if (!b->used) { b->used = 1; wcscpy(b->key, key); }
        if (kind == 0) { b->cf++; b->cfMiss += miss; } else { b->ga++; b->gaMiss += miss; }
        b->ticks += dt;
        if (b->nex < 2 && miss) { wcsncpy(b->ex[b->nex], p, 199); b->ex[b->nex][199] = 0; b->nex++; }
        break;
    }
    ReleaseSRWLockExclusive(&g_ioLock);
}
static HANDLE WINAPI hk_CreateFileW(LPCWSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD c, DWORD f, HANDLE t) {
    LARGE_INTEGER t0, t1; QueryPerformanceCounter(&t0);
    HANDLE r = o_CreateFileW(p, a, s, sa, c, f, t);
    DWORD e = GetLastError();
    QueryPerformanceCounter(&t1); io_note(p, 0, r == INVALID_HANDLE_VALUE, t1.QuadPart - t0.QuadPart);
    SetLastError(e); return r;
}
static BOOL WINAPI hk_GFAEx(LPCWSTR p, GET_FILEEX_INFO_LEVELS l, LPVOID o) {
    LARGE_INTEGER t0, t1; QueryPerformanceCounter(&t0);
    BOOL r = o_GFAEx(p, l, o);
    DWORD e = GetLastError();
    QueryPerformanceCounter(&t1); io_note(p, 1, !r, t1.QuadPart - t0.QuadPart);
    SetLastError(e); return r;
}
static void **iat_slot(const char *fn) {
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_base + ((IMAGE_DOS_HEADER *)g_base)->e_lfanew);
    IMAGE_DATA_DIRECTORY *d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR *id = (IMAGE_IMPORT_DESCRIPTOR *)(g_base + d->VirtualAddress); id->Name; id++) {
        if (!id->OriginalFirstThunk) continue;
        IMAGE_THUNK_DATA *oft = (IMAGE_THUNK_DATA *)(g_base + id->OriginalFirstThunk), *ft = (IMAGE_THUNK_DATA *)(g_base + id->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME *ib = (IMAGE_IMPORT_BY_NAME *)(g_base + oft->u1.AddressOfData);
            if (!strcmp((const char *)ib->Name, fn)) return (void **)&ft->u1.Function;
        }
    }
    return NULL;
}
static void set_slot(void **slot, void *v) { patch_bytes((uint8_t *)slot, &v, sizeof v); }
static int io_cmp(const void *a, const void *b) {
    uint64_t x = (*(iob_t *const *)a)->ticks, y = (*(iob_t *const *)b)->ticks; return x < y ? 1 : x > y ? -1 : 0;
}
static void io_report(void) {
    static iob_t *list[IOB]; int n = 0;
    LARGE_INTEGER fq; QueryPerformanceFrequency(&fq);
    AcquireSRWLockShared(&g_ioLock);
    for (int i = 0; i < IOB; i++) if (g_iob[i].used) list[n++] = &g_iob[i];
    qsort(list, n, sizeof list[0], io_cmp);
    FILE *f = _wfopen(g_ioPath, L"wb");
    if (f) {
        uint64_t all = 0; for (int i = 0; i < n; i++) all += list[i]->ticks;
        fprintf(f, "calls %llu, total time in these calls %.1f s, folders %d\n", (unsigned long long)g_ioTotal, (double)all / fq.QuadPart, n);
        fprintf(f, "ms\topen\topen_missing\tattr\tattr_missing\tfolder\texamples(missing)\n");
        for (int i = 0; i < n && i < 400; i++) {
            iob_t *b = list[i]; char k[600], e0[600] = "", e1[600] = "";
            WideCharToMultiByte(CP_UTF8, 0, b->key, -1, k, sizeof k, NULL, NULL);
            if (b->nex > 0) WideCharToMultiByte(CP_UTF8, 0, b->ex[0], -1, e0, sizeof e0, NULL, NULL);
            if (b->nex > 1) WideCharToMultiByte(CP_UTF8, 0, b->ex[1], -1, e1, sizeof e1, NULL, NULL);
            fprintf(f, "%.0f\t%llu\t%llu\t%llu\t%llu\t%s\t%s | %s\n", 1000.0 * b->ticks / fq.QuadPart,
                    (unsigned long long)b->cf, (unsigned long long)b->cfMiss, (unsigned long long)b->ga, (unsigned long long)b->gaMiss, k, e0, e1);
        }
        fclose(f);
    }
    ReleaseSRWLockShared(&g_ioLock);
}
static DWORD WINAPI io_thread(LPVOID unused) {
    (void)unused;
    for (int s = 0; s < 7 * 60; s += 10) { Sleep(10000); io_report(); }
    InterlockedExchange(&g_ioOn, 0);
    if (!g_fastOn) { set_slot(g_slotCF, (void *)o_CreateFileW); set_slot(g_slotGA, (void *)o_GFAEx); }
    io_report();
    logf("file access recorder: done, %llu calls", (unsigned long long)g_ioTotal);
    return 0;
}
static int take_flag(const wchar_t *name) {   /* plugins\<name> next to this DLL; deleted when found */
    wchar_t flag[MAX_PATH]; HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(void *)take_flag, &self);
    if (!GetModuleFileNameW(self, flag, MAX_PATH)) return 0;
    wchar_t *sl = wcsrchr(flag, L'\\'); if (!sl) return 0;
    wcscpy(sl + 1, name);
    if (GetFileAttributesW(flag) == INVALID_FILE_ATTRIBUTES) return 0;
    if (!DeleteFileW(flag)) { gamelog("cannot remove %ls - not starting", name); return 0; }
    return 1;
}
static void iotrace_maybe_start(void) {
    if (!take_flag(L"ConvoyHelper.iotrace.on")) return;
    g_iob = calloc(IOB, sizeof(iob_t)); if (!g_iob) return;
    swprintf(g_ioPath, MAX_PATH, L"%ls\\iotrace.txt", g_dir);
    if (g_fastOn) InterlockedExchange(&g_ioOn, 1);           /* the fast-lookup hooks feed the recorder */
    else {
        g_slotCF = iat_slot("CreateFileW"); g_slotGA = iat_slot("GetFileAttributesExW");
        if (!g_slotCF || !g_slotGA) { gamelog("file access recorder: imports not found"); return; }
        o_CreateFileW = (CreateFileW_t)*g_slotCF; o_GFAEx = (GetFileAttributesExW_t)*g_slotGA;
        InterlockedExchange(&g_ioOn, 1);
        set_slot(g_slotCF, (void *)hk_CreateFileW); set_slot(g_slotGA, (void *)hk_GFAEx);
    }
    HANDLE t = CreateThread(NULL, 0, io_thread, NULL, 0, NULL); if (t) CloseHandle(t);
    gamelog("file access recorder started (one-shot)");
}

/* ---------------- part 3: fast "file not found" for loose-folder mods ----------------
 * The game asks every mounted mod for every file it looks up. For mods stored as loose folders
 * (most Steam Workshop items) each question is a real CreateFileW / GetFileAttributesExW call,
 * ~144k per mod per load, >99% answered "not found". On first touch of a folder mod root
 * (...\workshop\content\227300\<id> or ...\mod\<name>) we list its files once; afterwards a
 * read-only lookup of a path that is not in the list fails at once without a system call.
 * Anything that exists, or any write/create, goes to Windows as before.
 * The index stores 64-bit path hashes: a collision can only make us ask Windows (safe).
 * Disable by putting a file named ConvoyHelper.nofastfs next to the DLL.                       */
typedef struct { uint64_t *h; uint32_t cap, n; } hset_t;
typedef struct { wchar_t root[MAX_PATH]; int rootLen; hset_t set; int ok; } froot_t;
static froot_t *g_fr; static int g_nfr; static SRWLOCK g_frLock = SRWLOCK_INIT;
static wchar_t g_wsPrefix[MAX_PATH], g_modPrefix[MAX_PATH]; static int g_wsLen, g_modLen;
static volatile LONG64 g_fastSkipped, g_fastPassed;

static uint64_t fnv64(const wchar_t *s, int n) {
    uint64_t h = 1469598103934665603ull;
    for (int i = 0; i < n; i++) { wchar_t c = s[i] == L'/' ? L'\\' : s[i]; if (c >= L'A' && c <= L'Z') c += 32; h = (h ^ c) * 1099511628211ull; }
    return h ? h : 1;
}
static void hs_add(hset_t *s, uint64_t h) {
    if ((s->n + 1) * 2 > s->cap) {
        uint32_t nc = s->cap ? s->cap * 2 : 1024; uint64_t *nh = calloc(nc, 8); if (!nh) return;
        for (uint32_t i = 0; i < s->cap; i++) if (s->h[i]) { uint32_t k = (uint32_t)s->h[i] & (nc - 1); while (nh[k]) k = (k + 1) & (nc - 1); nh[k] = s->h[i]; }
        free(s->h); s->h = nh; s->cap = nc;
    }
    uint32_t k = (uint32_t)h & (s->cap - 1);
    while (s->h[k]) { if (s->h[k] == h) return; k = (k + 1) & (s->cap - 1); }
    s->h[k] = h; s->n++;
}
static int hs_has(const hset_t *s, uint64_t h) {
    if (!s->cap) return 0;
    uint32_t k = (uint32_t)h & (s->cap - 1);
    while (s->h[k]) { if (s->h[k] == h) return 1; k = (k + 1) & (s->cap - 1); }
    return 0;
}
/* add every file and folder below dir, as paths relative to the root ("def\x.sii") */
static int fr_walk(hset_t *s, wchar_t *buf, int rootLen, int len, int depth) {
    if (depth > 40 || len > MAX_PATH * 2 - 8) return 1;
    wcscpy(buf + len, L"\\*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(buf, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    buf[len] = 0;
    if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    int ok = 1;
    do {
        if (fd.cFileName[0] == L'.' && (!fd.cFileName[1] || (fd.cFileName[1] == L'.' && !fd.cFileName[2]))) continue;
        int nl = (int)wcslen(fd.cFileName);
        if (len + 1 + nl >= MAX_PATH * 2 - 8) { ok = 0; continue; }
        buf[len] = L'\\'; wcscpy(buf + len + 1, fd.cFileName);
        hs_add(s, fnv64(buf + rootLen + 1, len + 1 + nl - rootLen - 1));
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            ok &= fr_walk(s, buf, rootLen, len + 1 + nl, depth + 1);
        else if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ok = 0;   /* links: don't trust the list */
        buf[len] = 0;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}
static int prefix_ci(const wchar_t *p, const wchar_t *pre, int n) {
    for (int i = 0; i < n; i++) {
        wchar_t a = p[i] == L'/' ? L'\\' : p[i], b = pre[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (a != b) return 0;
    }
    return 1;
}
/* -1: not ours (ask Windows), 0: certainly missing, 1: present (ask Windows) */
static int fast_lookup(LPCWSTR p) {
    if (!g_fastOn || !p) return -1;
    int base;
    if (g_wsLen && prefix_ci(p, g_wsPrefix, g_wsLen)) base = g_wsLen;
    else if (g_modLen && prefix_ci(p, g_modPrefix, g_modLen)) base = g_modLen;
    else return -1;
    int e = base; while (p[e] && p[e] != L'\\' && p[e] != L'/') e++;
    if (e == base || !p[e] || !p[e + 1]) return -1;                 /* the root itself */
    for (const wchar_t *q = p + e; *q; q++) if (*q == L'.' && (q[-1] == L'\\' || q[-1] == L'/') && (q[1] == L'.' || q[1] == L'\\' || q[1] == L'/' || !q[1])) return -1;
    int rootLen = e;
    froot_t *r = NULL;
    AcquireSRWLockShared(&g_frLock);
    for (int i = 0; i < g_nfr; i++) if (g_fr[i].rootLen == rootLen && prefix_ci(p, g_fr[i].root, rootLen)) { r = &g_fr[i]; break; }
    ReleaseSRWLockShared(&g_frLock);
    if (!r) {
        AcquireSRWLockExclusive(&g_frLock);
        for (int i = 0; i < g_nfr; i++) if (g_fr[i].rootLen == rootLen && prefix_ci(p, g_fr[i].root, rootLen)) { r = &g_fr[i]; break; }
        if (!r && g_nfr < 2048) {
            r = &g_fr[g_nfr];
            memset(r, 0, sizeof *r);
            for (int i = 0; i < rootLen; i++) { wchar_t c = p[i] == L'/' ? L'\\' : p[i]; if (c >= L'A' && c <= L'Z') c += 32; r->root[i] = c; }
            r->rootLen = rootLen;
            DWORD a = GetFileAttributesW(r->root);
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT)) {
                static wchar_t buf[MAX_PATH * 2];
                wcscpy(buf, r->root);
                r->ok = fr_walk(&r->set, buf, rootLen, rootLen, 0) && r->set.cap;
                char rr[MAX_PATH * 3]; WideCharToMultiByte(CP_UTF8, 0, r->root, -1, rr, sizeof rr, NULL, NULL);
                logf("fast lookups: %s -> %u entries%s", rr, r->set.n, r->ok ? "" : " (not used)");
            }
            g_nfr++;
        }
        ReleaseSRWLockExclusive(&g_frLock);
        if (!r) return -1;
    }
    if (!r->ok) return -1;
    /* the relative part must be in plain form, else let Windows decide (it normalizes these) */
    const wchar_t *rel = p + rootLen + 1; int n = (int)wcslen(rel);
    while (n > 0 && (rel[n - 1] == L'\\' || rel[n - 1] == L'/')) n--;            /* "dir\" == "dir" */
    if (n == 0) return -1;
    for (int i = 0; i < n; i++) {
        wchar_t c = rel[i], nx = i + 1 < n ? rel[i + 1] : L'\\';
        int sep = c == L'\\' || c == L'/', nsep = nx == L'\\' || nx == L'/';
        if (sep && nsep) return -1;                                              /* doubled separator */
        if ((c == L'.' || c == L' ') && nsep) return -1;                          /* trailing dot/space in a name */
        if (c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|' || c < 32) return -1;
    }
    return hs_has(&r->set, fnv64(rel, n)) ? 1 : 0;
}
static int parent_known(LPCWSTR p) {   /* for the right error code */
    int n = (int)wcslen(p);
    while (n > 0 && (p[n - 1] == L'\\' || p[n - 1] == L'/')) n--;        /* ignore a trailing separator */
    while (n > 0 && p[n - 1] != L'\\' && p[n - 1] != L'/') n--;          /* cut the last name */
    while (n > 0 && (p[n - 1] == L'\\' || p[n - 1] == L'/')) n--;
    if (n <= 0 || n >= MAX_PATH * 2) return 1;
    wchar_t tmp[MAX_PATH * 2]; memcpy(tmp, p, n * 2); tmp[n] = 0;
    return fast_lookup(tmp) != 0;
}

/* combined hooks (fast lookups + optional recorder) */
static HANDLE WINAPI hk2_CreateFileW(LPCWSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD c, DWORD f, HANDLE t) {
    if (c == OPEN_EXISTING && !(a & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)) && fast_lookup(p) == 0) {
        InterlockedIncrement64(&g_fastSkipped);
        if (g_ioOn) io_note(p, 0, 1, 0);
        SetLastError(parent_known(p) ? ERROR_FILE_NOT_FOUND : ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    InterlockedIncrement64(&g_fastPassed);
    return g_ioOn ? hk_CreateFileW(p, a, s, sa, c, f, t) : o_CreateFileW(p, a, s, sa, c, f, t);
}
static BOOL WINAPI hk2_GFAEx(LPCWSTR p, GET_FILEEX_INFO_LEVELS l, LPVOID o) {
    if (fast_lookup(p) == 0) {
        InterlockedIncrement64(&g_fastSkipped);
        if (g_ioOn) io_note(p, 1, 1, 0);
        SetLastError(parent_known(p) ? ERROR_FILE_NOT_FOUND : ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    InterlockedIncrement64(&g_fastPassed);
    return g_ioOn ? hk_GFAEx(p, l, o) : o_GFAEx(p, l, o);
}
static DWORD WINAPI fast_report_thread(LPVOID unused) {
    (void)unused;
    for (int i = 0; i < 12; i++) {
        Sleep(30000);
        logf("fast lookups: %lld answered without Windows, %lld passed through, %d mod folders indexed",
             (long long)g_fastSkipped, (long long)g_fastPassed, g_nfr);
    }
    return 0;
}
static void fastfs_init(void) {
    wchar_t flag[MAX_PATH]; HMODULE self = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)(void *)fastfs_init, &self);
    if (GetModuleFileNameW(self, flag, MAX_PATH)) {
        wchar_t *sl = wcsrchr(flag, L'\\');
        if (sl) { wcscpy(sl + 1, L"ConvoyHelper.nofastfs"); if (GetFileAttributesW(flag) != INVALID_FILE_ATTRIBUTES) { gamelog("fast lookups: off (ConvoyHelper.nofastfs)"); return; } }
    }
    g_slotCF = iat_slot("CreateFileW"); g_slotGA = iat_slot("GetFileAttributesExW");
    if (!g_slotCF || !g_slotGA) { gamelog("fast lookups: imports not found - off"); return; }
    g_fr = calloc(2048, sizeof(froot_t)); if (!g_fr) return;
    /* <steamapps>\workshop\content\227300\  and  <Documents>\Euro Truck Simulator 2\mod\   (lowercase) */
    if (g_steamapps[0]) { swprintf(g_wsPrefix, MAX_PATH, L"%ls\\workshop\\content\\227300\\", g_steamapps); }
    if (g_docsMod[0])   { swprintf(g_modPrefix, MAX_PATH, L"%ls\\", g_docsMod); }
    for (wchar_t *q = g_wsPrefix; *q; q++) { if (*q == L'/') *q = L'\\'; if (*q >= L'A' && *q <= L'Z') *q += 32; }
    for (wchar_t *q = g_modPrefix; *q; q++) { if (*q == L'/') *q = L'\\'; if (*q >= L'A' && *q <= L'Z') *q += 32; }
    g_wsLen = (int)wcslen(g_wsPrefix); g_modLen = (int)wcslen(g_modPrefix);
    o_CreateFileW = (CreateFileW_t)*g_slotCF; o_GFAEx = (GetFileAttributesExW_t)*g_slotGA;
    g_fastOn = 1;
    set_slot(g_slotCF, (void *)hk2_CreateFileW); set_slot(g_slotGA, (void *)hk2_GFAEx);
    HANDLE t = CreateThread(NULL, 0, fast_report_thread, NULL, 0, NULL); if (t) CloseHandle(t);
    gamelog("fast lookups: on for loose-folder mods");
}

/* ---------------- entry points ---------------- */
__declspec(dllexport) int __stdcall scs_telemetry_init(uint32_t version, const void *params) {
    (void)version;
    static int done;
    if (done) return 0;
    done = 1;
    InitializeCriticalSection(&g_logLock);
    wchar_t la[MAX_PATH];
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", la, MAX_PATH)) wcscpy(la, L".");
    swprintf(g_oldCachePath, MAX_PATH, L"%ls\\ETS2ConvoyHelper\\mod_hash_cache.txt", la);
    swprintf(g_dir, MAX_PATH, L"%ls\\ETS2ConvoyHelperData", la);
    CreateDirectoryW(g_dir, NULL);
    swprintf(g_logPath, MAX_PATH, L"%ls\\plugin.log", g_dir);
    swprintf(g_cachePath, MAX_PATH, L"%ls\\mod_hash_cache.txt", g_dir);
    swprintf(g_cacheTmp, MAX_PATH, L"%ls\\mod_hash_cache.tmp", g_dir);
    DeleteFileW(g_logPath);
    if (params) g_gameLog = ((const scs_common_params_t *)params)->log;

    g_base = (uint8_t *)GetModuleHandleW(NULL);
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_base + ((IMAGE_DOS_HEADER *)g_base)->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
        if (!memcmp(s->Name, ".text", 5)) { g_textOff = s->VirtualAddress; g_textLen = s->Misc.VirtualSize; }
    if (!g_textLen) { gamelog("no .text section?"); return 0; }

    gamelog("ConvoyHelper 1.6 loaded");
    {   /* <steamapps> from the exe path, <Documents>\Euro Truck Simulator 2\mod */
        wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
        wcscpy(g_steamapps, exe);
        for (int up = 0; up < 5; up++) { wchar_t *s = wcsrchr(g_steamapps, L'\\'); if (s) *s = 0; }  /* exe,win_x64,bin,ETS2,common */
        wchar_t docs[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, docs)))
            swprintf(g_docsMod, MAX_PATH, L"%ls\\Euro Truck Simulator 2\\mod", docs);
    }
    optional_patch();
    hash_cache_init();
    fastfs_init();
    sampler_maybe_start();
    iotrace_maybe_start();
    g_gameLog = NULL; /* only use the game's log during init */
    return 0;
}

__declspec(dllexport) void __stdcall scs_telemetry_shutdown(void) {
    if (g_dirty) save_cache();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { (void)h; (void)r; (void)p; return TRUE; }
