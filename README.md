# capa2dbg

**English** · [Türkçe](#türkçe)

x32dbg plugin that turns a [capa](https://github.com/mandiant/capa) verbose JSON report (`capa -vv -j`) into comments, labels, bookmarks, breakpoints, and silent API argument logs — with optional in-debugger capa runs and a SHA256 result cache.

> x32 only for now. ASLR-safe rebasing is included (works whether the image base is `0x400000` or relocated).

---

## Features

| Action | Behavior |
|---|---|
| **Comment** | Every absolute match address (deduped; multiple rules joined with ` \| `) |
| **Label** | Function-scope matches: `capa_<category>_<rule>` (e.g. `capa_proc_create_process_on_Windows`) |
| **Bookmark** | Every matched address |
| **Breakpoint** | Critical namespaces only (configurable allowlist), or all matches via toggle |
| **Arg / ret log** | On critical `call` sites: log stack args at the call, `ret={x:eax}` after the call (silent by default) |
| **Function summary** | Auto-comment on function entry when 2+ capa rules land inside it |
| **Run capa** | Optional: launch `capa.exe -j -vv` on the current target and apply the result |
| **Cache** | Disk cache keyed by target SHA256 — second run is near-instant; stale when `capa.exe` changes |

Comment format (no MITRE/MBC noise):

```text
[capa] create process on Windows | link function at runtime on Windows
```

Log window example after you run the sample:

```text
[capa] CreateProcessW cmd="C:\...\payload.bin"
[capa] CreateProcessW -> ret=0x1
```

---

## Requirements

- [x32dbg](https://x64dbg.com/) (FLARE VM or standalone)
- A capa JSON produced with `-j` (verbose `-vv` recommended so matches include addresses)
- Target PE loaded in the debugger
- Optional: `capa.exe` path in config for **Run capa on current target**

---

## Install

1. Build (or grab a release binary when available):

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

Output: `bin\Release\capa2dbg.dp32`

2. Copy into the x32dbg plugins folder:

```text
<x64dbg>\release\x32\plugins\capa2dbg.dp32
<x64dbg>\release\x32\plugins\capa2dbg.json
```

3. Restart x32dbg. You should see `[capa2dbg] yuklendi` in the Log window.

---

## Usage

1. Open the target PE in **x32dbg**.
2. Apply capa results with one of:
   - **Plugins → capa2dbg → Load capa JSON & Apply**
   - Command: `capa_load <path\to\report.json>`
   - **Run capa on current target** / `capa_run` (needs `capa_path` in config)
3. Inspect comments / labels / bookmarks / BPs. Run the sample and watch **View → Log** for argument dumps.
4. When finished: **Clear all capa marks (undo)**.

### Menu

| Entry | What it does |
|---|---|
| Load capa JSON & Apply | File picker → parse → apply |
| Run capa on current target | Launch capa, use cache if possible |
| Run capa (force, ignore cache) | Always re-analyse |
| Toggle breakpoints: Critical / All | Default = critical namespaces only |
| Toggle arg logging: On / Off | Default = On |
| Toggle log BP: Silent / Break | Default = Silent (does not stop) |
| Toggle cache: On / Off | Session toggle |
| Cache: show info | Entry count, size, directory |
| Cache: clear all | Wipe the disk cache |
| Clear all capa marks (undo) | Remove plugin-owned marks only |
| Show last summary in log | Re-print apply stats |

### Commands

```text
capa_load <path\to\report.json>
capa_run [force|-f]
capa_cache_info
capa_cache_clear
```

---

## Configuration

`capa2dbg.json` (next to the `.dp32`, or under `plugins\config\`):

```json
{
  "capa_path": "",
  "label_category_prefix": true,
  "cache_enabled": true,
  "cache_dir": "",
  "cache_max_mb": 512,
  "cache_adopt_manual": true,
  "breakpoint_namespaces": [
    "host-interaction/process",
    "host-interaction/thread",
    "host-interaction/registry",
    "data-manipulation",
    "persistence",
    "linking/runtime-linking",
    "collection",
    "host-interaction/clipboard",
    "anti-analysis",
    "communication",
    "c2"
  ]
}
```

| Field | Meaning |
|---|---|
| `capa_path` | Absolute path to `capa.exe` (empty = Run capa disabled) |
| `label_category_prefix` | Prefix labels with category (`capa_proc_...`) |
| `cache_enabled` | Persist capa JSON by target SHA256 |
| `cache_dir` | Override cache directory (empty = auto) |
| `cache_max_mb` | LRU prune threshold (default 512) |
| `cache_adopt_manual` | After `capa_load`, store JSON under the target hash |
| `breakpoint_namespaces` | Prefix allowlist for critical BPs |

Matching is **prefix-based**. Rules with `lib: true` never get breakpoints. If the config file is missing, the same allowlist is used as a built-in fallback.

---

## Rebase

capa addresses are absolute VAs relative to `meta.analysis.base_address` (often `0x400000`):

```text
rva     = capa_va - base_address
runtime = GetMainModuleBase() + rva
```

On FLARE with ASLR disabled this is often a no-op; with ASLR enabled the formula still holds.

---

## Cache

`capa_run` can take minutes. Results are stored on disk keyed by the **SHA256 of the target file**, so a second run applies almost instantly. Renamed/copied samples still hit; patched samples correctly miss.

```text
capa2dbg_cache/
  <sha256>.json         raw capa JSON
  <sha256>.meta.json    validation metadata
```

Directory selection (first writable wins):

1. `cache_dir` from config  
2. `<plugin_dir>\capa2dbg_cache\`  
3. `%LOCALAPPDATA%\capa2dbg\cache\`

A cache entry is a **HIT** only when meta parses with `schema: 1`, `target_sha256` matches, the recorded `capa.exe` size/mtime still match, and the payload is non-empty JSON. Anything else is logged as `STALE`, deleted, and re-analysed. Only successfully parsed JSON is ever written — failed capa runs never poison the cache.

```text
[capa2dbg] cache MISS sha=980aad870fa8... -> capa calisiyor
[capa2dbg] cache STORE sha=980aad870fa8... (366785 byte, capa 9.4.0)
[capa2dbg] cache HIT sha=980aad870fa8... (366785 byte)
[capa2dbg] cache STALE (capa.exe degisti) -> yeniden analiz
```

---

## Build

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

- Toolset: MSVC (VS 2022 / Build Tools), C++17, MultiByte  
- Links: `x32bridge.lib`, `x32dbg.lib`, `comdlg32.lib`, `bcrypt.lib`  
- Headers: `pluginsdk/` (x64dbg SDK), `third_party/json.hpp` (nlohmann/json)

### Offline checks

```bat
python tools\validate_capa_json.py path\to\report.json
python tools\cache_sim.py
powershell -ExecutionPolicy Bypass -File tools\smoke_check.ps1
```

Optional: set `CAPA2DBG_SAMPLE_JSON` to a capa report path so `smoke_check.ps1` also validates parsing.

---

## Project layout

```text
capa2dbg/
├── config/capa2dbg.json
├── src/
│   ├── pluginmain.cpp / .h
│   ├── capa_loader.cpp / .h
│   ├── capa_cache.cpp / .h
│   ├── capa_runner.cpp / .h
│   ├── applier.cpp / .h
│   ├── config.cpp / .h
│   ├── api_table.h
│   ├── capa_model.h
│   └── capa2dbg.def
├── pluginsdk/                 x64dbg SDK (headers + x32 libs)
├── third_party/json.hpp
├── tools/
│   ├── validate_capa_json.py
│   ├── cache_sim.py
│   └── smoke_check.ps1
└── capa2dbg.sln
```

---

## License

MIT — see [LICENSE](LICENSE).

---
---

<a id="türkçe"></a>

# capa2dbg (Türkçe)

[capa](https://github.com/mandiant/capa) verbose JSON çıktısını (`capa -vv -j`) x32dbg içinde otomatik comment, label, bookmark, breakpoint ve sessiz API argüman loguna çeviren eklenti. İstersen capa’yı debugger içinden de çalıştırır; sonuçları SHA256 anahtarlı diske cache’ler.

> Şimdilik yalnızca **x32**. ASLR’ye dayanıklı rebase dahil (image base `0x400000` olsa da olmasa da çalışır).

## Ne yapar?

- Eşleşen her adrese **comment** ve **bookmark**
- Fonksiyon kapsamlı kurallara kategori önekli **label** (`capa_proc_...`, `capa_reg_...`)
- Kritik namespace’lere (yapılandırılabilir) **breakpoint**
- Kritik `call` noktalarında argüman + dönüş değeri **log BP** (varsayılan: sessiz, durmaz)
- Fonksiyonda birden fazla yetenek varsa girişte **özet auto-comment**
- Opsiyonel: `capa.exe` çalıştırıp sonucu uygula + **cache**

## Kurulum

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

Çıktıyı kopyala:

```text
<x64dbg>\release\x32\plugins\capa2dbg.dp32
<x64dbg>\release\x32\plugins\capa2dbg.json
```

x32dbg’yi yeniden başlat → Log’da `[capa2dbg] yuklendi` görünmeli.

## Kullanım

1. Hedef PE’yi x32dbg’de aç.
2. Uygula:
   - **Plugins → capa2dbg → Load capa JSON & Apply**, veya
   - `capa_load <rapor.json>`, veya
   - `capa_run` (config’te `capa_path` dolu olmalı)
3. Comment / label / bookmark / BP’leri kontrol et; sample’ı çalıştırınca **View → Log**’da argüman dökümlerini gör.
4. Bitince: **Clear all capa marks (undo)**.

### Komutlar

```text
capa_load <path\to\report.json>
capa_run [force|-f]
capa_cache_info
capa_cache_clear
```

`capa_run force` cache’i atlar. `capa_cache_info` / `capa_cache_clear` cache durumunu gösterir / temizler.

## Yapılandırma

`capa2dbg.json` içinde önemli alanlar:

| Alan | Anlamı |
|---|---|
| `capa_path` | `capa.exe` tam yolu (boş = Run capa kapalı) |
| `cache_enabled` | Hedef SHA256’ya göre JSON cache |
| `cache_dir` | Cache dizini (boş = otomatik seçim) |
| `cache_max_mb` | LRU budama eşiği (varsayılan 512) |
| `cache_adopt_manual` | Elle yüklenen JSON’u da cache’e yaz |
| `breakpoint_namespaces` | Kritik BP allowlist’i (prefix eşleşme) |

Cache dizini sırası: config `cache_dir` → plugin yanındaki `capa2dbg_cache\` → `%LOCALAPPDATA%\capa2dbg\cache\`.

`capa.exe` güncellenince cache otomatik **STALE** sayılır ve yeniden analiz edilir. Sadece başarıyla parse edilen JSON yazılır; hatalı capa çıktısı cache’e girmez.

## Rebase

```text
rva     = capa_va - base_address
runtime = GetMainModuleBase() + rva
```

## Derleme bağımlılıkları

- MSVC C++17, MultiByte
- `pluginsdk/` (x64dbg SDK)
- `third_party/json.hpp`
- `bcrypt.lib` (SHA256 cache)

## Lisans

MIT — [LICENSE](LICENSE).
