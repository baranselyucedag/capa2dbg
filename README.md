# capa2dbg

**English** · [Türkçe](#türkçe)

Ever opened a malware sample in x32dbg and thought "okay... where do I even start?" That's the whole reason this plugin exists.

[capa](https://github.com/mandiant/capa) is a tool that looks at a program and tells you what it *does* — "this creates a process", "this writes to the registry", "this talks to a C2 server". The catch: capa gives you a wall of text with addresses, and you still have to go find those addresses in your debugger by hand.

**capa2dbg does that boring part for you.** You give it capa's report, and it jumps into x32dbg and marks everything up:

- Writes a **comment** at each interesting address, so you see "creates a process" right there in the disassembly
- Adds **bookmarks** so you can jump between findings
- Drops **breakpoints** on the spicy stuff (process creation, registry, network, anti-debug…)
- And the fun one: when a breakpoint hits, it **prints the actual arguments** to the log — the real command line, the real file path — without you touching anything

So instead of reading capa's report in one window and scrolling around your debugger in another, everything is just *there*, on the code, where you're already looking.

> Right now it's **x32dbg only** (32-bit).

---

## What it looks like

A comment sitting right on the instruction:

```text
[capa] create process on Windows | link function at runtime on Windows
```

And when you actually run the sample, the log fills up with what the malware is really doing:

```text
[capa] CreateProcessW cmd="C:\...\payload.bin"
[capa] CreateProcessW -> ret=0x1
```

No more manually dumping the stack to read a command line.

---

## What you need

- **x32dbg** (comes with FLARE VM, or grab it standalone)
- A capa report saved as JSON. Run capa like this: `capa -vv -j sample.exe > report.json`
  - The `-vv` matters — that's what makes capa include the addresses we need.
- Your sample already open in x32dbg
- *(Optional)* capa.exe installed, if you want the plugin to run capa for you

---

## Getting started

**1. Build it** (or grab a release binary later):

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

You'll get `bin\Release\capa2dbg.dp32`.

**2. Drop it into x32dbg's plugins folder:**

```text
<x64dbg>\release\x32\plugins\capa2dbg.dp32
<x64dbg>\release\x32\plugins\capa2dbg.json
```

**3. Restart x32dbg.** If you see `[capa2dbg] yuklendi` in the log, you're good.

---

## How you'll actually use it

1. Open your sample in x32dbg like you normally would.
2. Feed it the capa report — pick whichever is easier:
   - **Plugins → capa2dbg → Load capa JSON & Apply** (file picker)
   - or type `capa_load C:\path\to\report.json` in the command box
   - or, if you set up capa.exe, just hit **Run capa on current target** and it does everything
3. Now look at your disassembly — comments, bookmarks and breakpoints are all there. Run the sample and watch the **Log** window (View → Log) for the argument dumps.
4. Done for the day? **Clear all capa marks** wipes everything the plugin added, and *only* what the plugin added — your own comments stay safe.

### The menu, in plain terms

| Menu item | What it's for |
|---|---|
| Load capa JSON & Apply | Pick a report file and mark up the code |
| Run capa on current target | Let the plugin run capa for you |
| Run capa (force, ignore cache) | Same, but re-run even if we've seen this file before |
| Toggle breakpoints: Critical / All | Only the important stuff, or literally everything capa found |
| Toggle arg logging: On / Off | Whether to print API arguments to the log |
| Toggle log BP: Silent / Break | Silent = log and keep running. Break = actually stop at the call |
| Toggle cache: On / Off | Turn the "remember previous runs" feature on/off |
| Cache: show info | How much is cached and where |
| Cache: clear all | Forget everything cached |
| Clear all capa marks (undo) | Remove everything the plugin added |
| Show last summary in log | Re-print the "here's what I marked" summary |

### If you prefer typing commands

```text
capa_load <path\to\report.json>     load a report and apply it
capa_run [force]                    run capa yourself (force = ignore cache)
capa_cache_info                     show what's cached
capa_cache_clear                    clear the cache
```

---

## The cache (a.k.a. why the second run is instant)

Running capa on a big sample can take *minutes*. That's painful when you close the debugger and come back later, only to wait all over again.

So the plugin remembers. The first time it analyzes a file, it saves capa's result to disk. Next time you open the **same file** — even if you renamed or moved it — it recognizes it instantly and skips the wait entirely.

A few things it's smart about:

- It matches files by their **content**, not their name. Same file with a different name? Still recognized. A slightly modified (patched) file? Treated as new, so you never get stale results.
- If you **update capa itself**, the plugin notices and re-analyzes automatically — capa's rules live inside capa.exe, so a new capa means new results.
- It only ever saves results that actually worked. If a capa run fails, nothing gets cached, so a broken run can't poison your next one.

You barely have to think about it, but if you want control: `capa_run force` ignores the cache, `capa_cache_info` shows what's saved, and `capa_cache_clear` wipes it.

Where it saves things (it picks the first spot it can write to):

1. A folder you set yourself in the config (`cache_dir`)
2. A `capa2dbg_cache` folder next to the plugin
3. `%LOCALAPPDATA%\capa2dbg\cache` (fallback if the plugins folder is read-only)

And to be clear: it **only** saves capa's JSON report. It never copies the malware itself anywhere.

---

## Settings

Everything lives in `capa2dbg.json` (next to the `.dp32`, or in `plugins\config\`). You don't *have* to touch any of this — the defaults are fine — but here's what each knob does:

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
    "host-interaction/registry",
    "anti-analysis",
    "communication",
    "c2"
  ]
}
```

| Setting | What it does |
|---|---|
| `capa_path` | Full path to capa.exe. Leave empty if you'll always load reports by hand. |
| `label_category_prefix` | Adds a little category tag to labels (`capa_proc_...`) so they group nicely. |
| `cache_enabled` | Remember previous runs (the whole section above). |
| `cache_dir` | Force a specific cache folder. Empty = let the plugin choose. |
| `cache_max_mb` | Cache size limit. Old stuff gets cleaned up past this. |
| `cache_adopt_manual` | When you load a report by hand, also save it to the cache. |
| `breakpoint_namespaces` | Which categories count as "critical" enough for a breakpoint. |

That last one, `breakpoint_namespaces`, is just a list of capa categories. If a finding's category starts with one of these, it gets a breakpoint. Add or remove lines to taste. (The full default list is longer — process, thread, registry, persistence, crypto, collection, clipboard, and more.)

---

## A note on addresses (rebasing)

capa reports addresses assuming the program loads at a fixed spot (usually `0x400000`). Real programs sometimes load elsewhere. The plugin handles this automatically — it figures out where your program *actually* landed and shifts every address to match. On FLARE with ASLR off it's usually a no-op, but if addresses ever move, you're covered.

---

## Building it yourself

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

- Built with MSVC (VS 2022 / Build Tools), C++17
- Uses the x64dbg SDK (in `pluginsdk/`) and [nlohmann/json](https://github.com/nlohmann/json) (in `third_party/`)

### Sanity checks (no malware required)

These run on your machine without touching a debugger, just to confirm things are wired up right:

```bat
python tools\cache_sim.py                 REM tests the cache logic
python tools\validate_capa_json.py report.json   REM tests report parsing
powershell -ExecutionPolicy Bypass -File tools\smoke_check.ps1
```

---

## What's in the box

```text
capa2dbg/
├── config/capa2dbg.json      the settings file
├── src/                      all the plugin code
├── pluginsdk/                x64dbg SDK
├── third_party/json.hpp      JSON library
├── tools/                    offline test scripts
└── capa2dbg.sln
```

---

## License

MIT — do whatever you want with it. See [LICENSE](LICENSE).

---
---

<a id="türkçe"></a>

# capa2dbg (Türkçe)

x32dbg'de bir zararlı örneği açıp "tamam da... nereden başlasam ben şimdi?" dediğin oldu mu? Bu eklenti tam olarak o yüzden var.

[capa](https://github.com/mandiant/capa) bir programa bakıp ne yaptığını söyleyen bir araç — "burada process yaratıyor", "burada registry'ye yazıyor", "burada C2 sunucusuyla konuşuyor" gibi. Ama bir sıkıntısı var: capa sana bir sürü adres ve metin veriyor, sonra o adreslerin her birini debugger'da tek tek bulman gerekiyor.

**capa2dbg işte o sıkıcı kısmı senin yerine yapıyor.** capa'nın raporunu veriyorsun, o da x32dbg'ye girip her şeyi işaretliyor:

- Her önemli adrese **yorum** yazıyor, yani "process yaratıyor" ibaresini doğrudan disassembly'de görüyorsun
- **Bookmark** koyuyor, bulgular arasında zıplayabilesin diye
- Asıl kritik yerlere **breakpoint** atıyor (process yaratma, registry, ağ, anti-debug…)
- Ve en güzeli: breakpoint kırıldığında **argümanları otomatik log'a basıyor** — gerçek komut satırı, gerçek dosya yolu — sen hiçbir şeye dokunmadan

Yani capa raporunu bir pencerede okuyup debugger'da bir sağa bir sola kaydırmak yerine, her şey zaten kodun üstünde, tam baktığın yerde duruyor.

> Şu an sadece **x32dbg** (32-bit).

---

## Nasıl görünüyor

Yorum, doğrudan komutun üstünde:

```text
[capa] create process on Windows | link function at runtime on Windows
```

Ve örneği gerçekten çalıştırınca log, zararlının ne yaptığıyla doluyor:

```text
[capa] CreateProcessW cmd="C:\...\payload.bin"
[capa] CreateProcessW -> ret=0x1
```

Komut satırını okumak için artık stack'i elle dökmene gerek yok.

---

## Neye ihtiyacın var

- **x32dbg** (FLARE VM'de hazır gelir, ya da tek başına indir)
- JSON olarak kaydedilmiş bir capa raporu. capa'yı şöyle çalıştır: `capa -vv -j ornek.exe > rapor.json`
  - `-vv` önemli — adresleri rapora ekleten kısım o.
- Örneğin x32dbg'de zaten açık olsun
- *(İsteğe bağlı)* capa.exe kurulu olsun, eğer capa'yı eklentiye çalıştırtmak istiyorsan

---

## Başlangıç

**1. Derle** (ya da ileride hazır sürümü kap):

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

`bin\Release\capa2dbg.dp32` çıkacak.

**2. x32dbg'nin plugins klasörüne at:**

```text
<x64dbg>\release\x32\plugins\capa2dbg.dp32
<x64dbg>\release\x32\plugins\capa2dbg.json
```

**3. x32dbg'yi yeniden başlat.** Log'da `[capa2dbg] yuklendi` görüyorsan tamamdır.

---

## Pratikte nasıl kullanılıyor

1. Örneği her zamanki gibi x32dbg'de aç.
2. capa raporunu ver — hangisi kolayına gidiyorsa:
   - **Plugins → capa2dbg → Load capa JSON & Apply** (dosya seçici)
   - ya da komut kutusuna `capa_load C:\yol\rapor.json` yaz
   - ya da capa.exe'yi ayarladıysan sadece **Run capa on current target**'a bas, gerisini o halleder
3. Şimdi disassembly'ye bak — yorumlar, bookmark'lar ve breakpoint'ler orada. Örneği çalıştır ve argüman dökümleri için **Log** penceresini izle (View → Log).
4. İşin bittiyse **Clear all capa marks** eklentinin eklediği her şeyi siler — hem de *sadece* eklentinin eklediklerini, senin kendi yorumların yerinde kalır.

### Menü, sade haliyle

| Menü | Ne işe yarıyor |
|---|---|
| Load capa JSON & Apply | Rapor dosyası seç, kodu işaretle |
| Run capa on current target | capa'yı eklentiye çalıştırt |
| Run capa (force, ignore cache) | Aynısı, ama bu dosyayı daha önce görmüş olsak bile baştan çalıştır |
| Toggle breakpoints: Critical / All | Sadece önemli yerler mi, yoksa capa'nın bulduğu her şey mi |
| Toggle arg logging: On / Off | API argümanları log'a basılsın mı |
| Toggle log BP: Silent / Break | Silent = logla ve devam et. Break = çağrıda gerçekten dur |
| Toggle cache: On / Off | "Önceki çalıştırmaları hatırla" özelliğini aç/kapa |
| Cache: show info | Ne kadar şey saklanmış, nerede |
| Cache: clear all | Saklanan her şeyi unut |
| Clear all capa marks (undo) | Eklentinin eklediği her şeyi kaldır |
| Show last summary in log | "Şunları işaretledim" özetini tekrar bas |

### Komutla kullanmayı seviyorsan

```text
capa_load <yol\rapor.json>       raporu yükle ve uygula
capa_run [force]                 capa'yı sen çalıştır (force = cache'i yok say)
capa_cache_info                  cache'te ne var göster
capa_cache_clear                 cache'i temizle
```

---

## Cache (yani ikinci çalıştırma neden anında)

capa'yı büyük bir örnekte çalıştırmak *dakikalar* sürebiliyor. Debugger'ı kapatıp sonra geri döndüğünde aynı beklemeyi baştan yaşamak epey can sıkıcı.

O yüzden eklenti hatırlıyor. Bir dosyayı ilk analiz ettiğinde capa'nın sonucunu diske kaydediyor. **Aynı dosyayı** bir daha açtığında — adını değiştirmiş ya da başka yere taşımış olsan bile — onu anında tanıyıp beklemeyi tamamen atlıyor.

Birkaç akıllı davranışı var:

- Dosyaları adına değil **içeriğine** göre tanıyor. Aynı dosya farklı isimle mi? Yine tanır. Ufak bir değişiklik yapılmış (patch'lenmiş) dosya mı? Yeni sayar, yani asla eski/yanlış sonuç almazsın.
- **capa'yı güncellersen** eklenti bunu fark edip otomatik yeniden analiz eder — capa'nın kuralları capa.exe'nin içinde durur, yani yeni capa = yeni sonuç.
- Sadece gerçekten işe yarayan sonuçları saklar. Bir capa çalıştırması başarısız olursa hiçbir şey kaydedilmez, yani bozuk bir çalıştırma bir sonrakini zehirleyemez.

Aslında pek düşünmene gerek yok ama kontrol istersen: `capa_run force` cache'i yok sayar, `capa_cache_info` ne kaydedildiğini gösterir, `capa_cache_clear` hepsini siler.

Nereye kaydediyor (yazabildiği ilk yeri seçer):

1. Config'te kendin belirlediğin klasör (`cache_dir`)
2. Eklentinin yanındaki `capa2dbg_cache` klasörü
3. `%LOCALAPPDATA%\capa2dbg\cache` (plugins klasörü salt-okunursa yedek plan)

Ve net olalım: **sadece** capa'nın JSON raporunu saklar. Zararlının kendisini hiçbir yere kopyalamaz.

---

## Ayarlar

Her şey `capa2dbg.json` içinde (`.dp32`'nin yanında ya da `plugins\config\` altında). Hiçbirine dokunmak *zorunda* değilsin — varsayılanlar gayet iyi — ama her bir ayarın ne yaptığı şöyle:

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
    "host-interaction/registry",
    "anti-analysis",
    "communication",
    "c2"
  ]
}
```

| Ayar | Ne yapıyor |
|---|---|
| `capa_path` | capa.exe'nin tam yolu. Raporları hep elle yükleyeceksen boş bırak. |
| `label_category_prefix` | Label'lara küçük bir kategori etiketi ekler (`capa_proc_...`), düzenli görünsün diye. |
| `cache_enabled` | Önceki çalıştırmaları hatırlar (yukarıdaki koca bölüm). |
| `cache_dir` | Belirli bir cache klasörü zorla. Boş = eklenti seçsin. |
| `cache_max_mb` | Cache boyut sınırı. Bunu aşınca eskiler temizlenir. |
| `cache_adopt_manual` | Elle rapor yüklediğinde onu da cache'e kaydeder. |
| `breakpoint_namespaces` | Hangi kategoriler breakpoint'e değecek kadar "kritik" sayılıyor. |

Sondaki `breakpoint_namespaces` sadece bir capa kategori listesi. Bir bulgunun kategorisi bunlardan biriyle başlıyorsa breakpoint alır. İstediğin gibi satır ekle/çıkar. (Varsayılan liste daha uzun — process, thread, registry, persistence, kripto, collection, clipboard ve dahası.)

---

## Adresler hakkında ufak bir not (rebase)

capa adresleri, program sabit bir yere yüklenirmiş gibi verir (genelde `0x400000`). Gerçek programlar bazen başka yere yüklenir. Eklenti bunu otomatik halleder — programının *gerçekte* nereye düştüğünü bulup her adresi ona göre kaydırır. FLARE'de ASLR kapalıysa genelde hiçbir şey değişmez ama adresler kayarsa arkanı kollamış oluyorsun.

---

## Kendin derlemek istersen

```bat
msbuild capa2dbg.sln /p:Configuration=Release /p:Platform=Win32
```

- MSVC ile derlenir (VS 2022 / Build Tools), C++17
- x64dbg SDK'sını (`pluginsdk/`) ve [nlohmann/json](https://github.com/nlohmann/json)'u (`third_party/`) kullanır

### Kontrol scriptleri (zararlı gerekmez)

Bunlar debugger'a hiç dokunmadan makinende çalışır, her şey doğru bağlanmış mı diye:

```bat
python tools\cache_sim.py                       REM cache mantığını test eder
python tools\validate_capa_json.py rapor.json   REM rapor okumayı test eder
powershell -ExecutionPolicy Bypass -File tools\smoke_check.ps1
```

---

## Kutunun içinde ne var

```text
capa2dbg/
├── config/capa2dbg.json      ayar dosyası
├── src/                      eklentinin tüm kodu
├── pluginsdk/                x64dbg SDK
├── third_party/json.hpp      JSON kütüphanesi
├── tools/                    offline test scriptleri
└── capa2dbg.sln
```

---

## Lisans

MIT — ne istersen yap. [LICENSE](LICENSE)'a bak.
