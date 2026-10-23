# 🧪 probe

**Интерактивный runtime-экспериментатор для 32-битных Windows PE-бинарников.**

`probe` — это REPL-инструмент на Rust для изолированного вызова отдельных функций из `PE32/x86` приложений. Он маппит PE-образ в приватную память, разрешает IAT, дизассемблирует `.text`, находит функции и позволяет вызывать любую из них в отдельном потоке с возможностью подменять внутренние `CALL` заглушками (моками). Падение целевой функции не убивает `probe`.

---

## Что решает

- **CTF / crackme.** Найти `check_password`, замокать её `--return 1`, вызвать `login` — и получить `EAX = 1` без реверса тела функции.
- **Извлечение крипто-примитивов.** Вызвать `decrypt`/`verify` из закрытого бинарника, не поднимая весь процесс: `poke` кладёт входные байты, `--diff` показывает выходные.
- **Разведка «что если».** Замокать каждую зависимость валидатора с разными `--return` и посмотреть, какие комбинации приводят к успеху.
- **Юнит-тест скомпилированной функции.** Проверить `parse_config` из своей DLL без инициализации БД и сети.
- **Изучение ABI.** Смотреть `disasm` и `--diff`, чтобы восстановить сигнатуру функции в бинарнике без символов.

## Что не решает

- Только **PE32/x86**. x64 и ARM не поддерживаются.
- Discovery идёт от `EntryPoint`, экспортов и **прямых** `CALL`. Stripped EXE без экспортов, где стартовый код использует `call [mem]`, найдётся частично.
- **Косвенные вызовы** (`call eax`, `call [mem]`) не патчатся — мок для такой цели не встанет.
- **SEH (`__try/__except`)** внутри целевой функции не работает: ручной маппинг + SafeSEH → обработчик не находится в `.sxdata`.
- Только `int`, `pointer`, ANSI-строка и UTF-16LE-строка как аргументы. `float`/`double` через XMM не передаются.
- Потоки, созданные самой функцией, не отслеживаются. VEH ловит исключения только в sandbox-потоке.
- Функции, зависящие от **глобального состояния CRT** (lazy-init TLS, `__cinit`, инициализированные глобалы), могут вести себя не так, как в реальном процессе.

## Требования

- Rust 1.87+
- Target: `i686-pc-windows-msvc`
- Visual Studio Build Tools (linker `link.exe`)

```powershell
rustup target add i686-pc-windows-msvc
cargo build --target i686-pc-windows-msvc --release
```

Бинарник: `target\i686-pc-windows-msvc\release\probe.exe`.

> `probe` **обязан** быть 32-битным — иначе нельзя исполнить код из PE32.

---

## Быстрый старт

```powershell
.\probe.exe .\crackme\crackme.dll
```

```
[*] Loading PE image: .\crackme\crackme.dll
[+] imports: resolved=23, failed=0
[+] Mapped .\crackme\crackme.dll (24576 bytes) at 0x10000000; 56 functions; entry = 0x1000154D
[+] Default mocks generated for 5 functions (EAX=0)
[+] probe ready. type 'help' for commands.
probe>
```

Типичный workflow: **найти → изучить → подготовить → вызвать → проверить**.

```
probe> find function --sort name               # список экспортов и найденных функций
probe> get function login                      # карта вызовов, конвенция, размер
probe> alloc 64                                # буфер под out-параметр
probe> poke 0x<addr> "test"                    # записать строку в буфер
probe> set mock check_password --return 1      # подменить зависимость
probe> invoke function login ["admin" 0x<addr>] --diff 64
probe> call log                                # история экспериментов
```

---

## Справочник команд

Все команды — в нижнем регистре. Первое слово — глагол, второе — существительное (вдохновлено конвенцией PowerShell, но без pipeline и объектов). Параметры с `--` разделяются пробелами.

### Поиск и просмотр

```
find function [--sort address|name|size|calls|imports] [--filter "<col> <op> <value>"]
find mock     [--sort address|name|type|return_value]   [--filter "<col> <op> <value>"]
get function  <target>
disasm        <target> [count]
peek          0x<addr> [size]
```

**`find function`** — таблица всех найденных функций. Колонки: `Address`, `Name`, `Size`, `Calls`, `Convention`. Операторы фильтра: `>`, `<`, `==`. Примеры:

```
find function --sort calls
find function --filter "size > 256"
find function --filter "name == login"
```

**`find mock`** — таблица моков. Дополнительная колонка `Hits` отражает число вызовов **в последнем invoke** (счётчики сбрасываются перед каждым вызовом). Примеры:

```
find mock --filter "type == custom"
find mock --sort return_value
```

**`get function`** — детальная карта: размер, конвенция, текущий мок, список прямых CALL с целями.

**`disasm`** — дизассемблирование N инструкций (`iced-x86` + `IntelFormatter`).

**`peek`** — hexdump памяти с ASCII-представлением.

### Вызов функций

```
invoke function <target> [arg...] [--diff [N]]
invoke mock     <target> [arg...]
```

**`invoke function`** — исполняет **реальный код** функции. Все прямые `CALL` на функции, у которых есть мок, перенаправляются на заглушки **на время вызова**. После возврата оригинальные байты восстанавливаются.

- `--diff` — снять снапшоты всех `Pointer`/`String`/`WideString` аргументов **до и после**, показать изменения. Размер окна: `64` по умолчанию, либо `--diff N`.
- Если размер буфера известен из `alloc`, используется он (окно N игнорируется).

**`invoke mock`** — исполняет **заглушку**, установленную через `set mock`. Полезно для проверки, что мок действительно возвращает ожидаемое значение.

> **Моки перехватывают CALL из других функций, а не сам `invoke function`.** Если вы замокали `X` и вызываете `X` через `invoke function X`, будет исполнен **реальный** `X`. Чтобы проверить stub, используйте `invoke mock X`.

### Управление моками

```
set mock <target> --return <value>
set mock <target> --passthrough
reset mock <target>
reset mock --all
```

- `--return <value>` — установить custom mock, возвращающий `value` в `EAX`.
- `--passthrough` — снять мок для этой функции. Код пойдёт в оригинал.
- `reset mock <target>` — вернуть мок в `Default` (return 0).
- `reset mock --all` — сбросить все моки в `Default`. **Авто-моки генерируются только для экспортов**; внутренние (CRT-функции вроде `memset`) не мокаются, чтобы их побочные эффекты работали.

### Память

```
alloc <size>
poke 0x<addr> <byte>...
```

**`alloc`** — выделить `size` байт RWX-памяти. Возвращает адрес, который **нужно использовать** в следующих `invoke`. Адрес и размер запоминаются, чтобы `--diff` знал точный размер буфера.

**`poke`** — записать байты по адресу. Форматы: `0x41` (hex), `65` (decimal), `"hello"` (строка). Пример:

```
probe> alloc 16
[+] allocated 16 bytes at 0x01650000
probe> poke 0x01650000 0x41 0x42 0x43
[+] wrote 3 byte(s) to 0x01650000
    0x01650000: 41 42 43
probe> poke 0x01650000 "hello"
[+] wrote 5 byte(s) to 0x01650000
    0x01650000: 68 65 6C 6C 6F
```

### Журнал и сервис

```
call log
call log clear
help
exit
```

**`call log`** — история всех `invoke` в текущей сессии. Для каждого вызова: индекс, функция (или `mock:name`), `EAX`, статус (`ok` / `AV/0xNNN` / `CRASH`), число пропатченных CALL, суммарные попадания в моки.

---

## Синтаксис аргументов

В `[...]` после `invoke function` / `invoke mock`:

| Синтаксис | Тип | Пример |
|---|---|---|
| `123` | `u32` | `invoke function add [2 3]` |
| `0x1234` | **указатель**, не int! | `invoke function parse [0x01650000]` |
| `"string"` | ANSI-строка (UTF-8 байты + NUL) | `invoke function login ["admin"]` |
| `w"string"` | UTF-16LE-строка + `\0\0` | `invoke function GetFileVersionInfoSizeW [w"C:\path.dll" 0]` |

> ⚠️ `0xFF` в args — это **указатель** на адрес `0x000000FF`, не число 255. Для int используйте десятичную запись.

### Пример с wide-строкой

```
probe> invoke function GetFileVersionInfoSizeW [w"C:\Windows\System32\kernel32.dll" 0]
[*] invoke GetFileVersionInfoSizeW (0x52181680) args=[WideString("C:\\Windows\\System32\\kernel32.dll"), Integer(0)] diff=false
[+] done: EAX = 0x00000744 (1860)
```

---

## Примеры сценариев

### 1. Crackme: обход проверки пароля

```
probe> find function --sort name
# находим check_password, is_admin, login
probe> get function login
# видим два прямых CALL: на is_admin и на check_password

# Сценарий A: backdoor через is_admin
probe> set mock is_admin --return 1
probe> invoke function login ["user" "wrong"]
[+] done: EAX = 0x00000001 (1)
    patched call sites: 2
    runtime mock hits:
      -> 0x100011D0  is_admin         x1
# check_password пропатчен, но НЕ выполнился — early-return

# Сценарий B: честный пароль
probe> reset mock --all
probe> set mock check_password --passthrough
probe> invoke function login ["user" "s3cr3t"]
[+] done: EAX = 0x00000001 (1)  # реальная проверка прошла

# Сценарий C: пароль неверный
probe> invoke function login ["user" "wrong"]
[+] done: EAX = 0x00000000 (0)
```

Счётчики `runtime mock hits` показывают, **какая ветка реально выполнилась** — этого не видно в обычном отладчике без пошагового прохода.

### 2. Извлечение крипто-примитива с out-буфером

```
probe> find function --sort name
# находим decrypt (не экспорт — только через discovery)
probe> alloc 256
[+] allocated 256 bytes at 0x02010000
probe> poke 0x02010000 0x01 0x02 0x03 0x04
probe> alloc 32
[+] allocated 32 bytes at 0x02020000
probe> invoke function decrypt [0x02010000 4 0x02020000] --diff 32
[+] done: EAX = 0x00000004 (4)
    --- diff: 2 buffer(s) watched ---
    addr 0x02020000 (32 bytes) [4 bytes changed]
      before: 00 00 00 00 ...
      after:  A3 F1 22 87 ...         ← расшифрованные байты
```

### 3. Реальный Microsoft DLL — проверка загрузчика

```
PS> .\probe.exe C:\Windows\SysWOW64\version.dll
[+] imports: resolved=74, failed=0
[+] Mapped ... at 0x52180000; 35 functions
[+] Default mocks generated for 17 functions (EAX=0)

probe> find function --sort name
# 17 экспортов с именами
probe> invoke mock GetFileVersionInfoSizeW ["anything" 0]
[+] done: EAX = 0x00003039 (12345)   # stub

probe> invoke function GetFileVersionInfoSizeW [w"C:\Windows\System32\kernel32.dll" 0]
[+] done: EAX = 0x00000744 (1860)    # реальный размер VS_VERSIONINFO
```

`version.dll` — это доказательство, что `probe` работает на реальных Microsoft-бинарниках, а не только на crackme.

### 4. Crash-тест: изоляция падений

```
probe> invoke function copy_upper ["hello" 0x00A40000 5]
[!] warning: arg #1 (0x00A40000) is not readable; any dereference will fault
[*] invoke copy_upper ...
[UEF] sandbox exception deferred to WoW64: code=0xC0000005 eip=0x10001189
[!] sandbox crashed (code 0xC0000005)
    fault instruction: 0x10001189
    fault memory access: 0x00A40000
    EAX marker = 0xDEADFA11
probe>                          ← REPL жив
```

AV внутри функции ловится VEH, перехватывается в sandbox-потоке, выполнение безопасно прерывается. Тот же механизм ловит `EXCEPTION_ILLEGAL_INSTRUCTION`, `EXCEPTION_INT_DIVIDE_BY_ZERO`, `EXCEPTION_BREAKPOINT` и другие.

---

## Архитектура (для тех, кто хочет копать)

```
src/
├── main.rs              — точка входа, загрузка PE
├── repl.rs              — цикл rustyline, диспетчеризация
├── parser.rs            — лексер команд, парсинг args (int/pointer/string/wstring)
├── commands.rs          — реализация всех команд
├── context.rs           — SandboxContext, Mock, CallLogEntry, FunctionMeta
├── ffi.rs               — Win32 API bindings (VirtualAlloc, VEH, CreateThread, ...)
├── pe_loader.rs         — маппинг образа, разрешение IAT (FirstThunk!)
├── function_discovery.rs — рекурсивный обход CALL, определение конвенций
├── mock_engine.rs       — генерация x86-стабов (inc counter; mov eax,val; ret)
└── executor.rs          — патчинг CALL, VEH, sandbox-поток, --diff
```

### Как работает `invoke function X [args]`

1. **Патчинг.** Все прямые `CALL` внутри `X`, чьи цели имеют мок, переписываются на адрес заглушки (`E8 rel32` → `E8 rel32'`). Оригинальные 5 байт сохраняются.
2. **Аргументы.** `String`/`WideString` копируются в RWX-память; `Pointer`/`Integer` передаются как есть. Собирается массив `[u32; N]`.
3. **Изолированный поток.** `CreateThread` запускает `thread_trampoline`, который:
   - устанавливает `CURRENT_CTX` (thread-local);
   - вызывает asm-трамплин `probe_call_with_stack`;
   - asm кладёт аргументы на **родной** стек потока (`push ... call [ebp+8]`), переходит в `X`.
4. **VEH.** Если внутри `X` случается исключение, `veh_handler` видит активный `CURRENT_CTX`, подменяет `eip` на `probe_recovery_stub`, `esp` на сохранённый, `eax` на `0xDEADFA11`, возвращает `EXCEPTION_CONTINUE_EXECUTION`. Поток корректно завершается, `probe` жив.
5. **Восстановление.** После `WaitForSingleObject` оригинальные байты `CALL` возвращаются, временные строки освобождаются.
6. **--diff.** Снапшоты `Pointer`/`String` до и после, вывод изменений.

### Моки (заглушки)

Каждая заглушка — 20 байт в отдельной RWX-странице:

```asm
inc dword ptr [counter_addr]   ; FF 05 <addr>   — счётчик попаданий
mov eax, retval                ; B8 <val>
ret  /  ret N                  ; C3 / C2 <N> — по конвенции функции
```

`counter_addr` — ячейка `+16` внутри той же страницы. `invoke` сбрасывает счётчики всех моков **перед** запуском, после — читает не-нулевые и выводит как `runtime mock hits`.

### Почему IAT пишется в `FirstThunk`, а не `OriginalFirstThunk`

`IMAGE_IMPORT_DESCRIPTOR` содержит два похожих поля. `OriginalFirstThunk` (ILT) — таблица «какие имена импортируются». `FirstThunk` (IAT) — таблица «по каким адресам лежат реальные функции», и именно её читают thunk-инструкции вида `jmp dword ptr [IAT]` в PE.

Если записать адрес функции в ILT, рантайм продолжит читать из IAT, где лежит `RVA` имени функции (например, `0x3838`), и `jmp [IAT]` прыгнет на этот мусор → AV. Именно поэтому `resolve_imports` в `pe_loader.rs` пишет именно в `FirstThunk`, включая поддержку ordinal-импортов (`GetProcAddress(h, (LPCSTR)ordinal)`).

---

## Ограничения, которые важно понимать

| Симптом | Причина | Обход |
|---|---|---|
| `invoke function` падает на `call [mem]` внутри функции | Косвенный CALL не патчится | Не поддерживается в v0.1 |
| `VirtualAlloc at 0x... failed` при загрузке | `ImageBase` занят другим загрузчиком в этом процессе | Собрать target с `-C link-arg=/BASE:0x10000000` или использовать другой `ImageBase` |
| Внутренняя CRT-функция не мокается | Авто-моки только для экспортов | Явно: `set mock <addr> --return N` |
| Wide-функция вернула 0 на `"string"` | Передали ANSI вместо UTF-16 | Используйте `w"string"` |
| `EAX = 0` на `invoke function X` при `set mock X --return N` | Мок ловит CALL **из других** функций, не сам invoke | `invoke mock X` |
| AV в `ntdll!memset` при `fill` | `memset` — IAT-thunk, реальный код | Снять мок через `--passthrough` или ожидать, что моки не мешают |
| `[UEF] sandbox exception deferred to WoW64` | Информационно: второй шанс по 32-битному CONTEXT в 64-битной ОС | Не ошибка, так работает WoW64 |
| `__try/__except` внутри функции «не ловит» AV | SafeSEH + ручной маппинг → handler не в `.sxdata` | Не поддерживается |

---

## Roadmap

- **v0.2 — discovery для stripped-бинарников.** Linear sweep по `.text` с проверкой прологов и достижимости.
- **v0.2 — SEH.** Полноценная регистрация exception handlers при маппинге.
- **v0.3 — x64.** Отдельный проект по сложности: другая архитектура вызовов, другой CONTEXT, другой формат PE.
- **v0.3 — `float`/`double`.** Передача через XMM по System V / MS ABI.
- **v0.4 — FLIRT-сигнатуры.** Автоматическое распознавание статических CRT-функций в stripped-бинарниках.

---

## Сборка из исходников

```powershell
rustup target add i686-pc-windows-msvc
git clone <repo>
cd probe
cargo build --target i686-pc-windows-msvc --release
```

Зависимости:

```toml
goblin = "0.9"                  # парсинг PE
iced-x86 = { version = "1.21", features = ["intel"] }  # дизасм/ассемблер
rustyline = "14"                # REPL с историей
home = "=0.5.11"                # зафиксировано из-за MSRV транзитивных зависимостей
```

---

## Лицензия

MIT (или на ваш выбор).

---
