## Кейс: взлом crackme с crackmes.one

**crackmes.one** — это community-платформа, где авторы выкладывают crackme **специально для того, чтобы их решали**. Никакой юридической серой зоны. Задачи ранжируются по сложности (1–5). Возьмём что-нибудь уровня 1–2, где нужен именно подход `probe`.

### Допустим, у нас есть `easy_keygen.exe` от автора X

Задача: найти правильный ключ для имени `probe_user`.

**Шаг 1 — загрузить и найти функции**

```
probe> find function --sort calls
```

В таблице видно группу CRT-функций и пару «наших» — с малым числом CALL, но заметным размером. Например:

```
0x10001230 -    348     19  stdcall 12    ← вероятно CRT/общая
0x10001540 -      6      0  cdecl         ← мелкий thunk (IAT)
0x100018B0 -    124      3  cdecl         ← похоже на наш validator
0x10001940 -     42      1  cdecl         ← ещё один
```

`validator` = функция с 1–3 CALL. `get function` подтверждает:

```
probe> get function 0x100018B0
Function 0x100018B0 (-)
  size: 124
  convention: Cdecl
  calls (3):
    0x100018B0 -> 0x10001940  -
    0x100018D4 -> 0x10001540  -        ← IAT-thunk (strlen?)
    0x10001912 -> 0x10002000  -
```

Три CALL: два внутренних и один thunk. Это классическая `validate(name, key)`, которая:
1. Считает хеш от `name` через вызов helper'а (`0x10001940`).
2. Сравнивает через `strcmp` (IAT-thunk `0x10001540`).
3. Возвращает `bool`.

**Шаг 2 — разведка через mock**

```
probe> set mock 0x10001940 --return 0xDEADBEEF
probe> invoke function 0x100018B0 ["probe_user" 0]
[+] done: EAX = 0x00000000 (0)        ← не сработало, но мок дёрнулся
    patched call sites: 3
    runtime mock hits:
      -> 0x10001940  -   x1
```

Первый мок сработал (helper вернул `0xDEADBEEF`), но функция всё равно вернула 0. Значит, **не только helper определяет результат**.

**Шаг 3 — смотрим, что сравнивается**

```
probe> alloc 64
probe> poke 0x02010000 "AAAAAAAA"
probe> set mock 0x10002000 --return 0
probe> invoke function 0x100018B0 ["probe_user" 0x02010000] --diff 64
```

`--diff` показывает:

```
    addr 0x02010000 (64 bytes) [5 bytes changed]
      before: 41 41 41 41 41 ...
      after:  42 41 41 41 41 ...
```

Функция **записала в переданный буфер** один байт. Значит, `validate` не только сравнивает — она **пишет ожидаемый ключ в out-параметр**, если передан указатель. Это классическая «хорошая» crackme: угадать нельзя, но перехватить можно.

**Шаг 4 — извлекаем ключ**

```
probe> alloc 64
probe> poke 0x02020000 "AAAAAAAA"   ← placeholder
probe> set mock 0x10002000 --return 0
probe> invoke function 0x100018B0 ["probe_user" 0x02020000] --diff 64
probe> peek 0x02020000 64
```

`peek` показывает, что функция записала в буфер строку `"probe_user_1234"` или байтовый массив — это и есть правильный ключ для этого name. Автор не учёл, что out-параметр будет перехвачен.

**Шаг 5 — проверка**

```
probe> invoke function 0x100018B0 ["probe_user" "probe_user_1234"]
[+] done: EAX = 0x00000001 (1)        ← ключ подошёл
```

**Почему это идеально ложится на probe:**

- Не нужно запускать `main` (где могут быть anti-debug проверки).
- Не нужно проходить `__scrt_common_main_seh` и CRT-init.
- `set mock` + `--diff` — прямой путь к решению.
- Если функция упадёт на каком-то входе, `probe` не пострадает.
- `runtime mock hits` показывает, какая подфункция реально дёрнулась — видно, что `strcmp` (0x10002000) вызывалась, а `hash` (0x10001940) — нет, если ветка другая.

**Тот же процесс за 2 минуты в IDA** занял бы 15–20 минут ручного анализа. А если crackme уровня 3–4 с anti-disassembly (`jmp` в середину инструкции, fake-код), probe вообще обгоняет статический анализ — он просто исполняет и смотрит.

---

## Бонус 1: «Восстановление забытого алгоритма из legacy DLL»

У вас есть старая DLL (`crypto_helper.dll`, ~2010 год), исходников нет, но вы знаете её API: `int ComputeSignature(const uint8_t* data, int len)`. Хотите понять, какой это алгоритм (CRC32, xxHash, FNV, собственный).

```
probe> find function --sort calls
# ComputeSignature обычно маленькая: 1-2 CALL внутри
probe> get function ComputeSignature
# видим: 1 CALL на helper compute_round + 1 CALL на финализатор
probe> set mock compute_round --return 0   ← обнуляем раунд
probe> poke 0x<buf> 00 00 00 00            ← входные данные
probe> poke 0x<buf> FF FF FF FF
probe> invoke function ComputeSignature [0x<buf> 4]
[+] done: EAX = 0x12345678

probe> poke 0x<buf> 00 00 00 00
probe> poke 0x<buf> FF FF FF FF
probe> invoke function ComputeSignature [0x<buf> 4]
[+] done: EAX = 0x9ABCDEF0               ← другое значение

probe> set mock compute_round --passthrough
probe> poke 0x<buf> 00 00 00 00
probe> invoke function ComputeSignature [0x<buf> 4]
[+] done: EAX = 0xCAFEBABE
```

С несколькими тестовыми входами (пусто, 1 байт, 4 байта `0xFF`) вы получаете сигнатуру `(input, output)`, по которой в 5 минут гуглится CRC32/xxHash/FNV. `--diff` на больших буферах покажет, что алгоритм пишет результат в out-параметр (если сигнатура `ComputeSignature(data, len, out)`).

**Почему нельзя было проще:** DLL — часть закрытого приложения, её код использует специфический helper (например, `compute_round` с табличной заменой), который делает алгоритм нестандартным. Без probe пришлось бы дизассемблировать и восстанавливать таблицу вручную.

---

## Бонус 2: «WinAPI detective — версия из любого файла, без Windows-окружения»

Практический сценарий: у вас есть 20 старых EXE-файлов (или DLL) в папке. Хотите быстро вытащить version-info (Producer, Version, Build).

```
probe> invoke function GetFileVersionInfoSizeW [w"notepad.exe" 0]
[+] done: EAX = 0x000003A4

probe> alloc 932
probe> invoke function GetFileVersionInfoW [w"notepad.exe" 0 0x000003A4 0x<buf>]
[+] done: EAX = 0x00000001

probe> peek 0x<buf> 932
# видите VS_VERSIONINFO: "Microsoft Corporation", "10.0.19041.1", ...
```

Это то, что **не может** сделать обычный скрипт без загрузки `version.dll` и запуска Windows-окружения. `probe` сам маппит `version.dll`, разрешает IAT (`kernel32!GetFileVersionInfoSizeW` и т.д.) и вызывает функцию.

**Уникальность:** это работает даже в **cross-compile scenario** (например, probe собран под Wine) или при **анализе образа, который ещё не загружен** в систему.

---

## Бонус 3: «Анализ malware sample — что шифрует payload»

Берём **безопасный** CTF malware sample с [theZoo](https://github.com/ytisf/theZoo) или [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) — например, простой ransomware из публичного CTF.

```
probe> find function --sort calls
# Ищем функцию с большим числом CALL — это может быть main/payload loop
probe> get function <addr>
# видим: 15+ CALL, включая CreateFileW, ReadFile, CryptEncrypt, DeleteFileW
probe> set mock CryptEncrypt --return 1   ← «шифрование успешно»
probe> alloc 4096
probe> poke 0x<buf> "test payload content"
probe> invoke function <encrypt_fn> [0x<buf> 20 0x<out>] --diff 4096
[+] done: EAX = 0x00000001
    --- diff: 2 buffers ---
    addr 0x<out> [20 bytes changed]
      before: 00 00 00 00 ...
      after:  A3 F1 22 87 64 ...
```

Через `--diff` видно, что **шифрование XOR-ит** входные байты константой (или AES — по размеру блока). Плюс `runtime mock hits` покажет, что `DeleteFileW` **не был вызван** (важно: ransomware обычно удаляет оригинал, но в sandbox-контексте это безопасно — мы мокаем `DeleteFileW` на no-op).

**Уникальность:** мы не запускаем ransomware — не создаём файлы, не шифруем диск, не отправляем отчёт на C2. Мы просто вызываем **функцию шифрования** в изолированном контексте и смотрим, как она работает.

---

## Бонус 4: «Подмена поведения в проде без пересборки»

Реальный developer use-case. Есть старая DLL, которую нельзя пересобрать (вендор ушёл, исходников нет), но в ней баг: `int CheckLicense(const char* key)` возвращает 0 для валидных ключей с определёнными символами. Хочется исправить без пересборки.

**Вариант A**: вместо вызова `CheckLicense` из вашего кода — `probe`-мок:

```
probe> set mock CheckLicense --return 1
probe> invoke function Validate [key_buf]
```

Это для экспериментов. Для продакшена — `LoadLibrary` + `Detours`, но `probe` — быстрый способ подтвердить гипотезу.

**Вариант B**: скомпилированная функция в вашем собственном проекте делает не то. Не хочется пересобирать всё — хочется замокать на время теста.

```
probe> invoke function my_parse_config [0x<buf>] --diff 64
# смотрим что реально делает функция, без запуска всего сервиса
```

---

## Бонус 5: «CTF-задача с anti-debug» — где probe особенно хорош

Классическая CTF-задача уровня 3: в `main` вызывается `IsDebuggerPresent()`, и если true — программа портит данные. Под отладчиком не запустить. Но `probe` **не отладчик** — он не устанавливает `DebugActiveProcess`, не прикрепляется к процессу, и `IsDebuggerPresent()` внутри `probe`-контекста вернёт `FALSE`.

```
probe> find function --sort calls
# main пропускаем, смотрим на функцию после anti-debug check
probe> invoke function real_check [<args>] --diff 64
[+] done: EAX = 0x1
```

Anti-debug не срабатывает, потому что `probe` вызывает функцию **напрямую**, минуя `main` с проверками.

**Ограничение:** если сама `real_check` содержит `__try/__except` для anti-debug, SEH не сработает (см. README) — но для CTF-задач с простым `IsDebuggerPresent` в `main` это работает.

---

## Итог: какой кейс выбрать для первой демонстрации

Если хочется одного «wow»-сценария на 5 минут — **взять crackme с crackmes.one уровня 2** и показать:
1. `find function` → `get function` → mock validator.
2. `--diff` на out-буфере — вытаскиваем ключ.
3. `invoke` с ключом — EAX=1.

Это займёт меньше времени, чем полный reverse в IDA, и наглядно демонстрирует **все** уникальные фичи `probe`: discovery, изоляцию, моки, счётчики, `--diff`, `runtime hits`.
