# Состояние работы и как продолжить

Последнее обновление: 01.11.2026, ~22:15.

## Что уже сделано

| Блок | Где | Статус |
|---|---|---|
| Исследование (6 направлений) и итоговый отчёт | `reports/…`, `research_notes/…` | готово |
| План ВКР, артефакты, план статьи | `docs/plan.md`, `docs/artifacts.md`, `docs/paper.md` | черновики |
| MVP: TUF-клиенты, сетевые атаки, обрыв процесса, мутанты | `bench/`, `docs/mvp-results.md` | работает, прогон 31.10 |
| Каталог угроз v0.3 (40 угроз, ссылки сверены у всех, JSON Schema) | `bench/catalog/threats.yaml` | готово, см. «Проверить» ниже |
| Пилот уровня ОС: RAUC 1.8 + GRUB в QEMU | `docs/pilot-ab.md`, `bench/scripts/pilot_ab.py` | работает |
| Протокол адаптера v2 (уровень устройства): всё про RAUC и GRUB вынесено из сценариев в `bench/updaters/rauc-grub.yaml` | `docs/adapter-protocol.md`, `bench/otabench/device.py` | готово (01.11, задача A1) |
| MVP v3: событийные точки обрыва в `powercut-refresh`, мутант `naive-lazyroot`, единое правило вердиктов, JSON Schema каталога, сводная матрица угроз двух уровней | `bench/results/full-2026-11-01-v3/`, `bench/results/threat-matrix-2026-11-01/` | готово (01.11) |
| Блочное воспроизведение точек обрыва (`blklogwrites`) | `bench/otabench/writelog.py` | работает (префиксная модель) |
| Окно «обновление теряется после успеха» и его механизм | `docs/pilot-ab.md`, раздел «Механизм окна» | готово (01.11): 8 конфигураций, механизм установлен |
| Модель перестановок несброшенных записей | `WriteLog.crash_states()`, сценарий `reorder:*` | готово (01.11) для ext4, ext2, vfat |
| Сверка каталога с репозиториями MCUboot, Mender, aktualizr | шапка `bench/catalog/threats.yaml` | готово (01.11) |
| Живучесть из «рваного» состояния: vfat → `grubenv` 0 байт → `rauc install` отказывает | `docs/pilot-ab.md`, `scripts/replay_state.py`, угроза OTA-PWR-05 | готово (01.11) |
| **Исправление**: обработчик RAUC, пишущий окружение на месте | `vm/guest/otabench-bootenv`, варианты `*-inplace`, `docs/pilot-ab.md` «Исправление» | готово (01.11): убирает окно и порчу на ext4/ext2/vfat |
| Черновик issue для RAUC | `docs/upstream/rauc-grubenv-issue-draft.md` | черновик, **не опубликован** |
| Проверка на UEFI: `grubenv` на EFI-разделе (как в документации RAUC) | `docs/pilot-ab.md` «Проверка на UEFI», варианты `uefi-esp*` | готово (01.11): находка воспроизводится, исправление работает |
| Модель разрыва по секторам (`--torn`) | `WriteLog.crash_states(torn=True)`, `docs/pilot-ab.md` «Модель разрыва» | готово (01.11): `grubenv` не рвётся; 3 BRICK — разорванный журнал ext4 **работающего** слота A (угроза OTA-PWR-06) |
| Черновики глав ВКР 1–4 + рисунки | `docs/thesis/ch1…ch4*.md`, `docs/figures/fig4-*.svg` (генерирует `bench/scripts/make_figures.py`) | первые черновики (01.11): ~9,5 + 7 + 8 + 8,4 тыс. слов |
| Репозиторий | https://github.com/IWillBurn/ota-diploma, ветка работы `uefi-esp` | `main` = исходный импорт; **коммиты без соавторства Claude** |
| Черновик issue для tuf-conformance | `docs/upstream/tuf-conformance-transport-tests.md` | черновик, **не опубликован** |
| RAUC 1.15.2 (из исходников) и SWUpdate 2024.12.1 на том же A/B-образе | `updaters/rauc1.15.2-grub.yaml`, `updaters/swupdate-grub.yaml`, `results/pilot-ab-20261101-181255/`, `-183354/`, `-184534/` | системный и блочный уровень пройдены; окно под нагрузкой, ждёт чистого повтора |
| SUIT (libcsuit) — третья экосистема | `scripts/suit_bench.py`, `results/suit-2026-11-01/` | готово (01.11) |
| TOCTOU (OTA-INST-04) с контрольным установщиком `naive-rauc-grub` | сценарий `toctou` в `pilot_ab.py` | код готов, прогон идёт (журнал `P:\vm\pilot-q1.log`) |
| Подпись бандла plain > 2 ГиБ (CVE-2026-34155) | `scripts/rauc_sigcover.py`, `clients/rauc-verify/`, `results/rauc-sigcover-2026-11-01/` | готово: RAUC 1.8 (Debian 12) принимает подмену, 1.15.2 — нет |
| Корень только для чтения против OTA-PWR-06 | вариант `ext4-inplace-rootro`, `results/pilot-ab-20261101-191247/`, `-192320/` | 0 записей в слот A, 0 BRICK в модели разрыва |
| Word-версия ВКР по ГОСТ 7.32 | `docs/thesis/tools/build_docx.js`, `render_figures.ps1` → `docs/thesis/build/` | собирается; формулы перепечатать вручную |
| Введение, заключение, статьи | `docs/thesis/intro.md`, `conclusion.md`, `docs/papers/vak-article-draft.md`, `scored-draft.md` | черновики |

Главные результаты на сегодня:
* MVP: python-tuf и go-tuf не прерывают медленную отдачу (≥120 с), tuf-js прерывает через 100 с. Это расхождение реализаций, значимое для Uptane §5.4, а не для TUF.
* A/B: ни одного «кирпича» ни в одной модели обрыва. Найдено окно ~5 с после `rauc install` = succeeded: обрыв в этот момент → GRUB грузит старый слот, хотя ОС считает основным новый. Окно задаёт **период фонового сброса** (`vm.dirty_writeback_centisecs`), а не `commit=` и не `dirty_expire`. Без журнала (ext2, vfat) окна нет, **но** модель перестановок показывает нечитаемый `grubenv` (ext2: 1 из 14 состояний, vfat: 4 из 22). Бесплатной конфигурации нет; во всех случаях спасает аварийное правило в `grub.cfg`.
* Из «рваного» состояния на vfat устройство загружается, но **больше не обновляется**: `grubenv` 0 байт, и `rauc install` падает на первом шаге. Документация RAUC советует для `grubenv` EFI-раздел (vfat); **на UEFI с `grubenv` на ESP воспроизводится** (там окружение рвётся даже в префиксной модели).
* **Исправление найдено и проверено:** запись окружения на месте (без `O_TRUNC`) через `bootloader=custom` убирает окно и порчу на ext4, ext2 и vfat в обеих моделях обрыва; сквозной сценарий проходит на всех трёх. RAUC master по-прежнему использует `grub-editenv`.
* RAUC 1.8 в конфигурации по умолчанию принимает откат v2 → v1.
* Медленная отдача в python-tuf — осознанное решение мейнтейнеров (python-tuf#932), это не баг.
* В модели разрыва по секторам A/B не защищает **работающий** слот: разорванный блок журнала ext4 слота A (корень `rw`) → корень не монтируется → цикл загрузки. Защита: корень только для чтения, атомарная запись 4 КиБ, fsck в initramfs.

## С чего продолжить (по приоритету)

Полный список задач с приоритетами и критериями готовности — **`docs/BACKLOG.md`**. Состояние на 01.11.2026, ~22:15:

1. **Идут фоновые очереди** (журналы в `P:\vm`): `pilot-q1.log` (перестановки RAUC вокруг записи окружения), `pilot-q2.log` (резервированное окружение в модели разрыва), затем `quiet-batch.sh` → `pilot-quiet.log` — **окна на тихом хосте** (ждёт, пока не останется ни одного `pilot_ab.py`/`replay_state.py`; одна ВМ за раз): `net-slow:stream`, `rauc-grub window:ext4-c5,ext4-redundant`, `rauc1.15.2-grub window:ext4-c5,ext4-exponly,ext4-wbonly`, `swupdate-grub window:ext4-c5,vfat` с метками до 90 с, повтор реплея `replay-rauc18-1535b.log`; после неё `q5.sh` → `pilot-q5.log` (`reorder:ext4-inplace-rootro --torn` с повторной загрузкой BRICK).
2. **Текст главы 4 почти готов в заготовках** (`docs/thesis/drafts/`: `ch4_new_43.md`, `ch4_new_43_net.md`, `ch4_tail.md`, `fill_values.json`, `fill.py`, `ch4_patch_b.py`). После очередей: вписать в `fill_values.json` значения меток `W_RAUC1152`, `W_SWU`, `RAUC_SLOW`, `T418_RAUC_SLOW`, `RED_RESULT`, `T418_RED`, `CONCL_RED`, `CONCL_RAUC_NET`; `python fill.py` (должно остаться 0 меток); `python ch4_patch_b.py`. Заготовки лежат в репозитории.
3. Вставить в `docs/pilot-ab.md` новые разделы (заготовка `pilot_new_sections.md`), обновить сводную матрицу (`otabench threats … --out results/threat-matrix-2026-11-02`), примеры соответствия, `scored-draft.md` (окна), заключение (окна SWUpdate/RAUC 1.15.2), Word-сборку.
4. Не публиковать черновики в `docs/upstream/` (RAUC, SWUpdate, tuf-conformance, go-tuf, tough, libcsuit) без согласия автора.

Новое с прошлого обновления: TOCTOU (контроль FAIL, апдейтеры PASS); подпись бандла > 2 ГиБ (RAUC 1.8 принимает подмену); tough (4-й клиент TUF); фаззинг метаданных TUF (паника go-tuf v2.4.2, исправлена в master, не выпущена) и конверта SUIT; сетевые атаки на SWUpdate и потоковую установку RAUC (ложное сообщение SWUpdate о неудаче); выпадение из OTA на ext4 (RAUC 1.15.2, 1.8) и у SWUpdate на ext2/vfat; корень только для чтения и fsck в initramfs против OTA-PWR-06; две копии окружения; B5 (всё окно, 222 состояния); ложный BRICK под нагрузкой → повторная загрузка (Р24); пороги сервера по сумме байтов (Р25).

## Проверить перед тем, как писать главы
* ✅ (01.11) Названия тестов `mcuboot-sim`, `mender-integration`, `aktualizr-tests` в каталоге существуют (сверено с коммитами, см. шапку `threats.yaml`). Что проверяет каждый тест — `docs/external-tests.md` (01.11).
* ⏳ Категория «Вопросы кибербезопасности» (ISSN 2311-3456) — **вручную по официальному перечню ВАК**: веб-поиск подтверждает только вхождение в перечень. Поиск аналогов в eLibrary — тоже вручную.
* ✅ (01.11) slow retrieval в python-tuf: обсуждение #932 закрыто мейнтейнерами в 02.2025 как неразрешимое на уровне библиотеки, это ответственность интегратора. Issue в python-tuf и go-tuf **не заводить**. Черновик для tuf-conformance (только бесконечные данные и обрыв передачи): `docs/upstream/tuf-conformance-transport-tests.md`, не опубликован.

## Как запускать

| Что | Команда | Интерпретатор |
|---|---|---|
| MVP (TUF) | `bench\.venv\Scripts\python.exe -m otabench run --quick` | venv стенда |
| сводная матрица угроз | `bench\.venv\Scripts\python.exe -m otabench threats --mvp results\<run>\results.json --pilot results\pilot-ab-*\pilot.json --out results\<dir>` | venv стенда |
| автотесты стенда | `bench\.venv\Scripts\python.exe -m pytest -q bench\tests` | venv стенда |
| сборка A/B-образа (~6 мин) | `python scripts\build_ab_image.py` → `P:\vm\ab-v1.qcow2` | системный Python 3.13 |
| пилот A/B | `bench\.venv\Scripts\python.exe scripts\pilot_ab.py [--updater rauc-grub] --only <сценарии>` | venv стенда (нужен PyYAML: адаптер — YAML) |
| список сценариев пилота | `happy, broken, broken-unconfirmed, attacker, downgrade, cut-firstboot, cut-unconfirmed, crash-replay, window:<cfg>, reorder:<cfg> [--torn], happy:<cfg>`; `<cfg>` = `ext4-c5, ext4-c1, ext4-c30, ext4-wb1, ext4-wbonly, ext4-exponly, ext2, vfat, ext4-inplace, ext2-inplace, vfat-inplace, uefi-esp, uefi-esp-inplace` | |
| одно состояние из журнала + проверка живучести | `bench\.venv\Scripts\python.exe scripts\replay_state.py --base <вариант> --log <golden.log> --base-end N --extra M --liveness` | venv стенда |

Сценарии пилота пишут `bench/results/pilot-ab-<время>/pilot.json` **после каждого сценария**, так что прерывание не теряет готовое. Диски сценариев удаляются автоматически (`--keep-disks`, чтобы оставить).

## Данные на диске
* `P:\vm\debian-12-nocloud-amd64.qcow2` — базовый образ (0,4 ГБ).
* `P:\vm\ab-v1.qcow2` — A/B-образ, пересобран 01.11 с fstab `auto,nofail` (2,4 ГБ).
* `P:\vm\variants\` — кэш вариантов (оверлеи поверх `ab-v1`). С адаптером v2 имя `<адаптер>-<вариант>-<хэш>.qcow2`; хэш зависит от образа и текста шагов, поэтому после пересборки `ab-v1` или правки шага вариант пересоберётся сам (1–3 мин). Старые `ab-<вариант>.qcow2` (7,1 ГБ) больше не используются сценариями, **но нужны для разбора сохранённых журналов**: журнал воспроизводится только на тот диск, на котором записан (`ab-vfat.qcow2` → `reorder-vfat`, `ab-uefi-esp*.qcow2` → журналы UEFI, `ab-ext4-inplace.qcow2` → `--torn`). Не удалять, пока журналы нужны.
* Журналы записей для повторного анализа без нового прогона (по 1,1 ГБ): `P:\vm\pilot\20261031-225918\replay\golden.log` (45 точек, ext4), `P:\vm\pilot\20261101-003715\window-ext4-wb1\golden.log`, `P:\vm\pilot\20261101-103655\reorder-vfat\golden.log` (случай с нечитаемым `grubenv`).

## Подводные камни (уже наступали)
* **WHPX и тёплая перезагрузка:** ядро гостя зависает. Стенд эмулирует перезагрузку циклом питания (`VM.cold_reboot`). KVM в WSL на этой машине недоступен, лучше не тратить время на повторную проверку.
* **Кодировка консоли Windows (cp1251):** скрипты делают `sys.stdout.reconfigure(encoding="utf-8")`. Новые скрипты должны делать так же.
* **Сложные правки через встроенные heredoc в Bash ломаются на кавычках.** Писать патч в отдельный `.py`-файл и запускать его.
* **go-tuf-клиент** из tuf-conformance вызывает `date`; в `clients.yaml` для него добавлен PATH к Git `usr\bin`.
* **tuf-js под Node 24 на Windows** падает (assert libuv) на загрузке 2 МиБ, поэтому там вердикт ERROR, а не FAIL.
* **Место:** прогоны воспроизведения временно создают сырой диск на 12 ГБ и журнал на 1,1 ГБ; сырой диск удаляется в конце сценария. Если прогон прерван, проверить `P:\vm\pilot\*\*\replay.raw`.
* **Git:** `.gitattributes` держит LF во всём репозитории — гостевые файлы копируются в Linux-ВМ побайтно, CRLF их ломает. Коммиты — без строки `Co-Authored-By` (просьба автора).
* **Неподтверждённая загрузка не получается гонкой:** служба подтверждения иногда успевает раньше установки. Сценарии `*-unconfirmed` снимают подтверждение командой адаптера `unconfirm` и проверяют это по `status`.
* **Пилот запускается из venv** (`bench\.venv\Scripts\python.exe`): адаптер — YAML, а в системном Python 3.13 нет PyYAML.
* **UEFI-GRUB в Debian:** без `--no-uefi-secure-boot` `grub-install` ставит подписанный GRUB через shim, который игнорирует `--boot-directory` и грузит стоковое меню.
