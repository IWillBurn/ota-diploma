# otabench: MVP исполняемого бенчмарка систем OTA-обновлений

Стенд прогоняет клиентов обновления по каталогу угроз и строит матрицу
«угроза × реализация» с метриками. MVP покрывает экосистему TUF (три реальные
реализации и одну контрольную), атаки сетевого уровня и обрыв питания на уровне
процесса. Архитектура рассчитана на добавление Uptane, SUIT и A/B-апдейтеров
через тот же протокол адаптеров.

```
catalog/threats.yaml      машиночитаемый каталог угроз v0.2 (40 записей)
clients.yaml              реализации под тестом
clients/                  адаптеры: python-tuf, go-tuf (из tuf-conformance), tuf-js (свой), naive + 4 мутанта (контроль)
otabench/server.py        сервер-нарушитель: правила подмены/повтора/бесконечных/медленных данных/обрыва
otabench/adapter.py       протокол адаптеров (CLI tuf-conformance) + управление процессом: таймауты, kill
otabench/scenarios.py     16 сценариев с оракулами
otabench/runner.py        параллельный прогон матрицы
otabench/report.py        matrix.md / matrix.html, дифференциальный анализ, доля блокируемых атак
```

## Быстрый старт

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1     # один раз
.venv\Scripts\python.exe -m otabench list                       # сценарии
.venv\Scripts\python.exe -m otabench coverage                   # покрытие каталога
.venv\Scripts\python.exe -m otabench run --quick                # ~2 мин, 3 испытания, короткие лимиты
.venv\Scripts\python.exe -m otabench run --trials 10 --jobs 8   # полный прогон (~6–8 мин)
```

Результаты сохраняются в `results/<время>/`: `results.json` (сырые данные),
`matrix.md` и `matrix.html`.

## Уровень ОС: пилот A/B (RAUC + GRUB в QEMU)

Сценарии обращаются к апдейтеру только через адаптер устройства (протокол v2,
`docs/adapter-protocol.md`): `updaters/<имя>.yaml` описывает установку, состояние
устройства и строки загрузчика на консоли. Чтобы испытать другой апдейтер, нужен
его образ и такой файл; код сценариев не меняется.

```
updaters/rauc-grub.yaml   адаптер RAUC + GRUB: команды, артефакты, разбор консоли, варианты
otabench/device.py        загрузка адаптера v2, вызов его команд в госте
otabench/vm.py            управление ВМ: QMP (обрыв питания), serial-консоль, гостевой агент, blklogwrites
otabench/writelog.py      разбор и воспроизведение журнала блочных записей (формат dm-log-writes)
vm/guest/                 гостевые файлы: grub.cfg (выбор слота), system.conf RAUC, fstab, mark-good
scripts/build_ab_image.py сборка образа ab-v1.qcow2 из Debian 12 nocloud (~6 мин)
scripts/pilot_ab.py       сценарии: happy, broken, attacker, downgrade, cut-firstboot, crash-replay,
                          window:/reorder:/happy:<вариант>
scripts/replay_state.py   одно состояние из журнала записей: загрузить, осмотреть, проверить живучесть
vm/guest/otabench-bootenv обработчик загрузчика RAUC (bootloader=custom), пишущий grubenv на месте — исправление
scripts/vm_probe.py       проверка хоста: ускорение, время загрузки, blklogwrites
scripts/qmp_powercut.py   ручной обрыв питания запущенной ВМ
```

Что нужно: QEMU для Windows с WHPX (или Linux с KVM) и базовый образ
`debian-12-nocloud-amd64.qcow2` в `P:\vm\`.

```powershell
python scripts\build_ab_image.py                     # -> P:\vm\ab-v1.qcow2
.venv\Scripts\python.exe scripts\pilot_ab.py         # все сценарии, адаптер rauc-grub
.venv\Scripts\python.exe scripts\pilot_ab.py --only crash-replay --points 30 --liveness 3
.venv\Scripts\python.exe scripts\pilot_ab.py --updater <имя> --only happy,broken,attacker
```

Результаты пишутся в `results/pilot-ab-<время>/pilot.json`, разбор лежит в
`docs/pilot-ab.md`. Под WHPX тёплая перезагрузка гостя подвешивает ядро,
поэтому стенд эмулирует перезагрузку циклом питания: `-no-reboot` плюс
перезапуск QEMU на том же диске (см. `VM.cold_reboot`).

## Протокол адаптера

Используется CLI-протокол
[tuf-conformance](https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md)
без изменений: `init`, `refresh`, `download`, код возврата 0 или 1. Любой клиент,
у которого уже есть entrypoint для tuf-conformance, подключается одной строкой в
`clients.yaml`. Поверх протокола стенд добавляет:

* жёсткие таймауты и измерение времени;
* внешний «рубильник» `kill_switch`, который выполняет TerminateProcess/SIGKILL
  без atexit и flush; так эмулируется обрыв питания на уровне процесса;
* наблюдение только за внешними эффектами: что клиент сохранил как доверенные
  метаданные, какие байты артефакта оставил на диске, кто первым закрыл
  соединение.

Python-клиенты запускаются базовым интерпретатором с `PYTHONPATH` на
site-packages из venv. Лаунчер venv на Windows порождает дочерний процесс, и
kill попал бы не в него.

## Сценарии

| Сценарий | Угроза | Чем отличается от tuf-conformance |
|---|---|---|
| arb-target-substitution | OTA-AUTH-01 | есть аналог; добавлен для полноты матрицы |
| arb-metadata-tamper | OTA-AUTH-02 | есть аналог |
| arb-keyid-spoofing | OTA-AUTH-03 | подпись чужим ключом с keyid легитимного |
| freeze-expired-timestamp | OTA-FRESH-01 | реальное истечение срока, без faketime |
| rollback-timestamp | OTA-FRESH-02 | есть аналог |
| mix-and-match | OTA-FRESH-03 | частично есть |
| online-keys-downgrade | OTA-KEY-01 | модель нарушителя «скомпрометированы онлайн-ключи» явно |
| online-keys-arbitrary | OTA-KEY-02 | нет аналога |
| endless-metadata / endless-artifact | OTA-DOS-01/02 | **нет**: транспортный уровень, поток без Content-Length |
| slow-metadata / slow-artifact | OTA-DOS-03/04 | **нет**: капельная отдача ниже порога read-timeout |
| dropped-connection | OTA-NET-01 | **нет**: обрыв посреди артефакта и восстановление |
| powercut-refresh | OTA-PWR-01 | **нет**: kill в каждой событийной точке обновления метаданных с ротацией root (запрос i × 3 фазы) |
| powercut-download | OTA-PWR-02 | **нет**: kill во время загрузки и записи артефакта 2 МиБ |
| online-keys-freeze | OTA-KEY-04 | **нет**: свежие подписи онлайн-ключей указывают на истёкший targets |
| mirror-errors | OTA-DOS-05 | **нет**: единственное зеркало отвечает 503; клиент обязан сообщить об отказе, не испортив хранилище |
| drop-requests | OTA-DOS-06 | **нет**: соединение закрывается без ответа |
| extra-data-artifact | OTA-AUTH-04 | **нет**: байты после подписанного образа (конечные, с Content-Length) |
| unsupported-spec-version | OTA-PARSE-02 | **нет**: подписанный timestamp с `spec_version` 2.0.0 |

**Вердикты.** `PASS`: атака заблокирована или сбой пережит. `FAIL`: атака
удалась или клиент не восстановился. `PARTIAL`: пережита часть случайных испытаний (при переборе точек одна непережитая точка — уже `FAIL`).
`ERROR`: не выполнено предусловие. ERROR не считается вердиктом о безопасности.
Например, если честная загрузка 2 МиБ падает без всякого сбоя, сбой платформы
не будет приписан клиенту как проблема устойчивости.

**Метрики.** `time_to_abort_s` (время до прерывания загрузки), `bytes_pushed`
(сколько байт сервер успел отдать до разрыва), `survival_rate` (выживаемость
при обрыве), `mean_recovery_s` (время восстановления), `torn_file_observed`
(сколько раз после обрыва в каталоге целей лежал «рваный» файл).

**Контрольная реализация `naive`.** Клиент намеренно наивный: подписи и хэш
проверяет, а сроки, версии и лимиты нет, пишет файлы на месте и доверяет
существующему файлу. Если стенд не отличает его от настоящих TUF-клиентов,
стенд ничего не измеряет. Поэтому `naive` входит в каждый прогон. Мутанты
`naive-nosig`, `naive-anykey`, `naive-nohash` и `naive-keeptorn` отключают по
одной проверке. Раздел «Mutation analysis» в `matrix.md` показывает, кого ловит
каждый сценарий. Сценарий, который не ловит никого, ещё не доказал, что
способен что-то обнаружить.

**Дифференциальный анализ.** Сценарий помечается ⚡, если реальные реализации
одной спецификации дали разные вердикты.

## Ограничения MVP (честно)

* В MVP (TUF-клиенты) обрыв питания эмулируется только на уровне процесса:
  страничный кэш ОС не теряется. Уровни «блочные записи» и «полная система»
  реализованы в пилоте A/B (раздел выше, `docs/pilot-ab.md`).
* Прогоны выполнялись на Windows 11. На Linux поведение fsync и rename другое,
  итоговые эксперименты нужно ставить на Linux.
* tuf-js под Node 24.19 на Windows падает с assert libuv
  (`UV_HANDLE_CLOSING`, `src\win\async.c:94`) на загрузке 2 МиБ даже без сбоев.
  Сценарий `powercut-download` для него поэтому даёт ERROR, а не FAIL.
* Лимиты медленных атак (120 с) и бесконечных данных (64 МиБ / 30 с) являются
  политикой стенда, а не требованием спецификации. Решение принимается по
  метрике `time_to_abort_s`.
* Slow retrieval убрали из целей TUF в v1.0.7 (коммит `f9122f1`, 2020-09-08).
  Нормативное требование есть только в Uptane 2.1.0 §5.4 («All ECUs SHALL
  monitor the download speed»). Поэтому FAIL в сценариях slow-* означает
  «требование Uptane не выполнено» и «реализации TUF расходятся», а не
  «нарушен TUF 1.0.37».
