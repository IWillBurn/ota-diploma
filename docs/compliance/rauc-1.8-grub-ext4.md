# Свидетельства соответствия: rauc-grub: ext4 /boot (default)

Сформировано `otabench compliance` 02.11.2026 из каталога угроз и результатов стенда. Это **свидетельства в границах моделей нарушителя и сбоя стенда** для испытанной конфигурации, а не оценка соответствия: PASS значит «нарушение не наблюдалось», «—» — угроза к этой реализации применима, но не испытана.

## Регламент (ЕС) 2024/2847 (CRA), приложение I

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| Annex I Part I (2)(c) | OTA-PWR-05 | OTA-PWR-05: ✅ (env unreadable in 0/115) | ✅ PASS |
| Annex I Part I (2)(f) | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTH-04 | OTA-AUTH-01: ✅; OTA-AUTH-02: —; OTA-AUTH-04: — | ✅ PASS по 1 из 3 угроз, остальные не испытаны |
| Annex I Part I (2)(h) | OTA-DOS-01, OTA-DOS-02, OTA-DOS-03, OTA-DOS-04, OTA-DOS-05, OTA-NET-01, OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-DOS-06 | OTA-DOS-01: —; OTA-DOS-02: —; OTA-DOS-03: —; OTA-DOS-04: —; OTA-NET-01: —; OTA-PWR-02: —; OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅; OTA-PWR-05: ✅ (env unreadable in 0/115) | ✅ PASS по 3 из 9 угроз, остальные не испытаны |
| Annex I Part II (7) | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |

## Правила ООН № 156

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 7.2.1.1 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |
| 7.2.2.1.1 | OTA-NET-01, OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-PWR-06, OTA-INST-02 | OTA-NET-01: —; OTA-PWR-02: —; OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅; OTA-PWR-05: ✅ (env unreadable in 0/115); OTA-PWR-06: ✅ (BRICK 0 of 18 torn states); OTA-INST-02: — | ✅ PASS по 4 из 7 угроз, остальные не испытаны |
| 7.2.2.1.2 | OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04 | OTA-PWR-02: —; OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅ | ✅ PASS по 2 из 3 угроз, остальные не испытаны |
| 7.2.2.4 | OTA-INST-02 | OTA-INST-02: — | — не испытано |

## EN 18031-1:2024

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 6.3.2 [SUM-2] | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| 6.3.2.1 [SUM-2] | OTA-INST-04 | OTA-INST-04: ✅ | ✅ PASS |
| 6.3.2.4.2 [IC.SUM-2.AuthIntVal.SecChan] | OTA-NET-02 | OTA-NET-02: — | — не испытано |
| 6.3.2.4.6.3 [AU.SUM-2.Sign] | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTH-03, OTA-AUTH-04, OTA-AUTHZ-01 | OTA-AUTH-01: ✅; OTA-AUTH-02: —; OTA-AUTH-04: — | ✅ PASS по 1 из 3 угроз, остальные не испытаны |
| 6.3.3.3 Guidance: | OTA-PWR-03, OTA-PWR-04 | OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅ | ✅ PASS |
| [AU.SUM-2.SecChan] | OTA-AUTH-02, OTA-NET-02 | OTA-AUTH-02: —; OTA-NET-02: — | — не испытано |

## NIST SP 800-193

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 4.1.2(2) | OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-PWR-06 | OTA-PWR-02: —; OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅; OTA-PWR-05: ✅ (env unreadable in 0/115); OTA-PWR-06: ✅ (BRICK 0 of 18 torn states) | ✅ PASS по 4 из 5 угроз, остальные не испытаны |
| 4.2.1.1(2) | OTA-AUTH-01, OTA-AUTH-03 | OTA-AUTH-01: ✅ | ✅ PASS |
| 4.2.1.1(3) | OTA-AUTH-01, OTA-AUTH-02, OTA-PWR-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: —; OTA-PWR-02: — | ✅ PASS по 1 из 3 угроз, остальные не испытаны |
| 4.2.1.3(2) | OTA-FRESH-02, OTA-KEY-01 | OTA-FRESH-02: ❌ | ❌ FAIL |
| 4.4.1 | OTA-PWR-06 | OTA-PWR-06: ✅ (BRICK 0 of 18 torn states) | ✅ PASS |
| 4.4.1(1)–(2) | OTA-PWR-03, OTA-PWR-04 | OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅ | ✅ PASS |
| 4.4.1(13) | OTA-FRESH-02 | OTA-FRESH-02: ❌ | ❌ FAIL |

## Приказ ФСТЭК России № 117

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| п. 39 | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTHZ-01 | OTA-AUTH-01: ✅; OTA-AUTH-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |
| п. 52–53 | OTA-PWR-03, OTA-PWR-04 | OTA-PWR-03: ✅ (154 states, 55 DEGRADED); OTA-PWR-04: ✅ | ✅ PASS |

## Приказ ФСТЭК России № 239

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| ОПО.1 | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| ОПО.2 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |
| п. 29.3.2 | OTA-PARSE-01 | OTA-PARSE-01: — | — не испытано |

## Методика тестирования обновлений безопасности (ФСТЭК России, 2022)

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| Т001 | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| Т002 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |

