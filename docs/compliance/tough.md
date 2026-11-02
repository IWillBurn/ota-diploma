# Свидетельства соответствия: tough

Сформировано `otabench compliance` 02.11.2026 из каталога угроз и результатов стенда. Это **свидетельства в границах моделей нарушителя и сбоя стенда** для испытанной конфигурации, а не оценка соответствия: PASS значит «нарушение не наблюдалось», «—» — угроза к этой реализации применима, но не испытана.

## Регламент (ЕС) 2024/2847 (CRA), приложение I

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| Annex I Part I (2)(f) | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTH-04 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅; OTA-AUTH-04: ✅ | ✅ PASS |
| Annex I Part I (2)(h) | OTA-DOS-01, OTA-DOS-02, OTA-DOS-03, OTA-DOS-04, OTA-DOS-05, OTA-NET-01, OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-DOS-06 | OTA-DOS-01: ✅; OTA-DOS-02: ✅; OTA-DOS-03: ✅; OTA-DOS-04: ✅; OTA-DOS-05: ✅; OTA-NET-01: ✅; OTA-PWR-01: ✅; OTA-PWR-02: ✅; OTA-DOS-06: ✅ | ✅ PASS |
| Annex I Part II (7) | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅ | ✅ PASS |

## Правила ООН № 156

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 7.2.1.1 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅ | ✅ PASS |
| 7.2.2.1.1 | OTA-NET-01, OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-PWR-06, OTA-INST-02 | OTA-NET-01: ✅; OTA-PWR-01: ✅; OTA-PWR-02: ✅ | ✅ PASS |
| 7.2.2.1.2 | OTA-PWR-01, OTA-PWR-02, OTA-PWR-03, OTA-PWR-04 | OTA-PWR-01: ✅; OTA-PWR-02: ✅ | ✅ PASS |

## EN 18031-1:2024

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 6.3.2 [SUM-2] | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| 6.3.2.1 [SUM-2] | OTA-INST-04 | OTA-INST-04: — | — не испытано |
| 6.3.2.4.2 [IC.SUM-2.AuthIntVal.SecChan] | OTA-NET-02 | OTA-NET-02: — | — не испытано |
| 6.3.2.4.6.3 [AU.SUM-2.Sign] | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTH-03, OTA-AUTH-04, OTA-AUTHZ-01 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅; OTA-AUTH-03: ✅; OTA-AUTH-04: ✅; OTA-AUTHZ-01: — | ✅ PASS по 4 из 5 угроз, остальные не испытаны |
| [AU.SUM-2.AccContMech] | OTA-AUTHZ-01 | OTA-AUTHZ-01: — | — не испытано |
| [AU.SUM-2.SecChan] | OTA-AUTH-02, OTA-NET-02 | OTA-AUTH-02: ✅; OTA-NET-02: — | ✅ PASS по 1 из 2 угроз, остальные не испытаны |

## NIST SP 800-193

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| 4.1.2(2) | OTA-PWR-02, OTA-PWR-03, OTA-PWR-04, OTA-PWR-05, OTA-PWR-06 | OTA-PWR-02: ✅ | ✅ PASS |
| 4.1.2(2) RTU/CTU | OTA-PWR-01 | OTA-PWR-01: ✅ | ✅ PASS |
| 4.1.2(4) | OTA-KEY-03 | OTA-KEY-03: — | — не испытано |
| 4.2.1.1(2) | OTA-AUTH-01, OTA-AUTH-03 | OTA-AUTH-01: ✅; OTA-AUTH-03: ✅ | ✅ PASS |
| 4.2.1.1(3) | OTA-AUTH-01, OTA-AUTH-02, OTA-PWR-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅; OTA-PWR-02: ✅ | ✅ PASS |
| 4.2.1.3(2) | OTA-FRESH-02, OTA-KEY-01 | OTA-FRESH-02: ❌; OTA-KEY-01: ✅ | ❌ FAIL |
| 4.4.1(13) | OTA-FRESH-02 | OTA-FRESH-02: ❌ | ❌ FAIL |

## Приказ ФСТЭК России № 117

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| п. 39 | OTA-AUTH-01, OTA-AUTH-02, OTA-AUTHZ-01 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅; OTA-AUTHZ-01: — | ✅ PASS по 2 из 3 угроз, остальные не испытаны |

## Приказ ФСТЭК России № 239

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| ОПО.1 | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| ОПО.2 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅ | ✅ PASS |
| п. 29.3.2 | OTA-PARSE-01 | OTA-PARSE-01: ✅ | ✅ PASS |
| п. 31 | OTA-AUTHZ-01 | OTA-AUTHZ-01: — | — не испытано |

## Методика тестирования обновлений безопасности (ФСТЭК России, 2022)

| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |
|---|---|---|---|
| Т001 | OTA-AUTH-01 | OTA-AUTH-01: ✅ | ✅ PASS |
| Т002 | OTA-AUTH-01, OTA-AUTH-02 | OTA-AUTH-01: ✅; OTA-AUTH-02: ✅ | ✅ PASS |
| ≈ Т001 | OTA-DOS-05 | OTA-DOS-05: ✅ | ✅ PASS |

