# Исполняемый OTA-бенчмарк занимает пустую межэкосистемную нишу

Тема актуальна и защитимо нова, но новизна в сочетании, а не в отдельных техниках. По состоянию на 31.10.2026 не найдено ни одного открытого исполняемого бенчмарка, который проверял бы клиенты TUF, Uptane, IETF SUIT и A/B-апдейтеры (RAUC, SWUpdate, Mender) по единому каталогу угроз и одновременно измерял бы устойчивость к отключению питания. Ближайший аналог, tuf-conformance, гоняет 119 тестовых случаев на шести TUF-клиентах, но проверяет только обработку метаданных. В нём нет медленной и бесконечной отдачи, обрывов питания, установки и загрузки, Uptane и SUIT. Поток уязвимостей при этом не ослабевает: в 2026 г. опубликованы advisories по go-tuf, tough, RAUC, SWUpdate, Mender, ostree/bootc и MCUboot, и часть из них повторяет давно исправленные классы ошибок. Такие повторы ловит только набор, который перезапускают на каждом релизе. Регуляторы требуют «безопасного распространения обновлений»: CRA применяется с 11.12.2027, гармонизированных стандартов в OJ пока нет, к тому же действуют приказы ФСТЭК № 117 и № 239. Но защиту от заморозки ни один документ явно не требует, атомарность и восстановление после сбоя есть только в UN R156 и NIST SP 800-193, а проверка почти везде документальная. MVP стенда otabench уже дал первую дифференциальную находку. При медленной отдаче python-tuf 7.0.1 и go-tuf v2.4.2 не прервались за 120 с, а tuf-js 6.0.1 прервался через 100 с. Эту находку нужно формулировать относительно **Uptane 2.1.0 §5.4** («SHALL monitor the download speed»), а не как нарушение TUF: slow retrieval убран из спецификации TUF в **v1.0.7 (commit f9122f1, 2020-09-08)**. Защитима формулировка «насколько нам известно, первый открытый исполняемый кросс-экосистемный бенчмарк, который трассирует угрозы к моделям угроз спецификаций и к CRA/ФСТЭК и объединяет атаки со стороны репозитория с систематическим перебором точек сбоя питания». Формулировки «первая таксономия», «первый conformance-сьют», «первое тестирование безопасности OTA» и «доказательство соответствия» недопустимы.

## Пятнадцать advisories 2026 года бьют по реализациям, а не по спецификациям

Главный аргумент актуальности — не старые инциденты, а свежий поток advisories в тех реализациях, которые предстоит тестировать. Возьмём только узкий круг OTA-клиентов и апдейтеров (TUF-клиенты, RAUC, SWUpdate, Mender, ostree/bootc, MCUboot, U-Boot): в 2026 г. по ним опубликовано **не менее 15 advisories**. Примеры из TUF-клиентов:

| CVE | Реализация | Суть ошибки |
|---|---|---|
| CVE-2026-23992 | go-tuf/v2 до 2.3.1 | принимался порог делегирования 0, что «effectively disables signature verification» ([GHSA-fphv-w9fq-2525](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-fphv-w9fq-2525)) |
| CVE-2026-23991 | go-tuf/v2 | некорректно типизированные метаданные роняли клиент **до** проверки подписи ([GHSA-846p-jg2w-w324](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-846p-jg2w-w324)) |
| CVE-2026-6966 | tough | дубликаты подписей засчитывались в порог для делегированных ролей ([GHSA-8m7c-8m39-rv4x](https://github.com/awslabs/tough/security/advisories/GHSA-8m7c-8m39-rv4x)) |
| CVE-2026-6967 | tough | `load_delegations` пропускал проверки срока действия, хеша и длины ([GHSA-4v58-8p28-2rq3](https://github.com/awslabs/tough/security/advisories/GHSA-4v58-8p28-2rq3)) |

CVE-2026-6966 — **тот же класс ошибки, что CVE-2020-15093 шестью годами ранее** ([GHSA-5q2r-92f9-4m49](https://github.com/awslabs/tough/security/advisories/GHSA-5q2r-92f9-4m49)), только в другом пути кода. Все эти атаки спецификация TUF предотвращает. Ошибки сидят в коде клиентов, поэтому внешний исполняемый тест имеет смысл.

В embedded-Linux стеке картина та же, но классы ошибок шире:

| CVE | Реализация | Суть ошибки |
|---|---|---|
| CVE-2026-34155 | RAUC до 1.15.2 | при payload больше 2 ГиБ из-за целочисленного переполнения подпись покрывала «only the first few bytes of the payload» ([GHSA-6hj7-q844-m2hx](https://github.com/rauc/rauc/security/advisories/GHSA-6hj7-q844-m2hx)) |
| CVE-2025-41259 (опубликован 2026-06-03) | SWUpdate | хеши файлов проверялись при распаковке в `/tmp` и не перепроверялись перед установкой ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-41259)) |
| CVE-2026-109399 | SWUpdate по 2026.05.1 включительно | при построении цепочки доверия использовались сертификаты, вложенные в CMS SignedData ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109399)) |
| CVE-2025-67903 | Mender Client 5.0.0–5.0.3 | файлы payload, не перечисленные в манифесте с контрольной суммой, проходили мимо проверки подписи ([Mender](https://mender.io/blog/cve-2025-67903-signature-verification-bypass-in-mender-client)) |
| CVE-2026-16460 | bootc, ostree | подготовленные развёртывания финализировались без повторной проверки по текущей политике подписей ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-16460)) |
| CVE-2026-14296 | MCUboot (Direct XIP) | для основного и радиообраза могли быть выбраны разные слоты ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-14296)) |

Версия 2026.05.1 — последний релиз SWUpdate на дату исследования, то есть CVE-2026-109399 затрагивает актуальную версию. Классы этих ошибок — граничные размеры, неподписанные области, TOCTOU между проверкой и установкой, рассогласование состояния слотов. Все они лежат за пределами вопроса «подпись верна или нет». Поэтому бенчмарку нужен не только злонамеренный сервер, но и подготовленные артефакты, инъекция гонок и инъекция сбоев. TOCTOU-класс (RAUC CVE-2020-25860, SWUpdate CVE-2025-41259) злонамеренный сервер в принципе не ловит ([GHSA-cgf3-h62j-w9vv](https://github.com/rauc/rauc/security/advisories/GHSA-cgf3-h62j-w9vv)).

Есть и прямое доказательство, что исполняемый набор находит ошибки, которые пропускают аудиты. CVE-2024-47534 в go-tuf обнаружена при разработке `test_graph_traversal` в tuf-conformance ([GHSA-4f8r-qqr9-fq8j](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-4f8r-qqr9-fq8j)). Клиент обходил делегирования в недетерминированном порядке Go-map и мог скачать не тот артефакт. Пять advisories tough от 28.03.2025 (CVE-2025-2885…2888 и GHSA-j8x2-777p-23fc) прямо помечены «identified by the TUF-Conformance project» ([GHSA-5vmp-m5v2-hx47](https://github.com/awslabs/tough/security/advisories/GHSA-5vmp-m5v2-hx47)).

Регрессии дают отдельный довод. GRUB CVE-2021-3418 описан как «a reintroduction of CVE-2020-15705» ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-3418)). Обновление стека обслуживания Windows само откатило ранее выпущенные исправления (CVE-2024-43491) ([TechTarget](https://www.techtarget.com/cybersecurity/news/366610421/Microsoft-Zero-day-vulnerability-rolled-back-previous-patches)). Такие ошибки находит только набор, который перезапускают на каждом релизе, а не разовый аудит.

Инциденты делятся на два класса, и оба соответствуют половинам темы. Первый класс — атаки через канал обновлений. В SolarWinds и ShadowHammer вредоносное обновление было корректно подписано:

* SolarWinds: из примерно 33 000 уведомлённых клиентов «fewer than 18,000» могли установить заражённые сборки ([SEC 8-K](https://www.sec.gov/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm)).
* ShadowHammer: троянизированные апдейтеры были «signed with legitimate certificates», их установили более 57 000 пользователей Kaspersky ([Securelist](https://securelist.com/operation-shadowhammer/89992/)).

Клиентская проверка против таких атак бессильна, и бенчмарк должен честно вывести их за рамки. В свежих случаях проверка отсутствовала или была фиктивной:

* Notepad++: с июня по декабрь 2025 г. трафик выбранных целей перенаправлялся на манифесты атакующего. Корневая причина зафиксирована как «update metadata and installers are not cryptographically verified» (CVE-2025-15556) ([Notepad++](https://notepad-plus-plus.org/news/hijacked-incident-info-update/), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-15556)).
* AOMEI, 2026 г.: атакующий на 10, 6 и 5 минут подменял конфигурацию с URL и **MD5 ожидаемого пакета**. GTIG прямо пишет, что клиенты «should never rely solely on transport-layer HTTPS or remote checksums» ([Google GTIG](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)).

Случай AOMEI — готовый тест «сервер отдаёт совпадающий хеш для подменённого артефакта». Минутные окна подмены показывают, что серверный мониторинг здесь не спасает и надёжна только клиентская проверка.

Второй класс — отказоустойчивость. Обновление CrowdStrike затронуло **8,5 млн** Windows-устройств ([Microsoft](https://blogs.microsoft.com/blog/2024/07/20/helping-our-customers-through-the-crowdstrike-outage/)). OTA-обновление Jeep Wrangler 4xe вызвало потерю тяги и отзыв **24 238** автомобилей по кампании NHTSA 25V710 ([NHTSA](https://static.nhtsa.gov/odi/rcl/2025/RCLRPT-25V710-7238.pdf)).

## Регуляторы требуют безопасных обновлений, но проверяют их документами

CRA (Регламент (ЕС) 2024/2847, OJ 20.11.2024) применяется с **11.12.2027**. Обязанности по уведомлению по ст. 14 действуют с 11.09.2026 ([Springlex, Art. 71](https://www.springlex.eu/en/packages/cra/cra-regulation/article-71/); [ELI](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)). Приложение I требует ([Springlex, Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)):

* обновлений безопасности, по умолчанию автоматических, с возможностью отказа и отсрочки (Part I (2)(c));
* защиты целостности «programs» (Part I (2)(f));
* доступности основных функций и после инцидента (Part I (2)(h));
* «mechanisms to securely distribute updates» (Part II (7)).

Поиск по полному тексту Приложения I не находит слов «rollback», «downgrade», «freeze», «replay», «key compromise», «TUF», «Uptane». На 17.10.2026 в OJ не опубликован ни один гармонизированный стандарт CRA ([CRA Evidence](https://craevidence.com/blog/cyber-resilience-act-implementation-timeline-2027)). Горизонтальный EN 40000-1-4, который должен покрыть большую часть Part I, остаётся проектом prEN ([SecureHabits](https://www.securehabits.nl/knowledge/cra-harmonised-standards-overview/)). Для продуктов категории по умолчанию соответствие подтверждается самодекларацией по модулю A ([Springlex, Art. 32](https://www.springlex.eu/en/packages/cra/cra-regulation/article-32/)). Поэтому угрозы отката, заморозки, mix-and-match и компрометации ключей привязываются к CRA только интерпретационно, через (2)(f) и Part II (7). В диссертации это нужно подавать как трассировку, а не как цитату нормы.

Европейский слой радиооборудования и IoT ближе всего к исполняемой проверке, но только для базовой подлинности. Требование EN 18031-1 SUM-2 обязательно через делегированный акт RED с 1.08.2025. Его проверка функциональной достаточности [AU.SUM-2.Sign] требует подтвердить, что не устанавливаются ([NEK EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)):

* неподписанное обновление;
* обновление с изменённой подписью;
* изменённое обновление с подписью от неизменённого;
* обновление, подписанное неуполномоченным лицом.

Слово «roll-back» встречается только в 6.3.3.3 Guidance. По Restriction 1 разделы «rationale» и «guidance» презумпции соответствия не дают ([Commission EN 18031 guidance](https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/areas_interes/equipos-telecomunicacion/documents/Guia-aplicacion-EN-18031.pdf)). В ETSI EN 303 645 анти-откат упомянут только в EXAMPLE 7. По NOTE 7 к 5.3-10 доверительным отношением считается даже «confirmation by the user» ([EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf)). В TS 103 701 функциональный тест 5.3-2-2 сводится к фразе «the TL shall devise functional attacks», фиксированных векторов нет ([TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf)).

Единственная регуляторная норма, прямо требующая отказоустойчивости обновления, — UN R156 ([UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf)):

* 7.2.2.1.1: «restore systems to their previous version in case of a failed or interrupted update or … safe state»;
* 7.2.2.1.2: энергии должно хватить на обновление, включая возможное восстановление.

Но и здесь формула — «the vehicle manufacturer shall demonstrate», стандартизованной процедуры испытаний нет. UN R155 Annex 5 — единственный найденный регуляторный каталог угроз, который называет компрометацию криптографических ключей поставщика (12.4), DoS против сервера обновлений (13.1) и даунгрейд ЭБУ через replay (6.3) ([UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf)). Технически полнее всех NIST SP 800-193 ([SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf)):

* анти-откат: «shall be capable of preventing unauthorized updates … to an earlier authentic version» (4.2.1.3(2));
* работоспособность «even in the event of … power loss in the middle of a flash write operation» (4.1.2(2)).

Однако это рекомендации без тестовой методики.

Российская регуляторика описывает управление обновлениями на стороне оператора, а не свойства механизма обновления:

* **Приказ ФСТЭК № 117** (действует с 01.03.2026), п. 39: требует «проверки подлинности и целостности обновлений» и тестирования до применения в промышленном контуре; «бесконтрольная установка обновлений» не допускается ([fstec.ru](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117)).
* **Приказ № 239**: меры ОПО.1–ОПО.4 (доверенный источник, контроль целостности, тестирование, установка). Требования к разработчику по п. 29.3.3 оцениваются «на основе результатов анализа материалов и документов, представляемых разработчиком» (п. 29.4) ([legalacts.ru, № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/)).
* **«Методика тестирования обновлений безопасности»** ФСТЭК от 28.10.2022: шесть исполняемых тестов Т001–Т006. Они проверяют **пакет обновления**: идентичность при получении из разных источников, подлинность, антивирусный контроль, поиск опасных конструкций, мониторинг активности, ручной анализ. Об откате, заморозке или сбое питания в Методике ничего нет ([legalacts.ru, Методика](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/)).

Отсюда терминологическая коллизия, которую нужно снять уже в первой главе. В русскоязычной практике «тестирование обновлений безопасности» означает проверку обновлений по Методике; так её и автоматизируют Алейников и Жуков (2025) ([КиберЛенинка](https://cyberleninka.ru/article/n/ob-avtomatizatsii-testirovaniya-bezopasnosti-obnovleniy-programmnogo-obespecheniya-v-informatsionnoy-sisteme)). Тема же диссертации — тестирование **систем** обновления. Т001 (сверка идентичности обновлений из разных каналов) — единственный российский контроль, который хотя бы частично защищает от целевой подмены и злонамеренных зеркал.

| Свойство системы обновления | Где требуется нормативно | Как проверяется на практике |
|---|---|---|
| Подлинность и целостность | CRA Annex I; EN 18031 SUM-2; EN 303 645 5.3-10; R156 7.2.1.1; SP 800-193 4.2.1.1; приказ № 117 п. 39; приказ № 239 ОПО.2 | В основном документы. Исполняемые негативные тесты есть только в EN 18031 SUM-2 и в Методике ФСТЭК (Т002, выполняет оператор) |
| Анти-откат | SP 800-193 4.2.1.3(2) («shall»); SP 800-147 3.1.1 («should»). В EN 303 645 и R155 только как пример | Нормативного теста нет |
| Свежесть (защита от заморозки) | Явно нигде | — |
| Устойчивость к компрометации ключей | R155 12.4/M11; SP 800-193 4.1.2(4) | Аудит процессов |
| Атомарность, восстановление после сбоя | R156 7.2.2.1.1–7.2.2.1.2; SP 800-193 4.1.2(2), 4.4.1. В EN 18031 и EN 303 645 только информативно | «Demonstration» производителя |
| Защита от медленной и бесконечной отдачи | CRA Part I (2)(h) (DoS, интерпретационно); R155 13.1 (сервер) | Документы |

Вывод для позиционирования такой. Свежесть явно не требует ни один из рассмотренных документов. Анти-откат нормативен только у NIST, атомарность — только в R156 и SP 800-193, а исполняемые тесты есть лишь для базовой проверки «отклонить неподписанное». Поэтому бенчмарк разумно позиционировать как **исполняемое дополнение** к существующим требованиям:

* к EN 18031 SUM-2 — как расширение её негативных тестов;
* к TS 103 701 5.3-2-2 — как воспроизводимые версии атак, которые лаборатория должна «devise»;
* к R156 7.2.2.1.x — как проверяемый вариант формулы «demonstrate»;
* к п. 39 приказа № 117 — как тесты механизма поверх тестов содержимого.

Регуляторные столбцы каталога неизбежно будут разреженными. Это не дефект, а результат: пустые клетки нужно показывать пустыми, а не натягивать соответствие.

## Спецификации расходятся в деталях, и из расхождений строятся оракулы

Основу каталога составляют шесть документов, и их версии нужно зафиксировать:

| Документ | Версия и дата | Как цитировать |
|---|---|---|
| TUF | 1.0.37 (`Status: LS`), 2026-10-08 | ссылкой на тег, а не на «latest», который дрейфует ([TUF v1.0.37](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)) |
| Uptane Standard | 2.1.0, 2023 г. | [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md) |
| RFC 9019 | апрель 2021 | [RFC 9019](https://www.rfc-editor.org/rfc/rfc9019) |
| RFC 9124 | январь 2022 | [RFC 9124](https://www.rfc-editor.org/rfc/rfc9124) |
| draft-ietf-suit-manifest | -37, 18.06.2026; всё ещё Internet-Draft в очереди RFC Editor | как «work in progress» ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/)) |
| OWASP ISVS | 1.0, октябрь 2025 | [ISVS](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS) |

Модели угроз в этих документах устроены по-разному. TUF §1.5.2 перечисляет десять классов атак. Uptane §4.3 называет десять типов атак, сгруппированных по четырём целям нарушителя. Среди них есть отсутствующие в TUF «Partial bundle installation attack» и «Drop-request attack». RFC 9124 вводит 18 идентификаторов THREAT.\*, 21 REQ.SEC.\* и 14 REQ.USE.\*, но угроз отключения питания, бесконечной или медленной отдачи в нём нет ([RFC 9124](https://www.rfc-editor.org/rfc/rfc9124)).

Для MVP важнее всего история slow retrieval:

1. В **TUF v1.0.6** цель защиты звучала так: «**Slow retrieval attacks.** An attacker cannot prevent clients from being aware of interference with receiving updates by responding to client requests so slowly that automated updates never complete» ([TUF v1.0.6](https://github.com/theupdateframework/specification/blob/v1.0.6/tuf-spec.md)).
2. **Коммит f9122f1** (Joshua Lock, **2020-09-08**, «Remove slow retrieval attacks from protections») убрал этот пункт. Обоснование: «nothing in the specification provides any protections against this class of attack… implementers are left to their own devices». Там же признано: «The reference implementation does not currently protect against slow retrieval attacks» ([commit f9122f1](https://github.com/theupdateframework/specification/commit/f9122f1662426b217accbc4017d1a3f36afc3e16)).
3. Изменение влито через PR #111 29.09.2020 и впервые вышло в **TUF v1.0.7** ([PR #111](https://github.com/theupdateframework/specification/pull/111)). Это подтверждено по истории репозитория спецификации: `git log -S` находит ровно два коммита, добавление пункта и его удаление.

В действующей версии 1.0.37 slow retrieval среди целей защиты нет. Uptane 2.1.0, напротив, сохраняет «_Slow retrieval attack_» в §4.3.2 и в **§5.4** требует: «All ECUs SHALL monitor the download speed of image metadata and image binaries to detect and respond to a slow retrieval attack» ([Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)). С SHOULD до SHALL это требование подняли в версии 2.0.0 (2022-01-18) ([Uptane changelog](https://github.com/uptane/deployment-considerations)). Числового порога Uptane не задаёт. Поэтому проверяемое свойство звучит как «клиент обнаруживает атаку и прерывает загрузку или сообщает о ней за ограниченное время», а не как фиксированная минимальная скорость.

Расхождения помельче для оракулов не менее важны:

* **Равные версии.** TUF 5.4.3.1 требует строго большей версии timestamp, а при равной — прервать работу **без ошибки**. Uptane 5.4.4.4 s3 допускает «less than or equal». Для root TUF 5.3.5 требует ровно N+1, Uptane 5.4.4.3 s2.4 — «less than or equal» ([TUF v1.0.37 §5](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#detailed-client-workflow); [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)).
* **Mix-and-match.** В TUF это метаданные, которые никогда не существовали вместе. В Uptane §4.3.3 это взаимно несовместимые **образы**. FRESH-03 стоит разделить на 03a и 03b.
* **Откат в SUIT.** REQ.SEC.SEQUENCE в RFC 9124 защищает последовательность **манифестов** и прямо разрешает намеренный даунгрейд через манифест с большим номером ([RFC 9124 §4.3](https://www.rfc-editor.org/rfc/rfc9124#section-4.3)).
* **Уполномоченный откат.** NIST IR 8259A требует возможности отката для уполномоченных лиц, а SP 800-193 запрещает его неуполномоченным ([IR 8259A](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf)). Правильный тест: «уполномоченный даунгрейд возможен, неуполномоченный отклонён».

Формальный анализ Lorch и соавт. (RAID 2024) нашёл в Uptane шесть новых уязвимостей. Finding 1 — заморозка на Secondary с частичной верификацией: §5.4.3.1 не предписывает прерываться, если аттестации времени нет ([RAID 2024](https://doi.org/10.1145/3678890.3678927)). Это готовый сценарий OTA-TIME-01 и пример моста «формальная находка → исполняемый тест». Сами формальные работы такого моста не строят.

Для отказоустойчивости нормативные опоры слабее:

* RFC 9019 §3: «Devices must not fail when a disruption, such as a power failure or network interruption, occurs during the update process» ([RFC 9019 §3](https://www.rfc-editor.org/rfc/rfc9019#section-3)).
* SUIT -37 §6.3.1 «Resilience to Disruption»: процессор манифестов «MUST guarantee that manifests can be either resumed or reapplied» ([SUIT -37 §6.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-37#section-6.3.1)).
* TUF требует сохранять метаданные в энергонезависимой памяти (5.3.8, 5.4.5, 5.5.7, 5.6.6), но об атомарности записи молчит.
* Uptane ограничивается рекомендацией (SHOULD) создавать резервную копию образа.
* В RFC 9124 и ISVS клиентских требований о питании нет.

Поэтому строки PWR-01…04 каталога честнее маркировать как «robustness». Оракул для A/B-апдейтеров лучше брать из их собственных задокументированных гарантий ([RAUC docs](https://rauc.readthedocs.io/en/latest/); [OSTree](https://ostreedev.github.io/ostree/atomic-upgrades/); [Mender docs](https://docs.mender.io/)):

* RAUC обещает «Fail-Safe & Atomic»;
* OSTree — «you will have either the old system, or the new one»;
* Mender — откат загрузчиком, если устройство перезагрузилось до commit.

Сведение спецификаций уже дало каталогу 24 идентификатора (группы AUTH, FRESH, KEY, DOS, NET, PWR, INST, PARSE) с привязкой к пунктам TUF, Uptane, RFC 9124 и ISVS. Оно же выявило ещё 14 классов, которые спецификации называют, а каталог пока не покрывает. Среди них:

* «Extraneous dependencies attacks»;
* TOCTOU между проверкой и использованием (THREAT.MFST.TOCTOU, ISVS 3.4.4);
* неверный базовый образ дельта-обновления (THREAT.UPD.WRONG_PRECURSOR);
* лишние данные после образа (THREAT.IMG.EXTRA);
* replay Director Targets без образов;
* отсутствие аттестации времени.

Источники: [TUF v1.0.37](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md), [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md), [RFC 9124](https://www.rfc-editor.org/rfc/rfc9124), [ISVS](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS).

| Класс каталога | TUF 1.0.37 | Uptane 2.1.0 | RFC 9124 / RFC 9019 / SUIT | ISVS 1.0 |
|---|---|---|---|---|
| FRESH-01 заморозка | §1.5.2; 5.3.10, 5.4.4, 5.5.6, 5.6.5 | §4.3.2; §5.4 (SHALL, безопасный источник времени) | REQ.SEC.EXP (уровень MAY) | нет |
| FRESH-02 откат | 5.3.5, 5.4.3.1, 5.4.3.2, 5.5.5 | §4.3.3; 5.4.4.3–5.4.4.6; release counter | REQ.SEC.SEQUENCE | 3.4.6 (только L3) |
| DOS-01/02 бесконечные данные | §1.5.2; лимиты W/X/Y/Z; 5.7.3 | §4.3.3; лимиты X/Y/Z | нет (≈ REQ.SEC.MFST.CONST) | нет |
| DOS-03/04 медленная отдача | **нет (удалено в v1.0.7, f9122f1)** | **§4.3.2; §5.4 SHALL** | нет | нет |
| PWR-01/02 обрыв при записи метаданных или артефакта | сохранение без требования атомарности | 5.4.2.6; 5.4.3.3 (резервная копия, SHOULD) | RFC 9019 §3; SUIT -37 §6.3.1 | 3.4.7 |
| PWR-03/04 обрыв при записи слота или переключении | нет (вне целей TUF, §1.4) | нет | ≈ RFC 9019 §4.1 | 3.4.7; 3.1.5 |

## tuf-conformance покрывает 119 случаев, но останавливается на метаданных

Ближайший аналог — tuf-conformance (v2.5.0, 2026-09-02). Он задаёт протокол «client-under-test CLI» из трёх команд: `init`, `refresh`, `download`. Клиента он оценивает только по четырём наблюдаемым величинам: код возврата, доверенные метаданные в `--metadata-dir`, файлы в `--target-dir` и журнал HTTP-запросов ([CLIENT-CLI.md](https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md)). Репозиторий-симулятор хранится в памяти и раздаётся через `ThreadingHTTPServer` на localhost. Тело ответа всегда полное, с корректным `Content-length` ([simulator_server.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/simulator_server.py)). `ClientRunner` не ставит таймаута на команду ([client_runner.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/client_runner.py)). Тесты сроков действия опираются на `faketime`. В девяти файлах 56 тестовых функций, которые разворачиваются в 119 случаев. Ночной отчёт на 31.10.2026 ([Client Conformance Report](https://theupdateframework.github.io/tuf-conformance/)):

| Клиент | Прошло | Xfail | Доля |
|---|---|---|---|
| python-tuf | 119 | 0 | 100% |
| sigstore-rust | 119 | 0 | 100% |
| go-tuf | 116 | 3 | 97% |
| tuf-js | 116 | 3 | 97% |
| sigstore-java | 86 | 22 | 80% |
| sigstore-ruby | нет данных | — | — |

Важнее то, чего в нём нет. Это проверено по коду, а не по README:

* нет атак транспортного уровня: ни медленной отдачи, ни бесконечных данных; заморозка покрыта только через истечение срока и `faketime`;
* клиента ни разу не убивают посреди записи, атомарность сохранения метаданных не проверяется;
* нет установки, A/B-переключения и загрузки;
* нет Uptane (Director, несколько репозиториев, map file TAP 4) и SUIT;
* нет TLS, зеркал и прокси;
* результат — pass/fail по тесту, без шкалы и без дифференциального сравнения ([tuf-conformance](https://github.com/theupdateframework/tuf-conformance)).

Клиенты tough, rust-tuf и php-tuf в отчёт не входят. Для rust-tuf открыт issue об интеграции ([rust-tuf #410](https://github.com/theupdateframework/rust-tuf/issues/410)). Расхождения реализаций всплывают и здесь. Клиенты по-разному обрабатывают дублирующиеся keyid и keyid без соответствующего ключа (открытые [#143](https://github.com/theupdateframework/tuf-conformance/issues/143) и [#144](https://github.com/theupdateframework/tuf-conformance/issues/144)). go-tuf держит xfail по issue #759: кэшированная делегированная роль не перепроверяется относительно текущего делегатора ([go-tuf xfails](https://github.com/theupdateframework/go-tuf/blob/master/.github/scripts/tuf-conformance-client.xfails)).

Аудиторы прямо просили о дифференциальном тестировании. X41 в аудите go-tuf (2023) написал, что «a differential fuzzing approach could not be implemented», и описал, как его следует строить ([X41](https://x41-dsec.de/static/reports/X41-go-tuf-Audit-2023-Final-Report-PUBLIC.pdf)). OSTIF нашёл расхождение в кодировании канонического JSON между php-tuf и python-tuf ([OSTIF](https://ostif.org/wp-content/uploads/2024/01/OSTIF-2023-Q3-PHP-TUF-Multi-Final-Report-Updated-v2.pdf)).

Остальные исполняемые наработки ограничены одним проектом:

* **tuf-test-vectors** (HERE, 2017–2020, последний push в 2022 г.) — прямой предшественник кросс-спецификационных векторов TUF+Uptane. Он заброшен и не знает SUIT, A/B и сбоев ([tuf-test-vectors](https://github.com/uptane/tuf-test-vectors)).
* **uptane-test** — официальный тест-план Uptane. Он архивирован, был документом, а не исполняемым набором, и исключал SHOULD и MAY ([uptane-test](https://github.com/uptane/uptane-test)).
* **aktualizr** содержит `test_io_failure.py` со случайными сбоями ввода-вывода. Вероятность сбоя 0,00025, оценка числа прогонов — около 50 000 по задаче о собирателе купонов ([test_io_failure.py](https://github.com/uptane/aktualizr/blob/master/tests/test_io_failure.py)).
* **Симулятор MCUboot** — сильнейший прецедент для отказоустойчивости. Он считает число флеш-операций N чистого обновления, затем прерывает обновление на каждом шаге i от 1 до N, перезагружает загрузчик и проверяет образы и трейлеры ([MCUboot image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs)). Так нашли лишний swap после прерванного revert (PR #485). Но это один загрузчик, без сети и метаданных.
* **RAUC** гоняет весь набор тестов в QEMU, однако «Rebooting is not supported, so testing covers only a single boot cycle» ([RAUC contributing](https://rauc.readthedocs.io/en/latest/contributing.html)).
* **Mender**: проверка с отключением питания — ручной пункт чеклиста интеграции ([Mender checklist](https://docs.mender.io/3.3/client-installation/integration-checklist)).
* **SWUpdate**: юнит-тесты на cmocka, без фаззинга и без сбоев.
* **Apertis**: самый конкретный публичный автоматический тест — `aum-power-cut` в LAVA. Его история показательна: на быстрых платах задержка больше 3 с давала обновлению завершиться, тест падал, и задержку пришлось ограничить ([Apertis commit](https://gitlab.apertis.org/tests/apertis-test-cases/-/commit/2ee9764b2b404c1c53e74fffffeb81407d8e97eb)). Точки обрыва по времени хрупки.
* **Свежие работы**: препринт engrXiv от 29.10.2026 с HIL-методикой, но без инструмента и без названных реализаций ([engrXiv 8657](https://engrxiv.org/preprint/view/8657)), и учебная лаборатория `qemu-ota-recovery-lab` (16 сценариев, только RAUC) ([GitHub](https://github.com/chubuchnyi/qemu-ota-recovery-lab)).

Из целевых проектов в OSS-Fuzz есть только RAUC ([oss-fuzz rauc](https://github.com/google/oss-fuzz/tree/master/projects/rauc)). python-tuf, go-tuf, tough, SWUpdate, Mender, MCUboot, libcsuit и aktualizr там отсутствуют.

Реализаций для 9–10 экспериментов хватает, но распределены они неравномерно:

* **TUF.** Четыре активных клиента. tough (Rust, 0.24.0 от 2026-07-10) активно развивается и не охвачен tuf-conformance, поэтому его адаптер — самый чистый новый вклад ([tough](https://github.com/awslabs/tough)).
* **Uptane.** Единственный поддерживаемый открытый клиент — aktualizr: последний релиз 2020.10, но push в репозиторий был в 2026 г. ([aktualizr](https://github.com/uptane/aktualizr)). Интероперабельность ограничена POUF, поскольку стандарт «does not specify data binding formats» ([POUFs](https://github.com/uptane/POUFs); [Moore et al. 2020](https://doi.org/10.4271/11-02-02-0011)). Это угроза валидности для сравнения внутри Uptane.
* **SUIT.** Экосистема держится на libcsuit (v1.0.2, реализует suit-manifest-34) ([libcsuit](https://github.com/kentakayama/libcsuit)) и на модуле SUIT в RIOT, основанном на драфте v9 ([RIOT](https://api.riot-os.org/group__sys__suit.html)). Nordic удалил SUIT из NCS v3.1.0 ([Nordic](https://nrfconnectdocs.nordicsemi.com/ncs/latest/nrf/releases_and_maturity/migration/migration_3.1_54h_suit_ironside.html)).

Рекомендуемый набор:

| № | Реализация | Экосистема | Язык | Версия | Адаптер |
|---|---|---|---|---|---|
| 1 | python-tuf ngclient | TUF | Python | 7.0.1 | есть (tuf-conformance); в MVP |
| 2 | go-tuf v2 | TUF | Go | v2.4.2 | есть (tuf-conformance); в MVP |
| 3 | tuf-js | TUF | TypeScript | 6.0.1 | свой; в MVP |
| 4 | tough | TUF | Rust | 0.24.0 | нужен новый; вне tuf-conformance |
| 5 | aktualizr | Uptane | C++ | 2020.10 (push 2026) | нужен; можно переиспользовать `fake_uptane_server.py` |
| 6 | libcsuit | SUIT | C | v1.0.2 | нужен (обёртка над `examples/process`) |
| 7 | RIOT SUIT на `native` | SUIT (драфт v9) | C | 2026.10-RC3 | нужен; даёт дифференциал версий драфта |
| 8 | RAUC | A/B | C | v1.15.2 | нужен (QEMU) |
| 9 | SWUpdate | A/B | C | 2026.05.1 | нужен (QEMU) |
| 10 | Mender client | A/B | C++ | 5.2.0 | нужен (QEMU) |
| опц. | MCUboot | загрузчик МК | C | v2.5.0 | эталон методики сбоев питания |

## Каждая техника уже опубликована, их соединение — нет

Академическая линия задаёт словарь угроз, но не исполняемую межэкосистемную оценку. «A Look in the Mirror: Attacks on Package Managers» (CCS 2008) уже построил матрицу «угроза × реализация»: все десять изученных менеджеров пакетов оказались уязвимы для MITM или злонамеренного зеркала ([DOI](https://doi.org/10.1145/1455770.1455841)). «Survivable Key Compromise in Software Update Systems» (CCS 2010) ввёл модель ролей, порогов и сроков действия, лежащую в основе TUF ([DOI](https://doi.org/10.1145/1866307.1866315)). Словарь «freeze, rollback, endless data, slow retrieval, mix-and-match» канонический с 2008–2010 гг., поэтому новизна каталога не может состоять в новых угрозах. AoT (EuroS&P 2023) повторил структуру «модель угроз → категоризация → измерение многих реализаций» на 23 устройствах и 6 SDK, а дактилоскопирование расширило выборку до 1 356 приложений ([DOI](https://doi.org/10.1109/eurosp57164.2023.00065)). Но работа касается обновлений через приложения-компаньоны и не даёт переиспользуемого стенда.

Ближайшие работы вида «каталог угроз → исполняемые тесты» для OTA проверяют одну реализацию:

* Mahmood, Nguyen и Shaikh строят деревья атак и модельно-ориентированные тесты для Uptane (ICSTW 2020; Vehicular Communications 2022) ([DOI 2022](https://doi.org/10.1016/j.vehcom.2022.100468); [DOI 2020](https://doi.org/10.1109/icstw50294.2020.00019)).
* Kirk и соавт. переводят Uptane и модель атакующего в CSP и исполняют сгенерированные тесты на стенде (JLAMP 2022) ([DOI](https://doi.org/10.1016/j.jlamp.2022.100812)).

Формальные анализы проверяют дизайн, а не реализации: Lorch и соавт. (RAID 2024, Kind 2 + Tamarin, шесть новых уязвимостей) и Boureanu (SMC 2023, Tamarin) ([RAID](https://doi.org/10.1145/3678890.3678927); [SMC](https://doi.org/10.1109/smc53992.2023.10394216)). Символьного анализа самого TUF или SUIT/RFC 9019 найти не удалось.

У регуляторного сопоставления тоже есть прецедент. Seo и соавт. (VehicleSec 2023) уточнили требования UN R156 моделированием угроз и верифицировали архитектуру SUMS в Event-B ([DOI](https://doi.org/10.14722/vehiclesec.2023.23087)). Этой работой стоит легитимировать сам ход «регуляторика → проверяемый артефакт».

Рецензенты отнесут работу к жанру, сложившемуся на соседних протоколах:

| Работа | Охват | Результат |
|---|---|---|
| TLS-Anvil (USENIX Security 2022) | 13 реализаций TLS, тесты выведены из требований RFC | результаты по категориям: 2 новых эксплойта в MatrixSSL, 15 проблем интероперабельности, 116 проблем обработки alert ([USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/maehren)) |
| JWTeemo (NDSS 2026) | 43 реализации JWT на 10 языках | 31 неизвестная уязвимость, из них 20 с CVE ([DOI](https://doi.org/10.14722/ndss.2026.240697)) |
| Дифференциальное тестирование JSON-парсеров (AsiaCCS 2024) | 22 парсера | консенсусный оракул без точной спецификации ([DOI](https://doi.org/10.1145/3634737.3657003)) |
| QUIC Interop Runner | 10 реализаций QUIC | контейнерные адаптеры поверх симулированной сети ([DOI](https://doi.org/10.1145/3405796.3405826)) |

Масштаб в 9–10 реализаций для жанра типичен. Новизна — в разбросе по четырём семействам спецификаций, а не в числе реализаций. Из того же жанра следуют ожидания к результатам:

* категориальная таксономия исходов вместо pass/fail;
* ground truth из известных ошибок по образцу Magma ([DOI](https://doi.org/10.1145/3410220.3456276));
* для фаззинга — практики из SoK Schloegel и соавт. (S&P 2024): повторные прогоны, статистические тесты, доступность артефакта ([DOI](https://doi.org/10.1109/sp54263.2024.00137)).

Методы имитации отключения питания отработаны на хранилищах, но к OTA не применялись:

| Работа | Результат |
|---|---|
| ALICE (OSDI 2014) | 60 уязвимостей согласованности при сбоях в 11 приложениях ([USENIX](https://www.usenix.org/node/186195)) |
| «Torturing Databases for Fun and Profit» (OSDI 2014) | все 8 баз данных ведут себя некорректно при обрыве, 7 нарушают ACID ([PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)) |
| CrashMonkey/ACE (OSDI 2018) | воспроизведены 24 из 26 известных ошибок, найдено 10 новых; в изученной выборке ошибок файловых систем Linux за пять лет все проявлялись после сбоев вокруг fsync ([arXiv](https://arxiv.org/abs/1810.02904)) |
| LazyFS (PVLDB 2024) | 8 новых ошибок; в 9 из 12 изученных случаев проблема была в журналах или файлах метаданных ([PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)) |

Именно такие мелкие файлы состояния хранят OTA-апдейтеры: окружение загрузчика, статусы RAUC, Mender и SWUpdate, доверенные метаданные TUF. Работы, которая применяла бы перебор crash-состояний в духе ALICE или CrashMonkey к OTA-апдейтерам или загрузчикам, не найдено. Есть только практика без методики и метрик:

* 200 случайных обрывов питания на Jetson Orin NX без «кирпичей» ([Peridio](https://docs.peridio.com/field-notes/2026/06/15/power-pull-orin-nx));
* bootloop после обрыва при A/B-обновлении UEFI-капсулой ([NVIDIA forum](https://forums.developer.nvidia.com/t/36-4-0-uefi-a-b-capsule-update-bootloop-after-power-loss/357686));
* «кирпич» MCUboot при swap using move ([Nordic DevZone](https://devzone.nordicsemi.com/f/nordic-q-a/96156/mcuboot-swap-using-move-will-brick-device-when-power-interrupted-during-move));
* незагружаемая система из-за окружения U-Boot без избыточной копии ([CIP issue #5](https://gitlab.com/cip-project/cip-sw-updates/cip-sw-updates-tasks/-/issues/5)).

Это самый сильный исследовательский пункт темы.

Риск для формулировки каталога — DeOTA-IoT (Sensors 2025): каталог из 34 техник в 6 механизмах, привязанных к атрибутам качества ([DOI](https://doi.org/10.3390/s26010193)). Это каталог **техник проектирования**, а не машиночитаемый каталог угроз с трассировкой к спецификациям, регуляторике и тестам. Разницу нужно проговорить явно.

Исследования CRA пока юридические и процессные ([Teichmann 2025](https://doi.org/10.1365/s43439-025-00162-4); [Ruohonen, Timmers 2025](https://doi.org/10.60097/acig/213350)). Исполняемой трассировки к Annex I нет.

В русскоязычной литературе работ по TUF, Uptane или SUIT и по состязательному тестированию OTA-клиентов не найдено. Поиск шёл по КиберЛенинке; eLibrary проверить не удалось. Мировую планку магистерского уровня задают работы вроде STRIDE-моделирования с тестированием самописной OTA-системы ([Bhiwapurkar, NCI](https://openalex.org/W7209298662)). Тема её заведомо превосходит хотя бы числом реальных реализаций.

## MVP otabench нашёл расхождение, значимое для Uptane, а не для TUF

Первый прогон стенда выполнен на Windows 11 (Python 3.13.15, Go 1.27.1, Node 24.19.0). В нём участвовали python-tuf 7.0.1, go-tuf v2.4.2 (клиент из tuf-conformance), tuf-js 6.0.1 (собственный адаптер) и наивный контрольный клиент. Прогон включал 16 сценариев, по 10 испытаний на каждый сценарий обрыва питания, и занял около 6 минут ([MVP стенда otabench, прогон 31.10.2026](../docs/mvp-results.md)).

| Сценарий | ID | python-tuf | go-tuf | tuf-js | naive (контроль) |
|---|---|---|---|---|---|
| подмена артефакта, подделка метаданных, подмена keyid | AUTH-01..03 | ✅ | ✅ | ✅ | ✅ |
| заморозка, откат timestamp, mix-and-match | FRESH-01..03 | ✅ | ✅ | ✅ | ❌ |
| онлайн-ключи: даунгрейд прошивки | KEY-01 | ✅ | ✅ | ✅ | ❌ |
| онлайн-ключи: произвольное ПО | KEY-02 | ✅ | ✅ | ✅ | ✅ |
| бесконечные данные (метаданные / артефакт) | DOS-01/02 | ✅ 0,4 с | ✅ 0,07 с | ✅ 0,2 с | ❌ принял 64 МиБ |
| медленная отдача метаданных, 2 Б/с | DOS-03 | ❌ ≥120 с | ❌ ≥120 с | ✅ 100 с | ❌ |
| медленная отдача артефакта, 64 Б/с | DOS-04 | ❌ ≥120 с | ❌ ≥120 с | ✅ 100 с | ❌ |
| обрыв соединения и восстановление | NET-01 | ✅ | ✅ | ✅ | ✅ |
| обрыв питания при refresh с ротацией root | PWR-01 | 10/10 | 10/10 | 10/10 | 10/10 |
| обрыв питания при загрузке 2 МиБ | PWR-02 | 10/10 | 10/10 | ERROR | 0/10, принят «рваный» файл |

Контрольный клиент подтверждает, что оракулы работают. Без базового прогона остаётся 15 сценариев. Наивный клиент проваливает ровно те 9 из них, где у него нет защиты: проверки сроков и версий, лимиты объёма, атомарная запись. Настоящие клиенты эти сценарии проходят. Итог MVP: python-tuf и go-tuf по 87%, tuf-js 100%, naive 40% ([MVP стенда otabench, прогон 31.10.2026](../docs/mvp-results.md)).

У этого аргумента два слабых места, и их лучше закрыть до защиты.

1. **Различающая способность шести сценариев не показана.** AUTH-01..03, KEY-02, NET-01 и PWR-01 проходят все четыре клиента, включая контрольный. Её даёт ground truth по образцу Magma: закреплённые уязвимые версии, на которых сценарий обязан упасть.
   * go-tuf v2.0.0 для CVE-2024-47534 ([GHSA-4f8r-qqr9-fq8j](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-4f8r-qqr9-fq8j));
   * go-tuf до 2.3.1 для порога 0 ([GHSA-fphv-w9fq-2525](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-fphv-w9fq-2525));
   * tough до 0.20.0 для пакета 2025 г. ([GHSA-5vmp-m5v2-hx47](https://github.com/awslabs/tough/security/advisories/GHSA-5vmp-m5v2-hx47));
   * tough до 0.22.0 для дубликатов подписей в делегированных ролях ([GHSA-8m7c-8m39-rv4x](https://github.com/awslabs/tough/security/advisories/GHSA-8m7c-8m39-rv4x)).
2. **Проценты посчитаны по разным знаменателям.** 87% у python-tuf и go-tuf — это 13 из 15. 100% у tuf-js — 14 из 14, потому что ячейка ERROR исключена. Для сравнимости нужна таксономия исходов в духе TLS-Anvil, где ERROR — отдельная категория, а не выпавшая строка.

Главная находка MVP — дифференциальная. При медленной отдаче три реализации одного семейства ведут себя по-разному:

* **python-tuf** ограничивает только паузу между байтами (`socket_timeout=30` в `urllib3_fetcher.py`). Отдача по байту раз в 0,5 с этот таймаут не задевает.
* **go-tuf** не прервался в пределах окна наблюдения стенда, 120 с.
* **tuf-js** прервался через 100 с благодаря общему таймауту запроса `fetchTimeout: 100000`, реализованному через `AbortSignal.timeout`.

При 2 Б/с и лимите snapshot около 2 МБ (значение по умолчанию в go-tuf) загрузка заняла бы порядка 11 суток. Всё это время клиент «заморожен» и не выдаёт ни одной ошибки ([MVP стенда otabench, прогон 31.10.2026](../docs/mvp-results.md)).

Формулировать находку как нарушение TUF **нельзя**. Slow retrieval убран из целей защиты TUF в v1.0.7 коммитом f9122f1 от 2020-09-08 с прямым указанием, что такая защита — «an aspiration for implementations» ([commit f9122f1](https://github.com/theupdateframework/specification/commit/f9122f1662426b217accbc4017d1a3f36afc3e16)). Значит, поведение python-tuf и go-tuf соответствует TUF 1.0.37. Более того, MVP показывает, что признание из того же коммита — «The reference implementation does not currently protect against slow retrieval attacks» — для python-tuf верно и шесть лет спустя.

Корректная рамка — **Uptane 2.1.0 §5.4**: «All ECUs SHALL monitor the download speed of image metadata and image binaries» ([Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)). В конфигурации по умолчанию python-tuf и go-tuf не дают свойства, которое Uptane делает обязательным для ECU. Интегратор, который строит на этих библиотеках Uptane-подобную систему, должен реализовать мониторинг скорости сам. Преамбула TUF §1.5.2 («the framework must detect when a client is unable to update») годится как мотивация, но это не требование конкретного шага клиентского workflow. Ссылаться на неё как на нарушенное требование не стоит.

У «прохождения» tuf-js тоже есть оговорка. Общий таймаут запроса — не мониторинг скорости. Наша гипотеза, которую нужно проверить: тот же таймаут оборвёт и легитимную загрузку крупного образа, если она на медленном канале длится дольше 100 с. Поэтому оракул DOS-03/04 стоит сделать двусторонним:

* злонамеренно медленная отдача прерывается или о ней сообщается за время T;
* легитимная отдача со скоростью не ниже R завершается успешно.

Тогда стенд различит три случая: защиту по скорости, грубый общий таймаут и отсутствие защиты. Порог 120 с — параметр стенда, а не норма: Uptane числового порога не задаёт.

Прецедент того, что сопровождающие считают временную DoS проблемой безопасности, уже есть. В python-tuf CVE-2020-6173 множество невалидных подписей задерживало проверку «for at least a few minutes» ([GHSA-2828-9vh6-9m6j](https://github.com/theupdateframework/python-tuf/security/advisories/GHSA-2828-9vh6-9m6j)). Перед тем как заводить issue upstream, нужно проверить существующие обсуждения в python-tuf и go-tuf. Находку следует описывать как расхождение реализаций, значимое для Uptane, а не как уязвимость TUF. Поведение tough стоит проверить отдельно: его интеграционные тесты используют прокси сетевых сбоев `noxious` ([tough](https://github.com/awslabs/tough)).

Вторая находка методологическая: обрыв на уровне процесса слабо различает реализации. Даже наивный клиент пережил 10/10 обрывов во время refresh. Мелкие файлы пишутся одним вызовом, а kill процесса не теряет страничный кэш ([MVP стенда otabench, прогон 31.10.2026](../docs/mvp-results.md)). Это ровно то, что предсказывает литература. CrashMonkey находит ошибки после сбоев вокруг fsync ([arXiv](https://arxiv.org/abs/1810.02904)). LazyFS моделирует потерю именно несинхронизированных данных командой `clear-cache` ([PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)). Так у главы 3 появляется эмпирическое обоснование двух следующих уровней:

* блочные записи: dm-log-writes с воспроизведением префиксов до каждого flush/FUA ([kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html));
* полная система: QEMU.

На загрузке артефакта обрыв процесса уже различает реализации. Наивный клиент пишет поток прямо в итоговый файл и доверяет уже существующему файлу. После обрыва в 10 случаях из 10 оставался «рваный» файл, и повторный запуск возвращал успех. python-tuf и go-tuf пережили все 10 обрывов.

Следующий шаг — заменить случайные задержки детерминированным перебором точек сбоя: `strace --inject` с `signal=SIGKILL` на каждом `fsync`, `rename` и `write` ([strace man](https://man7.org/linux/man-pages/man1/strace.1.html)). Это снимет хрупкость точек обрыва по времени, которую показала история Apertis.

Ошибки самого стенда, найденные в MVP, — готовый материал для раздела «угрозы валидности» ([MVP стенда otabench, прогон 31.10.2026](../docs/mvp-results.md)):

* **Поздний kill-таймер.** Таймер обрыва срабатывал уже после завершения прогона и убивал проверочный прогон, из-за чего go-tuf получал ложный PARTIAL (1/3).
* **Сбой платформы под видом находки.** tuf-js под Node 24.19 на Windows падает с assert libuv (`UV_HANDLE_CLOSING`, `src\win\async.c:94`) на любой загрузке 2 МиБ. Без контрольного предусловия это выглядело бы как «tuf-js не переживает обрыв питания, 0/10».
* **Отсутствие `date` на Windows.** go-tuf-клиент из tuf-conformance вызывает `date +%s` ради faketime и без Git usr/bin падал на любом сценарии.

Платформа — не только источник шума, но и законное измерение. python-tuf до 7.0.0 сопоставлял шаблоны путей делегирования с учётом регистра на POSIX и без учёта регистра на Windows (GHSA-qp9x-wp8f-qgjj) ([GHSA](https://github.com/theupdateframework/python-tuf/security/advisories/GHSA-qp9x-wp8f-qgjj)). Основные результаты при этом нужно получать на Linux, где доступны faketime, strace, dm-log-writes и KVM. Windows-прогон стоит оставить как кросс-платформенный дифференциал.

## Пробел состоит из четырёх незанятых слоёв

Источники в совокупности показывают пробел не как «никто не тестирует OTA», а как четыре незанятых слоя:

1. **Межэкосистемный.** Каждый исполняемый набор ограничен одним проектом или одним семейством спецификаций: tuf-conformance, tuf-test-vectors, симулятор MCUboot, qemu-test RAUC, интеграционные тесты Mender, тесты отказов aktualizr.
2. **Транспортный.** Медленная и бесконечная отдача и злонамеренные зеркала не покрыты даже в TUF-сьюте.
3. **Устойчивость к сбоям.** Систематического перебора crash-состояний для OTA-клиентов и A/B-апдейтеров с метриками и покрытием точек сохранения в рецензируемой литературе нет.
4. **Регуляторный.** Исполняемой трассировки к CRA и ФСТЭК нет нигде, а сами регуляторы для отката, заморозки и атомарности исполняемых тестов не задают.

Пятым, локальным слоем можно считать русскоязычный: работа станет одной из первых отечественных публикаций по TUF, Uptane и SUIT. Но это утверждение опирается на поиск без eLibrary и требует перепроверки.

| Вклад | Ближайшее прошлое | Новизна | Что утверждать | Чего не утверждать |
|---|---|---|---|---|
| Машиночитаемый каталог (24 + 14 ID) с трассировкой к TUF/Uptane/RFC 9124/ISVS, CRA и ФСТЭК; анализ покрытия существующих сьютов | обзоры; деревья атак Mahmood 2022; DeOTA-IoT 2025; Seo 2023 | средне-высокая | унификация со стабильными ID; нормативный статус по каждой спецификации; измеренное покрытие tuf-conformance и других наборов | «первая таксономия угроз OTA» |
| Протокол адаптеров: обобщение CLI tuf-conformance на `install`, `status`, `reboot` | tuf-conformance; QUIC Interop Runner | низко-средняя, инженерная | обобщение на Uptane, SUIT и A/B с описанными пределами (POUF) | «новый протокол тестирования» |
| Серверы-нарушители | CCS 2008/2010; tuf-conformance | низкая по отдельности | переиспользуемая библиотека атак, впервые единообразно применённая к не-TUF апдейтерам; измеренная дельта к tuf-conformance (DOS-01..04) | «новые атаки» |
| Дифференциальное тестирование | Frankencerts, NEZHA, JSON 2024, JWT 2026; issues #143/#144; находка OSTIF L2 | средне-высокая | систематический дифференциальный оракул для обработки метаданных обновлений; первая находка по slow retrieval уже есть | «впервые обнаружены расхождения TUF-клиентов» |
| Имитация отключения питания на уровнях процесса, блочных записей и QEMU | ALICE, CrashMonkey, LazyFS; симулятор MCUboot; `test_io_failure` в aktualizr; Apertis; qemu-ota-recovery-lab | высокая | перебор crash-состояний для OTA-клиентов и A/B-апдейтеров с метриками (доля «кирпичей», нарушения атомарности, корректность отката, liveness) и покрытием точек сохранения | «первое тестирование OTA на обрыв питания» |
| Фаззинг | анализ загрузчиков (NDSS 2025); OSS-Fuzz для RAUC | низкая как метод | харнессы там, где их нет (TUF-клиенты, SWUpdate, Mender, libcsuit); дифференциальный фаззинг двух парсеров Mender-артефактов | новизну метода |
| Эксперименты на 9–10 реализациях | TLS-Anvil (13), QUIC Interop Runner (10) | типичный масштаб для жанра | разброс по 4 семействам спецификаций и 6 языкам | «крупнейшее исследование» |
| Передача тестов и находок upstream | приём тестов в tuf-conformance; обратная связь JWTeemo в IETF | подтверждающая | число принятых PR, issues и CVE | — |

Главные риски для заявки на новизну известны заранее:

* **Дельта к tuf-conformance.** Он уже покрывает значительную часть TUF-столбца, поэтому дельту нужно измерить: сколько тестов добавлено, какие ID каталога впервые покрыты, какие ошибки найдены сверх того, что находит сьют.
* **Матрицы и тестирование Uptane уже были.** «A Look in the Mirror» и AoT строили матрицы «угроза × реализация», а Mahmood и Kirk — исполняемое тестирование Uptane по модели угроз. Слова «первая матрица» и «первое систематическое тестирование безопасности OTA» исключены.
* **Разнородные модели угроз.** У TUF это компрометация репозитория, у SUIT — ограниченное устройство, у A/B — обрыв питания. Без заранее определённой применимости клеток и семантики N/A единая матрица будет выглядеть как сравнение несравнимого.
* **POUF.** Сравнение внутри Uptane ограничено профилями POUF ([Moore et al. 2020](https://doi.org/10.4271/11-02-02-0011)).
* **Отсутствие аналогов не доказано.** Утверждения опираются на OpenAlex и веб-поиск без dblp и eLibrary. Перед подачей нужен финальный поиск по arXiv, dblp и eLibrary.

Формулировка, которая выдерживает эти риски:

> «Насколько нам известно, впервые предложен открытый исполняемый бенчмарк, позволяющий единообразно оценивать клиенты обновления разных экосистем (TUF, Uptane, IETF SUIT, A/B-апдейтеры) по единому машиночитаемому каталогу угроз, трассируемому к моделям угроз спецификаций и к требованиям CRA и ФСТЭК России, с одновременной оценкой защищённости от атак со стороны репозитория и сети и устойчивости к сбоям питания на уровнях процесса, блочных записей и полной системы. Бенчмарк развивает подход tuf-conformance, добавляет дифференциальные оракулы и оракулы согласованности после сбоя и применён к N реализациям; по K выявленным проблемам исправления или тесты приняты upstream».

Для находки MVP:

> «Выявлено, что три реализации TUF (python-tuf 7.0.1, go-tuf v2.4.2, tuf-js 6.0.1) расходятся в поведении при атаке медленной отдачи. Поведение двух из них допустимо по TUF 1.0.37, где эта угроза исключена из целей защиты начиная с v1.0.7, но не обеспечивает свойство, обязательное для ECU по Uptane 2.1.0 §5.4».

Для англоязычной публикации подходит такая версия:

> "To the best of our knowledge, this is the first open, executable benchmark that evaluates update clients from different update-security ecosystems (TUF, Uptane, IETF SUIT, and A/B image updaters) against a single machine-readable threat catalog, traceable both to the specifications' threat models and to regulatory requirements (EU CRA, FSTEK), and that measures both adversarial-repository security and power-loss fault tolerance within one harness."

Регуляторную часть стоит формулировать как «трассировка и исполняемые свидетельства в поддержку оценки соответствия», а не как «доказательство соответствия». CRA сформулирован как набор принципов, гармонизированных стандартов нет, и любое сопоставление интерпретационно. Слова «первая таксономия», «первый conformance-сьют», «первое тестирование безопасности OTA» и «доказывает соответствие» в тексте работы лучше не использовать вовсе.

## Опорные источники и площадки для публикации

| Группа | Источник | Для чего цитировать |
|---|---|---|
| Спецификации | [TUF v1.0.37 (тег)](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md) | классы атак §1.5.2, шаги клиента §5 |
| Спецификации | [commit f9122f1](https://github.com/theupdateframework/specification/commit/f9122f1662426b217accbc4017d1a3f36afc3e16), [PR #111](https://github.com/theupdateframework/specification/pull/111), [TUF v1.0.6](https://github.com/theupdateframework/specification/blob/v1.0.6/tuf-spec.md) | история удаления slow retrieval |
| Спецификации | [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md), [changelog](https://github.com/uptane/deployment-considerations) | §4.3, §5.4 (SHALL monitor), полная и частичная верификация |
| Спецификации | [RFC 9019](https://www.rfc-editor.org/rfc/rfc9019), [RFC 9124](https://www.rfc-editor.org/rfc/rfc9124), [draft-ietf-suit-manifest-37](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) | архитектура SUIT, идентификаторы THREAT/REQ, §6.3.1 |
| Спецификации | [OWASP ISVS 1.0](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS) | V3 3.4.x (требования к обновлениям) |
| Тест-сьюты | [tuf-conformance](https://github.com/theupdateframework/tuf-conformance), [CLIENT-CLI.md](https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md), [отчёт](https://theupdateframework.github.io/tuf-conformance/) | основа протокола адаптеров, базовая линия для дельты |
| Тест-сьюты | [tuf-test-vectors](https://github.com/uptane/tuf-test-vectors), [uptane-test](https://github.com/uptane/uptane-test) | предшественники кросс-спецификационных векторов |
| Тест-сьюты | [симулятор MCUboot](https://github.com/mcu-tools/mcuboot/blob/main/sim/README.rst), [RAUC contributing](https://rauc.readthedocs.io/en/latest/contributing.html), [Apertis aum-power-cut](https://lavaphabbridge.apertis.org/testcases/v2019/aum-power-cut.html) | прецеденты тестирования обрыва питания и их пределы |
| Уязвимости | [GHSA-4f8r-qqr9-fq8j](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-4f8r-qqr9-fq8j), [GHSA-5vmp-m5v2-hx47](https://github.com/awslabs/tough/security/advisories/GHSA-5vmp-m5v2-hx47), [GHSA-8m7c-8m39-rv4x](https://github.com/awslabs/tough/security/advisories/GHSA-8m7c-8m39-rv4x) | исполняемые сьюты находят ошибки; регрессии; ground truth |
| Уязвимости | [RAUC CVE-2026-34155](https://github.com/rauc/rauc/security/advisories/GHSA-6hj7-q844-m2hx), [SWUpdate CVE-2025-41259](https://nvd.nist.gov/vuln/detail/CVE-2025-41259), [Mender CVE-2025-67903](https://mender.io/blog/cve-2025-67903-signature-verification-bypass-in-mender-client) | классы ошибок A/B-апдейтеров |
| Инциденты | [Notepad++](https://notepad-plus-plus.org/news/hijacked-incident-info-update/), [AOMEI (GTIG)](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering), [CrowdStrike PIR](https://www.crowdstrike.com/en-us/blog/falcon-content-update-preliminary-post-incident-report/) | мотивация актуальности |
| Регуляторика | [CRA (ELI)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng), [EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf), [EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf), [TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf) | трассировка к требованиям ЕС |
| Регуляторика | [UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf), [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf), [NIST SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) | отказоустойчивость, анти-откат, компрометация ключей |
| Регуляторика | [Приказ № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117), [Приказ № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/), [Методика 28.10.2022](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/) | трассировка к ФСТЭК; снятие терминологической коллизии |
| Научные | [CCS 2008](https://doi.org/10.1145/1455770.1455841), [CCS 2010](https://doi.org/10.1145/1866307.1866315), [Mahmood 2022](https://doi.org/10.1016/j.vehcom.2022.100468), [Kirk 2022](https://doi.org/10.1016/j.jlamp.2022.100812), [RAID 2024](https://doi.org/10.1145/3678890.3678927), [AoT](https://doi.org/10.1109/eurosp57164.2023.00065) | позиционирование относительно ближайших работ |
| Научные | [TLS-Anvil](https://www.usenix.org/conference/usenixsecurity22/presentation/maehren), [JWTeemo](https://doi.org/10.14722/ndss.2026.240697), [JSON 2024](https://doi.org/10.1145/3634737.3657003), [QUIC Interop Runner](https://doi.org/10.1145/3405796.3405826) | методологические аналоги жанра |
| Научные | [ALICE](https://www.usenix.org/node/186195), [CrashMonkey](https://arxiv.org/abs/1810.02904), [LazyFS](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf), [Torturing Databases](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf) | методика имитации отключения питания |
| Научные | [Schloegel SoK 2024](https://doi.org/10.1109/sp54263.2024.00137), [Magma](https://doi.org/10.1145/3410220.3456276), [DeOTA-IoT](https://doi.org/10.3390/s26010193), [Seo 2023](https://doi.org/10.14722/vehiclesec.2023.23087), [Moore 2020](https://doi.org/10.4271/11-02-02-0011), [Алейников, Жуков 2025](https://cyberleninka.ru/article/n/ob-avtomatizatsii-testirovaniya-bezopasnosti-obnovleniy-programmnogo-obespecheniya-v-informatsionnoy-sisteme) | строгость фаззинга, ground truth, риски формулировки, российский контекст |

Несколько ссылок из исходного брифа нужно поправить или убрать:

* UpKit опубликован на ICDCS 2019, а не на ESORICS.
* Обзор Bettayeb и соавт. — доклад на конференции ArabWIC 2019.
* Площадка CHAINIAC (USENIX Security 2017) и статья об Uptane в ;login: в ходе исследования не подтверждены.
* Систему обновлений «CANDID» найти не удалось, её лучше исключить.

Приказ № 117 цитируется по официальной странице fstec.ru с учётом изменений от 08.05.2026. Текст CRA прочитан через зеркало Springlex, а в библиографии стоит давать ссылку ELI на EUR-Lex.

Площадки для публикации:

| Площадка | Почему подходит | Сроки |
|---|---|---|
| ACM SCORED | лучшее совпадение по тематике: в темах 2026 г. прямо есть «Datasets and benchmarking» ([rb-general](https://lists.reproducible-builds.org/pipermail/rb-general/2026-May/004114.html)) | дедлайн 2026 г. — 12.07.2026; издание 2027 г. по аналогии ожидается летом (вывод по прошлым годам) |
| USENIX VehicleSec | автомобильная и Uptane-часть, в том числе мост «формальные находки → тесты» ([CfP](https://www.usenix.org/node/315631)) | дедлайн 2026 г. — 24.02.2026; дедлайн 2027 г. ожидается в конце февраля (вывод) |
| escar Europe | автомобильная безопасность | дедлайн 2026 г. — 10.05.2026 ([EasyChair](https://easychair.org/cfp/24th-escarEurope2026)) |
| «Вопросы кибербезопасности» | русскоязычная статья о каталоге угроз и сопоставлении с CRA и ФСТЭК; журнал из перечня ВАК, по стороннему списку К1 (официально не проверено) ([КиберЛенинка](https://cyberleninka.ru/journal/n/voprosy-kiberbezopasnosti)) | — |
| «Труды ИСП РАН», Открытая конференция ИСП РАН | тестирование и фаззинг | конференция проходит в декабре |

Поскольку tuf-conformance активно развивается, приоритет лучше закрепить ранним препринтом на arXiv с артефактом на Zenodo.

## Заключение

Источники меняют представление о пробеле. Он проходит не между «тестируют» и «не тестируют», а по границе, на которой останавливаются существующие проверки: на проверке подписи метаданных. Всё, что дальше, — время, транспорт, сохранение состояния, загрузка — это зона, где спецификации молчат или расходятся, а регуляторы отсылают к оценке рисков и формуле «demonstrate». Реализации в этой зоне, как показал MVP, ведут себя по-разному. Отсюда неочевидное следствие для дизайна. Одно и то же наблюдаемое поведение получает разные вердикты в разных спецификациях: бесконечное ожидание при медленной отдаче соответствует TUF 1.0.37 и нарушает Uptane 2.1.0 §5.4. Поэтому каждая клетка матрицы результатов должна нести нормативный статус по каждой спецификации, а не один pass/fail. Такой вердикт «по спецификации» в принципе не может выдать ни один набор, ограниченный одним семейством. Это, пожалуй, самый чистый аргумент в пользу кросс-экосистемности.

Второе следствие касается распределения усилий. MVP показал, что обрыв на уровне процесса почти не различает реализации, хотя именно отказоустойчивость — единственный вклад с высокой оценкой новизны. Значит, исследовательский вес работы должен сместиться на блочный уровень и QEMU, а TUF-часть должна служить калибровкой стенда относительно опубликованного отчёта tuf-conformance. Порядок действий, который следует из источников:

1. Повторить прогон на Linux.
2. Добавить адаптер tough — первого TUF-клиента вне tuf-conformance.
3. Переоформить DOS-03/04 как двусторонний Uptane-оракул с контрольной легитимной загрузкой.
4. Закрепить заведомо уязвимые версии как ground truth.
5. Перейти к детерминированному перебору точек сбоя (`strace --inject`, dm-log-writes).
6. Сделать первый A/B-адаптер: RAUC в QEMU с реальной перезагрузкой, которой нет в его собственном CI.
