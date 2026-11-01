# Regulatory and standards requirements for secure software/firmware update mechanisms (EU, international, automotive, Russia): status as of 31 October 2026

Scope note: these notes list the requirements on update mechanisms, with clause numbers, short verbatim quotes and dates, and say for each whether it is verified by documentation or by tests. Where the primary text was read in full, this is stated. The texts read in full were: CRA Annexes I/II/VIII and Art. 13/32/71 through the Springlex mirror of OJ L 2024/2847 (EUR-Lex blocked automated access); EN 18031-1:2024 (full text published by NEK); ETSI EN 303 645 V3.1.3; ETSI TS 103 701 V2.1.1; UN R155/R156 adopted texts; NIST SP 800-193/800-147/IR 8259A/IR 8425; FSTEK Orders 117 and 239; the FSTEK update-testing Methodology. "UNVERIFIED" marks claims that rest only on secondary sources or search snippets.

---

## 1. EU Cyber Resilience Act, Regulation (EU) 2024/2847: dates, Annex I update requirements, support period, standards and guidance

### Takeaway
The CRA (OJ L 2024/2847, 20.11.2024; in force 10.12.2024) requires security updates, automatic by default with opt-out where applicable, notification and postponement (Annex I Part I (2)(c)). It also requires "mechanisms to securely distribute updates" (Annex I Part II (7)) and free, prompt dissemination with advisories (Part II (8)). It does not name any concrete technical property of an update system: no anti-rollback, freshness/anti-freeze, atomicity or key-compromise resilience. As of October 2026 no CRA harmonised standard is cited in the OJ. The horizontal standard expected to carry generic product requirements, EN 40000-1-4, is still a draft, so conformity is currently shown through the manufacturer's documentation and risk assessment.

### Cited Findings
**Dates and status**
- Published in OJ L 2024/2847 on **20.11.2024**. Art. 71(1): it "shall enter into force on the twentieth day following that of its publication", which gives **10.12.2024** (my calculation). Art. 71(2): "This Regulation shall apply from **11 December 2027**. However, Article 14 shall apply from **11 September 2026** and Chapter IV (Articles 35 to 51) shall apply from **11 June 2026**." — [Springlex, CRA Art. 71 (OJ text)](https://www.springlex.eu/en/packages/cra/cra-regulation/article-71/); official ELI: [eur-lex.europa.eu/eli/reg/2024/2847/oj](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) (EUR-Lex returned empty or 202 to automated fetches, so the text was read via Springlex, which reproduces "OJ L 2024/2847, 20.11.2024 · Consolidated text").
- Article 14 reporting (actively exploited vulnerabilities and severe incidents) has applied since 11.09.2026. ENISA's Single Reporting Platform opened at portal.cra-srp.enisa.europa.eu. Deadlines: early warning in 24 h, notification in 72 h, final report within 14 days of a fix. — [cyberresilienceact.eu, guidance news (updated 11.09.2026)](https://www.cyberresilienceact.eu/news/commission-cra-application-guidance-published-27-july-2026.html); [SecureHabits, Oct 2026](https://www.securehabits.nl/knowledge/cra-harmonised-standards-overview/)

**Annex I, Part I (essential cybersecurity requirements on product properties); point (2) "On the basis of the cybersecurity risk assessment … and where applicable, products with digital elements shall:"**
- **(2)(c)**: "ensure that vulnerabilities can be addressed through security updates, including, where applicable, through automatic security updates that are installed within an appropriate timeframe enabled as a default setting, with a clear and easy-to-use opt-out mechanism, through the notification of available updates to users, and the option to temporarily postpone them;" — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(2)(f)**: "protect the integrity of stored, transmitted or otherwise processed data, personal or other, commands, **programs** and configuration against any manipulation or modification not authorised by the user, and report on corruptions;" — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(2)(h)**: "protect the availability of essential and basic functions, also after an incident, including through resilience and mitigation measures against denial-of-service attacks;" — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(2)(j)/(k)**: limit attack surfaces; "reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques". **(2)(b)** secure-by-default, "including the possibility to reset the product to its original state". — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)

**Annex I, Part II (vulnerability handling requirements): "Manufacturers … shall:"**
- **(1)** identify and document vulnerabilities and components, "including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies". — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(2)** "address and remediate vulnerabilities without delay, including by providing security updates; where technically feasible, new security updates shall be provided separately from functionality updates;" — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(3)** "apply effective and regular tests and reviews of the security of the product". — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(7)**: "provide for mechanisms to securely distribute updates for products with digital elements to ensure that vulnerabilities are fixed or mitigated in a timely manner and, where applicable for security updates, in an automatic manner;" — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- **(8)**: "ensure that, where security updates are available to address identified security issues, they are disseminated without delay and, unless otherwise agreed between a manufacturer and a business user in relation to a tailor-made product …, free of charge, accompanied by advisory messages providing users with the relevant information, including on potential action to be taken." — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- None of these words appear in the Annex I text: "rollback", "downgrade", "freeze", "replay", "key compromise", "Uptane", "TUF" (term search over the full Annex I text). — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)

**Recitals**
- Recital 56: manufacturers should ensure "functions that enable the notification, distribution, download and installation of security updates automatically, in particular in the case of consumer products … possibility to approve the download and installation … as a final step. Users should retain the ability to deactivate automatic updates". The automatic-update requirements "are not applicable to products … primarily intended to be integrated as components into other products" nor to products "for which users would not reasonably expect automatic updates, including … professional ICT networks, and especially in critical and industrial environments where an automatic update could cause interference with operations". — [Springlex, CRA Annex I (recital 56)](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)
- Recital 57: separate security updates from functionality updates where technically feasible. Recital 64: security updates free of charge. — [Springlex, CRA Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/)

**Annex II (information and instructions to the user)**
- Point (7): "the type of technical security support offered by the manufacturer and the end-date of the support period during which users can expect vulnerabilities to be handled and to receive security updates". Point (8): detailed instructions on, among others, "(c) how security-relevant updates can be installed" and "(e) how the default setting enabling the automatic installation of security updates, as required by Part I, point (2)(c), of Annex I, can be turned off". Sub-point letters are inferred from list order in the OJ text and should be checked against EUR-Lex. — [Springlex, CRA Annex II](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-2/)

**Article 13: support period and availability of updates**
- Art. 13(8), third subparagraph: "the support period shall be at least five years". It is shorter only where the product is expected to be in use for less than five years. — [Springlex, CRA Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/)
- Art. 13(9): each security update made available during the support period "remains available after it has been issued for a minimum of 10 years or for the remainder of the support period, whichever is longer". — [Springlex, CRA Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/)
- Art. 13(10): for subsequent substantially modified software versions, the manufacturer may ensure compliance "only for the version that it has last placed on the market", provided users of earlier versions get it free of charge. — [Springlex, CRA Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/)
- Art. 13(19): the end date of the support period must be specified at purchase "clearly and understandably … including at least the month and the year". — [Springlex, CRA Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/)

**Conformity assessment route (relevant to the thesis claim)**
- Art. 32(1): the manufacturer may use (a) internal control (module A), (b) EU-type examination (module B) plus module C, (c) full quality assurance (module H), or (d) an EU cybersecurity certification scheme. Class I important products may use module A only if harmonised standards, common specifications or certification schemes (at least 'substantial') are applied in full. Otherwise they need B+C or H. Class II needs B+C, H or a scheme. Critical products need a scheme under Art. 8(1). — [Springlex, CRA Art. 32](https://www.springlex.eu/en/packages/cra/cra-regulation/article-32/)
- Annex VIII Part I (module A): "the manufacturer … ensures and declares on its sole responsibility that the products … satisfy all the essential cybersecurity requirements". Part II (module B): the notified body assesses design adequacy "through the examination of the technical documentation and supporting evidence … and the examination of specimens of one or more critical parts of the product", and shall "carry out appropriate examinations and tests, or have them carried out". The supporting evidence includes "where necessary, the results of tests carried out by the appropriate laboratory of the manufacturer". — [Springlex, CRA Annex VIII](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-8/)

**Harmonised standards under M/606 (status October 2026)**
- SecureHabits overview (19.10.2026, updated 23.10.2026, based on DIN/DKE CRA status list Oct 2026 and the ETSI TC CYBER work programme of 16.10.2026):
  - EN 40000-1-1 (vocabulary): Adopted.
  - EN 40000-1-2 (principles, risk management, lifecycle; M/606 #1): Adopted.
  - EN 40000-1-3 (vulnerability handling; #15): "FV pending".
  - EN 40000-1-4 (generic security requirements; #2–14, "including much of Annex I, Part I"): "prEN draft". This is "the one most manufacturers are waiting for".
  - ETSI is drafting 17 vertical EN 304 6xx standards. Examples: EN 304 617 browsers, 304 618 password managers, 304 623 boot managers, 304 626 operating systems, 304 627 routers/modems/switches, 304 634 wearables, 304 635 hypervisors/container runtimes (class II), 304 636 firewalls/IDS/IPS (class II). They are at "prEN vote" or "EN draft"; for ten of them votes closed mid-Sept to mid-Oct 2026 with results pending.
  - CLC/TC 65X is drafting the EN 50770 series (OT products), plus EN IEC 62443-4-1/prAA and 62443-4-2/prAA (EN draft) and 62443-3-3/prAA (NWI).
  - Source: [SecureHabits, CRA harmonised standards (Oct 2026)](https://www.securehabits.nl/knowledge/cra-harmonised-standards-overview/)
- Conflicting status reports for EN 40000-1-1/-1-2: one tracker lists them "Under Approval" with ratification scheduled for **2.11.2026** ([CRA Evidence tracker](https://craevidence.com/cra-compliance/harmonised-standards-status)). Another says they were approved by CENELEC members in October 2026, with publication scheduled for **25.11.2026** and national adoption by **31.05.2027** ([GlobalNorm](https://compliance.globalnorm.de/en/product-compliance-news/detail/eu-cyber-resilience-act-cra-standards-en-40000-1-x-series/)). SecureHabits lists both as "Adopted". These sources disagree, and I did not verify on the CEN-CENELEC database.
- As of 17.10.2026 "no CRA harmonised standard has been published in the Official Journal and no common specification has been adopted" — [CRA Evidence, timeline](https://craevidence.com/blog/cyber-resilience-act-implementation-timeline-2027). The Commission guidance status (27.07.2026) says the same — [cyberresilienceact.eu](https://www.cyberresilienceact.eu/news/commission-cra-application-guidance-published-27-july-2026.html)
- I found no harmonised standard dedicated to secure update. Update requirements are expected inside EN 40000-1-4 (generic) and the vertical EN 304 6xx standards. The draft content is not public.

**Commission / ENISA guidance**
- Draft Art. 26 guidance was published on 3.03.2026 for consultation ([Linklaters](https://techinsights.linklaters.com/post/102mmlo/eu-cyber-resilience-act-commission-issues-first-draft-guidance-10-key-points-y)). The final guidance was published **27.07.2026** as Communication **C(2026) 5252** with an annex: non-binding, with 67 practical examples. It treats substantial modification (Art. 3(30)) and support period (Art. 3(20)). Its official links: [digital-strategy.ec.europa.eu – guidance](https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation) and the CRA implementation FAQs updated 2.07.2026 ([digital-strategy FAQ](https://digital-strategy.ec.europa.eu/en/library/cyber-resilience-act-implementation-frequently-asked-questions)). Sources: [cyberresilienceact.eu](https://www.cyberresilienceact.eu/news/commission-cra-application-guidance-published-27-july-2026.html); [Thomas Murray](https://cyber.thomasmurray.com/insights/eu-cyber-resilience-act-commission-publishes-implementation-guidance).
- Per commentary, the guidance's update-related point is that for software updates "the focus is on whether an update introduces new threat vectors or materially alters existing attack scenarios", and that genuine security updates are generally not substantial modifications. UNVERIFIED against the Commission text. — [search summary of Linklaters / cyberresilienceact.eu](https://techinsights.linklaters.com/post/102mmlo/eu-cyber-resilience-act-commission-issues-first-draft-guidance-10-key-points-y)

### Inferences
- Through Annex I, the CRA demands authenticity and integrity of updates (Part II (7) "securely distribute"; Part I (2)(f) integrity of "programs"), availability and timeliness (Part II (2), (7), (8); Art. 13(8)–(9)), transparency and user control (Part I (2)(c); Annex II (7), (8)), and resilience of essential functions (Part I (2)(h), relevant to fail-safe update). Anti-rollback, anti-freeze, mix-and-match and key-compromise resilience are left to the risk assessment and future harmonised standards. Mapping these threats to the CRA therefore goes through (2)(f) plus Part II (7). That mapping is an interpretation, not literal text.
- No harmonised standard is in the OJ as of October 2026, and default-category products use module A self-declaration. So for most products, demonstrating "secure distribution of updates" today is a manufacturer-authored technical file (Annex VII) plus a risk assessment. This supports the thesis claim for the CRA specifically.

### Gaps
- The text of prEN 40000-1-4 and of the EN 304 6xx drafts on update mechanisms is not publicly available, so I could not determine whether they will require anti-rollback or fail-safe behaviour.
- The exact final dates for EN 40000-1-1/-1-2 (ratification on 2.11.2026 and publication on 25.11.2026) are reported only by trackers. Check them on the CEN-CENELEC search.
- I could not retrieve the C(2026) 5252 annex text itself. Its treatment of automatic updates is unverified.
- Annex II sub-point letters (8)(c)/(8)(e) are inferred from list order.

---

## 2. Other EU/ETSI: RED Delegated Act 2022/30 + EN 18031 (SUM-1..3), ETSI EN 303 645 §5.3, ETSI TS 103 701

### Takeaway
The RED cybersecurity delegated act applies from 1.08.2025. EN 18031-1/-2/-3:2024 are cited (with restrictions) via Implementing Decision (EU) 2025/138. Its update requirements are SUM-1 (an update mechanism must exist), SUM-2 ("only install software whose integrity and authenticity are valid at the time of the installation") and SUM-3 (automated updates). SUM-2 is the most "executable" EU requirement: its functional sufficiency assessment prescribes concrete negative tests (unsigned, modified signature, modified payload, unauthorized signer; MITM for secure-channel designs). Neither EN 18031 nor EN 303 645 normatively requires anti-rollback, freshness, key-compromise resilience or fail-safe/atomic installation. These appear only in informative "Guidance" or "EXAMPLE" text, which (for EN 18031) is explicitly excluded from presumption of conformity.

### Cited Findings
**RED DA (EU) 2022/30 and EN 18031**
- The Commission's EN 18031 guidance says the Art. 3(3)(d), (e), (f) requirements, "rendered applicable through Commission Delegated Regulation 2022/30 … will apply as of **1 August 2025**". EN 18031-1/-2/-3:2024 "are cited, with some restrictions, in the Official Journal … via Commission Implementing Decision (EU) 2022/2191". — [European Commission DG GROW, Guidance on EN 18031 (hosted by digital.gob.es)](https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/areas_interes/equipos-telecomunicacion/documents/Guia-aplicacion-EN-18031.pdf)
- The amending Implementing Decision (EU) **2025/138 of 28.01.2025** added EN 18031-1/2/3:2024 with restrictions. The OJ citation was published 30.01.2025 — [Ezurio](https://www.ezurio.com/resources/blog/understanding-eu-commission-implementation-of-decision-eu-2025-138-new-harmonized-standards-and-restrictions); [TÜV SÜD](https://www.tuvsud.com/en-gb/resource-centre/blogs/uk/testing-and-certification-blog/red-cyber-standards-oj-citation). Delegated Regulation 2023/2444 moved the application date to 1.08.2025 — [UL Japan](https://japan.ul.com/resources/nb検証についての公表事項)
- **Restriction 1** (all three parts): "The sections named 'rationale' and 'guidance' do not confer a presumption of conformity". Restriction 2: clauses 6.2.5.1/6.2.5.2 (allowing no password) give no presumption. Restriction 3 (EN 18031-2): parental access control. — [Commission EN 18031 guidance](https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/areas_interes/equipos-telecomunicacion/documents/Guia-aplicacion-EN-18031.pdf)
- The EN 18031-1:2024 full text is publicly available from NEK (header: "CLC/ECJ ruling C588/21P on CEN and CENELEC – Request on CENELEC homegrown hENs via regulation 1049/2001"). — [NEK EN 18031-1:2024 (PDF)](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- **6.3.1 [SUM-1] Applicability of update mechanisms**, 6.3.1.1 Requirement: "The equipment shall provide at least one update mechanism for updating software, including firmware, affecting security assets and/or network assets, except for software: — where functional safety implications do not allow updatability; or — which is immutable; or — where alternative measures protect the affected security assets and/or network assets during the entire lifecycle of the equipment." Functional sufficiency (6.3.1.4.6): the manufacturer provides "updated software (SW-a) which is integrity-protected and authenticity-protected"; the assessor installs SW-a, and the verdict is PASS if "no evidence that an installation of SW-a is not successful". Functional completeness: "None." — [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- **6.3.2 [SUM-2] Secure updates**, 6.3.2.1: "Each update mechanism as required per SUM-1 shall only install software whose integrity and authenticity are valid at the time of the installation." Implementation categories (6.3.2.4.2):
  - [IC.SUM-2.AuthIntVal.Sign]: digital signatures by authorized entities;
  - [IC.SUM-2.AuthIntVal.SecChan]: secure communication to the authorized source per SCM-1/SCM-2;
  - [IC.SUM-2.AuthIntVal.AccContMech]: access control per ACM-1 "combined with hash-protected software update";
  - [IC.SUM-2.AuthIntVal.Generic]: other methods.
  - Source: [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- SUM-2 conceptual assessment (6.3.2.4.4): check that each documented path through "the decision tree in Figure 12" ends in PASS and that the justification [E.Just.DT.SUM-2] is correct. This is document-based. Functional completeness (6.3.2.4.5) is "not necessary". — [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- SUM-2 functional sufficiency (6.3.2.4.6.3), the only normative executable checks on update security in EU standards found:
  - [AU.SUM-2.Sign]: "functionally confirm that: it is implemented using best practice cryptography according to CRY-1; an unsigned software update is not installed; a software update with a modified signature is not installed; a modified software update with a valid signature for the unmodified software update is not installed; a software update with a signature from an unauthorized entity is not installed."
  - [AU.SUM-2.SecChan]: "a software update from an unauthorized source is not installed; the secure communication channel does not allow to impersonate the authorized software updates source via a man-in-the-middle attack; a software update that is modified during communication is not installed."
  - [AU.SUM-2.AccContMech]: modified update with valid hash of unmodified update not installed; unsupported hash function not accepted; update by unauthorized entity not installed.
  - [AU.SUM-2.Generic]: invalid integrity or authenticity → not installed.
  - Source: [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- **6.3.3 [SUM-3] Automated updates**, 6.3.3.1: "Each update mechanism that is required per SUM-1 shall be capable of updating the software: — without human intervention at the equipment; or — via scheduling the installation of an update under human approval; or — via triggering the installation of an update under human approval or supervision where there is the need to prevent any unexpected damage in the operational environment." Functional sufficiency: check the version, make an update available at the source, and observe whether the equipment updates as documented. — [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- The only "roll-back" mention in EN 18031-1 is in **6.3.3.3 Guidance** (informative): "In case the installation of the new software version fails, e.g., validation of the software image(s) is unsuccessful, a best practice is to apply a roll-back policy to re-activate the previous software version, unless not enough memory is available to store the update." EN 18031-1 contains no mention of downgrade/anti-rollback, freeze or key compromise (term search over the full text). — [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf); under Restriction 1, guidance does not confer presumption — [Commission EN 18031 guidance](https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/areas_interes/equipos-telecomunicacion/documents/Guia-aplicacion-EN-18031.pdf)
- EN 18031 uses a three-step evaluation: conceptual assessment, functional completeness, functional sufficiency — [TÜV SÜD webinar](https://www.tuvsud.com/en-us/resource-centre/webinar/en-18031-evaluation-explained-in-red-assessment-walk-through); [Applus+](https://appluslaboratories.com/global/en/news/publications/exploring-the-en-18031-standard:-cybersecurity-testing-for-red-compliance)

**ETSI EN 303 645 V3.1.3 (2024-09), §5.3 "Keep software updated"** — source for all items: [ETSI EN 303 645 V3.1.3 PDF](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf)
- Status legend (Annex B): M = mandatory, R = recommendation, C = conditional, F = applies to a feature. Condition (12) is "an update mechanism is implemented"; condition (15) is "no resource constraint determined by the use case".
- Provisions:
  - 5.3-1 (R F): "All software components in consumer IoT devices that are not immutable due to security reasons should be securely updateable."
  - 5.3-2 (M C(15)): "The consumer IoT device shall have a secure update mechanism unless the device has a resource constraint determined by the use case that prevents the implementation."
  - 5.3-3 (M F): "An update shall be simple for the user to apply."
  - 5.3-4 Void.
  - 5.3-4A (R F): "One secure update mechanism should be configurable to be automated."
  - 5.3-4B (R F): "During initialization the consumer IoT device should activate an automatic secure update mechanism after user's consent."
  - 5.3-5 (R F): device or associated service "should check after initialization whether security updates are available."
  - 5.3-6 Void.
  - 5.3-6A (R F): user able to enable/disable automatic updates "and postpone the installation".
  - 5.3-6B (R F): enable/disable update notifications.
  - 5.3-7 (M F): "The consumer IoT device shall use best practice cryptography to facilitate secure update mechanisms."
  - 5.3-8 (M C(12)): "Security updates shall be timely."
  - 5.3-9 (R F): "The consumer IoT device should verify the authenticity and integrity of software updates."
  - 5.3-10 (M F): "Where updates are delivered over a network interface, the consumer IoT device shall verify the authenticity and integrity of each update via a trust relationship."
  - 5.3-11 (R C(12)): inform the user that a security update is required, "together with information on the risks mitigated".
  - 5.3-12 (R C(12)): notify the user "when the application of a software update will disrupt the basic functioning".
  - 5.3-13 (M): "The manufacturer shall publish … the defined support period."
  - 5.3-14 (R C(3)): for non-updatable devices, publish the rationale and hardware replacement support.
  - 5.3-15 Void.
  - 5.3-15A/15B (R C(3)): non-updatable devices "should be isolable" / hardware "should be replaceable".
  - 5.3-16 (M): model designation clearly recognizable.
- Informative text on the threats in the thesis:
  - EXAMPLE 6: "authentic software update servers, integrity protected communications channels, verifying the authenticity and integrity of software updates".
  - **EXAMPLE 7: "An anti-rollback policy based on version checking can be used to prevent downgrade attacks."**
  - After 5.3-4B: "If an automatic update fails, then a user can, in some circumstances, no longer be able to use a device. Detection mechanisms such as watchdogs and the use of dual-bank flash or recovery partitions can ensure that the consumer IoT device returns to either a known good version or the factory state."
  - NOTE 7 (5.3-10) lists valid trust relationships: "authenticated communication channels, presence on a network that requires … a critical security parameter or password to join, digital signature based verification of the update, or confirmation by the user." The last two options mean that trust-on-network or user confirmation satisfies the mandatory provision.

**ETSI TS 103 701 V2.1.1 (2025-05), test specification for EN 303 645** — source for all items: [ETSI TS 103 701 V2.1.1 PDF](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf)
- Assessment procedure (§4.3):
  - Phase 1: the Supplier Organization (SO) completes the identification of the device under test (DUT).
  - Phase 2: the SO completes the ICS (Implementation Conformance Statement).
  - Phase 3: the SO completes the IXIT (Implementation eXtra Information for Testing).
  - The Test Laboratory (TL) then verifies the IXIT and ICS (Phase 4) and runs the assessment (Phase 5).
- Each provision has "conceptual" test cases (design review against the IXIT) and, for some, "functional" ones:
  - **5.3-2-1 (conceptual)**: the TL assesses whether the design prevents misuse "according to the 'Security Guarantees'". EXAMPLE: "A misuse can be the installation of an old software update to downgrade the security capabilities of the DUT or the injection of malware by manipulating a valid update."
  - **5.3-2-2 (functional)**: "the TL shall devise functional attacks to misuse the update mechanism based on the 'Description'". EXAMPLE 1: MITM. NOTE 1: "An attack can be trying to resume the sequence of update steps after some failure of a specific update step, installing an older firmware version that contains security vulnerabilities, or changing one byte in a signed firmware to check that it is rejected." NOTE 2: an old update package can be used "even if no update is available during the assessment".
  - **5.3-7-1**: conceptual only (cryptography).
  - **5.3-8-1**: conceptual only (timeliness).
  - **5.3-9-1**: conceptual only (authenticity/integrity verification).
  - **5.3-10-1 (conceptual/functional)**: conceptual check of the trust relationship. The functional part only checks "whether update mechanisms that are not documented in IXIT 7-UpdMech are available via a network interface" (e.g. with network traffic analysers).
  - 5.3-11 and 5.3-12: conceptual only.
  - 5.3-13: conceptual plus functional (publication check).

### Inferences
- The thesis claim "assessment relies on vendor documentation" needs refining for the EU radio/consumer-IoT layer. EN 18031 SUM-2 and TS 103 701 5.3-2-2 do require executable tests, but:
  - (a) the tests are scoped by vendor-supplied documentation ([E.Info]/IXIT);
  - (b) TS 103 701 leaves the attack design to the lab ("shall devise"), with no fixed test vectors;
  - (c) the normative negative tests cover only basic authenticity/integrity (unsigned, bad signature, tampered payload, wrong signer, MITM).
- Rollback/downgrade, resume-after-failure and power loss appear only as non-binding EXAMPLE/NOTE/Guidance text. No standardized executable tests exist for freeze, mix-and-match, key compromise, rollback or atomicity. That is the gap an executable cross-ecosystem benchmark could fill.
- Under EN 303 645 5.3-10 NOTE 7, "confirmation by the user" or network membership counts as a trust relationship. Mandatory conformity can therefore be met without cryptographic verification of the update itself. This is a weak point to emphasise.

### Gaps
- I did not extract the EN 18031-2/-3 SUM text. EN 18031-3 is listed with the same SUM-1..3 structure ([DIN TOC](https://www.din.de/de/mitwirken/normenausschuesse/nia/veroeffentlichungen/wdc-beuth:din21:383496173/toc-3674607/download)), but I did not check its content.
- I did not check whether later amendments to Implementing Decision 2022/2191 (e.g. one dated 9.12.2025 per [UL Japan](https://japan.ul.com/resources/nb検証についての公表事項)) changed the EN 18031 restrictions.
- I did not verify how the RED requirements transition to the CRA. The CRA is expected to supersede RED 3(3)(d)-(f) for covered products from 11.12.2027, but I have no source fetched for this.

---

## 3. Automotive: UNECE R156 (SUMS), R155 (CSMS), ISO 24089:2023, ISO/SAE 21434:2021

### Takeaway
UN R156 is the only regulation found that normatively requires fail-safe update behaviour: "restore systems to their previous version in case of a failed or interrupted update or … safe state" (7.2.2.1.1) and "enough power to complete the update process (including that needed for a possible recovery…)" (7.2.2.1.2). It also requires that "authenticity and integrity of software updates shall be protected" (7.2.1.1). Compliance is shown through manufacturer demonstration and documentation ("the vehicle manufacturer shall demonstrate…"). R155 Annex 5 is the only regulatory threat catalogue found that explicitly names key compromise (12.4), update denial-of-service (13.1) and downgrade via replay (6.3).

### Cited Findings
**UN R156** (adopted text ECE/TRANS/WP.29/2020/80, dated 31.03.2020, voted at the WP.29 181st session, 23–25.06.2020) — [UN ODS: ECE/TRANS/WP.29/2020/80](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf). Entry into force **22.01.2021**; published in the EU OJ as 2021/388 — [EUR-Lex 2021/388](https://eur-lex.europa.eu/eli/reg/2021/388/oj) (date from search snippet). Paragraph numbers below come from the adopted proposal. Later supplements may have changed wording (not checked).
- §1 Scope: "applies to vehicles of Categories M, N, O, R, S and T that permit software updates."
- 7.1 (SUMS process requirements): 7.1.1.x processes include records of "all initial and updated software versions, including integrity validation data". 7.1.2.3: "For every RXSWIN, there shall be an auditable register describing all the software relevant to the RXSWIN … before and after an update … software versions and their integrity validation data". 7.1.2.5 requires documentation per update, including "(h) Confirmation that the software update will be conducted safely and securely; (i) Confirmation that the software update has undergone and successfully passed verification and validation procedures."
- **7.1.3 "Security – the vehicle manufacturer shall demonstrate:"**
  - 7.1.3.1: "The process they will use to ensure that software updates will be protected to reasonably prevent manipulation before the update process is initiated";
  - 7.1.3.2: "The update processes used are protected to reasonably prevent them being compromised, including development of the update delivery system";
  - 7.1.3.3: verification and validation of software functionality and code.
- 7.1.4.1: processes "to assess that over the air updates will not impact safety, if conducted during driving". 7.1.4.2: skilled-person requirement for complex post-update actions.
- **7.2.1.1 (vehicle type)**: "The authenticity and integrity of software updates shall be protected to reasonably prevent their compromise and reasonably prevent invalid updates."
- 7.2.1.2.1–7.2.1.2.3: RXSWIN "uniquely identifiable" and "easily readable … at least by the standard interface (OBD port)". A further paragraph (7.2.1.3, numbering inferred) requires protecting "the RXSWINs and/or software version(s) on a vehicle against unauthorised modification".
- **7.2.2 OTA, 7.2.2.1 "The vehicle shall have the following functionality":**
  - **7.2.2.1.1**: "The vehicle manufacturer shall ensure that the vehicle is able to restore systems to their previous version in case of a failed or interrupted update or that the vehicle can be placed into a safe state after a failed or interrupted update."
  - **7.2.2.1.2**: "The vehicle manufacturer shall ensure that software updates can only be executed when the vehicle has enough power to complete the update process (including that needed for a possible recovery to the previous version or for the vehicle to be placed into a safe state)."
  - **7.2.2.1.3**: "When the execution of an update may affect the safety of the vehicle, the vehicle manufacturer shall demonstrate how the update will be executed safely. This shall be achieved through technical means that ensures the vehicle is in a state where the update can be executed safely."
- **7.2.2.2**: the user is informed before execution: (a) purpose/criticality; (b) changes to functions; (c) expected time; (d) unavailable functionalities; (e) instructions.
- 7.2.2.3: where the update may not be safe while driving, the manufacturer demonstrates how it will "(a) Ensure the vehicle cannot be driven during the execution of the update; (b) Ensure that the driver is not able to use any functionality … that would affect the safety … or the successful execution of the update."
- 7.2.2.4: after execution, the user "is able to be informed of the success (or failure) of the update" and of changes.
- 7.2.2.5: "The vehicle shall ensure that preconditions have to be met before the software update is executed."
- The R156 text contains no mention of rollback/downgrade protection, replay or key compromise (term search). Its "restore … previous version" is about recovery, not anti-rollback. — [UN ODS R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf)

**UN R155** (ECE/TRANS/WP.29/2020/79) — [UN ODS: ECE/TRANS/WP.29/2020/79](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf)
- Annex 5 Part A Table A1, 4.3.3 "Threats to vehicles regarding their update procedures":
  - 12 "Misuse or compromise of update procedures":
    - 12.1 "Compromise of over the air software update procedures. This includes fabricating the system update program or firmware";
    - 12.2 the same for local/physical update;
    - 12.3 "The software is manipulated before the update process (and is therefore corrupted), although the update process is intact";
    - **12.4 "Compromise of cryptographic keys of the software provider to allow invalid update"**.
  - **13.1 "Denial of Service attack against update server or network to prevent rollout of critical software updates and/or unlock of customer specific features"**.
- Table A1 item 6.3 (session hijacking/replay): "Replay attack, for example an attack against a communication gateway allows the attacker to **downgrade software of an ECU or firmware of the gateway**".
- Annex 5 Part B Table B2 mitigations:
  - 12.1–12.3 → **M16** "Secure software update procedures shall be employed";
  - 12.4 → **M11** "Security controls shall be implemented for storing cryptographic keys";
  - 13.1 → **M3** "Security Controls shall be applied to back-end systems. Where back-end servers are critical to the provision of services there are recovery measures in case of system outage".

**EU application of R155/R156**
- Under the General Safety Regulation (EU) 2019/2144, R155/R156 compliance became mandatory for new EU whole-vehicle types from July 2022 and for all new vehicles from **7 July 2024**: refusal of type approval and prohibition of registration. — [Regulation 2019/2144 Annex (legislation.gov.uk copy)](https://legislation.gov.uk/eur/2019/2144/annexes/data.pdf); [Applus+](https://www.appluslaboratories.com/global/en/news/publications/new-cybersecurity-regulations-vehicles-unece-wp29). A Spanish CERT guide gives 1 July 2024 ([INCIBE](https://www.incibe.es/en/incibe-cert/blog/new-2024-cybersecurity-regulations-vehicles)), which conflicts with the 7 July date in the annex.

**ISO 24089:2023 "Road vehicles — Software update engineering"**
- Clause structure from the official sample:
  - 5 Project level (5.3.1 project management, 5.3.2 tailoring, 5.3.3 interoperability, **5.3.4 Integrity**);
  - 6 Infrastructure level (6.3.1 managing risk, 6.3.2 vehicle configuration information, 6.3.3 communicating campaign information, 6.3.4 processing software update packages);
  - 7 Vehicle and vehicle systems level (7.3.1–7.3.4, same topics);
  - 8 Software update package (8.3.1 identification of targets and contents, 8.3.2 assembly, 8.3.4 approval for release);
  - 9 Software update campaign (9.3.1 preparation, 9.3.2 execution, 9.3.3 completion).
  - Source: [ISO 24089:2023 sample (iTeh)](https://cdn.standards.iteh.ai/samples/77796/aab70139ffd74d589ac5d21dc2efe66f/ISO-24089-2023.pdf)
- An amendment ISO 24089:2023/Amd 1:2024 is reported to exist — UNVERIFIED (search summary only).

**ISO/SAE 21434:2021**
- Clause 13 "Operations and maintenance" covers "cybersecurity incident response and updates to an item or component". Clause 14 covers "End of cybersecurity support and decommissioning". Clause 8 defines vulnerability management "until end of cybersecurity support". — [UL Solutions training description](https://ul.com/sis/training/introduction-isosae-21434)

**Assessment practice**
- Most R156 paragraphs are phrased as "the vehicle manufacturer shall demonstrate…" or "Documentation describing…". Type-approval technical services offer "assessment of software update procedures" — [UN ODS R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf); [TÜV SÜD](https://www.tuvsud.com/en-ae/industries/mobility-and-automotive/automotive-and-oem/autonomous-driving/assessment-of-automotive-software-updates)

### Inferences
- R156 7.2.2.1.1 and 7.2.2.1.2 map directly to the thesis's atomicity/fail-safe and recoverability threats (interrupted update, power loss). R155 12.4/M11 maps to key-compromise resilience, 13.1/M3 to update DoS/availability, and 6.3 to rollback/downgrade.
- No requirement found demands freshness (anti-freeze) or protection against mix-and-match of ECU images. RXSWIN registers with integrity validation data (7.1.2.3) support inventory consistency but are documentation artefacts.
- In UN R156, verification is "demonstration" to the approval authority. The regulation itself specifies no standardized test procedure for fail-safe behaviour.

### Gaps
- I could not access ISO 24089 and ISO/SAE 21434 requirement texts (paywalled), including the RQ-13-xx IDs. Detailed requirements on update-package integrity and campaign failure handling are unverified.
- I did not check the later R156 supplements and amendments, or the UNECE interpretation document for R156.
- **Russia (automotive):** I found no Russian national standard (ГОСТ Р) on vehicle OTA/SUMS. I also did not verify whether Russia applies UN R155/R156 under the 1958 Agreement or the EAEU vehicle safety regulation (ТР ТС 018/2011). — searches on normacs.info and gostinfo returned nothing relevant ([normacs](https://www.normacs.info/projects/7875)).

---

## 4. US / UK / international: NIST SP 800-193, SP 800-147, IR 8259A, IR 8425 + FCC Cyber Trust Mark, UK PSTI, IEC 62443-4-1/4-2, FDA

### Takeaway
NIST SP 800-193 (May 2018) is the most technically complete text on update-system properties. It requires:
- signature-verified updates anchored in a Root of Trust for Update (RTU);
- non-bypassability;
- anti-rollback: "shall be capable of preventing unauthorized updates … to an earlier authentic version";
- recoverability "even in the event of … power loss in the middle of a flash write";
- authenticated key-store update for key-compromise recovery;
- authenticated recovery.

These are guidelines without a mandated test procedure. NIST IR 8259A/8425 and the FCC Cyber Trust Mark require only "receive, verify, and apply verified software updates". The UK PSTI Regulations require only publication of the support period.

### Cited Findings
**NIST SP 800-193 "Platform Firmware Resiliency Guidelines" (May 2018)** — source for all items: [NIST SP 800-193 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf)
- 4.1.2 (RTU/CTU):
  - (1) "Each platform device with mutable firmware shall rely on either a Root of Trust for Update (RTU), or a Chain of Trust for Update (CTU) … to authenticate firmware updates."
  - **(2)** a mutable RTU/CTU is updated via an authenticated update mechanism; "During such an update, the RTU or CTU shall always be operational or recoverable upon a subsequent reboot even in the event of an unexpected, catastrophic event (e.g., **power loss in the middle of a flash write operation**)."
  - (3) key store plus FIPS 186-4 signature verification.
  - **(4)** "If the key store is updateable, then the key store shall be updated using an authenticated update mechanism". Note: "Updatable key stores provide a means to recover from compromise of the signing key".
  - (5) authenticated update mechanism "shall be the exclusive means for updating device firmware, absent unambiguous physical presence".
- **4.2.1.1 Authenticated Update Mechanism**:
  - (1) signed with FIPS 186-4 algorithm, ≥112-bit strength;
  - (2) "signed by an authorized entity";
  - (3) "The digital signature of a new or recovery firmware update image shall be verified by an RTU or a CTU prior to the non-volatile storage completion of the update process."
- 4.2.1.2 Integrity Protection: flash regions "modifiable only through an authenticated update mechanism or by a secure local update mechanism".
- **4.2.1.3 Non-Bypassability**:
  - (1) "The protection mechanisms shall ensure that authenticated update mechanisms are not bypassed."
  - **(2) "The authenticated update mechanism shall be capable of preventing unauthorized updates of the device firmware to an earlier authentic version that has a security weakness or would enable updates to a version with a known security weakness."**
  - Note: "unauthorized rollback could allow an attacker to restore a vulnerable firmware image".
- **4.4.1 Recovery of Mutable Code**:
  - (1) recovery mechanisms "shall resist attacks which corrupt the active critical data or the primary firmware image";
  - (2) RTRec/CTRec "shall be capable of obtaining an authentic device firmware image";
  - (4) non-local recovery uses the authenticated update mechanism;
  - (8) logging of recovery events "should";
  - (12) administrator-forced recovery;
  - **(13) "The recovery process should protect against unauthorized recovery to an earlier firmware version that contains a security weakness."**

**NIST SP 800-147 "BIOS Protection Guidelines" (April 2011)** — source for all items: [NIST SP 800-147 PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf)
- 3.1.1 BIOS Update Authentication: an RTU with signature verification and key store; images signed per SP 800-89 with FIPS 186-3, ≥112 bits. "The update mechanism shall ensure that the BIOS update image has been digitally signed … before updating the BIOS." "The authenticated update mechanism **should prevent the unauthorized rollback** of the BIOS to an earlier authentic version that has a known security weakness … by verifying that the version number … is larger than the currently installed".
- 3.1.2 Secure Local Update "shall ensure the authenticity and integrity … by requiring physical presence".
- 3.1.3 Integrity Protection.
- 3.1.4 Non-Bypassability: "The authenticated BIOS update mechanism shall be the exclusive mechanism for modifying the system BIOS".

**NIST IR 8259A "IoT Device Cybersecurity Capability Core Baseline" (May 2020)**
- "Software Update: The IoT device's software can be updated by authorized entities only using a secure and configurable mechanism." Common elements:
  - "1. … remote … and/or local means";
  - "2. The ability to verify and authenticate any update before installing it";
  - "**3. The ability for authorized entities to roll back updated software to a previous version**";
  - "4. … restrict updating actions to authorized entities only";
  - "5. … enable or disable updating";
  - 6a: automatic/manual configuration;
  - 6b: notification.
- The rationale notes the trade-off with "the risk of someone intentionally or inadvertently rolling software back to a vulnerable version".
- Reference mapping includes "IEC: CR 3.4, EDR 3.10".
- Source: [NIST IR 8259A PDF](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf)

**NIST IR 8425 (September 2022) and the FCC Cyber Trust Mark**
- NIST IR 8425 "Software Update" outcome: software "can be updated by authorized individuals, services, and other IoT product components only by using a secure and configurable mechanism". "1. Each IoT product component can receive, verify, and apply verified software updates. 2. The IoT product implements measures to keep software … up to date (i.e., automatic application of updates or consistent customer notification…)". — [NIST IR 8425 PDF](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8425.pdf)
- FCC Report and Order FCC 24-26 (PS Docket 23-239): adopted **14.03.2024**, released 15.03.2024, Federal Register 30.07.2024. It sets up a voluntary label. Cybersecurity Label Administrators (CLAs) test products against NIST IR 8425 criteria, and the Lead Administrator develops "the specific technical standards and testing procedures". — [FCC 24-26](https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf); [Federal Register 2024-14148](https://www.govinfo.gov/content/pkg/FR-2024-07-30/html/2024-14148.htm)
- UL LLC was selected as Lead Administrator in December 2024 and **withdrew effective 19.12.2025** after an FCC national-security review over alleged ties to China — [Cybersecurity Dive](https://www.cybersecuritydive.com/news/fcc-cyber-trust-mark-iot-labeling-ul-withdraw/808732/); [TechRadar](https://www.techradar.com/pro/security/firm-overseeing-fccs-cyber-trust-mark-program-withdraws-over-ties-to-china). The FCC opened a new window in January 2026 ([Global Policy Watch](https://www.globalpolicywatch.com/2026/01/fcc-opens-application-window-for-new-cyber-trust-mark-program-lead-administrator/)) and selected **ioXt Alliance** as Lead Administrator in **April 2026** ([Nextgov](https://www.nextgov.com/cybersecurity/2026/04/fcc-selects-ioxt-alliance-lead-cyber-labeling-program/412800)). As of October 2026, requirements were still being finalised, and a commissioner "hopes Cyber Trust Mark products reach shoppers within a year" ([Nextgov, Oct 2026](https://www.nextgov.com/cybersecurity/2026/10/fcc-commissioner-hopes-cyber-trust-mark-products-reach-shoppers-within-year/416878/)).

**UK PSTI**
- The Product Security and Telecommunications Infrastructure (Security Requirements for Relevant Connectable Products) Regulations 2023 (SI 2023/1007) came into force **29.04.2024** — [legislation.gov.uk SI 2023/1007](https://www.legislation.gov.uk/uksi/2023/1007/made)
- Schedule 1 para 3 "Information on minimum security update periods":
  - (2) "The defined support period must be published."
  - (3) an extension must be published "as soon as is practicable".
  - (4) it must be "accessible, clear and transparent … without prior request … in English … free of charge … understandable by a reader without prior technical knowledge".
  - (6) "The security requirements in this paragraph are not met if the defined support period is shortened after the publication".
  - Source: [legislation.gov.uk SI 2023/1007 Sch. 1](https://www.legislation.gov.uk/uksi/2023/1007/schedule/1/made)
- I found no technical requirement on the update mechanism itself in Schedule 1 (para 1 covers passwords, para 2 vulnerability reporting, para 3 support period). — [legislation.gov.uk Sch. 1](https://www.legislation.gov.uk/uksi/2023/1007/schedule/1/made)

**IEC 62443**
- IEC 62443-4-1 Practice 7 "Security update management":
  - SUM-1 Security update qualification;
  - SUM-2 Security update documentation;
  - SUM-3 Dependent component or operating system security update documentation;
  - SUM-4 Security update delivery;
  - SUM-5 Timely delivery of security patches.
  - Source: [jtsec, IEC 62443-4-1 practices (PDF)](https://www.jtsec.es/es/files/IEC%2062443-4-1%20Practices%20&%20Requirementes.pdf)
- A survey of industrial manufacturers found the SUM practice among the hardest to meet — [arXiv 2505.14325](https://arxiv.org/pdf/2505.14325)
- IEC 62443-4-2:
  - CR 3.10 "Support for updates", with RE(1) for validating authenticity and integrity of updates required at SL-C 2 and above ([ISA/ISASecure webinar 2019](https://isasecure.org/hubfs/Webinars/Webinars%20PDFs/2019-August-8-Webinar.pdf));
  - component-specific EDR/HDR/NDR 3.10 "Support for updates" and 3.10 RE(1) "Update authenticity and integrity" ([CIP IEC 62443-4-2 FR-3 assessment table](https://2025-cip.readthedocs.io/en/latest/security/iec62443-4-2-FR-3.html));
  - CR 3.4 Software and information integrity ([NIST IR 8259A reference mapping](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf)).
- CRA-oriented amendments EN IEC 62443-4-1/prAA and 4-2/prAA are at "EN draft" stage (Oct 2026) — [SecureHabits](https://www.securehabits.nl/knowledge/cra-harmonised-standards-overview/)

**US FDA (medical devices)**
- Final guidance "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions" was issued 27.06.2025 (Federal Register vol. 90 no. 122). It added Section VII on "cyber devices" under FD&C Act §524B — [Federal Register 2025-11669](https://www.govinfo.gov/content/pkg/FR-2025-06-27/html/2025-11669.htm)
- §524B(b)(2)(A)/(B) require processes to address known unacceptable vulnerabilities "on a reasonably justified regular basis" and to make critical updates and patches available promptly (as summarised by commentators) — [Morgan Lewis](https://www.morganlewis.com/blogs/asprescribed/2025/11/from-vulnerability-to-violation-fda-cybersecurity-requirements-for-medical-devices-and-fca-enforcement)
- A revised version aligned with the QMSR (in effect since 2.02.2026) was reportedly issued **3.02.2026**, with "Quality Management System Considerations" in the title — [DLA Piper (Feb 2026)](https://www.dlapiper.com/en-lu/insights/publications/2026/02/fda-issues-revised-cybersecurity-premarket-submission-guidance); [Innolitics](https://innolitics.com/articles/2026-cybersecurity-guidance/). This rests on secondary sources; I did not verify it on fda.gov.

### Inferences
- SP 800-193 is the best normative anchor for the thesis's anti-rollback (4.2.1.3(2)), fail-safe and power loss (4.1.2(2)), key-compromise recovery (4.1.2(4) note) and recoverability (4.4.1) threats. No NIST test specification accompanies it in the documents reviewed.
- Requirements conflict: NIST IR 8259A element 3 calls for rollback capability for authorized entities, while SP 800-193/800-147 call for anti-rollback against unauthorized entities. A benchmark should test "authorized downgrade possible, unauthorized downgrade rejected".
- None of the US/UK texts reviewed demand freshness (anti-freeze, e.g. metadata expiry) or mix-and-match protection.

### Gaps
- I could not access the IEC 62443-4-1/-4-2 exact requirement wording (paywalled). ISASecure CSA/SDLA test methodology for CR 3.10 is not verified.
- I did not obtain the FCC Cyber Trust Mark test procedures for "software update". They were not finalised as of October 2026.
- I did not fetch the FDA guidance text on updatability (Appendix 1 security architecture "updatability/patchability" views). This is UNVERIFIED.
- I did not research UK PSTI enforcement practice (OPSS).

---

## 5. Russia: FSTEK Order No. 117 (2025), FSTEK update-testing Methodology (28.10.2022), Order No. 239 (KII), certification, GOST R 56939-2024

### Takeaway
Russian requirements regulate update management on the operator side, not the security properties of the update mechanism.
- Order No. 117 (in force 1.03.2026) requires "проверки подлинности и целостности обновлений", testing before production and controlled, authorised installation. It forbids "бесконтрольная установка обновлений".
- Order No. 239 (КИИ) has the measures ОПО.0–ОПО.4: trusted source, integrity control, testing, installation.
- The FSTEK Methodology of 28.10.2022 defines six executable tests per update (T001–T006). They focus on malicious content and authenticity checks.
- None of these documents mention rollback/downgrade protection, freeze, interrupted-update recovery or power loss.
- Requirements on vendors (Order 239 п. 29.3.3) are assessed "на основе результатов анализа материалов и документов, представляемых разработчиком", that is, documentary assessment.

### Cited Findings
**Приказ ФСТЭК России от 11.04.2025 № 117** — main source: [fstec.ru: Требования, утв. приказом № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117) (page updated 09.10.2026)
- Title: «Требования о защите информации, содержащейся в государственных информационных системах, иных информационных системах государственных органов, государственных унитарных предприятий, государственных учреждений». The official page notes «с изменениями, внесенными приказом ФСТЭК России от 8 мая 2026 г. N 137».
- In force **01.03.2026**, replacing Order No. 17 of 11.02.2013; registered by Minjust on 16.06.2025 (per Kontur) — [Контур.Норматив](https://normativ.kontur.ru/document?moduleId=1&documentId=500478); [ppt.ru](https://ppt.ru/amp/obzory/vstupaet-v-silu/prikaz-fstek-rossii-11-04-2025-117). The registration date is UNVERIFIED on pravo.gov.ru.
- Internal regulations must define «порядок получения, оценки, тестирования и применения обновлений программных, программно-аппаратных средств (далее — управление обновлениями)» and «порядок выявления, оценки и устранения уязвимостей … (далее — управление уязвимостями)». They must also cover «требования к резервному копированию информации, программного обеспечения и его конфигураций».
- п. 34: the mandatory activities include «в) управление уязвимостями; г) управление обновлениями; … м) обеспечение разработки безопасного программного обеспечения; … о) обеспечение непрерывности функционирования информационных систем при возникновении нештатных ситуаций; … с) обеспечение защиты от компьютерных атак, направленных на отказ в обслуживании».
- п. 37: контроль конфигураций must «исключать несанкционированное изменение состава программных, программно-аппаратных средств … а также обеспечивать обнаружение фактов несанкционированных изменений».
- п. 38: vulnerabilities must be remediated (or compensated) «в отношении уязвимостей критического уровня опасности — в срок не более 24 часов; в отношении уязвимостей высокого уровня опасности — в срок не более 7 календарных дней». Vulnerabilities not in the BDU must be reported to FSTEK within 5 working days.
- **п. 39 (verbatim):** «Мероприятия по управлению обновлениями должны включать проведение проверки подлинности и целостности обновлений программных, программно-аппаратных средств, тестирование обновлений до их применения в контурах промышленной эксплуатации информационных систем, выдачу разрешения подразделениям (работникам) оператора (обладателя информации) на применение обновлений программных, программно-аппаратных средств в контурах промышленной эксплуатации информационных систем с использованием безопасных настроек и конфигураций, установленных во внутренних стандартах по защите информации. Бесконтрольная установка обновлений программных, программно-аппаратных средств не допускается. Сроки применения обновлений …, предназначенных для устранения уязвимостей, устанавливаются во внутреннем регламенте по защите информации в зависимости от сроков устранения уязвимостей соответствующих уровней опасности и рисков, связанных с применением обновлений».
- п. 50: in-house development must implement «меры, предусмотренные разделами 4 и 5 ГОСТ Р 56939-2024». For contractors these may be included in the technical specification.
- п. 52–53: continuity measures, including «создание достаточного количества резервных копий программных, программно-аппаратных средств и их конфигураций»; restore intervals (class 1 systems: «не более 24 часов»); drills «не реже одного раза в два года».
- п. 66–67: controls on the protection level («автоматизированное и (или) ручное выявление уязвимостей…», «тестирование … путем моделирования реализации актуальных угроз»), at least once every three years.
- п. 68: measures are implemented «с использованием методических документов ФСТЭК России». This is the link to the update-testing Methodology.
- **п. 71:** certified protection tools «должны быть обеспечены со стороны их разработчиков поддержкой безопасности на территории Российской Федерации, включая выпуск и применение обновлений программного обеспечения, обеспечивающих устранение выявленных уязвимостей, дефектов и недостатков».
- The order introduces the protection metric Кзи (sent to FSTEK every 6 months) and the maturity metric Пзи — [Habr / commentary](https://habr.com/ru/articles/945170); [securitylab.ru](https://www.securitylab.ru/blog/personal/Bitshield/360365.php)
- Commentaries recommend testing updates on test machines or segments separate from production, and planning for «отмены установки обновления и "отката" к предыдущему состоянию». This is a commentary or methodical recommendation, not the order's text. UNVERIFIED attribution (search snippet; candidates: [fstec.infobezopasnost.ru](https://fstec.infobezopasnost.ru/stati/prikaz-fstek-117-ot-11-04-2025-polnoe-rukovodstvo-k-dejstviju/), [startx.team](https://startx.team/blog/prikaz-fstek-117-trebovaniya-kzi)).

**«Методика тестирования обновлений безопасности программных, программно-аппаратных средств» (утв. ФСТЭК России 28 октября 2022 г.)** — source for all items: [legalacts.ru (full text)](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/)
- Approved **28.10.2022**. One presentation says 20.10.2022 ([ITSEC 2024 slides](https://www.itsec.ru/hubfs/Digital/SS/SS_ADAPT/ITSEC24_13-06-24_%D0%9D%D0%B8%D0%BA%D0%BE%D0%BD%D0%BE%D0%B2.pdf?hsLang=ru)). Most sources give 28.10.2022.
- п. 1.2: the Methodology «определяет порядок и содержание работ по тестированию программного обеспечения» that removes vulnerabilities. It is mandatory for operators of GIS and significant КИИ objects.
- п. 3.1.1 test types:
  - **Т001** «сверка идентичности обновлений безопасности»: compare updates received from different sources or channels by checksums (п. 3.2). Example: download from IP addresses inside and outside Russia, п. 3.2.2.
  - **Т002** «проверка подлинности обновлений безопасности»: by checksums, electronic signature or other vendor criteria (п. 3.3.2).
  - **Т003** «антивирусный контроль»: at least two AV tools from different vendors (п. 3.4.1).
  - **Т004** «поиск опасных конструкций»: IoCs, YARA, contextual search (п. 3.5.2).
  - **Т005** «мониторинг активности»: in a test environment (п. 3.6.3, including network packet analysis and file-system state before/after).
  - **Т006** «ручной анализ» (п. 3.7).
- п. 2.3 indicators of НДВ:
  - (а) access to data unrelated to the function;
  - (б) hidden access to unknown addresses;
  - (в) malware-like system calls;
  - (г) dangerous file-system changes;
  - (д) unrelated configuration changes;
  - (е) «отключение средств защиты информации и функций безопасности информации».
- п. 2.6: test environments are «исследовательский стенд», «тестовая зона информационной системы ("песочница")» or the production system. Ways of obtaining updates are «не рассматриваются».
- п. 1.5 / 3.1.4: «Решение об установке протестированных обновлений безопасности принимается оператором информационной системы с учетом результатов тестирования».
- The document does **not** mention rollback (откат), freeze/stale updates, power failure, or recovery after failed installation. There is no separate "compare with previous version" test; the closest are Т001 and the file-system diff in п. 3.6.3в.
- FSTEK's BDU publishes results of FSTEK's own testing of security updates for foreign software — [ComNews, 23.01.2023](https://www.comnews.ru/content/224015/2023-01-23/2023-w04/fstek-proverila-obnovleniya)

**Приказ ФСТЭК России от 25.12.2017 № 239** (requirements for significant КИИ objects; ред. от 28.08.2024) — main source: [legalacts.ru, приказ № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/)
- Measure group «XIV. Управление обновлениями программного обеспечения (ОПО)», all marked «+» for significance categories 1, 2 and 3:
  - ОПО.0 «Регламентация правил и процедур управления обновлениями программного обеспечения»;
  - **ОПО.1** «Поиск, получение обновлений программного обеспечения от доверенного источника»;
  - **ОПО.2** «Контроль целостности обновлений программного обеспечения»;
  - **ОПО.3** «Тестирование обновлений программного обеспечения»;
  - **ОПО.4** «Установка обновлений программного обеспечения».
- п. 12.6 в): vulnerability analysis by «анализа состава установленного программного обеспечения и обновлений безопасности». п. 13.3 г): «управление обновлениями программных и программно-аппаратных средств, в том числе средств защиты информации, с учетом особенностей функционирования значимого объекта».
- **п. 29.3.3 «Требования к поддержке безопасности программного обеспечения»** (applied software for significant objects):
  - «наличие процедур отслеживания и исправления обнаруженных ошибок и уязвимостей»;
  - «определение способов и сроков доведения разработчиком (производителем) программного обеспечения до его пользователей информации об уязвимостях …, способов получения пользователями программного обеспечения его обновлений, проверки их целостности и подлинности»;
  - for category 1, «процедур информирования … об окончании производства и (или) поддержки».
- п. 29.3.2: static analysis, fuzzing, and dynamic analysis for category 1.
- **п. 29.4**: compliance with 29.3.1–29.3.3 «оценивается лицом, выполняющим работы по созданию … значимого объекта … на этапе проектирования … **на основе результатов анализа материалов и документов, представляемых разработчиком (производителем) программного обеспечения**».
- п. 31: «В значимом объекте не допускаются: наличие удаленного доступа к программным и программно-аппаратным средствам … для обновления или управления со стороны лиц, не являющихся работниками субъекта критической информационной инфраструктуры…; наличие локального бесконтрольного доступа … для обновления…».

**Certification system and vendor-side obligations**
- Приказ ФСТЭК № 55 of 03.04.2018 «Положение о системе сертификации средств защиты информации» (registered 11.05.2018 No. 51063; current edition listed as of 20.01.2026) — [legalacts.ru, приказ № 55](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-03042018-n-55-ob-utverzhdenii/). Amendment by Order No. 121 of 05.08.2021 (effective 07.11.2021): a serially produced SZI is considered certified if, among other things, the manufacturer or applicant provides technical support — [securitylab.ru (Комаров)](https://www.securitylab.ru/blog/personal/valerykomarov/351569.php). Based on secondary summaries; I did not read the clause text.
- Practice: re-certifying updates of certified products took «минимум полгода», per Habr citing Vedomosti, 15.04.2024. FSTEK planned to shift toward certifying the development process; these are proposals, not adopted norms — [Habr, 15.04.2024](https://habr.com/en/news/807921)
- FSTEK information message of 28.05.2026 (No. 240/24/3693) introduced a new methodology for finding vulnerabilities and НДВ in software. It applies to initial certification and «изменений в уже сертифицированных решениях», aligns with ГОСТ Р 56939-2024, and replaces the methodology of 25.12.2020 — [Anti-Malware.ru, 05.06.2026](https://www.anti-malware.ru/news/2026-06-05-111332/50292?page=2). I could not find the official title or text.
- Приказ ФСТЭК № 76 of 02.06.2020 (уровни доверия) applies to SZI for state secrets, other restricted information and КИИ — [klerk.ru extract](https://www.klerk.ru/doc/596373/); [Kaspersky RegulHub PDF](https://regulhub.kaspersky.ru/assets/files/%D0%9F%D1%80%D0%B8%D0%BA%D0%B0%D0%B7%20%D0%A4%D0%A1%D0%A2%D0%AD%D0%9A%20%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D0%B8%2076.pdf). The public extract does not contain the detailed requirements on security support or updates.

**ГОСТ Р 56939-2024 «Защита информации. Разработка безопасного программного обеспечения. Общие требования»**
- Approved by Rosstandart order of **24.10.2024 № 1504-ст** (footnote [5] in Order 117) — [fstec.ru, приказ № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117)
- In force **20.12.2024**, replacing ГОСТ Р 56939-2016 — [Habr](https://habr.com/ru/articles/925966); [meganorm](https://meganorm.ru/Index/83/83777.htm)
- It describes 25 processes in section 5. Per webinar materials, 5.21 «Обеспечение безопасности при выпуске готовой к эксплуатации версии программного обеспечения», 5.22 «Безопасная поставка программного обеспечения пользователям», 5.23 «Реагирование на информацию об уязвимостях», and the 25th process «поиск уязвимостей при эксплуатации» — [vc.ru (А. Карпов)](https://vc.ru/id371670). The numbering is UNVERIFIED against the standard text.
- Audits use checklists, interviews and documentation analysis — [Anti-Malware.ru](https://www.anti-malware.ru/analytics/Technology_Analysis/GOST-R-56939-2024-Secure-Development-Audit)

### Inferences
- In Russian regulation, update authenticity and integrity is an operator duty, checked per update (Order 117 п. 39, 239 ОПО.1–ОПО.2, Методика Т001–Т002). It is not stated as a design property of the vendor's update client. Vendor obligations stop at describing «способов получения … обновлений, проверки их целостности и подлинности» (239 п. 29.3.3), which is checked from documents (п. 29.4).
- Rollback/downgrade protection, freeze, key-compromise resilience and atomicity/power-loss behaviour are absent from all Russian texts reviewed. Recovery appears only as generic backup/continuity (117 п. 52–53). An executable benchmark would therefore add a layer the Russian regulatory framework does not currently specify.
- Т001 (cross-source identity check) is the only Russian control that partly addresses targeted or malicious-mirror attacks, by comparing updates obtained via different channels.

### Gaps
- I did not research ГОСТ Р 71207-2024 (static analysis): date and relevance unverified.
- No FSTEK requirements specific to "update tools" (средства обновления) were found. I did not review the trusted boot requirements (средства доверенной загрузки, Order No. 119 of 2013).
- I did not research ГОСТ Р 57580 (Bank of Russia).
- The Order 76 "поддержка безопасности" requirement text is not public in full.
- The Order 55 clauses on changes to certified SZI were not read in full.
- I did not establish whether a new КИИ order is replacing Order 239 in 2026.

---

## 6. Conformity assessment practice: documentation vs executable tests

### Takeaway
Across regimes, update-mechanism security is mostly evidenced by manufacturer documentation, declarations and process audits:
- CRA module A, notified-body review of documentation (module B);
- UN R156 "shall demonstrate";
- FSTEK 239 п. 29.4 "анализ материалов и документов";
- ICS/IXIT questionnaires in TS 103 701;
- decision-tree justifications in EN 18031.

Executable tests exist (EN 18031 SUM-2 functional sufficiency, TS 103 701 5.3-2-2, the FSTEK Методика), but they are either limited to basic signature/integrity rejection or aimed at the content of an update rather than the update system's resistance to rollback, freeze, mix-and-match, key compromise or interrupted installation. No standardized cross-ecosystem test suite for these properties was found.

### Cited Findings
- CRA: module A "the manufacturer … declares on its sole responsibility". Module B: NB examines "technical documentation and supporting evidence" and specimens, and "carry out appropriate examinations and tests". — [Springlex, CRA Annex VIII](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-8/); [Springlex, Art. 32](https://www.springlex.eu/en/packages/cra/cra-regulation/article-32/). No harmonised standard is cited in the OJ yet — [cyberresilienceact.eu](https://www.cyberresilienceact.eu/news/commission-cra-application-guidance-published-27-july-2026.html)
- EN 18031: conceptual assessment checks the vendor's decision-tree path and justification ([E.Info.DT.SUM-2]/[E.Just.DT.SUM-2]). Functional sufficiency prescribes negative tests (unsigned, modified signature, modified payload, unauthorized signer, MITM). — [NEK EN 18031-1:2024](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf)
- ETSI TS 103 701: the SO fills in the ICS and IXIT; the TL verifies "completeness, consistency and soundness of the IXIT". For update security, 5.3-7/5.3-8/5.3-9 are conceptual only, and the functional test 5.3-2-2 is attacker-devised by the TL. — [ETSI TS 103 701 V2.1.1](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf)
- UN R156: SUMS requirements are framed as "Documentation describing…" and "shall demonstrate". Vehicle requirements (7.2.2.x) are demonstrated to the approval authority. — [UN ODS R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf)
- FSTEK: Order 239 п. 29.4 (document-based evaluation of vendor security support). Order 117 п. 39 relies on operator internal regulations, and effectiveness is self-assessed through Кзи (п. 35). The Methodology of 28.10.2022 is an operator-run executable test procedure per update. — [legalacts.ru, приказ № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/); [fstec.ru, приказ № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117); [legalacts.ru, Методика](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/)
- GOST R 56939-2024 audits: checklists, interviews and documentation analysis, with claimed attention to "фактическая реализация процессов" — [Anti-Malware.ru](https://www.anti-malware.ru/analytics/Technology_Analysis/GOST-R-56939-2024-Secure-Development-Audit)
- FCC Cyber Trust Mark: CLAs test against NIST IR 8425. The test procedures are delegated to the Lead Administrator (ioXt since April 2026) and were not finalised in October 2026 — [FCC 24-26](https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf); [Nextgov](https://www.nextgov.com/cybersecurity/2026/10/fcc-commissioner-hopes-cyber-trust-mark-products-reach-shoppers-within-year/416878/)
- CTIA IoT Cybersecurity Certification test plan: includes a check that the device "supports manual installation software upgrades from an authorized source" (secondary mapping) — [OWASP IoT Top 10 mapping of CTIA test plan](https://scriptingxss.gitbook.io/owasp-iot-top-10-mapping-project/mappings/ctia-cybersecurity-certification-test-plan-for-iot-devices). I did not read the official plan.
- SESIP (EN 17927, published November 2023): "Secure Update of Platform" is listed as a mandatory SFR (unless justified as not applicable), in a lifecycle group that also covers anti-rollback (GlobalPlatform slide) — [GlobalPlatform automotive presentation](https://globalplatform.org/wp-content/uploads/2023/09/John-Boggie_Automotive_GP_Presentation_V1.4.pdf); [EN 17927 (iTeh)](https://iteh.es/catalog/standards/cen/e545f156-f87b-4463-a711-9483b31a202d/en-17927-2023)
- Term search across the full texts of CRA Annex I, EN 18031-1, EN 303 645, TS 103 701, R155, R156 and SP 800-193 found no mention of "Uptane", "TUF"/"The Update Framework" or "freeze". "Rollback/downgrade" appears normatively only in SP 800-193 (and as an R155 threat example). EN 303 645 has it as an informative example, TS 103 701 as test examples, EN 18031-1 in guidance. — sources as listed in sections 1–4.

### Inferences
- The thesis claim holds for the EU CRA (no standards yet, mostly self-declaration), R156 (demonstration and documentation) and Russian vendor-side obligations (document review). For EU radio equipment (EN 18031), the claim should be stated as follows: executable tests are prescribed, but only for basic authenticity and integrity rejection. The scope is defined by vendor-supplied information, and the higher-order update threats (rollback, freeze, mix-and-match, key compromise, fail-safe) have no normative test.
- A benchmark with reproducible test vectors could be positioned as an executable complement to: EN 18031 SUM-2 (it extends the negative tests), TS 103 701 5.3-2-2 (it makes the attacks the TL is meant to "devise" reproducible), R156 7.2.2.1.1/7.2.2.1.2 (it makes the "demonstrate" claims testable), and FSTEK п. 39/Методика (it adds update-mechanism tests on top of the per-update content tests).

### Gaps
- I did not verify the test content of ioXt profiles, PSA Certified (Level 1 questionnaire vs Level 2 lab), NIAP protection profiles (FPT_TUD_EXT.1 trusted update evaluation activities) or the ISASecure CSA test methodology for CR 3.10. Common Criteria cPP assurance activities are likely another source of executable "reject invalid signature" tests, but this is unconfirmed.
- I found no public data on how many EN 18031 or R156 assessments actually ran functional update tests.

---

## 7. Mapping table: requirement → update-system property → verification in practice

### Takeaway
Of the nine properties, authenticity and integrity are required everywhere. Transparency/notification and availability/timeliness are widely required. Atomicity, fail-safe behaviour and recoverability are normative only in UN R156 and NIST SP 800-193. Anti-rollback is normative only in SP 800-193 ("shall"), SP 800-147 ("should") and SESIP. Key-compromise resilience appears only in R155 (12.4/M11) and SP 800-193 (4.1.2(4)). Freshness/anti-freeze is not required explicitly anywhere reviewed. Verification is documentation-based in most cells; executable tests exist mainly for basic authenticity and integrity.

### Cited Findings
Legend:
- Properties: Au = authenticity; In = integrity; Fr = freshness/anti-freeze; AR = anti-rollback; KC = key-compromise resilience; At = atomicity/fail-safe; Rec = recoverability; Av = availability/DoS/timeliness; Tr = transparency/notification/user control.
- Force: N = normative; I = informative only.
- Verification in practice: Doc = documentation or declaration; Proc = process audit; Test = executable test prescribed; Lab = test designed by the lab.

| # | Requirement (source + clause) | Property | Force | Verified in practice by | Source |
|---|---|---|---|---|---|
| 1 | CRA Annex I Pt I (2)(c): security updates; automatic by default with opt-out; notification; postponement | Tr, Av | N | Doc (module A self-declaration; no hEN in OJ yet) | [Springlex Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/) |
| 2 | CRA Annex I Pt I (2)(f): integrity of "programs" against unauthorised modification; report corruptions | In (indirectly Au, AR via "unauthorised modification") | N | Doc | [Springlex Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/) |
| 3 | CRA Annex I Pt I (2)(h): availability of essential functions, also after an incident; DoS resilience | Av, At/Rec (interpretation) | N | Doc | [Springlex Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/) |
| 4 | CRA Annex I Pt II (7): "mechanisms to securely distribute updates … timely … automatic" | Au, In, Av | N | Doc; NB examination of docs/specimens for class I/II under module B/H | [Springlex Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/); [Annex VIII](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-8/) |
| 5 | CRA Annex I Pt II (2), (8): without delay; separate from functionality updates; free; advisory messages | Av, Tr | N | Doc/Proc (NB periodic audits of vulnerability handling under module B) | [Springlex Annex I](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-1/); [Annex VIII](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-8/) |
| 6 | CRA Art. 13(8), (9), (19): support ≥5 years; each update available ≥10 years; end date (month/year) at purchase | Av (over lifetime), Tr | N | Doc | [Springlex Art. 13](https://www.springlex.eu/en/packages/cra/cra-regulation/article-13/) |
| 7 | CRA Annex II (7), (8): support end date; how to install updates; how to turn off auto-update | Tr | N | Doc (user instructions) | [Springlex Annex II](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-2/) |
| 8 | EN 18031-1 6.3.1 SUM-1: at least one update mechanism | (capability) | N | Doc (conceptual) + Test (install SW-a) | [NEK EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf) |
| 9 | EN 18031-1 6.3.2 SUM-2: install only software with valid integrity and authenticity "at the time of the installation" | Au, In | N | Doc (decision tree) + **Test** (unsigned / modified signature / modified payload / unauthorized signer; MITM; hash with ACM) | [NEK EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf) |
| 10 | EN 18031-1 6.3.3 SUM-3: automated updates | Av, Tr | N | Doc + Test (observe automatic update) | [NEK EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf) |
| 11 | EN 18031-1 6.3.3.3 Guidance: roll-back policy on failed installation | At, Rec | **I** (no presumption, Restriction 1) | Not assessed | [NEK EN 18031-1](https://www.nek.no/wp-content/uploads/2025/02/nek-en-18031-1_2024_en_001.pdf); [Commission guidance](https://digital.gob.es/content/dam/portal-mtdfp/avance-digital/telecomunicacion-e-infraestructuras-digitales/areas_interes/equipos-telecomunicacion/documents/Guia-aplicacion-EN-18031.pdf) |
| 12 | EN 303 645 5.3-2 (M C) secure update mechanism; EXAMPLE 6/7 (auth servers, anti-rollback) | Au, In; AR only informative | N / I | TS 103 701 5.3-2-1 conceptual + 5.3-2-2 **Lab** (attacks devised by TL; NOTE 1 mentions rollback, resume after failure, byte flip) | [EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf); [TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf) |
| 13 | EN 303 645 5.3-7 (M) best-practice crypto for update | Au, In | N | Doc (conceptual only) | [TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf) |
| 14 | EN 303 645 5.3-9 (R) / 5.3-10 (M) verify authenticity and integrity "via a trust relationship" | Au, In | N (5.3-10) | Doc (conceptual); functional only to discover undocumented network update mechanisms | [EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf); [TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf) |
| 15 | EN 303 645 informative text after 5.3-4B: watchdogs, dual-bank flash, recovery partitions → known good version | At, Rec | I | Not assessed | [EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) |
| 16 | EN 303 645 5.3-4A/4B/5/6A/6B/11/12 (R), 5.3-8 (M C), 5.3-13 (M) | Tr, Av | N/R | Mostly Doc; some functional checks (config of auto-update and notifications; publication of support period) | [TS 103 701](https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ts_103701v020101p.pdf) |
| 17 | UN R156 7.1.3.1–7.1.3.2: protect updates against manipulation before update; protect update processes and delivery system | In, Au, KC (supply chain, partially) | N | Proc/Doc ("shall demonstrate") | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 18 | UN R156 7.2.1.1: authenticity and integrity protected; "reasonably prevent invalid updates" | Au, In | N | Doc/demonstration at type approval | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 19 | UN R156 7.1.2.3, 7.2.1.2.x: RXSWIN register with integrity validation data; readable via OBD; protected against unauthorised modification | In, version consistency (supports AR / mix-and-match detection) | N | Doc | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 20 | **UN R156 7.2.2.1.1**: restore previous version or safe state after failed/interrupted update | **At, Rec** | N | Demonstration (no standardized test) | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 21 | **UN R156 7.2.2.1.2**: enough power incl. for recovery | **At** (power-loss) | N | Demonstration | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 22 | UN R156 7.2.2.1.3, 7.2.2.3, 7.2.2.5: safe execution; no driving; preconditions | At (safety), Av | N | Demonstration | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 23 | UN R156 7.2.2.2, 7.2.2.4: inform user before; success/failure after | Tr | N | Demonstration | [UN R156](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/80&l=en&t=pdf) |
| 24 | UN R155 Annex 5 threats 12.1–12.3 → M16 "Secure software update procedures" | Au, In | N (CSMS must cover) | Proc (CSMS audit) | [UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf) |
| 25 | **UN R155 threat 12.4** "Compromise of cryptographic keys of the software provider" → M11 key storage | **KC** | N | Proc | [UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf) |
| 26 | UN R155 threat 13.1 DoS against update server/network → M3 back-end controls + recovery | Av | N | Proc | [UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf) |
| 27 | UN R155 threat 6.3 replay → "downgrade software of an ECU" | AR | N (threat to consider) | Proc | [UN R155](https://documents.un.org/api/symbol/access?s=ECE/TRANS/WP.29/2020/79&l=en&t=pdf) |
| 28 | NIST SP 800-193 4.1.2(1),(3),(5); 4.2.1.1(1)–(3); 4.2.1.2 | Au, In (RTU, signature before commit, exclusivity) | Guideline ("shall") | No mandated test (product-specific) | [SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) |
| 29 | **NIST SP 800-193 4.1.2(2)**: operational or recoverable after power loss mid-flash | **At, Rec** | Guideline | No mandated test | [SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) |
| 30 | **NIST SP 800-193 4.1.2(4)** + note: authenticated key-store update; "recover from compromise of the signing key" | **KC** | Guideline | No mandated test | [SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) |
| 31 | **NIST SP 800-193 4.2.1.3(2)**: prevent unauthorized update to earlier vulnerable version; 4.4.1(13) for recovery | **AR** | Guideline ("shall"/"should") | No mandated test | [SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) |
| 32 | NIST SP 800-193 4.4.1(1)–(12): authenticated recovery, logging, forced recovery | Rec, Tr | Guideline | No mandated test | [SP 800-193](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf) |
| 33 | NIST SP 800-147 3.1.1–3.1.4: signed BIOS, RTU, "should prevent the unauthorized rollback", non-bypassability | Au, In, AR | Guideline | No mandated test | [SP 800-147](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf) |
| 34 | NIST IR 8259A Software Update elements 1–6 (verify and authenticate; authorized rollback; enable/disable; notification) | Au, In, Rec (authorized rollback), Tr | Baseline | Not specified | [IR 8259A](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf) |
| 35 | NIST IR 8425 Software Update / FCC Cyber Trust Mark: "receive, verify, and apply verified software updates"; automatic or notification | Au, In, Av, Tr | Voluntary label | Test by CLAs; procedures by Lead Administrator (not final, Oct 2026) | [IR 8425](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8425.pdf); [FCC 24-26](https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf) |
| 36 | UK PSTI Regs 2023 Sch. 1 para 3: publish the defined support period; no shortening | Tr, Av (lifetime) | N (since 29.04.2024) | Doc (publication) | [legislation.gov.uk](https://www.legislation.gov.uk/uksi/2023/1007/schedule/1/made) |
| 37 | IEC 62443-4-2 CR/EDR/HDR/NDR 3.10 + RE(1) "Update authenticity and integrity"; CR 3.4 | Au, In | N (for claimed SL) | Certification testing (details unverified) | [ISA webinar](https://isasecure.org/hubfs/Webinars/Webinars%20PDFs/2019-August-8-Webinar.pdf); [CIP table](https://2025-cip.readthedocs.io/en/latest/security/iec62443-4-2-FR-3.html) |
| 38 | IEC 62443-4-1 SUM-1..SUM-5 (qualification, documentation, delivery, timeliness) | Av, Tr, In (delivery) | N (process) | Proc | [jtsec](https://www.jtsec.es/es/files/IEC%2062443-4-1%20Practices%20&%20Requirementes.pdf) |
| 39 | Приказ ФСТЭК № 117 п. 39: «проверки подлинности и целостности обновлений», testing before production, authorised installation, «бесконтрольная установка … не допускается» | Au, In, (At via pre-testing) | N (since 01.03.2026) | Proc/Doc (internal regulation; Кзи self-assessment; GIS attestation) | [fstec.ru № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117) |
| 40 | Приказ № 117 п. 38: remediation ≤24 h (critical), ≤7 days (high) | Av (timeliness) | N | Doc/monitoring | [fstec.ru № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117) |
| 41 | Приказ № 117 п. 52–53: backups of software and configurations; restore intervals; drills every ≤2 years | Rec | N | Test (drills) / Doc | [fstec.ru № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117) |
| 42 | Приказ № 117 п. 71: certified SZI with vendor security support «включая выпуск и применение обновлений» | Av | N | Doc (certificate, support contract) | [fstec.ru № 117](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/trebovaniya-utverzhdeny-prikazom-fstek-rossii-ot-11-aprelya-2025-g-n-117) |
| 43 | Методика ФСТЭК 28.10.2022 Т001 (identity across sources), Т002 (checksums/signature) | Au, In (Т001 partly vs targeted/mirror attacks) | N for GIS/КИИ operators | **Test** (operator, per update) | [legalacts.ru Методика](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/) |
| 44 | Методика Т003–Т006 (AV, dangerous constructs, activity monitoring, manual analysis; НДВ indicators п. 2.3) | malicious content (not an update-mechanism property) | N | **Test** (operator) | [legalacts.ru Методика](https://legalacts.ru/doc/metodicheskii-dokument-metodika-testirovanija-obnovlenii-bezopasnosti-programmnykh-programmno-apparatnykh-sredstv/) |
| 45 | Приказ № 239 ОПО.1 «от доверенного источника»; ОПО.2 «Контроль целостности»; ОПО.3 «Тестирование»; ОПО.4 «Установка» (categories 1–3) | Au, In | N | Proc/Doc (operator) | [legalacts.ru № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/) |
| 46 | Приказ № 239 п. 29.3.3: vendor defines ways of obtaining updates and «проверки их целостности и подлинности»; end-of-support notice | Au, In, Tr | N | **Doc** (п. 29.4 «анализа материалов и документов, представляемых разработчиком») | [legalacts.ru № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/) |
| 47 | Приказ № 239 п. 31: no remote or uncontrolled local update access by third parties | Au (authorization of update source/actor) | N | Doc/organisational | [legalacts.ru № 239](https://legalacts.ru/doc/prikaz-fstek-rossii-ot-25122017-n-239-ob-utverzhdenii/) |
| 48 | ГОСТ Р 56939-2024 processes 5.21 (release), 5.22 (secure delivery), 5.23 (vulnerability response); numbering UNVERIFIED | In, Au (delivery), Av | N (via Order 117 п. 50 for in-house dev) | Proc (audit: checklists, interviews, documents) | [vc.ru](https://vc.ru/id371670); [Anti-Malware.ru](https://www.anti-malware.ru/analytics/Technology_Analysis/GOST-R-56939-2024-Secure-Development-Audit) |
| 49 | SESIP / EN 17927:2023 "Secure Update of Platform" (mandatory unless justified); lifecycle group incl. anti-rollback | Au, In, AR | Certification scheme | Lab evaluation (details unverified) | [GlobalPlatform slides](https://globalplatform.org/wp-content/uploads/2023/09/John-Boggie_Automotive_GP_Presentation_V1.4.pdf) |

### Inferences
- **Fr (freshness/anti-freeze):** no reviewed text requires it explicitly. The nearest are "timely" (EN 303 645 5.3-8), "without delay" (CRA Pt II (2), (8)), 117 п. 38 deadlines, and EN 303 645 5.3-5 (check for updates after initialisation). None of these protects against an attacker serving stale but validly signed metadata. This is the clearest regulatory gap for a benchmark to expose.
- **AR (anti-rollback):** normative only in NIST SP 800-193 4.2.1.3(2) and (as "should") SP 800-147 3.1.1. It is informative in EN 303 645, a threat example in R155 and a test example in TS 103 701. It is absent from the CRA, EN 18031 (normative parts), R156 and the FSTEK texts.
- **KC (key compromise):** only R155 12.4/M11 (key storage) and SP 800-193 4.1.2(4) (updatable key store for recovery). No text requires threshold signatures, role separation or key rotation as in TUF/Uptane.
- **At/Rec (atomicity, recoverability):** normative in R156 7.2.2.1.1–7.2.2.1.2 and SP 800-193 4.1.2(2), 4.4.1. Informative in EN 303 645 and EN 18031. In Russian texts only generic backup/restore (117 п. 52–53).
- **Verification:** "Test" appears only for rows 8–10 (EN 18031), 12 (TS 103 701 lab-devised), 35 (FCC, procedures pending), 41 (FSTEK drills) and 43–44 (FSTEK per-update tests). The rest is documentation, process audit or "demonstration".

### Gaps
- Rows 37, 48 and 49 rest on secondary sources for requirement wording.
- Rows for ISO 24089 and ISO/SAE 21434 are omitted because their requirement texts could not be accessed.
- In row 19, the link between RXSWIN version registers and AR/mix-and-match is my interpretation, not regulatory text.
