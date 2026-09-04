---
id: BB-DOC-001
title: BulbBee EU Declaration of Conformity (Module A, self-declared)
category: Compliance
status: DONE
severity: N/A
affected_components: [bulbbee]
regulation: EU Cyber Resilience Act (Regulation (EU) 2024/2847)
version: 1.0
date: 2026-09-04
owner: BulbBee manufacturer (fictional)
---

# EU Declaration of Conformity

> Fictional, self-declared under Module A (internal control) for a default-category product. It deliberately declares conformity that the device contradicts, that over-confident self-declaration is the finding a market-surveillance authority would challenge (see the assessor gap key).

**1. Product**: BulbBee smart light (WS2812 RGB), model BB-100, all hardware/software versions of the reference build.

**2. Manufacturer**: BulbBee Home Ltd (fictional), contact `security@bulbbee.example`.

**3. This declaration of conformity is issued under the sole responsibility of the manufacturer.**

**4. Object of the declaration**: the BulbBee smart light with its embedded firmware (the lighting service, the BLE GATT control server, and the update agent).

**5. The object described above is in conformity with the relevant Union harmonisation legislation**: Regulation (EU) 2024/2847 (Cyber Resilience Act), the essential cybersecurity requirements of Annex I Parts I and II.

**6. Conformity assessment procedure**: Module A, internal control (CRA Annex VIII). No notified body was involved (permitted for a default-category product not listed in Annex III or Annex IV).

**7. Standards applied**: ETSI EN 303 645 (consumer IoT baseline), used as the presumption-of-conformity reference for the Annex I essential requirements. The requirement-by-requirement mapping is in BB-ERM-002.

**8. Additional information**: the Software Bill of Materials is BB-SBOM-003, the user information and coordinated-disclosure channel are in BB-UM-004.

**Signed for and on behalf of**: BulbBee Home Ltd, product security lead, Malaga, 2026-09-04.

CE marking affixed on the manufacturer's own responsibility.

---

> **Assessor note (training)**: statement 5 self-declares conformity with Annex I. The BulbBee finding catalogue (`../Vulns/`) documents seven essential-requirement breaches. The declaration is therefore false as issued, which is exactly the kind of unverified Module A self-declaration the CRA lets a default-category manufacturer make and a market-surveillance authority later disproves. See `99-Assessor-Gap-Key.md`.
