# AegisNet Baseline Anomaly Detection Model — Comprehensive Training & Evaluation Report

**Project:** AegisNet — Network Security Telemetry Pipeline  
**Module:** Stage 0: Baseline Anomaly Detection  
**Date:** April 3, 2026  

---

## Table of Contents
1. [Objective & Approach](#1-objective--approach)
2. [Why Unsupervised Anomaly Detection](#2-why-unsupervised-anomaly-detection)
3. [Candidate Models & Why We Chose Them](#3-candidate-models--why-we-chose-them)
4. [Training Dataset Analysis](#4-training-dataset-analysis)
5. [Feature Engineering Pipeline](#5-feature-engineering-pipeline)
6. [Feature Importance & Anti-Cheating Verification](#6-feature-importance--anti-cheating-verification)
7. [Testing Methodology](#7-testing-methodology)
8. [Evaluation Results](#8-evaluation-results)
9. [Per-Attack Detection Breakdown](#9-per-attack-detection-breakdown)
10. [Metric Definitions](#10-metric-definitions)
11. [Final Model Selection](#11-final-model-selection)

---

## 1. Objective & Approach

### Problem Statement
AegisNet's detection pipeline needs a **first line of defense** that can identify anomalous network traffic without requiring labeled attack data. This is critical because:
- New (zero-day) attacks have no signatures
- Labeled malicious training data is expensive and quickly outdated
- Enterprise networks generate millions of flows daily — we need fast, low-overhead detection

### Approach: Unsupervised Baseline Learning
We train models **only on benign (normal) traffic** to learn what "normal" looks like. Any traffic that deviates significantly from this learned baseline is flagged as anomalous. This is known as **one-class classification** or **novelty detection**.

### Pipeline Position
This model operates as **Stage 0** in AegisNet's multi-stage detection engine:

```
Flow Ingestion → [Stage 0: Baseline Anomaly] → Stage 1: JA4 Classifier → Stage 2: TTP → Stage 3: APT
```

---

## 2. Why Unsupervised Anomaly Detection

| Supervised (What we're NOT doing) | Unsupervised (What we ARE doing) |
|---|---|
| Requires labeled malicious + benign data | Only needs benign data for training |
| Can only detect attacks it was trained on | Can detect previously unseen attack patterns |
| High precision but limited to known attacks | Generalizes to zero-day anomalies |
| Requires retraining when new attacks emerge | Baseline adapts to network evolution |

**Justification:** AegisNet is deployed across diverse enterprise networks where the attack landscape is unpredictable. An unsupervised baseline detector provides a safety net that catches anomalous patterns the supervised JA4 classifier may miss.

---

## 3. Candidate Models & Why We Chose Them

We evaluated **4 fundamentally different** unsupervised anomaly detection architectures to ensure a fair, comprehensive comparison:

### Model 1: Deep Autoencoder (Neural Network — Reconstruction-Based)

**Architecture:**
```
Input (128) → [Dense 64 → BN → ReLU → Dropout] → [Dense 32 → BN → ReLU → Dropout] → Bottleneck (16)
                                                                                          ↓
Output (128) ← [Dense 64 → BN → ReLU → Dropout] ← [Dense 32 → BN → ReLU → Dropout] ← Decoder
```

**How it detects anomalies:** Learns to compress and reconstruct normal traffic with low error. Malicious traffic produces high reconstruction error because it deviates from learned normal patterns.

**Why included:** Deep learning captures complex, non-linear feature interactions that simpler models miss. The bottleneck forces the model to learn the most essential characteristics of normal traffic.

### Model 2: Variational Autoencoder / VAE (Neural Network — Probabilistic)

**Architecture:** Similar encoder/decoder to Autoencoder, but with a probabilistic latent space using KL-divergence regularization.

**How it detects anomalies:** Same reconstruction error principle, but the probabilistic latent space provides smoother, more regularized representations — theoretically better generalization.

**Why included:** VAEs are considered more theoretically sound than standard autoencoders. The KL-divergence term prevents the model from memorizing training data.

### Model 3: Isolation Forest (Ensemble — Tree-Based)

**Architecture:** Ensemble of 200 random decision trees that partition the feature space.

**How it detects anomalies:** Anomalies are "isolated" faster (fewer tree splits) because they occupy sparse regions of the feature space. Normal samples require many splits.

**Why included:** Fundamentally different approach from neural networks. Extremely fast training (7 seconds vs 12+ minutes), no GPU needed, robust to irrelevant features.

### Model 4: One-Class SVM (Kernel — Boundary-Based)

**Architecture:** RBF kernel maps data to high-dimensional space and finds a tight boundary around normal samples.

**How it detects anomalies:** Anything outside the learned decision boundary is flagged. Uses margin-based optimization.

**Why included:** Strong theoretical foundation (support vector theory). Effective when the normal class forms a compact cluster in feature space.

---

## 4. Training Dataset Analysis

### Dataset Sources

| Source | Rows | Type | Purpose |
|--------|------|------|---------|
| **CIC-IDS-2017 — Monday** | 395,076 | Enterprise network traffic | HTTP, HTTPS, DNS, NTP, SMTP, SSH — Monday is the designated "benign-only" day |
| **DoHBrw-2020 — Non-Malicious** | 302,736 | DNS-over-HTTPS browser traffic | Benign encrypted DNS queries via common DoH providers |
| **Total Benign** | **697,812** | — | **100% benign baseline** |

### Dataset Composition

```
                    CIC-IDS-2017 Monday (56.6%)
                    ████████████████████████████
                    
                    DoHBrw-2020 Benign (43.4%)
                    ██████████████████████
```

### Protocol Distribution

| Protocol | Count | Percentage |
|----------|-------|------------|
| TCP (6) | 464,870 | 66.6% |
| UDP (17) | 232,942 | 33.4% |

### Top Destination Ports

| Port | Count | Service |
|------|-------|---------|
| 443 | 208,575 | HTTPS |
| 53 | 85,792 | DNS |
| 80 | 24,605 | HTTP |
| 123 | 6,785 | NTP |
| 137 | 1,531 | NetBIOS |

### Raw Feature Count
The raw dataset contains **189 columns** across these categories:
- **Network identifiers** (5): src_ip, dst_ip, src_port, dst_port, protocol
- **Flow statistics** (48): duration, packet counts, bytes, IAT, flags
- **Packet length statistics** (28): mean, std, min, max, percentiles, kurtosis
- **Timing statistics** (20): IAT variance, median, mode, skew, CoV
- **Response time statistics** (8): mean, std, min, max, variance, median, mode, CoV
- **Bulk transfer features** (12): fwd/bwd bulk bytes, packets, rates
- **JA4 fingerprint fields** (40): ja4, ja4s, ja4h, ja4ssh, ja4x, subfields
- **DoH indicators** (4): is_known_doh_server, uses_port_443, uses_port_853, sni_matches_doh
- **Payload analysis** (6): entropy, header/payload ratios
- **DNS features** (2): dns_query_count, dns_answer_count
- **Metadata** (3): captured_at, dataset_name, source_pcap

---

## 5. Feature Engineering Pipeline

### Overview: 189 raw columns → 128 clean features

The preprocessing pipeline follows strict ML best practices to ensure the model learns genuine network behavior, not data artifacts.

### Step 1: Drop Identifiers (7 columns removed)

These columns would cause the model to memorize specific machines/files instead of learning general traffic patterns.

| Column | Reason for Removal |
|--------|-------------------|
| `src_ip` | Model must not memorize specific source machines |
| `dst_ip` | Model must not memorize specific destination machines |
| `captured_at` | Raw timestamp — time of capture is not a traffic behavior |
| `dataset_name` | Build artifact — CIC-IDS-2017 vs DoHBrw-2020 label |
| `source_pcap` | Build artifact — PCAP file path |
| `matched_sni_domain` | String identifier (domain name) |
| `ja4d_fqdn` | DNS FQDN string |

### Step 2: Drop Zero-Variance Constants (10 columns removed)

These columns have **identical values (all zero)** across all 697,812 rows. They provide zero mathematical information to any model.

| Column | Value | Reason |
|--------|-------|--------|
| `fwd_urg_flags` | 0 | No urgent flags observed in training data |
| `bwd_urg_flags` | 0 | Same — all zeros, identical to fwd_urg_flags |
| `urg_flag_count` | 0 | Same — all zeros |
| `idle_mean` | 0 | No idle periods detected in flow extraction |
| `idle_std` | 0 | Same — all zeros |
| `idle_max` | 0 | Same — all zeros |
| `idle_min` | 0 | Same — all zeros |
| `uses_port_853` | 0 | No DNS-over-TLS (port 853) traffic in dataset |
| `dns_query_count` | 0 | DNS query counting not populated by our extractor |
| `dns_answer_count` | 0 | Same — all zeros |

### Step 3: Drop Exact Duplicate Features (18 columns removed)

These column pairs contain **bitwise identical values** across all rows. Keeping both would give the model a false sense of feature importance.

| Kept | Dropped (Identical) | Verification |
|------|--------------------|-|
| `total_fwd_packets` | `subflow_fwd_packets` | r=1.0000 |
| `total_bwd_packets` | `subflow_bwd_packets` | r=1.0000 |
| `fwd_pkt_len_mean` | `avg_fwd_segment_size` | r=1.0000 |
| `bwd_pkt_len_mean` | `avg_bwd_segment_size` | r=1.0000 |
| `flow_iat_mean` | `active_mean` | r=1.0000 |
| `flow_iat_std` | `active_std` | r=1.0000 |
| `flow_iat_max` | `active_max` | r=1.0000 |
| `flow_iat_min` | `active_min` | r=1.0000 |
| `fwd_psh_flags` | `fwd_psh_ack_count` | r=1.0000 |
| `bwd_psh_flags` | `bwd_psh_ack_count` | r=1.0000 |
| `fwd_payload_bytes` | `fwd_bulk_bytes` | r=1.0000 |
| `bwd_payload_bytes` | `bwd_bulk_bytes` | r=1.0000 |
| `pkt_len_mean` | `avg_pkt_size` | r=1.0000 |
| `pkt_len_var` | `pkt_len_variance` | r=1.0000 |
| `fwd_bulk_rate` | `fwd_avg_bulk_rate` | r=1.0000 |
| `bwd_bulk_rate` | `bwd_avg_bulk_rate` | r=1.0000 |
| `subflow_fwd_bytes` | `flow_bytes_sent` | r=1.0000 |
| `subflow_bwd_bytes` | `flow_bytes_received` | r=1.0000 |

### Step 4: Drop High-Correlation Redundancies (10 columns removed)

Beyond exact duplicates, these columns have Pearson correlation |r| ≥ 0.95, creating multicollinearity.

| Dropped | Correlated With | r value |
|---------|----------------|---------|
| `ack_flag_count` | `total_packets` | 0.9999 |
| `fwd_iat_total` | `flow_duration` | 0.9976 |
| `fwd_header_len` | `total_fwd_packets` | 0.9964 |
| `response_time_mode` | `response_time_min` | 0.9989 |
| `fwd_avg_bytes_bulk` | `fwd_bulk_rate` | ~1.0 |
| `bwd_avg_bytes_bulk` | `bwd_bulk_rate` | ~1.0 |
| `fwd_avg_packets_bulk` | near-constant | — |
| `bwd_avg_packets_bulk` | near-constant | — |
| `subflow_fwd_bytes` | `fwd_payload_bytes` | 0.9999 |
| `subflow_bwd_bytes` | `bwd_payload_bytes` | 0.9991 |

### Step 5: Drop Sparse JA4 Sub-fields (18 columns removed)

These JA4 fingerprint fields have extremely low fill rates, making them noise rather than signal.

| Column Group | Fill Rate | Reason |
|-------------|-----------|--------|
| `ja4x` (certificate) | 0.0% | Never populated in our dataset |
| `ja4d` + sub-fields (6 cols) | 0.0% | DNS fingerprint — essentially empty |
| `ja4ssh` | 0.2% | SSH fingerprint — 1,054 of 697,812 rows |
| `ja4h` + sub-fields (9 cols) | 3.8% | HTTP fingerprint — too sparse for reliable patterns |

### Step 6: Encode Remaining Categorical Features

**Port Categorization** → One-hot encoded:
- `dst_port` → `port_well_known` (0-1023), `port_registered` (1024-49151), `port_dynamic` (49152+)
- `src_port` → dropped (ephemeral, no meaningful pattern)

**Protocol** → One-hot encoded:
- `protocol` → `proto_6` (TCP), `proto_17` (UDP)

**JA4 Hash Strings** → Frequency encoded:
- Each JA4 hash string replaced by its occurrence count in the training set
- Applied to: `ja4`, `ja4s`, `ja4l_c`, `ja4l_s`, `ja4t`, `ja4ts`, `ja4_cipher_hash`, `ja4_extension_hash`, `ja4s_cipher`, `ja4s_ext_hash`, `ja4t_tcp_options`, `ja4ts_tcp_options`

**JA4 Categorical Fields** → Label encoded:
- `ja4_version`, `ja4_sni`, `ja4_alpn`, `ja4s_version`, `ja4s_alpn`

### Step 7: Scale All Numeric Features

- **Method:** `StandardScaler` (zero mean, unit variance)
- **Critical rule:** Scaler fitted ONLY on training data, then applied (transform only) to validation and test sets
- **Purpose:** Prevents data leakage and ensures large-valued features (like byte counts in millions) don't dominate small-valued features (like flag counts of 0-10)

### Final Feature Count: 128

---

## 6. Feature Importance & Anti-Cheating Verification

### Methodology: Permutation Importance

For each feature, we **shuffle its values** while keeping all other features intact, then measure how much the model's anomaly score changes. A high change means the model relies heavily on that feature.

This verifies:
- No single feature dominates unnaturally (cheating)
- The model uses diverse, semantically meaningful features
- No data leakage artifacts

### Deep Autoencoder — Top 15 Features

![Feature Importance — Deep Autoencoder](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/feature_importance_ae.png)

| Rank | Feature | Importance (Δ) | Category | Interpretation |
|------|---------|----------------|----------|---------------|
| 1 | `cwe_flag_count` | 0.0297 | TCP flags | CWE/congestion flag presence |
| 2 | `ece_flag_count` | 0.0282 | TCP flags | ECN-Echo flag presence |
| 3 | `bwd_psh_flags` | 0.0164 | TCP flags | Push flags in backward direction |
| 4 | `pkt_time_variance` | 0.0163 | Timing | Variance of inter-packet timing |
| 5 | `ja4s_freq` | 0.0157 | TLS fingerprint | Server TLS fingerprint frequency |
| 6 | `ja4_extension_count` | 0.0151 | TLS fingerprint | Number of TLS extensions |
| 7 | `psh_flag_count` | 0.0150 | TCP flags | Total push flag count |
| 8 | `has_tls` | 0.0149 | Encryption | Whether flow uses TLS |
| 9 | `ja4_sni_enc` | 0.0146 | TLS fingerprint | SNI indicator type |
| 10 | `ja4_cipher_count` | 0.0146 | TLS fingerprint | Number of cipher suites offered |
| 11 | `proto_6` | 0.0145 | Protocol | TCP protocol indicator |
| 12 | `proto_17` | 0.0144 | Protocol | UDP protocol indicator |
| 13 | `ja4_version_enc` | 0.0142 | TLS fingerprint | TLS version |
| 14 | `ja4l_ttl_c` | 0.0141 | Network | Client-side TTL value |
| 15 | `pkt_len_mean` | 0.0139 | Flow statistics | Average packet size |

### Isolation Forest — Top 15 Features
![Feature Importance — Isolation Forest](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/feature_importance_if.png)

### Anti-Cheating Verification ✅

> [!NOTE]
> **No single feature dominates.** The top feature (`cwe_flag_count`) accounts for only Δ=0.0297, while the 15th feature contributes Δ=0.0139 — a ratio of only 2.1×. This confirms the model distributes its decision-making across **TCP flags, TLS fingerprints, timing statistics, and flow metadata** — all semantically meaningful network properties.
>
> **No artifact cheating.** Features like `src_ip`, `dst_ip`, `captured_at`, and `dataset_name` were removed before training, so the model cannot memorize specific machines or timestamps.

---

## 7. Testing Methodology

### Test Data: CIC-IDS-2017 Friday (Properly Labeled)

CIC-IDS-2017 Friday contains **both benign enterprise traffic and 3 specific attack campaigns**. We labeled each flow using the **official CIC documentation** combining:
- **Attacker IP addresses** (from CIC network topology)
- **Attack time windows** (from CIC published schedule)

### Official Attack Schedule (Friday, July 7, 2017)

| Attack | Local Time (EDT) | UTC Time | Attacker IPs | Victim IPs |
|--------|-----------------|----------|-------------|------------|
| **Botnet ARES** | 10:02–11:02 AM | 14:02–15:02 | `205.174.165.73` (Kali) | `.5`, `.8`, `.9`, `.14`, `.15` |
| **PortScan (Nmap)** | 1:55–3:29 PM | 17:55–19:29 | `205.174.165.73` (Kali) | `192.168.10.50` |
| **DDoS LOIT** | 3:56–4:16 PM | 19:56–20:16 | `.69`, `.70`, `.71` (Win 8.1) | `192.168.10.50` |

### Labeling Rule
A flow is labeled **malicious** if and only if:
1. Its timestamp falls within an attack window, **AND**
2. Its source or destination IP matches a known attacker or victim IP (including the NAT firewall `172.16.0.1`)

### Resulting Label Distribution

| Label | Count | Percentage |
|-------|-------|------------|
| **Benign** | 383,456 | 68.5% |
| **PortScan** | 161,418 | 28.8% |
| **Bot** | 14,806 | 2.6% |
| **DDoS** | 126 | 0.0% |
| **Total Malicious** | **176,350** | **31.5%** |

### Combined Test Set
| Source | Count | Label |
|--------|-------|-------|
| Held-out Monday+DoH benign | 104,672 | Benign |
| Friday benign flows | 383,456 | Benign |
| Friday attack flows | 176,350 | Malicious |
| **Total** | **664,478** | **73.5% benign / 26.5% malicious** |

---

## 8. Evaluation Results

### Comparison Table (Properly Labeled Test Set)

| Model | AUC-ROC | AUC-PR | Precision | Recall | F1-Score | Accuracy |
|-------|---------|--------|-----------|--------|----------|----------|
| **Isolation Forest** | 0.8092 | 0.6048 | **0.8661** | 0.5288 | **0.6567** | **0.8533** |
| **Deep Autoencoder** | **0.8570** | 0.7114 | 0.7979 | **0.5540** | 0.6540 | 0.8444 |
| **One-Class SVM** | 0.8299 | **0.7186** | 0.8386 | 0.5342 | 0.6526 | 0.8491 |
| **VAE** | 0.8510 | 0.7144 | 0.8077 | 0.5438 | 0.6500 | 0.8446 |

### ROC & Precision-Recall Curves

![ROC and PR Curves](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/roc_pr_corrected.png)

### Confusion Matrices

![Confusion Matrices](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/confusion_matrices.png)

### Anomaly Score Distributions

````carousel
![Deep Autoencoder — Anomaly Score Distribution](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/dist_deep_autoencoder.png)
<!-- slide -->
![Isolation Forest — Anomaly Score Distribution](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/dist_isolation_forest.png)
````

### Detailed Breakdown Per Model

#### Deep Autoencoder
```
              precision    recall  f1-score   support
      Benign       0.85      0.95      0.90    488,128
     Anomaly       0.80      0.55      0.65    176,350
    accuracy                           0.84    664,478
```
- **True Positives:** 97,701 attack flows correctly detected
- **False Positives:** 24,740 benign flows incorrectly flagged
- **True Negatives:** 463,388 benign flows correctly passed
- **False Negatives:** 78,649 attack flows missed

#### Isolation Forest
```
              precision    recall  f1-score   support
      Benign       0.85      0.97      0.91    488,128
     Anomaly       0.87      0.53      0.66    176,350
    accuracy                           0.85    664,478
```
- **True Positives:** 93,256 attack flows correctly detected
- **False Positives:** 14,416 benign flows incorrectly flagged (lowest!)
- **True Negatives:** 473,712 benign flows correctly passed
- **False Negatives:** 83,094 attack flows missed

---

## 9. Per-Attack Detection Breakdown

````carousel
![Deep Autoencoder — Per-Attack Detection](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/attack_breakdown_ae.png)
<!-- slide -->
![Isolation Forest — Per-Attack Detection](C:/Users/isbab/.gemini/antigravity/brain/011d64b8-4dba-44c4-ae86-ca6dd93996eb/attack_breakdown_if.png)
````

---

## 10. Metric Definitions

| Metric | Formula | What It Means for AegisNet |
|--------|---------|---------------------------|
| **Precision** | TP / (TP + FP) | When the model flags a flow as anomalous, how often is it actually an attack? High precision = low alert fatigue for SOC analysts. |
| **Recall** | TP / (TP + FN) | Of all actual attacks, what percentage did the model catch? High recall = fewer missed attacks. |
| **F1-Score** | 2 × (Precision × Recall) / (Precision + Recall) | Harmonic mean balancing precision and recall. The primary ranking metric. |
| **AUC-ROC** | Area under ROC curve | How well the model ranks malicious flows higher than benign flows across ALL thresholds. 1.0 = perfect, 0.5 = random. |
| **AUC-PR** | Area under Precision-Recall curve | Similar to AUC-ROC but more informative for imbalanced datasets (our test set is 73.5% benign). |
| **Accuracy** | (TP + TN) / Total | Overall correctness. Can be misleading on imbalanced data — a model that predicts everything as benign gets 73.5% accuracy. |

### Threshold Selection
The anomaly threshold is set at the **95th percentile** of validation set anomaly scores. This means:
- ~5% of normal validation traffic is expected to be flagged (controlled false positive rate)
- Any test flow scoring above this threshold is classified as anomalous

---

## 11. Final Model Selection

### Head-to-Head Summary

| Criterion | Best Model | Value |
|-----------|-----------|-------|
| **Highest F1-Score** | Isolation Forest | 0.6567 |
| **Highest AUC-ROC** | Deep Autoencoder | 0.8570 |
| **Highest AUC-PR** | One-Class SVM | 0.7186 |
| **Highest Precision** | Isolation Forest | 86.6% |
| **Highest Recall** | Deep Autoencoder | 55.4% |
| **Fastest Training** | One-Class SVM | 4.4s |
| **Fastest Inference** | VAE | 0.008 ms/sample |
| **Smallest Size** | AE / VAE | 0.09 MB |

### Decision: Two Viable Winners

**By F1-Score → Isolation Forest** (0.6567)
- Highest precision (86.6%) with competitive recall
- Lowest false positive count (14,416 vs 24,740 for AE)
- Extremely fast training (7 seconds) and small footprint
- Best for: minimizing SOC analyst alert fatigue

**By AUC-ROC → Deep Autoencoder** (0.8570)
- Best overall anomaly ranking across all thresholds
- Highest recall (55.4%) — catches the most attacks
- Captures complex non-linear patterns
- Best for: maximum detection coverage

### Recommended: Deep Autoencoder

> [!IMPORTANT]
> **We recommend the Deep Autoencoder** as the production Stage 0 baseline model because:
>
> 1. **Highest AUC-ROC (0.857)** — superior ranking ability means the threshold can be tuned post-deployment without retraining
> 2. **Highest recall (55.4%)** — in security, missing attacks is more costly than false positives
> 3. **0.009 ms inference** — handles 100K+ flows/second on CPU
> 4. **0.09 MB model** — trivial deployment footprint
> 5. **Operates before Stage 1 JA4 classifier** — false positives from Stage 0 are filtered by the supervised model downstream
>
> The Isolation Forest remains an excellent alternative if false positive reduction is prioritized over detection coverage.

### Model Artifacts

| File | Size | Description |
|------|------|-------------|
| `baseline_autoencoder.pt` | 0.09 MB | Trained Deep Autoencoder weights |
| `baseline_scaler.pkl` | 3.6 KB | Fitted StandardScaler |
| `baseline_freq_maps.pkl` | 3.8 MB | JA4 frequency encoding maps |
| `baseline_cat_maps.pkl` | 211 B | Categorical encoding maps |
| `baseline_features.json` | 2.8 KB | Ordered list of 128 feature columns |
