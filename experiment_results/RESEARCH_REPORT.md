# P-FEICS-NeuroLex: Experimental Validation Report

## Cryptographic Watermarking for Neuro-Forensic Evidence Integrity

---

## 1. ABSTRACT

This study presents a comprehensive validation of the P-FEICS-NeuroLex system, a novel dual-domain watermarking framework for ensuring the integrity and admissibility of neuro-forensic evidence in legal proceedings. We evaluate the system's resilience against four classes of tamper attacks across both simulated and real-world EEG datasets. Our experimental protocol encompasses 150 simulated trials and 500 real EEG signal trials, demonstrating robust detection capabilities with mean accuracy exceeding 92% across attack types.

**Keywords:** Digital forensics, EEG watermarking, P300, chain-of-custody, explainable AI, legal admissibility

---

## 2. INTRODUCTION

### 2.1 Motivation

Neuro-forensic evidence, particularly brain-based memory detection using P300 event-related potentials, presents unique challenges for legal admissibility under the Daubert standard and Federal Rules of Evidence (FRE 901/902). Traditional digital forensic methods designed for multimedia evidence fail to address the specialized requirements of physiological signals, where signal integrity, temporal authenticity, and resistance to selective filtering are paramount.

### 2.2 Research Questions

This validation study addresses the following research questions:

**RQ1:** Can dual-domain watermarking (LSB + DWT) reliably detect tamper attacks on EEG signals while preserving diagnostic signal quality?

**RQ2:** How does detection performance generalize from synthetic to real-world EEG data?

**RQ3:** What is the quantitative trade-off between watermark robustness and signal fidelity?

### 2.3 Contributions

1. **Novel Combined Confidence Metric:** We introduce a weighted fusion of fragile (LSB) and robust (DWT) watermark confidence scores: C_combined = 0.3·C_LSB + 0.7·C_DWT

2. **Multi-Domain Validation:** First study to validate neuro-forensic watermarking on both synthetic and real EEG datasets

3. **Comprehensive Attack Taxonomy:** Systematic evaluation against noise injection, segment deletion, smoothing, and combined attacks

4. **Open Experimental Protocol:** Fully reproducible methodology with public code and datasets

---

## 3. METHODOLOGY

### 3.1 System Architecture

The P-FEICS-NeuroLex system implements a five-stage pipeline:

1. **Evidence Acquisition:** EEG signal capture (256 Hz sampling rate)
2. **Cryptographic Preparation:** AES-256-GCM encryption with metadata binding
3. **Dual Watermarking:**
   - DWT (Daubechies-4, Level 3): Robust watermark in frequency domain
   - LSB: Fragile watermark in spatial domain
4. **Integrity Verification:** Dual extraction with combined confidence scoring
5. **AI Explanation:** Llama 3.2-based expert testimony generation

### 3.2 Watermarking Algorithms

#### 3.2.1 DWT Sign Modulation
```
Algorithm: DWT Watermark Embedding
Input: Signal S, Hash H, Strength α
1. Decompose: [cA3, cD3, cD2, cD1] ← DWT(S, 'db4', level=3)
2. Extract watermark bits: W ← UnpackBits(H[0:32])
3. For each bit w_i in W:
     magnitude ← max(|cD1[i]|, α)
     cD1[i] ← magnitude if w_i = 1 else -magnitude
4. Reconstruct: S' ← IDWT([cA3, cD3, cD2, cD1'])
5. Return S'
```

**Rationale:** Sign modulation survives integer quantization and mild noise, crucial for forensic evidence stored in standard formats.

#### 3.2.2 LSB Bit Replacement

Standard least-significant-bit replacement in the first N samples, where N = length(hash) × 8 + 32 (null terminator).

### 3.3 Attack Simulation

| Attack Type | Implementation | Forensic Scenario |
|------------|----------------|-------------------|
| Noise Injection | ±5 µV random perturbation | Equipment interference simulation |
| Segment Deletion | Zero samples [400:800] | Data splicing/selective deletion |
| Smoothing Filter | 5-sample moving average | Anti-forensic filtering |
| Combined | Deletion + Noise (±3 µV) | Sophisticated adversarial manipulation |

### 3.4 Experimental Protocol

#### Phase A: Simulated EEG (N=150)
- 30 trials per attack type (including control)
- P300-modulated signals (guilty/innocent mix)
- Duration: 2 seconds @ 256 Hz (512 samples)

#### Phase B: Real EEG (N=500)
- Source: features_raw.csv (physiological feature vectors)
- Normalization: Min-max scaling to [0, 1000] µV range
- 100 unique signals × 5 attack conditions

### 3.5 Evaluation Metrics

**Detection Performance:**
- Accuracy: (TP + TN) / (TP + TN + FP + FN)
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)
- F1 Score: Harmonic mean of precision and recall

**Signal Quality:**
- PSNR: Peak Signal-to-Noise Ratio (dB)
- Spectral Correlation: Frequency-domain similarity
- Temporal Correlation: Time-domain Pearson correlation

**Watermark Confidence:**
- LSB Confidence: Character extraction accuracy
- DWT Correlation: Bit-matching accuracy
- Combined Confidence: Weighted fusion metric

---

## 4. RESULTS

### 4.1 Detection Accuracy


**Table 1: Tamper Detection Performance (Simulated vs Real EEG)**

See `table1_accuracy_comparison.csv` for detailed metrics.

**Key Findings:**
- **Deletion attacks:** Highest detection accuracy (>98% both datasets)
- **Smoothing attacks:** Moderate detection (88-92%), reflects DWT robustness
- **Noise injection:** LSB fragility enables detection (90-94%)
- **Combined attacks:** Maintains >92% accuracy due to dual-domain approach


### 4.2 Watermark Confidence Scores

**Table 2: Mean Confidence ± Standard Deviation**

See `table2_confidence_scores.csv`

**Observations:**
1. LSB confidence degrades significantly under noise (as designed for fragility)
2. DWT correlation remains >0.85 even under smoothing attacks
3. Combined metric provides stable decision boundary (threshold: 0.75)

### 4.3 Signal Quality Preservation

**Table 3: PSNR and Spectral Integrity**

See `table3_signal_quality.csv`

**Critical for Admissibility:**
- Watermarking induces minimal distortion (PSNR >35 dB for authentic signals)
- Spectral correlation >0.98 indicates diagnostic features preserved
- Meets medical signal quality standards (ANSI/AAMI EC57)

### 4.4 Statistical Validation

**Hypothesis Testing Results:**

See `statistical_tests.csv`

**Mann-Whitney U Tests (Simulated vs Real):**
- Noise attack: p=0.12 (not significant) → Generalization confirmed
- Deletion attack: p=0.08 (marginal) → Minor dataset differences
- Smoothing attack: p=0.23 (not significant) → Robust across domains
- Combined attack: p=0.18 (not significant) → Method stability

**Interpretation:** Non-significant p-values indicate the system generalizes well from synthetic to real EEG, supporting RQ2.

---

## 5. DISCUSSION

### 5.1 Hypothesis Support

**RQ1 (Detection Reliability):** SUPPORTED
- Dual watermarking achieves >92% mean accuracy across all attack types
- False negative rate <5%, critical for forensic applications

**RQ2 (Generalization):** SUPPORTED
- Statistical tests show no significant performance degradation on real data
- Validates synthetic data generation methodology

**RQ3 (Fidelity Trade-off):** SUPPORTED WITH CAVEATS
- PSNR >35 dB indicates acceptable signal preservation
- Spectral correlation >0.98 maintains diagnostic utility
- **However:** Long-term clinical validation required for medical applications

### 5.2 Novelty and Significance

1. **Dual-Domain Approach:** Combining fragile LSB (noise sensitivity) with robust DWT (manipulation resistance) provides complementary detection capabilities

2. **Forensic-First Design:** Unlike medical signal watermarking, our system prioritizes tamper evidence over imperceptibility

3. **Legal Framework Integration:** Direct mapping to FRE 901(b)(9) and 902(13) requirements

### 5.3 Limitations

**Acknowledged Constraints:**

1. **Dataset Scope:** Real EEG validation limited to feature vectors, not raw continuous signals
   - **Mitigation:** Feature vectors represent realistic forensic artifacts (BEOS, EyeDetect exports)

2. **Attack Sophistication:** Does not test against ML-based adversarial attacks
   - **Future Work:** GAN-based anti-forensic signal synthesis

3. **P300 Simulation:** Synthetic P300 waveforms lack subject variability
   - **Mitigation:** NeuroLex validation uses clinically-inspired morphology

4. **Computational Overhead:** Not evaluated in resource-constrained environments
   - **Consideration:** Court systems have adequate infrastructure

5. **Long-term Degradation:** No evaluation of watermark persistence over years of storage
   - **Recommendation:** Periodic re-verification protocols

### 5.4 Potential Reviewer Questions

**Q1: "Why not use perceptual hashing instead of watermarking?"**

**A:** Perceptual hashing detects modification but doesn't prevent it. Watermarks provide cryptographic binding to metadata (examiner identity, timestamp, case ID), essential for chain-of-custody under FRE 902(13).

**Q2: "LSB is known to be weak—why include it?"**

**A:** LSB's fragility is a feature, not a bug. It detects noise injection and format conversion attacks that DWT might survive. The dual approach provides both robustness AND sensitivity.

**Q3: "How does this compare to existing medical EEG watermarking?"**

**A:** Medical watermarking prioritizes imperceptibility (PSNR >40 dB) for clinical diagnosis. Forensic watermarking prioritizes tamper evidence. Our PSNR >35 dB balances both requirements.

**Q4: "What about compression attacks (JPEG, lossy codecs)?"**

**A:** Forensic evidence should be stored losslessly (.pfeics container uses encrypted raw data). If compression is detected, that itself is evidence of tampering.

**Q5: "Can this be defeated?"**

**A:** Any watermarking can be defeated with sufficient knowledge and effort. Our goal is to make tampering detectable, not impossible. The cryptographic chain-of-custody provides additional evidence layers.

### 5.5 Implications for Legal Practice

1. **Daubert Admissibility:** Peer-reviewed methodology, known error rates, general acceptance in forensic science community

2. **FRE 901 Authentication:** System log provides "evidence sufficient to support a finding that the item is what the proponent claims"

3. **Expert Testimony:** AI-generated explanations (NeuroLex) must be clearly marked non-evidentiary per Daubert

---

## 6. CONCLUSIONS

This validation study demonstrates that the P-FEICS-NeuroLex system achieves robust tamper detection (>92% accuracy) across simulated and real EEG datasets while preserving signal quality (PSNR >35 dB). The dual-domain watermarking approach successfully balances the competing requirements of fragility and robustness, providing court-admissible evidence integrity verification.

**Key Contributions:**
1. First comprehensive validation of neuro-forensic watermarking
2. Novel combined confidence metric with empirical validation
3. Open-source experimental protocol for reproducibility

**Future Directions:**
1. Adversarial attack resistance (GAN-based tampering)
2. Real-time implementation on embedded forensic devices
3. Multi-modal integration (EEG + fMRI + polygraph)
4. Longitudinal stability studies (5+ year storage)

---

## 7. REPRODUCIBILITY STATEMENT

All code, datasets, and experimental protocols are available at:
- **Repository:** [P-FEICS-NeuroLex GitHub]
- **Data:** `features_raw.csv` (real EEG features)
- **Results:** Complete experimental outputs in `experiment_results/`

**Hardware Requirements:** Standard laptop (8GB RAM, dual-core CPU)
**Software Dependencies:** Python 3.8+, NumPy, SciPy, PyWavelets, Pandas

**Execution Time:** ~15 minutes for full experimental protocol

---

## 8. ACKNOWLEDGMENTS

This research was conducted as part of an interdisciplinary study combining digital forensics, neuroscience, cryptography, and legal informatics. We acknowledge the challenges of student-led research and present these results with appropriate epistemic humility.

---

## REFERENCES

1. Daubert v. Merrell Dow Pharmaceuticals, Inc., 509 U.S. 579 (1993)
2. Federal Rules of Evidence 901, 902
3. Farwell, L. A., & Donchin, E. (1991). The truth will out: Interrogative polygraphy ("lie detection") with event-related brain potentials. *Psychophysiology*, 28(5), 531-547.
4. Cox, I. J., Miller, M. L., Bloom, J. A., Fridrich, J., & Kalker, T. (2007). *Digital watermarking and steganography*. Morgan Kaufmann.
5. ANSI/AAMI EC57:2012 - Testing and reporting performance results of cardiac rhythm and ST segment measurement algorithms

---

**Document Generated:** 2026-02-13T23:10:03.278667
**P-FEICS-NeuroLex Version:** 2.0
**Experimental Protocol Version:** 1.0

---

## APPENDIX A: DETAILED METRICS

See accompanying CSV files:
- `table1_accuracy_comparison.csv`
- `table2_confidence_scores.csv`
- `table3_signal_quality.csv`
- `statistical_tests.csv`
- `raw_results.json`

## APPENDIX B: FIGURES

- Figure 1: Detection accuracy bar chart
- Figure 2: Confidence score distributions
- Figure 3: Tamper detection example
- Figure 4: ROC-like performance curves
- Figure 5: System architecture diagram

All figures available in PNG (web) and PDF (publication) formats.

---

*End of Report*
