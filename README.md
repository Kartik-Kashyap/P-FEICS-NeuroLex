# P-FEICS-NeuroLex: Psycho-Forensic Evidence Integrity System

**P-FEICS (Psycho-Forensic Evidence Integrity & Chain-of-Custody System)** is a court-admissible forensic management system designed to secure physiological signals (EEG, BEOS) against tampering. This repository contains the source code for the system v2.0, along with the complete experimental validation suite used to generate the data, tables, and figures for the accompanying research paper.

## Abstract

Neuro-forensic evidence faces unique admissibility challenges under the Daubert standard due to the fragility of physiological data. P-FEICS addresses this by implementing a **Dual-Domain Watermarking** technique (LSB + DWT) combined with AES-256-GCM encryption and a hash-chained custody log. This ensures that any manipulation—such as signal splicing, selective filtering, or noise injection—is instantly detectable while preserving the diagnostic quality of the P300 waveforms.

## Problem Statement

It is difficult to look at the raw EEG signal and identify the state of the human mind or detect subtle manipulative alterations. In forensic contexts, ensuring the authenticity of these signals is critical. Traditional digital signatures do not protect the raw signal data from subtle "anti-forensic" attacks like smoothing or splicing which can alter legal conclusions without invalidating file-level checksums.

## The Dataset

The validation of this system utilizes a subset of the **DEAP (Database for Emotion Analysis using Physiological Signals)** dataset.

The dataset consists of two parts:

1. **Online Ratings:** Ratings from an online self-assessment where 120 one-minute extracts of music videos were each rated by 14-16 volunteers based on arousal, valence, and dominance.
2. **Experiment Data:** Participant ratings, physiological recordings, and face video of an experiment where 32 volunteers watched a subset of 40 of the above music videos. EEG and physiological signals were recorded, and each participant also rated the videos as above.

**Preprocessing for this Study:**

* Labels and channel data have been extracted into separate files.
* Data from each channel is stored row-wise versus time in columns for each trial, per person.
* The dataset (`features_raw.csv`) contains **8,086 entries**, including channels such as Fp1, AF3, F3, F7, etc.

## Repository Structure

```text
.
└── P-FEICS-NeuroLex/
    ├── main.py                                    # Main GUI application (P-FEICS v2.0)
    ├── EXPERIMENT_RUNNER.py                       # Experiment execution & artifact generation
    ├── graphviz_figure5_architecture_compact.py   # Compact architecture diagram generator
    ├── features_raw.csv                           # Real EEG dataset (DEAP subset)
    └── experiment_results/
        ├── detailed_metrics.json
        ├── raw_results.json
        ├── RESEARCH_REPORT.md
        ├── statistical_tests.csv
        ├── table1_accuracy_comparison.csv
        ├── table2_confidence_scores.csv
        ├── table3_signal_quality.csv
        ├── table4_latency.csv
        ├── figure1_accuracy_comparison.png
        ├── figure1_accuracy_comparison.pdf
        ├── figure2_confidence_distribution.png
        ├── figure2_confidence_distribution.pdf
        ├── figure3_tamper_example.png
        ├── figure3_tamper_example.pdf
        ├── figure4_performance_curves.png
        ├── figure4_performance_curves.pdf
        ├── figure5_architecture.png
        ├── figure5_architecture.pdf
        ├── figure5_compact.png
        └── figure5_compact.pdf

```

## Installation

### Prerequisites

* Python 3.8 or higher
* [Graphviz](https://graphviz.org/download/) (for architecture diagram generation)
* [Ollama](https://ollama.com/) with `llama3.2` model (for AI interpretation features)

### Dependencies

Install the required Python packages:

```bash
pip install numpy pandas scipy matplotlib seaborn scikit-image pywavelets pycryptodome reportlab fpdf plotly requests graphviz

```

*Note: For the AI interpretation module to work, ensure Ollama is running locally:*

```bash
ollama run llama3.2

```

## Usage

### 1. Running the Forensic Software

The `main.py` file launches the P-FEICS v2.0 GUI, intended for use by forensic examiners.

```bash
python main.py

```

**Key Capabilities:**

* **Cryptographic Auth:** RSA-4096 keypair generation for examiner signatures.
* **Evidence Acquisition:** Simulates BEOS/EEG sensor input.
* **Dual Watermarking:** Applies both DWT (Robust) and LSB (Fragile) watermarks.
* **Tamper Simulation:** Includes tools to simulate "Splicing" and "Noise" attacks to demonstrate detection.
* **Secure Export:** Generates encrypted `.pfeics` containers and signed PDF reports.

### 2. Reproducing Research Results

The `EXPERIMENT_RUNNER.py` script is the core validation engine for the research paper. It runs a full battery of statistical tests on both simulated and real EEG data.

```bash
python EXPERIMENT_RUNNER.py

```

**This script will automatically:**

1. Run **150 simulated trials** across 4 attack vectors (Noise, Deletion, Smoothing, Combined).
2. Run **500 real EEG trials** using the `features_raw.csv` dataset.
3. Perform statistical hypothesis testing (t-test, Mann-Whitney U).
4. Generate publication-ready figures (PNG/PDF) in `experiment_results/`.
5. Write a comprehensive `RESEARCH_REPORT.md` summarizing the findings.

### 3. Generating Architecture Diagrams

To generate the high-resolution architecture diagrams included in the paper:

```bash
python graphviz_figure5_architecture_compact.py

```

## Research Methodology

The system is validated using a **Dual-Domain** approach:

1. **Spatial Domain (LSB):** Used for fragility. Detects minute noise injection and re-encoding attacks.
2. **Frequency Domain (DWT - Daubechies 4):** Used for robustness. Survives mild signal processing but fails under structural tampering.

**Combined Confidence Metric:**


This weighted metric allows the system to distinguish between benign environmental noise and malicious tampering attempts.

## Key Findings

* **Detection Accuracy:** >92% across all attack vectors on real EEG data.
* **Signal Fidelity:** Maintained PSNR > 35 dB, ensuring the watermarking process does not degrade the diagnostic value of the P300 signal.
* **Latency:** Average processing time < 50ms per signal, suitable for real-time acquisition.

## Security & Compliance

* **Encryption:** AES-256-GCM (Galois/Counter Mode) for all raw evidence.
* **Signatures:** RSA-4096 digital signatures for chain-of-custody logs.
* **Compliance:** Designed to meet Federal Rules of Evidence (FRE) 901(b)(9) and 902(13).

## Author

### Primary Author

**Kartik Kashyap** <br>
Software Engineer & Researcher<br>
B.Tech Information Technology<br>
*Interests: Forensics, Criminology, Human‑Centered AI, Technology Law, Humanology, Ethics*<br>
Contact: kartikkashyapworks247@gmail.com

### Forensic Domain Advisor

**Vaibhav Laxmi**<br>
B\.Sc / M\.Sc Criminology & Forensic Science, NFSU<br>
*Interests: Forensics, Criminology, Understanding Human Behavior, Criminal Psychology, History*<br>
Contact: vaibhav.bsmscrfs2242925@nfsu.ac.in

### Inspiration & Acknowledgement

**Mr. Rithin Parker Joseph**<br>
Assistant Professor NFSU (Behavioural Forensics), Researcher (Criminal Psychology)

## License

This repository is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for full text.

---

*This software is for research and educational purposes only. It is designed to demonstrate the application of cryptographic watermarking in neuro-forensics.*