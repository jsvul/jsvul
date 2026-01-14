# JsVul: A function-level dataset of vulnerable and fixed source code in JavaScript and TypeScript

**JsVul** is a comprehensive tool and dataset for JavaScript and TypeScript vulnerability detection. It aggregates
security fixes from seven major sources, cleanses the data using language-specific heuristics (syntax normalization,
minification detection), and produces a high-quality function-level dataset suitable for training machine learning
models.

This repository contains the **curation pipeline** used to generate the dataset.

🔗 **The final dataset is available on Zenodo:** https://doi.org/10.5281/zenodo.18195838

---

## 🚀 Features

* **Multi-Source Aggregation:** Collects data from CrossVul, CVEFixes, JS Vulnerability Dataset, OSSF CVE benchmark,
  SecBench.JS, OSV, and NVD.
* **Language-Aware Processing:** Specific pipeline for JavaScript and TypeScript that handle minified code and syntax
  variations.
* **Noise Reduction:**
    * **Syntax Normalization:** Uses ESLint and Prettier to remove formatting noise (whitespace, indentation) before
      diffing.
    * **Heuristic Filtering:** Detects and removes minified files, test files, and build artifacts.
* **Advanced Deduplication:** Dedupes at the commit level, intra-commit level (moved functions), and global function
  level.
* **Temporal Safety:** Preserves publication timestamps to allow for temporally split training sets (preventing
  look-ahead bias).

---

## Requirements

- Node.js installed (tested with v24)
- Python installed (tested with 3.13)

## 🛠️ Installation

### Prerequisites

The pipeline requires **Python** (tested with 3.13) and **Node.js** (tested with v24).

### 1. Clone the Repository

	```bash
	git clone [https://github.com/jsvul/jsvul.git](https://github.com/jsvul/jsvul.git)
	cd jsvul
	```

### 2. Environment Setup

To run the merge or process steps, create a `.env` file in the root folder based on the included `.env.sample`.

**For the Merge Step (`-m`):**
You need API tokens to increase rate limits and access data:

* **GitHub:** Create a GitHub token with `repo` access and add it as `GH_TOKEN` in your `.env` file.
* **NVD:** Create an NVD API key and add it as `NVD_API_KEY`.

**For the Process Step (`-p`):**
You must clone and configure the two external helper tools:

1. **js-minify-helper**:
    * Clone the repo: [https://github.com/jsvul/js-minify-helper](https://github.com/jsvul/js-minify-helper)
    * Run `npm install` inside its folder.
    * Set `JSMH_PATH` in your `.env` file to the full path of this folder.
2. **js-function-extractor**:
    * Clone the repo: [https://github.com/jsvul/js-function-extractor](https://github.com/jsvul/js-function-extractor)
    * Run `npm install` inside its folder.
    * Set `JSFE_PATH` in your `.env` file to the full path of this folder.

### 3. Install Python Dependencies

	```bash
	pip install -r requirements.txt
	```

---

## 💻 Usage

The main entry point is `tool.py`. You can run the entire pipeline with default settings, or use specific arguments to
run individual stages.

### Quick Start

Run the tool with default settings:

```bash
python tool.py
```

### Arguments

| Argument             | Description                                                                                                                                                                                               |
|:---------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-w`, `--work-dir`   | Path to the working directory where data and cache files are stored during tool execution.                                                                                                                |
| `-f`, `--force`      | By default, the tool resumes from the last completed step. Use this flag to force a re-run of the selected steps from scratch (e.g., `python tool.py -u -f` will completely re-run the unification step). |
| **Stage 1: Merge**   |                                                                                                                                                                                                           |
| `-m`, `--merge`      | Run the data acquisition and merge step.                                                                                                                                                                  |
| `-d`, `--datasets`   | List of sources to merge. Options: `all`, `nvd`, `osv`, `ossf_cve_benchmark`, `js_vuln`, `cvefixes`, `crossvul`, `secbenchjs`.                                                                            |
| **Stage 2: Process** |                                                                                                                                                                                                           |
| `-p`, `--process`    | Run filtering, normalization, and extraction steps.                                                                                                                                                       |
| `--filters`          | Specific filters to apply. Options: `all`, `added_removed`, `irrelevant`, `test`, `minified`.                                                                                                             |
| **Stage 3: Unify**   |                                                                                                                                                                                                           |
| `-u`, `--unify`      | Consolidate processed data into the final JSONL format.                                                                                                                                                   |
| `--unify-dir`        | Directory to save the final JSONL output.                                                                                                                                                                 |
| `--unify-split`      | Ratios for splitting data (e.g., `8 1 1` for 80/10/10 split).                                                                                                                                             |
| `--unify-po`         | Generate a "Pairs Only" dataset (only entries with both pre-fix and post-fix functions).                                                                                                                  |

---

## ⏩ Advanced Usage: Skipping Steps

You can save time by downloading pre-computed intermediate data instead of running the full pipeline from scratch.

### 1. Using Merged Data (Skip Merge Step)
Instead of running the merge step, you can download the raw aggregated data and metadata.
1. Download `merged_data.zip` from [Zenodo](https://doi.org/10.5281/zenodo.18195839).
2. Unzip the archive into the `_data/merged_data` folder.
    * If using `--work-dir`, place it in `[WORK_DIR]/_data/merged_data`.
    * If no work directory is specified, place it in `[PROJECT_ROOT]/_data/merged_data`.
3. Run the processing and unification steps:
	```bash
	python tool.py -p -u
	```

### 2. Using Processed Data (Skip Process Step)
Download the result of the process step to run only the final unification and splitting.
1. Download `08_final.zip` from the [GitHub Releases](https://github.com/jsvul/jsvul/releases) page.
2. Unzip it's content to the `_data/08_final` folder of your project root or specified working directory.
3. Run the unification step:
	```bash
	python tool.py -u
	```

---

## 💾 Pre-Computed Datasets

The final curated datasets, including the recommended **80-10-10 (train-validation-test)** splits, are available for direct download on **Zenodo**.

* **Complete Dataset (`js_vul.zip`)**: The full curated dataset.
* **Pairs-Only Dataset (`js_vul_pairs_only.zip`)**: A subset containing only matched pre/post-fix pairs.

📥 **Download here:** [https://doi.org/10.5281/zenodo.18195839](https://doi.org/10.5281/zenodo.18195839)

---

## ⚙️ Pipeline Overview

The tool operates in three distinct phases:

1.  **Merge (`-m`)**: Aggregates raw data from selected sources, downloads repositories, and unifies metadata.
2.  **Process (`-p`)**: Filters noise, normalizes syntax using ESLint/Prettier, extracts functions, and labels vulnerabilities.
3.  **Unify (`-u`)**: Consolidates entries, performs global deduplication, and applies chronological splits.

---

## 📄 License

This project is licensed under the GNU GPLv3 License - see the [LICENSE](LICENSE) file for details.
