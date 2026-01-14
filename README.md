# JsVul: A function-level dataset of vulnerable and fixed source code in JavaScript and TypeScript

**JsVul** is a function-level dataset and curation pipeline for JS/TS vulnerability detection. It aggregates
security fixes from seven sources, applying language-specific normalization and deduplication to produce
high-quality training data.

🔗 **Final Dataset (Zenodo):** https://doi.org/10.5281/zenodo.18195838

---

## 🚀 Key Features

* **Multi-Source:** Aggregates data from NVD, OSV, CVEFixes, CrossVul, JS Vulnerability Dataset, OSSF, and SecBench.JS.
* **Noise Reduction:** Filters minified code, tests, and build artifacts.
* **Normalization:** Standardizes code via ESLint/Prettier to isolate semantic changes.
* **Deduplication:** Commit-level, intra-commit (moves/cosmetic), and global deduplication.
* **Temporal Splits:** Sorted by `publish_time` to prevent look-ahead bias.

---

## 🛠️ Installation & Setup

**Requirements:** Python 3.13+, Node.js v24+, SQLite3 (for CVEFixes), gsutil (for OSV)

1. **Clone & Install Primary Tool:**
   ```bash
   git clone https://github.com/jsvul/jsvul.git && cd jsvul
   pip install -r requirements.txt
   ```

2. **Configure Environment:** Create a `.env` file in the root folder based on `.env.sample`.

3. **Merge Step Setup (`-m`):**
   To increase API rate limits during data collection, add your tokens to `.env`:
    * `GH_TOKEN`: [Create a GitHub Personal Access Token](https://github.com/settings/tokens) (`repo` scope).
    * `NVD_API_KEY`: [Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key).

4. **Process Step Setup (`-p`):**
   The processing pipeline requires two Node.js helper tools. For each tool, you must:
    * **Download/Clone** the repository to your machine.
    * **Install dependencies** by running `npm install` inside the tool's directory.
    * **Link the path** in your `.env` file to the tool's location.

   | Helper Tool            | Repository URL                                                          | .env Variable                                      |
   |:-----------------------|:------------------------------------------------------------------------|:---------------------------------------------------|
   | **Minify Helper**      | [js-minify-helper](https://github.com/jsvul/js-minify-helper)           | `JSMH_PATH=/path/to/js-minify-helper/tool.js`      |
   | **Function Extractor** | [js-function-extractor](https://github.com/jsvul/js-function-extractor) | `JSFE_PATH=/path/to/js-function-extractor/tool.js` |

5. **Manual Data Acquisition:** Before running the Merge step (`-m`), you must manually collect the following metadata
   files and place them in the `_data/` folder:

   | Source               | Download Link / Instructions                                                                                                                                                                        | Destination Path                               |
   |:---------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------|
   | **CrossVul**         | [Zenodo 4734050](https://zenodo.org/records/4734050). Download & extract `dataset.zip`, then copy `metadata.json`                                                                                   | `_data/crossvul/metadata.json`                 |
   | **CVEFixes**         | [Zenodo 13118970](https://zenodo.org/records/13118970). Download & extract `CVEfixes_v1.0.8.zip`, run: `gunzip -c CVEfixes_v1.0.8.sql.gz \| sqlite3 CVEfixes.db`, then copy `CVEfixes.db`           | `_data/cvefixes/CVEfixes.db`                   |
   | **JS Vuln. Dataset** | [U-Szeged Page](https://www.inf.u-szeged.hu/~ferenc/papers/JSVulnerabilityDataSet/). Download & extract `JSVulnerabilityDataSet-1.0.zip`, then copy `JSVulnerabilityDataSet-1.0.csv`                | `_data/js_vuln/JSVulnerabilityDataSet-1.0.csv` |
   | **OSSF Benchmark**   | [GitHub Repo](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark). Clone repo & copy all JSON files from `CVEs/`                                                                              | `_data/ossf_cve_benchmark/*.json`              |
   | **SecBench.JS**      | [GitHub Repo](https://github.com/cristianstaicu/SecBench.js). Clone repo & copy data folders: `code-injection`, `command-injection`, `incubator`, `path-traversal`, `prototype-pollution`, `redos`. | `_data/secbenchjs/[category_folders]`          |
   | **OSV**              | Run: `gsutil cp gs://osv-vulnerabilities/all.zip .`. Extract the result `all.zip` file, then copy all JSON files from it                                                                            | `_data/osv/*.json`                             |
   | **NVD**              | *No manual download required; handled automatically via API.*                                                                                                                                       | Managed by tool                                |

---

## 💻 Usage

The main entry point is `tool.py`. By default, running `python tool.py` without any stage flags executes the full
pipeline with default settings.

### Quick Start (Automated)

If you want to test the pipeline without manual downloads, you can run it using only the **NVD** source, which the tool
fetches automatically via API:

```bash
python tool.py -mpu -d nvd
```

### 1. Execution Stages

| Stage       | Flag | Description                                     | Default Output Directory |
|:------------|:-----|:------------------------------------------------|:-------------------------|
| **Merge**   | `-m` | Aggregates data & downloads repositories.       | `_data/merged_data`      |
| **Process** | `-p` | Normalizes code, extracts functions, & dedupes. | `_data/08_final`         |
| **Unify**   | `-u` | Formats JSONL & applies temporal splits.        | `_data/js_vul`           |

### 2. Parameters & Options

* **Global Options:**
    * `-w`, `--work-dir`: Path for data/cache storage. Defaults to project root.
    * `-f`, `--force`: Overwrites completion markers to re-run the specified steps from scratch.
* **Merge Options (Requires `-m`):**
    * `-d`, `--datasets`: Space-separated list. Options: `all`, `nvd`, `osv`, `ossf_cve_benchmark`, `js_vuln`,
      `cvefixes`, `crossvul`, `secbenchjs`.
* **Process Options (Requires `-p`):**
    * `--filters`: Space-separated list. Options: `all`, `added_removed`, `irrelevant`, `test`, `minified`.
* **Unify Options (Requires `-u`):**
    * `--unify-dir`: Specify a custom output directory for the final dataset.
    * `--unify-split`: Space-separated list for Train/Val/Test distribution ratios (e.g., `8 1 1`).
    * `--unify-po`: Run unification only for paired examples (vulnerable + fixed versions).

> **Note:** Dependent parameters cannot be used with the default "no-flag" run. To customize a stage, you must specify
> its flag. Example: `python tool.py -p --filters test`.

---

## ⏩ Advanced: Skipping Steps

Skip stages by placing pre-computed data in `_data/` (or `[WORK_DIR]/_data/`):

1. **Skip Merge:** Unzip `merged_data.zip` ([Zenodo](https://doi.org/10.5281/zenodo.18195839)) into `_data/merged_data`.
   Run `python tool.py -p -u`.
2. **Skip Process:** Unzip `08_final.zip` ([Releases](https://github.com/jsvul/jsvul/releases)) into `_data/08_final`.
   Run `python tool.py -u`.

---

## ⚙️ Pipeline Overview

1. **Merge (`-m`)**: Aggregates raw data from selected sources, downloads repositories, and unifies metadata.
2. **Process (`-p`)**: Filters noise, normalizes syntax, extracts functions, labels vulnerabilities, and performs all
   deduplication.
3. **Unify (`-u`)**: Consolidates processed entries into JSONL format and applies chronological splits.

---

## 📄 License

This project is licensed under the GNU GPLv3 License - see the [LICENSE](LICENSE) file for details.
