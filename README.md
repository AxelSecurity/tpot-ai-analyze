# 🧠🔍 T-Pot AI Analyzer

**T-Pot AI Analyzer** is an advanced Threat Intelligence tool that transforms raw data from a T-Pot honeypot into actionable and intelligent security reports.

The final output is twofold:
- A **Markdown text report** for technical analysis.
- An **interactive, visually appealing HTML report** for presentation and sharing.

---

## ✨ Key Features

- **Automated Data Pipeline**: Securely connects to Elasticsearch, extracts, and aggregates data from the last 24 hours.
- **Machine Learning Campaign Clustering**: Utilizes the **DBSCAN** algorithm to distinguish coordinated attack campaigns (e.g., botnets) from random internet background noise.
- **Generative AI Analysis**: Leverages Google Gemini to act as a senior security analyst, interpreting data and generating insights on attacker TTPs.
- **Multi-Format Output**: Produces both a clean `.md` text report and a visually rich, interactive `.html` report featuring charts and a polished UI.
- **Simple & Reproducible Setup**: Cleanly manages dependencies and sensitive configurations through `requirements.txt` and `.env` files.

---

## 🏛️ Architecture and Workflow

The analysis process is orchestrated in several stages, each designed to enrich the data and turn it into knowledge.

### 1. 📥 Data Collection (Fetch)
- Two parallel queries are run against Elasticsearch:
  1. An **aggregation query** to get high-level statistics (Top 10 IPs, Countries, Honeypots, etc.).
  2. A **raw data extraction query** to download up to 2000 events from interactive honeypots (like Cowrie and Heralding).

### 2. 🤖 Machine Learning Analysis (Clustering)
- **Feature Engineering**: Textual data (IPs, usernames, passwords, commands) and categorical data (honeypot type, ASN) are transformed into a **multi-dimensional numerical vector**.
- **Clustering with DBSCAN**: The DBSCAN algorithm is applied to the vectorized data. Its ability to identify clusters of varying densities and to isolate noise makes it perfectly suited for this use case.

### 3. 🧠 Generative AI Analysis (Gemini)
- The aggregated stats and the details of the identified campaigns are formatted into a comprehensive prompt for Google Gemini.
- The prompt instructs the AI to act as a senior analyst and follow a specific report structure.

### 4. 📄 Final Report Generation
- **Text Report (`.md`)**: The raw Markdown output from Gemini is saved directly to a file.
- **HTML Report (`.html`)**: The Gemini-generated text is parsed to extract individual sections. These sections, along with chart data, are injected into an HTML template using the **Jinja2** templating engine.

---

## 🛠️ Setup and Installation

### ✅ Prerequisites
- Python 3.9+
- Access to a T-Pot instance with a reachable Elasticsearch service.
- A Google Gemini API Key

### 🔧 Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/AxelSecurity/tpot-ai-analyzer.git
   cd tpot-ai-analyzer
   ```

2. **Create and activate a Python virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the required dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure your API Key**
   - Create a `.env` file in the project's root directory:
     ```bash
     nano .env
     ```
   - Add your Google Gemini API key to it:
     ```env
     GOOGLE_API_KEY="YOUR_API_KEY_HERE"
     ```

---

## 🚀 Usage

Once the setup is complete, running the script is straightforward.

```bash
# Ensure your virtual environment is active
python tpot_analyzer_ML.py
```

The script will generate two report files in the project directory:

- `tpot_report_YYYY-MM-DD.md`
- `tpot_report_YYYY-MM-DD.html`

---

## 📄 License

This project is licensed under the **MIT License**.
