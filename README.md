### README.md

```markdown
# T-Pot AI Analyzer 🧠🔍

**T-Pot AI Analyzer** is an advanced Threat Intelligence tool that transforms raw data from a T-Pot honeypot into actionable and intelligent security reports. By leveraging a powerful analysis pipeline that combines **Machine Learning** for campaign detection and **Generative AI (Google Gemini)** for qualitative analysis, this project automates the work of a security analyst.

The final output is twofold: a **Markdown text report** for technical analysis and an **interactive, visually appealing HTML report** for presentation and sharing.

---

## ✨ Key Features

-   **Automated Data Pipeline**: Securely connects to Elasticsearch, extracts, and aggregates data from the last 24 hours.
-   **Machine Learning Campaign Clustering**: Utilizes the **DBSCAN** algorithm to distinguish coordinated attack campaigns (e.g., botnets) from random internet background noise.
-   **Generative AI Analysis**: Leverages Google Gemini to act as a senior security analyst, interpreting data and generating insights on attacker Tactics, Techniques, and Procedures (TTPs).
-   **Multi-Format Output**: Produces both a clean `.md` text report and a visually rich, interactive `.html` report featuring charts (via Chart.js) and a polished UI (via Pico.css).
-   **Simple & Reproducible Setup**: Cleanly manages dependencies and sensitive configurations through `requirements.txt` and `.env` files.

---

## 🏛️ Architecture and Workflow

The analysis process is orchestrated in several stages, each designed to enrich the data and turn it into knowledge.

1.  **Data Collection (Fetch)**
    -   Two parallel queries are run against Elasticsearch:
        1.  An **aggregation query** to get high-level statistics (Top 10 IPs, Countries, Honeypots, etc.).
        2.  A **raw data extraction query** to download up to 2000 events from interactive honeypots (like Cowrie and Heralding), which serve as the input for the ML model.

2.  **Machine Learning Analysis (Clustering)**
    -   This is the core innovation of the project. Raw events are processed to identify coordinated campaigns.
    -   **Feature Engineering**: Textual data (IPs, usernames, passwords, commands) and categorical data (honeypot type, ASN) are transformed into a **multi-dimensional numerical vector**. Techniques like `TfidfVectorizer` and `OneHotEncoder` are used for this conversion.
    -   **Clustering with DBSCAN**: The DBSCAN algorithm is applied to the vectorized data. Its ability to identify clusters of varying densities and to isolate noise makes it perfectly suited for this use case. The identified clusters represent the **attack campaigns**.

3.  **Generative AI Analysis (Gemini)**
    -   The aggregated stats and the details of the identified campaigns are formatted into a comprehensive prompt.
    -   The prompt instructs Gemini to act as a senior analyst, requesting a report that follows a specific structure (Executive Summary, Campaign Analysis, IoCs, Recommendations).

4.  **Final Report Generation**
    -   **Text Report (.md)**: The raw Markdown output from Gemini is saved directly to a file.
    -   **HTML Report**: The Gemini-generated text is **parsed** to extract individual sections. These sections, along with the aggregated data for the charts, are injected into an HTML template using the **Jinja2** templating engine, creating a complete and interactive final report.

---

## 🛠️ Setup and Installation

Follow these steps to get the analyzer up and running on your machine.

#### Prerequisites
-   Python 3.9+
-   Access to a T-Pot instance with a reachable Elasticsearch service.
-   A Google Gemini API Key.

#### Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/[your-username]/tpot-ai-analyzer.git
    cd tpot-ai-analyzer
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure your API Key:**
    -   Create a `.env` file in the project's root directory:
        ```bash
        nano .env
        ```
    -   Add your Google Gemini API key to it:
        ```
        GOOGLE_API_KEY="YOUR_API_KEY_HERE"
        ```

---

## 🚀 Usage

Once the setup is complete, running the script is straightforward.

```bash
# Ensure your virtual environment is active
python analyzer.py
```

The script will print its progress to the console and, upon completion, will generate two report files in the project directory:

-   `tpot_report_YYYY-MM-DD.md`: The full text-based report.
-   `tpot_report_YYYY-MM-DD.html`: The interactive HTML report. Open it in any web browser.

---

## 💡 Future Enhancements

This project serves as a solid foundation. Here are some ideas for future expansion:

-   **Real-time Alerting**: Create a parallel script that runs every 5 minutes and sends notifications (e.g., via Telegram or Discord) for high-severity events.
-   **IoC Enrichment**: Integrate services like AbuseIPDB or VirusTotal to enrich detected IPs and file hashes with external reputation data.
-   **MISP Integration**: Automate the submission of Indicators of Compromise (IoCs) to a Threat Intelligence Platform like MISP.
-   **Historical Analysis**: Compare the current day's data with the previous week's to identify anomalies and activity spikes.

---

## 📄 License

This project is licensed under the **MIT License**.
```
