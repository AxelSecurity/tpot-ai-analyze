Hai perfettamente ragione, l'ho notato anche io dall'immagine. Il problema è sottile ma molto comune.

**Non è che Markdown sia "rotto", ma quasi certamente i caratteri che hai incollato non sono quelli corretti.**

### La Causa Esatta del Problema: Backtick "Smart" vs. Backtick "Plain"

Il problema risiede nei caratteri usati per il formato `inline code`. Markdown si aspetta il carattere **backtick** (accento grave), che sulla tastiera italiana di solito si trova premendo `ALT` + `96` sul tastierino numerico, o a volte vicino al tasto `Invio`. Il suo aspetto è ` ` `.

Molto spesso, quando si copia e incolla testo da editor "ricchi" (come Word, Google Docs, a volte anche da pagine web o client di chat), questi sostituiscono il backtick standard con dei caratteri tipograficamente "belli" ma tecnicamente sbagliati, come un apostrofo inclinato (`‘` o `’`).

GitHub non riconosce questi caratteri "smart" come delimitatori di codice, e quindi non applica la formattazione.

Nell'immagine, si vede chiaramente che `requirements.txt`, `.md` e `.html` non hanno lo sfondo grigio tipico del codice, confermando questa diagnosi.

### La Soluzione: Il Codice Corretto da Incollare

Ti fornisco qui sotto la versione del `README.md` in inglese, ma con la certezza assoluta che tutti i caratteri speciali di Markdown siano corretti.

**Azione Correttiva:**

1.  Vai sul tuo repository GitHub.
2.  Clicca sul file `README.md`.
3.  Clicca sull'icona della matita ("Edit this file") in alto a destra.
4.  Seleziona **TUTTO** il testo presente e **cancellalo**.
5.  Copia e incolla il blocco di codice che ti fornisco qui sotto.
6.  Scorri in fondo alla pagina e clicca sul pulsante verde **"Commit changes"**.

Con questa operazione, il tuo `README` verrà renderizzato in modo perfetto.

---

### README.md (Versione Corretta)

```markdown
# T-Pot AI Analyzer 🧠🔍

**T-Pot AI Analyzer** is an advanced Threat Intelligence tool that transforms raw data from a T-Pot honeypot into actionable and intelligent security reports.

The final output is twofold: a **Markdown text report** for technical analysis and an **interactive, visually appealing HTML report** for presentation and sharing.

---

## ✨ Key Features

-   **Automated Data Pipeline**: Securely connects to Elasticsearch, extracts, and aggregates data from the last 24 hours.
-   **Machine Learning Campaign Clustering**: Utilizes the **DBSCAN** algorithm to distinguish coordinated attack campaigns (e.g., botnets) from random internet background noise.
-   **Generative AI Analysis**: Leverages Google Gemini to act as a senior security analyst, interpreting data and generating insights on attacker TTPs.
-   **Multi-Format Output**: Produces both a clean `.md` text report and a visually rich, interactive `.html` report featuring charts and a polished UI.
-   **Simple & Reproducible Setup**: Cleanly manages dependencies and sensitive configurations through `requirements.txt` and `.env` files.

---

## 🏛️ Architecture and Workflow

The analysis process is orchestrated in several stages, each designed to enrich the data and turn it into knowledge.

1.  **Data Collection (Fetch)**
    -   Two parallel queries are run against Elasticsearch:
        1.  An **aggregation query** to get high-level statistics (Top 10 IPs, Countries, Honeypots, etc.).
        2.  A **raw data extraction query** to download up to 2000 events from interactive honeypots (like Cowrie and Heralding).

2.  **Machine Learning Analysis (Clustering)**
    -   This is the core innovation of the project. Raw events are processed to identify coordinated campaigns.
    -   **Feature Engineering**: Textual data (IPs, usernames, passwords, commands) and categorical data (honeypot type, ASN) are transformed into a **multi-dimensional numerical vector**.
    -   **Clustering with DBSCAN**: The DBSCAN algorithm is applied to the vectorized data. Its ability to identify clusters of varying densities and to isolate noise makes it perfectly suited for this use case.

3.  **Generative AI Analysis (Gemini)**
    -   The aggregated stats and the details of the identified campaigns are formatted into a comprehensive prompt for Google Gemini.
    -   The prompt instructs the AI to act as a senior analyst and follow a specific report structure.

4.  **Final Report Generation**
    -   **Text Report (`.md`)**: The raw Markdown output from Gemini is saved directly to a file.
    -   **HTML Report (`.html`)**: The Gemini-generated text is parsed to extract individual sections. These sections, along with chart data, are injected into an HTML template using the **Jinja2** templating engine.

---

## 🛠️ Setup and Installation

Follow these steps to get the analyzer up and running.

#### Prerequisites
-   Python 3.9+
-   Access to a T-Pot instance with a reachable Elasticsearch service.
-   A Google Gemini API Key.

#### Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AxelSecurity/tpot-ai-analyzer.git
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

The script will generate two report files in the project directory:

-   `tpot_report_YYYY-MM-DD.md`
-   `tpot_report_YYYY-MM-DD.html`

---

## 📄 License

This project is licensed under the **MIT License**.
