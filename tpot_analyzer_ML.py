# ==============================================================================
# TPOT-AI-ANALYZER v5.0 - by Gemini & User Collaboration
#
# Genera un report di threat intelligence sinergico, dove l'analisi
# dell'IA viene estratta e iniettata in un report HTML interattivo e visivo,
# utilizzando il machine learning per identificare campagne di attacco.
# ==============================================================================

import os
import datetime
import warnings
import re
import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ElasticsearchWarning
import google.generativeai as genai
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

# --- CONFIGURAZIONE GLOBALE ---
warnings.simplefilter('ignore', (ElasticsearchWarning, UserWarning))
load_dotenv()

ES_HOST = "localhost"
ES_PORT = 64298
ES_INDEX = "logstash-*"
IPS_TO_EXCLUDE = ["10.0.0.5"]  # Aggiungi qui IP interni da escludere

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("Chiave API di Gemini non trovata. Assicurati di aver creato un file .env")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash-latest')

# --- FUNZIONI DI CONNESSIONE E FETCH DATI ---

def get_elasticsearch_client():
    """Crea e restituisce un client Elasticsearch."""
    es_url = f"http://{ES_HOST}:{ES_PORT}"
    print(f"Tentativo di connessione a Elasticsearch su: {es_url}")
    try:
        client = Elasticsearch([es_url], verify_certs=False, ssl_show_warn=False, request_timeout=30)
        if not client.ping():
            raise ConnectionError("client.ping() ha restituito False.")
        print("Connessione a Elasticsearch riuscita.")
        return client
    except Exception as e:
        print(f"Errore durante la connessione a Elasticsearch: {e}")
        return None

def fetch_aggregation_data(es_client):
    """Esegue le query di aggregazione standard su Elasticsearch."""
    query = {
        "size": 0,
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": "now-24h/h", "lt": "now/h"}}}], "must_not": [{"terms": {"src_ip.keyword": IPS_TO_EXCLUDE}}]}},
        "aggs": {
            "top_ips": {"terms": {"field": "src_ip.keyword", "size": 10}},
            "top_countries": {"terms": {"field": "geoip.country_name.keyword", "size": 10}},
            "top_honeypots": {"terms": {"field": "type.keyword", "size": 10}},
            "top_usernames": {"filter": {"exists": {"field": "username.keyword"}}, "aggs": {"usernames": {"terms": {"field": "username.keyword", "size": 10}}}},
            "top_passwords": {"filter": {"exists": {"field": "password.keyword"}}, "aggs": {"passwords": {"terms": {"field": "password.keyword", "size": 10}}}},
        }
    }
    print("Esecuzione query di aggregazione...")
    try:
        return es_client.options(request_timeout=120).search(index=ES_INDEX, body=query).get('aggregations')
    except Exception as e:
        print(f"Errore durante l'esecuzione della query di aggregazione: {e}")
        return None

def fetch_raw_events_for_clustering(es_client, max_events=2000):
    """Scarica eventi grezzi significativi per il clustering delle campagne."""
    query = {
        "size": max_events,
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": "now-24h/h", "lt": "now/h"}}}, {"terms": {"type.keyword": ["Cowrie", "Heralding", "Dionaea"]}}], "must_not": [{"terms": {"src_ip.keyword": IPS_TO_EXCLUDE}}]}},
        "_source": ["src_ip", "geoip.asn", "type", "username", "password", "input"]
    }
    print(f"Esecuzione query per scaricare fino a {max_events} eventi grezzi per il clustering...")
    try:
        return [hit['_source'] for hit in es_client.search(index=ES_INDEX, body=query, scroll='2m')['hits']['hits']]
    except Exception as e:
        print(f"Errore durante il recupero dei dati grezzi: {e}")
        return []

# --- FUNZIONI DI MACHINE LEARNING ---

def preprocess_data_for_clustering(events):
    """Prepara i dati grezzi trasformandoli in un formato numerico per DBSCAN."""
    if not events: return None, None
    print("Inizio pre-processing dei dati per il clustering...")
    df = pd.DataFrame(events)
    expected_cols = {'src_ip': 'N/A', 'geoip.asn': 0, 'type': 'N/A', 'username': 'N/A', 'password': 'N/A', 'input': 'N/A'}
    for col, default_value in expected_cols.items():
        if col not in df.columns:
            print(f"ATTENZIONE: La colonna '{col}' non è stata trovata. Verrà creata con valori di default.")
            df[col] = default_value
    df.fillna(value=expected_cols, inplace=True)
    df['geoip.asn'] = df['geoip.asn'].astype(int)
    df['src_ip_subnet'] = df['src_ip'].str.extract(r'(\d{1,3}\.\d{1,3}\.\d{1,3})').fillna('0.0.0')[0]
    preprocessor = ColumnTransformer(transformers=[('num', StandardScaler(), ['geoip.asn']), ('cat', OneHotEncoder(handle_unknown='ignore'), ['type', 'src_ip_subnet']), ('user_tfidf', TfidfVectorizer(max_features=50), 'username'), ('pass_tfidf', TfidfVectorizer(max_features=50), 'password'), ('input_tfidf', TfidfVectorizer(max_features=100), 'input')], remainder='drop')
    print("Applicazione della pipeline di pre-processing...")
    X_processed = preprocessor.fit_transform(df)
    print(f"Dati trasformati in una matrice di shape: {X_processed.shape}")
    return X_processed, df

def find_attack_campaigns(X_processed):
    """Esegue l'algoritmo DBSCAN per trovare i cluster (campagne)."""
    if X_processed is None or X_processed.shape[0] < 5:
        print("Dati insufficienti per il clustering.")
        return None
    print("Esecuzione di DBSCAN per identificare le campagne...")
    dbscan = DBSCAN(eps=1.2, min_samples=5, metric='euclidean')
    clusters = dbscan.fit_predict(X_processed)
    n_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
    n_noise = list(clusters).count(-1)
    print(f"Clustering completato. Trovate {n_clusters} campagne e {n_noise} eventi di rumore.")
    return clusters

# --- FUNZIONI DI FORMATTAZIONE E PREPARAZIONE DATI ---

def prepare_chart_and_campaign_data(aggs, df_campaigns, clusters):
    """Prepara i dati strutturati per i grafici e le campagne."""
    print("Preparazione dati strutturati per i report...")
    chart_data, campaign_details = {}, []
    if aggs:
        for agg_name in ['top_countries', 'top_honeypots', 'top_usernames', 'top_passwords']:
            path = [agg_name.replace('top_', '')] if agg_name in ['top_usernames', 'top_passwords'] else []
            temp_agg = aggs.get(agg_name, {})
            for key in path: temp_agg = temp_agg.get(key, {})
            buckets = temp_agg.get('buckets', [])
            chart_data[agg_name] = {'labels': [b['key'] for b in buckets], 'data': [b['doc_count'] for b in buckets]}
    if clusters is not None and df_campaigns is not None:
        df_campaigns['cluster'] = clusters
        unique_clusters = sorted([c for c in df_campaigns['cluster'].unique() if c != -1])
        for cluster_id in unique_clusters:
            cluster_df = df_campaigns[df_campaigns['cluster'] == cluster_id]
            campaign_details.append({
                'event_count': len(cluster_df), 'unique_ips': cluster_df['src_ip'].nunique(),
                'top_ips': [f"{ip} ({c})" for ip, c in cluster_df['src_ip'].value_counts().nlargest(3).items()],
                'top_honeypots': [f"{hp} ({c})" for hp, c in cluster_df['type'].value_counts().nlargest(2).items()],
                'top_usernames': [f"{u} ({c})" for u, c in cluster_df[df_campaigns['username'] != 'N/A']['username'].value_counts().nlargest(3).items()],
                'top_passwords': [f"{p} ({c})" for p, c in cluster_df[df_campaigns['password'] != 'N/A']['password'].value_counts().nlargest(3).items()],
                'top_commands': [f"{i} ({c})" for i, c in cluster_df[df_campaigns['input'] != 'N/A']['input'].value_counts().nlargest(3).items()]})
    return chart_data, campaign_details

def format_data_for_llm(aggs, campaign_data_list):
    """Formatta tutti i dati in un singolo blocco di testo per l'LLM."""
    summary_parts = ["**PARTE 1: DATI AGGREGATI GENERALI**"]
    if aggs:
        def append_buckets(title, buckets_data, empty_msg):
            summary_parts.append(f"\n=== {title} ===")
            if buckets_data: [summary_parts.append(f"- {b['key']} ({b['doc_count']} eventi)") for b in buckets_data]
            else: summary_parts.append(f"- {empty_msg}")
        append_buckets("Top 10 Paesi di Origine", aggs.get('top_countries', {}).get('buckets', []), "Nessun paese rilevato.")
        append_buckets("Top 10 Honeypot Colpiti", aggs.get('top_honeypots', {}).get('buckets', []), "Nessun honeypot colpito.")
    
    campaign_parts = ["\n\n**PARTE 2: ANALISI DELLE CAMPAGNE COORDINATE**"]
    if not campaign_data_list:
        campaign_parts.append("Nessuna campagna coordinata significativa è stata identificata.")
    else:
        for i, campaign in enumerate(campaign_data_list):
            campaign_parts.append(f"\n--- Campagna #{i + 1} ---")
            for key, value in campaign.items():
                title = key.replace('_', ' ').title()
                val_str = ', '.join(value) if isinstance(value, list) else str(value)
                campaign_parts.append(f"* {title}: {val_str}")
    
    return "\n".join(summary_parts) + "\n".join(campaign_parts)

# --- FUNZIONI DI GENERAZIONE REPORT ---

def parse_gemini_report(report_text):
    """Estrae le sezioni specifiche dal report Markdown di Gemini."""
    print("Parsing del report di Gemini per estrarre le sezioni HTML...")
    sections_map = {
        'executive_summary': r"\*\*1\. Sintesi Esecutiva.*?\*\*(.*?)(?=\*\*2\.|\Z)",
        'campaign_analysis': r"\*\*2\. Analisi delle Campagne di Attacco.*?\*\*(.*?)(?=\*\*3\.|\Z)",
        'background_noise':  r"\*\*3\. Osservazioni sul Rumore di Fondo.*?\*\*(.*?)(?=\*\*4\.|\Z)",
        'iocs':              r"\*\*4\. Indicatori di Compromissione \(IoC\) Rilevanti.*?\*\*(.*?)(?=\*\*5\.|\Z)",
        'recommendations':   r"\*\*5\. Conclusioni e Raccomandazioni Strategiche.*?\*\*(.*)"
    }
    parsed_sections = {}
    for key, pattern in sections_map.items():
        match = re.search(pattern, report_text, re.DOTALL | re.IGNORECASE)
        content = match.group(1).strip() if match else f"<p>Sezione '{key}' non trovata nel report di Gemini.</p>"
        content = re.sub(r'^\*\*(.*?)\*\*', r'<h4>\1</h4>', content, flags=re.MULTILINE)
        content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
        content = re.sub(r'^\* (.*?)$', r'<li>\1</li>', content, flags=re.MULTILINE)
        content = re.sub(r'(<li>.*?</li>)+', r'<ul>\g<0></ul>', content, flags=re.DOTALL)
        parsed_sections[key] = content
    return parsed_sections

def generate_reports(chart_data, campaign_list, text_report):
    """Orchestra la creazione di entrambi i report: Markdown e HTML."""
    print("Avvio generazione di tutti i report...")
    today_str = datetime.datetime.now().strftime("%Y-%m-%d")

    # 1. Salva il report testuale (Markdown)
    filename_md = f"tpot_report_{today_str}.md"
    with open(filename_md, "w", encoding="utf-8") as f:
        f.write(text_report)
    print(f"Report testuale salvato nel file: {filename_md}")

    # 2. Esegui il parsing del report di Gemini per ottenere le sezioni HTML
    gemini_sections = parse_gemini_report(text_report)

    # 3. Genera il report HTML
    print("Generazione del report HTML...")
    env = Environment(loader=FileSystemLoader('.'))
    try:
        template = env.get_template('template.html')
    except Exception as e:
        print(f"ERRORE: Impossibile trovare 'template.html'. Assicurati che il file sia nella stessa directory. Dettagli: {e}")
        return

    html_context = {
        'report_title': f"T-Pot Intelligence Report - {today_str}",
        'generation_date': datetime.datetime.now().strftime("%d %B %Y, %H:%M:%S"),
        'chart_data': chart_data,
        'gemini_sections': gemini_sections
    }
    rendered_html = template.render(html_context)
    filename_html = f"tpot_report_{today_str}.html"
    with open(filename_html, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print(f"Report HTML salvato nel file: {filename_html}")

def generate_analysis_with_gemini(data_for_llm):
    """Invia i dati a Gemini e restituisce il report testuale completo."""
    if not data_for_llm: return "Dati insufficienti per il report."
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")
    prompt = f"""
Sei un analista di cybersecurity senior. Analizza i dati da un honeypot T-Pot e produci un report esecutivo dettagliato in italiano usando Markdown, seguendo ESATTAMENTE questa struttura, inclusi i numeri e i titoli in grassetto.

{data_for_llm}

**COMPITO - STRUTTURA OBBLIGATORIA:**
**1. Sintesi Esecutiva:** Un paragrafo che riassume i risultati più importanti, focalizzandosi sulle campagne.
**2. Analisi delle Campagne di Attacco:** Per ogni campagna, fornisci un'analisi dettagliata (obiettivo, provenienza, sofisticazione, strumenti).
**3. Osservazioni sul Rumore di Fondo:** Descrivi brevemente il "rumore di fondo" generale.
**4. Indicatori di Compromissione (IoC) Rilevanti:** Estrai una lista pulita degli IoC più importanti.
**5. Conclusioni e Raccomandazioni Strategiche:** Conclusioni e raccomandazioni per il team di sicurezza.
"""
    print("Invio richiesta a Gemini. Attendi...")
    try:
        response = model.generate_content(prompt, request_options={'timeout': 180})
        print("Analisi di Gemini ricevuta.")
        return response.text
    except Exception as e:
        print(f"Errore con l'API di Gemini: {e}")
        return "Impossibile generare l'analisi a causa di un errore API."

# --- ESECUZIONE PRINCIPALE ---

if __name__ == "__main__":
    es_client = get_elasticsearch_client()
    if es_client:
        aggs_data = fetch_aggregation_data(es_client)
        raw_events_data = fetch_raw_events_for_clustering(es_client)
        
        processed_ml_data, original_df = preprocess_data_for_clustering(raw_events_data)
        cluster_labels = find_attack_campaigns(processed_ml_data)
        
        chart_data, campaign_list = prepare_chart_and_campaign_data(aggs_data, original_df, cluster_labels)
        
        data_per_llm = format_data_for_llm(aggs_data, campaign_list)
        
        full_text_report = generate_analysis_with_gemini(data_per_llm)
        
        if "Impossibile generare" not in full_text_report:
            generate_reports(chart_data, campaign_list, full_text_report)
        
        print("\nProcesso completato.")
