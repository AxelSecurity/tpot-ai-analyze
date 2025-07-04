import os
import datetime
import warnings
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ElasticsearchWarning
import google.generativeai as genai
from dotenv import load_dotenv

# Ignoriamo i warning di deprecazione
warnings.simplefilter('ignore', ElasticsearchWarning)

# --- CONFIGURAZIONE ---
load_dotenv()
ES_HOST = "localhost"
ES_PORT = 64298
ES_INDEX = "logstash-*"

# NUOVA CONFIGURAZIONE: Lista degli IP da escludere dall'analisi
# Puoi aggiungere altri IP interni qui se necessario, es. ["10.0.0.5", "192.168.1.1"]
IPS_TO_EXCLUDE = ["10.0.0.5"]

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("Chiave API di Gemini non trovata. Assicurati di aver creato un file .env")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash-latest')

# --- FUNZIONI ---

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

def fetch_data(es_client):
    """Esegue le query su Elasticsearch e aggrega i dati."""
    if not es_client:
        return None
    
    # Query principale che ora esclude gli IP interni
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-24h/h",
                                "lt": "now/h"
                            }
                        }
                    }
                ],
                "must_not": [
                    {
                        "terms": {
                            "src_ip.keyword": IPS_TO_EXCLUDE
                        }
                    }
                ]
            }
        },
        "aggs": {
            "top_ips": {"terms": {"field": "src_ip.keyword", "size": 10}},
            "top_countries": {"terms": {"field": "geoip.country_name.keyword", "size": 10}},
            "top_honeypots": {"terms": {"field": "type.keyword", "size": 10}},
            "top_usernames": {
                "filter": {"bool": {"must": [{"exists": {"field": "username.keyword"}}]}},
                "aggs": {"usernames": {"terms": {"field": "username.keyword", "size": 10}}}
            },
            "top_passwords": {
                "filter": {"bool": {"must": [{"exists": {"field": "password.keyword"}}]}},
                "aggs": {"passwords": {"terms": {"field": "password.keyword", "size": 10}}}
            },
            "top_suricata_alerts": {
                "filter": {"term": {"type.keyword": "Suricata"}},
                "aggs": {"alerts": {"terms": {"field": "alert.signature.keyword", "size": 10}}}
            },
            "wget_curl_commands": {
                "filter": {
                    "bool": {
                        "must": [
                            {"term": {"type.keyword": "Cowrie"}},
                            {"query_string": {"query": "input:(*wget* OR *curl*)"}}
                        ]
                    }
                },
                "aggs": {"commands": {"terms": {"field": "input.keyword", "size": 20}}}
            }
        }
    }
    
    print("Esecuzione query di aggregazione su Elasticsearch (con esclusione IP)...")
    try:
        response = es_client.options(request_timeout=120).search(index=ES_INDEX, body=query)
        return response['aggregations']
    except Exception as e:
        print(f"Errore durante l'esecuzione della query: {e}")
        return None

def format_data_for_llm(aggs):
    """Formatta i dati aggregati in un testo leggibile per l'LLM."""
    if not aggs:
        return "Nessun dato da analizzare."
    
    report_parts = ["Riepilogo Attività Honeypot - Ultime 24 ore:\n"]

    def append_buckets_to_report(title, buckets_data, empty_message):
        report_parts.append(f"\n=== {title} ===")
        if buckets_data:
            for bucket in buckets_data:
                report_parts.append(f"- {bucket['key']} ({bucket['doc_count']} eventi)")
        else:
            report_parts.append(f"- {empty_message}")

    top_ips_buckets = aggs.get('top_ips', {}).get('buckets', [])
    append_buckets_to_report("Top 10 IP Attaccanti", top_ips_buckets, "Nessun IP attaccante rilevato.")
    top_countries_buckets = aggs.get('top_countries', {}).get('buckets', [])
    append_buckets_to_report("Top 10 Paesi di Origine", top_countries_buckets, "Nessun paese di origine rilevato.")
    top_honeypots_buckets = aggs.get('top_honeypots', {}).get('buckets', [])
    append_buckets_to_report("Top 10 Honeypot più Colpiti", top_honeypots_buckets, "Nessun honeypot colpito.")
    top_usernames_buckets = aggs.get('top_usernames', {}).get('usernames', {}).get('buckets', [])
    append_buckets_to_report("Top 10 Username Tentati", top_usernames_buckets, "Nessun username tentato.")
    top_passwords_buckets = aggs.get('top_passwords', {}).get('passwords', {}).get('buckets', [])
    append_buckets_to_report("Top 10 Password Tentate", top_passwords_buckets, "Nessuna password tentata.")
    top_suricata_buckets = aggs.get('top_suricata_alerts', {}).get('alerts', {}).get('buckets', [])
    append_buckets_to_report("Top 10 Allarmi Suricata", top_suricata_buckets, "Nessun allarme Suricata rilevato.")
    wget_curl_buckets = aggs.get('wget_curl_commands', {}).get('commands', {}).get('buckets', [])
    append_buckets_to_report("Comandi di Download Malware (wget/curl)", wget_curl_buckets, "Nessun comando di download rilevato.")
        
    print("Dati aggregati e formattati.")
    return "\n".join(report_parts)

def generate_report_with_gemini(data_summary):
    """Invia i dati a Gemini e genera il report finale."""
    if not data_summary or data_summary == "Nessun dato da analizzare.":
        return "Non sono stati trovati dati sufficienti per generare un report."
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")
    prompt = f"""
Sei un analista di cybersecurity senior con 20 anni di esperienza in threat intelligence e analisi di honeypot. Il tuo compito è analizzare il seguente riepilogo di dati grezzi provenienti da un honeypot T-Pot e produrre un report esecutivo dettagliato per un team di sicurezza.

Il report deve essere in italiano, scritto in modo professionale ma chiaro. Deve identificare le principali tendenze, le campagne di attacco, i vettori più comuni e fornire raccomandazioni o spunti di riflessione. Struttura il report in sezioni chiare usando la formattazione Markdown.

Ecco i dati aggregati delle ultime 24 ore:

{data_summary}

Produci il report seguendo questa struttura:
### Report di Threat Intelligence T-Pot - {today_date} ###

**1. Sintesi Esecutiva (Executive Summary):**
   * Un paragrafo che riassume i risultati più importanti della giornata.

**2. Principali Tendenze e Osservazioni:**
   * Descrivi le tendenze generali. C'è stato un aumento di attacchi da un paese specifico? Un tipo di honeypot è stato più bersagliato?

**3. Analisi Dettagliata degli Attacchi:**
   * **Campagne di Brute-Force e Autenticazione:** Analizza i dati sugli username e le password tentati. Commenta le credenziali usate, gli IP più attivi e gli honeypot bersagliati (es. Cowrie, Wordpot, Heralding).
   * **Attività Post-Exploitation:** Descrivi se sono stati eseguiti comandi sospetti (wget/curl) e da quali IP. Che tipo di malware stavano cercando di installare?
   * **Scansioni e Tentativi di Exploit:** Analizza i dati di Suricata. Che tipo di vulnerabilità stavano cercando?

**4. Indicatori di Compromissione (IoC) Rilevanti:**
   * Fornisci una lista pulita degli IoC più importanti (IP, username, password, URL di malware) emersi oggi.

**5. Conclusioni e Raccomandazioni:**
   * Qual è la conclusione principale? Stiamo vedendo attacchi mirati o rumore di fondo di internet? Ci sono raccomandazioni per il team?
"""
    print("Invio richiesta a Gemini. Attendi...")
    try:
        response = model.generate_content(prompt)
        print("Report ricevuto da Gemini.")
        return response.text
    except Exception as e:
        print(f"Errore durante la comunicazione con l'API di Gemini: {e}")
        return "Impossibile generare il report a causa di un errore API."

# --- ESECUZIONE PRINCIPALE ---

if __name__ == "__main__":
    es_client = get_elasticsearch_client()
    if es_client:
        aggregated_data = fetch_data(es_client)
        if aggregated_data:
            formatted_summary = format_data_for_llm(aggregated_data)
            final_report = generate_report_with_gemini(formatted_summary)
            
            print("\n" + "="*80)
            print("REPORT GENERATO")
            print("="*80 + "\n")
            print(final_report)

            today_str = datetime.datetime.now().strftime("%Y-%m-%d")
            filename = f"tpot_report_{today_str}.md"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(final_report)
            print(f"\nReport salvato nel file: {filename}")
