import os
import json
import warnings
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ElasticsearchWarning

# Ignoriamo i warning di deprecazione
warnings.simplefilter('ignore', ElasticsearchWarning)

# --- CONFIGURAZIONE ---
ES_HOST = "localhost"
ES_PORT = 64298
ES_INDEX = "logstash-*"

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

def discover_all_honeypot_schemas(es_client):
    """Trova tutti i tipi di honeypot e recupera un campione per ciascuno."""
    if not es_client:
        return None

    # 1. Trova tutti i tipi di honeypot unici usando un'aggregazione
    query_types = {
        "size": 0,
        "aggs": {
            "honeypot_types": {
                "terms": {
                    "field": "type.keyword",
                    "size": 50  # Prende fino a 50 tipi diversi, più che sufficiente
                }
            }
        }
    }
    
    print("\nFase 1: Ricerca di tutti i tipi di honeypot attivi...")
    try:
        response = es_client.search(index=ES_INDEX, body=query_types)
        buckets = response.get('aggregations', {}).get('honeypot_types', {}).get('buckets', [])
        if not buckets:
            print("Nessun tipo di honeypot trovato. L'indice potrebbe essere vuoto.")
            return None
        
        honeypot_types = [bucket['key'] for bucket in buckets]
        print(f"Tipi di honeypot trovati: {honeypot_types}")
        
    except Exception as e:
        print(f"Errore durante la ricerca dei tipi di honeypot: {e}")
        return None

    # 2. Per ogni tipo trovato, recupera l'ultimo log di esempio
    sample_logs = {}
    print("\nFase 2: Recupero di un campione per ogni tipo di honeypot...")
    for hp_type in honeypot_types:
        print(f" - Recupero campione per '{hp_type}'...")
        query_sample = {
            "size": 1,
            "query": {
                "term": {
                    "type.keyword": hp_type
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        try:
            response = es_client.search(index=ES_INDEX, body=query_sample)
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                sample_logs[hp_type] = hits[0]['_source']
        except Exception as e:
            print(f"   - Errore nel recuperare il campione per '{hp_type}': {e}")
            
    return sample_logs

# --- ESECUZIONE PRINCIPALE ---

if __name__ == "__main__":
    es_client = get_elasticsearch_client()
    if es_client:
        all_samples = discover_all_honeypot_schemas(es_client)
        
        if all_samples:
            print("\n" + "="*80)
            print("CATALOGO DEGLI SCHEMI DATI PER OGNI HONEYPOT ATTIVO")
            print("="*80 + "\n")
            
            for honeypot_type, log_data in all_samples.items():
                print(f"--- CAMPIONE PER HONEYPOT TIPO: '{honeypot_type}' ---")
                print(json.dumps(log_data, indent=2, ensure_ascii=False))
                print("\n" + "#"*50 + "\n")
        else:
            print("Impossibile generare il catalogo. Nessun dato recuperato.")
