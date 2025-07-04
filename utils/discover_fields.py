import os
import json
import warnings
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ElasticsearchWarning

# Ignoriamo i warning di deprecazione che potrebbero apparire
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
        client = Elasticsearch(
            [es_url],
            verify_certs=False,
            ssl_show_warn=False,
            request_timeout=30
        )
        if not client.ping():
            raise ConnectionError("client.ping() ha restituito False.")
        print("Connessione a Elasticsearch riuscita.")
        return client
    except Exception as e:
        print(f"Errore durante la connessione a Elasticsearch: {e}")
        return None

def fetch_latest_logs(es_client, num_logs=5):
    """Recupera un numero specificato degli ultimi log."""
    if not es_client:
        return None
    
    # Query per recuperare gli ultimi N log, ordinati per timestamp decrescente
    query = {
        "size": num_logs,
        "query": {
            "match_all": {} # Prende tutto
        },
        "sort": [
            {"@timestamp": {"order": "desc"}} # Ordina dal più recente al più vecchio
        ]
    }
    
    print(f"Recupero degli ultimi {num_logs} log da Elasticsearch...")
    try:
        response = es_client.search(index=ES_INDEX, body=query)
        # Estraiamo solo la parte '_source' di ogni documento, che contiene i dati
        return [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        print(f"Errore durante l'esecuzione della query: {e}")
        return None

# --- ESECUZIONE PRINCIPALE ---

if __name__ == "__main__":
    es_client = get_elasticsearch_client()
    if es_client:
        latest_logs = fetch_latest_logs(es_client, num_logs=5)
        
        if latest_logs:
            print("\n" + "="*80)
            print("ULTIMI 5 LOG RILEVATI - ESEMPIO DI STRUTTURA DATI")
            print("="*80 + "\n")
            
            # Stampa ogni log come un JSON formattato in modo leggibile
            for i, log in enumerate(latest_logs):
                print(f"--- LOG ESEMPIO #{i+1} ---")
                # usiamo json.dumps per un "pretty print"
                print(json.dumps(log, indent=2))
                print("\n" + "-"*30 + "\n")
        else:
            print("Nessun log trovato. Assicurati che T-Pot stia raccogliendo dati.")
