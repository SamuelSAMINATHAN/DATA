#!/usr/bin/env python3
"""
Script pour nettoyer et transformer les logs Tetragon (legit.json)
pour l'entraînement d'un modèle Autoencoder (détection d'anomalies).
"""

import json
import csv
from pathlib import Path
from os.path import basename

def normalize_binary_name(binary_path):
    """Extrait le nom du binaire du chemin complet."""
    if binary_path.startswith('['):
        # Processus du kernel
        return binary_path
    return basename(binary_path)

def flatten_legit_record(event):
    """
    Aplati un enregistrement d'événement Tetragon.
    Retourne None si l'événement n'est pas process_exec ou process_exit.
    """
    
    # Déterminer le type d'événement
    event_type = None
    process_data = None
    parent_data = None
    
    if 'process_exec' in event:
        event_type = 0  # exec
        process_data = event['process_exec']['process']
        parent_data = event['process_exec']['parent']
    elif 'process_exit' in event:
        event_type = 1  # exit
        process_data = event['process_exit']['process']
        parent_data = event['process_exit']['parent']
    else:
        return None
    
    if not process_data or not parent_data:
        return None
    
    # Extraire et transformer les champs
    record = {
        'event_type': event_type,
        'proc_bin': normalize_binary_name(process_data['binary']),
        'proc_args': process_data.get('arguments', '') or 'none',
        'proc_uid': process_data['uid'],
        'parent_bin': normalize_binary_name(parent_data['binary']),
        'proc_flags': process_data.get('flags', '')
    }
    
    # Remplacer arguments vide par "none"
    if not record['proc_args'] or record['proc_args'].strip() == '':
        record['proc_args'] = 'none'
    
    return record

def process_legit_json_csv(input_file, output_file):
    """Transforme legit.json en CSV pour Autoencoder."""
    
    records = []
    
    try:
        with open(input_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Erreur JSON ligne {line_num}: {e}")
                    continue
                
                flattened = flatten_legit_record(event)
                if flattened:
                    records.append(flattened)
        
        # Écrire en CSV
        if records:
            fieldnames = ['event_type', 'proc_bin', 'proc_args', 'proc_uid', 'parent_bin', 'proc_flags']
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(records)
            
            print(f"✓ CSV créé: {output_file}")
            print(f"  - Lignes: {len(records)}")
        else:
            print("⚠ Aucun enregistrement valide trouvé")
        
    except Exception as e:
        print(f"✗ Erreur: {e}")

def process_legit_json_nested(input_file, output_file):
    """Transforme legit.json en JSON structuré pour Autoencoder."""
    
    records = []
    
    try:
        with open(input_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Erreur JSON ligne {line_num}: {e}")
                    continue
                
                flattened = flatten_legit_record(event)
                if flattened:
                    records.append(flattened)
        
        # Écrire en JSON
        if records:
            output_data = {
                'metadata': {
                    'total_records': len(records),
                    'columns': ['event_type', 'proc_bin', 'proc_args', 'proc_uid', 'parent_bin', 'proc_flags']
                },
                'data': records
            }
            
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"✓ JSON créé: {output_file}")
            print(f"  - Lignes: {len(records)}")
        else:
            print("⚠ Aucun enregistrement valide trouvé")
        
    except Exception as e:
        print(f"✗ Erreur: {e}")

if __name__ == '__main__':
    input_path = Path(__file__).parent / 'raw_data' / 'legit.json'
    csv_output_path = Path(__file__).parent / 'legit_autoencoder.csv'
    json_output_path = Path(__file__).parent / 'legit_autoencoder.json'
    
    print("Traitement de legit.json...")
    print()
    
    # Créer les deux formats
    print("1. Format CSV:")
    process_legit_json_csv(input_path, csv_output_path)
    print()
    
    print("2. Format JSON:")
    process_legit_json_nested(input_path, json_output_path)
