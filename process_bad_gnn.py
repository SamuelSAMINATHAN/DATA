#!/usr/bin/env python3
"""
Script pour transformer les logs Tetragon (bad.json) en graphe GNN.
Détecte les attaques de type T1003.008 (Memory Dumping).
"""

import json
from pathlib import Path
from os.path import basename
from collections import defaultdict

def normalize_binary(binary_path):
    """Extrait le nom du binaire du chemin complet."""
    if binary_path.startswith('['):
        # Processus du kernel
        return binary_path
    return basename(binary_path)

def is_attack_binary(binary_name):
    """Vérifie si le binaire est suspect pour une attaque de dump mémoire."""
    attack_binaries = {'gcore', 'gdb', 'pgrep'}
    return normalize_binary(binary_name) in attack_binaries

def is_interpreter(binary_name):
    """Vérifie si le binaire est un interpréteur."""
    interpreters = {'sh', 'bash', 'python', 'python3', 'perl', 'ruby'}
    return normalize_binary(binary_name) in interpreters

def process_bad_json(input_file, output_file):
    """Transforme bad.json en structure GNN avec détection d'anomalies."""
    
    nodes_dict = {}  # unique nodes by (binary_name, uid)
    edges_set = set()  # unique edges
    edge_details = {}  # details about edges
    attack_nodes = set()  # nodes impliqués dans une attaque
    
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
                
                # Extraire process et parent
                process = None
                parent = None
                
                if 'process_exec' in event:
                    process = event['process_exec']['process']
                    parent = event['process_exec']['parent']
                elif 'process_exit' in event:
                    process = event['process_exit']['process']
                    parent = event['process_exit']['parent']
                elif 'process_kprobe' in event:
                    process = event['process_kprobe']['process']
                    parent = event['process_kprobe']['parent']
                else:
                    continue
                
                if not process or not parent:
                    continue
                
                # Créer nœuds
                proc_binary = normalize_binary(process['binary'])
                parent_binary = normalize_binary(parent['binary'])
                proc_uid = process['uid']
                parent_uid = parent['uid']
                
                # Compter les arguments
                proc_args = process.get('arguments', '')
                proc_args_count = len(proc_args.split()) if proc_args else 0
                
                parent_args = parent.get('arguments', '')
                parent_args_count = len(parent_args.split()) if parent_args else 0
                
                # Clés uniques pour les nœuds
                proc_key = (proc_binary, proc_uid)
                parent_key = (parent_binary, parent_uid)
                
                # Ajouter les nœuds
                if proc_key not in nodes_dict:
                    nodes_dict[proc_key] = {
                        'binary_name': proc_binary,
                        'uid': proc_uid,
                        'arguments_count': proc_args_count
                    }
                
                if parent_key not in nodes_dict:
                    nodes_dict[parent_key] = {
                        'binary_name': parent_binary,
                        'uid': parent_uid,
                        'arguments_count': parent_args_count
                    }
                
                # Créer lien parent -> child
                edge = (parent_key, proc_key)
                if edge not in edge_details:
                    edges_set.add(edge)
                    edge_details[edge] = {
                        'parent_binary': parent_binary,
                        'child_binary': proc_binary,
                        'parent_uid': parent_uid,
                        'child_uid': proc_uid
                    }
                
                # Détecter les attaques : suspect_binary enfant d'un interpréteur
                if is_attack_binary(proc_binary) and is_interpreter(parent_binary):
                    attack_nodes.add(proc_key)
                    attack_nodes.add(parent_key)
        
        # Ajouter les labels (target)
        nodes_list = []
        for (binary, uid), attrs in nodes_dict.items():
            node = attrs.copy()
            node['target'] = 1 if (binary, uid) in attack_nodes else 0
            nodes_list.append(node)
        
        # Créer les liens au format [source, destination]
        links_list = []
        for (parent_key, child_key), _ in edge_details.items():
            parent_binary, parent_uid = parent_key
            child_binary, child_uid = child_key
            links_list.append({
                'source': {'binary_name': parent_binary, 'uid': parent_uid},
                'target': {'binary_name': child_binary, 'uid': child_uid}
            })
        
        # Output
        output_data = {
            'nodes': nodes_list,
            'links': links_list,
            'attack_count': sum(1 for n in nodes_list if n['target'] == 1)
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"✓ GNN Graph créé: {output_file}")
        print(f"  - Nœuds: {len(nodes_list)}")
        print(f"  - Liens: {len(links_list)}")
        print(f"  - Nœuds anomalies: {output_data['attack_count']}")
        
    except Exception as e:
        print(f"✗ Erreur: {e}")

if __name__ == '__main__':
    input_path = Path(__file__).parent / 'raw_data' / 'bad.json'
    output_path = Path(__file__).parent / 'bad_graph_gnn.json'
    
    process_bad_json(input_path, output_path)
