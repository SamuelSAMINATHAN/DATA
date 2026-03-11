# Scripts de Traitement des Logs Tetragon

Ce répertoire contient deux scripts Python pour traiter et transformer les logs Tetragon pour deux cas d'usage différents.

## 📊 Script 1: `process_bad_gnn.py` - Graphe GNN pour les Anomalies

### Objectif
Transformer les logs malveillants (`bad.json`) en structure de graphe pour entraîner un modèle GNN (Graph Neural Network) capable de détecter la technique MITRE **T1003.008 (Memory Dumping)**.

### Fonctionnalités
- **Création de nœuds** : Chaque processus unique devient un nœud avec:
  - `binary_name` : Nom du binaire normalisé (ex: `/usr/bin/gcore` → `gcore`)
  - `uid` : Identifiant utilisateur
  - `arguments_count` : Nombre d'arguments du processus
  
- **Création de liens** : Relations parent-child entre processus

- **Détection d'anomalies** : Identifie les séquences d'attaque où:
  - Un binaire suspect (`gcore`, `gdb`, `pgrep`) 
  - Est exécuté par un interpréteur (`sh`, `bash`, `python`, `python3`)
  - Ces nœuds sont marqués avec `target: 1` (anomalie)

- **Labellisation** :
  - `target: 1` → Nœud impliqué dans une attaque (anomalie)
  - `target: 0` → Nœud normal

### Format de Sortie
Fichier JSON: `bad_graph_gnn.json`
```json
{
  "nodes": [
    {
      "binary_name": "sh",
      "uid": 1000,
      "arguments_count": 28,
      "target": 1
    }
  ],
  "links": [
    {
      "source": {"binary_name": "python3", "uid": 1000},
      "target": {"binary_name": "sh", "uid": 1000}
    }
  ],
  "attack_count": 5
}
```

### Utilisation
```bash
python process_bad_gnn.py
```

**Résultats:**
- Nœuds identifiés: 35
- Liens créés: 33
- Anomalies détectées: 5

---

## 📈 Script 2: `process_legit_autoencoder.py` - Données pour Autoencoder

### Objectif
Nettoyer et transformer les logs légitimes (`legit.json`) en format approprié pour entraîner un **Autoencoder** (détection d'anomalies).

### Transformation des Données

#### Extraction
- Identifie le type d'événement:
  - `event_type: 0` → Process execution (`process_exec`)
  - `event_type: 1` → Process exit (`process_exit`)

#### Aplatissement (Flattening)
Fields conservés et renommés:
- `process.binary` → `proc_bin` (nom du binaire uniquement)
- `process.arguments` → `proc_args` (remplacé par "none" si vide)
- `process.uid` → `proc_uid`
- `parent.binary` → `parent_bin`
- `process.flags` → `proc_flags`

#### Suppression
Les champs suivants sont supprimés:
- `pid`, `tid`, `exec_id`, `node_name`, `time`

#### Normalisation
- Chemins binaires simplifiés: `/usr/libexec/tracker-extract-3` → `tracker-extract-3`
- Arguments vides remplacés par `"none"`

### Formats de Sortie

#### 1. CSV: `legit_autoencoder.csv`
```csv
event_type,proc_bin,proc_args,proc_uid,parent_bin,proc_flags
1,tracker-extract-3,--socket-fd 3,1000,tracker-miner-fs-3,execve clone
0,tracker-extract-3,--socket-fd 3,1000,tracker-miner-fs-3,execve clone
1,[kworker/0:1H-kblockd],none,0,[kthreadd],procFS
```

#### 2. JSON: `legit_autoencoder.json`
```json
{
  "metadata": {
    "total_records": 416,
    "columns": ["event_type", "proc_bin", "proc_args", "proc_uid", "parent_bin", "proc_flags"]
  },
  "data": [
    {
      "event_type": 1,
      "proc_bin": "tracker-extract-3",
      "proc_args": "--socket-fd 3",
      "proc_uid": 1000,
      "parent_bin": "tracker-miner-fs-3",
      "proc_flags": "execve clone"
    }
  ]
}
```

### Utilisation
```bash
python process_legit_autoencoder.py
```

**Résultats:**
- Enregistrements traités: 416
- Format CSV: `legit_autoencoder.csv`
- Format JSON: `legit_autoencoder.json`

---

## 📁 Structure des Fichiers

```
DATA-main/
├── raw_data/
│   ├── bad.json          # Logs malveillants
│   └── legit.json        # Logs légitimes
├── process_bad_gnn.py          # Script GNN
├── process_legit_autoencoder.py # Script Autoencoder
├── bad_graph_gnn.json          # Output GNN (35 nœuds, 33 liens)
├── legit_autoencoder.csv       # Output CSV (416 lignes)
├── legit_autoencoder.json      # Output JSON (416 lignes)
├── README_bad.md               # Spécifications GNN
├── README_legit.md             # Spécifications Autoencoder
└── README.md                   # Ce fichier
```

---

## 🔍 Exemple d'Analyse

### Bad.json - Attaque détectée
La séquence malveillante identifiée:
```
python3 (uid: 1000)
  └─> sh (uid: 1000)  [ANOMALIE]
       ├─> pgrep (uid: 1000)  [ANOMALIE - outil de dump]
       └─> gcore (uid: 1000)  [ANOMALIE - outil de dump]
```

Ces nœuds sont marqués avec `target: 1`.

### Legit.json - Comportement normal
```
tracker-miner-fs-3 (uid: 1000)
  └─> tracker-extract-3 (uid: 1000)
```

Format plat:
- event_type: 0 (exec) ou 1 (exit)
- proc_bin: tracker-extract-3
- proc_args: --socket-fd 3
- etc.

---

## ⚙️ Requirements
- Python 3.6+
- Modules standard: `json`, `csv`, `pathlib`

## 🚀 Exécution

```bash
# Transformer bad.json en graphe GNN
python process_bad_gnn.py

# Transformer legit.json en données Autoencoder
python process_legit_autoencoder.py
```

Tous les fichiers de sortie seront créés dans le répertoire courant.

---

## 📝 Notes

- **GNN**: Utilisé pour détecter les relations parent-child complexes et identifier les chaînes d'attaquesmémoire.
- **Autoencoder**: Utilisé pour détecter les anomalies en apprenant les patterns de comportement normal.

