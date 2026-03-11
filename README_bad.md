Rôle : Expert en GNN (Graph Neural Networks) et Threat Hunting.

Objectif : Transformer les logs Tetragon fournis (bad.json) en une structure de graphe pour entraîner un modèle à détecter la technique MITRE T1003.008 (Memory Dumping).

Instructions de structuration :

Définition des Nœuds (Nodes) : Chaque processus unique doit devenir un nœud.

Attributs du nœud : binary_name, uid, arguments_count.

Normalisation : Simplifie le chemin du binaire (ex: /usr/bin/gcore -> gcore).

Définition des Liens (Edges) : Crée un lien dirigé entre le parent_binary et le process_binary.

Le lien représente la relation "Parent-Child" (Process Creation).

Nettoyage spécifique à l'attaque :

Identifie les séquences où un binaire suspect (gcore, gdb, pgrep) est enfant d'un interpréteur (sh, python, bash).

Supprime les IDs éphémères (pid, exec_id) mais utilise-les pour maintenir l'intégrité des liens dans le graphe.

Labellisation :

Marque les nœuds impliqués dans le dump mémoire (gcore, gdb) avec le label target: 1 (Anomalie/T1003.008).

Marque les autres avec target: 0.

Format de sortie :

Un dictionnaire JSON avec deux listes : "nodes" (liste d'objets avec attributs) et "links" (liste de paires source-destination).
