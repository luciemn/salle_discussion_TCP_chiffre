# Chatroom TCP chiffree avec RSA maison (modifiable) pour experimenter des vulnerabilites.

## Fichiers

| Fichier     | Rôle                                      |
| ----------- | ----------------------------------------- |
| `main.py`   | Script unique : RSA + serveur + client    |
| `keys/`     | Export JSON des clés (créé à l'exécution) |
| `README.md` | Documentation                             |

## Librairies requises

Aucune dépendance externe. Bibliothèque standard Python 3 uniquement :

`argparse`, `json`, `math`, `os`, `secrets`, `socket`, `threading`, `datetime`

Python 3.8+ recommandé.

## Lancer

Terminal 1 :

```bash
py -3 main.py server
```

Terminal 2 / 3 :

```bash
py -3 main.py client --name Alice
py -3 main.py client --name Bob
```

## Arguments

| Argument     | Défaut      | Description                |
| ------------ | ----------- | -------------------------- |
| `mode`       | _(requis)_  | `server` ou `client`       |
| `--host`     | `127.0.0.1` | Adresse du serveur         |
| `--port`     | `5555`      | Port TCP                   |
| `--name`     | _(saisie)_  | Nom d'utilisateur (client) |
| `--bits`     | `1024`      | Taille de clé RSA          |
| `--keys-dir` | `keys`      | Dossier d'export JSON      |

## Fonctionnement

1. Serveur et clients génèrent chacun une paire RSA (export `.json`).
2. Handshake : échange des clés publiques + pseudo chiffré.
3. Messages client → serveur chiffrés avec la clé du serveur.
4. Serveur déchiffre et re-chiffre pour chaque client (broadcast).

## Expérimenter

Dans `main.py`, modifier en haut du fichier :

```python
BITS = 1024
E = 65537
```

Ou via `--bits 128` en ligne de commande.

Le bloc RSA est au début de `main.py` : `is_prime`, `keygen`, `enc`, `dec`.

## Export JSON

Fichiers créés dans `keys/` :

```text
keys/keys_<nom>_<horodatage>.json
```

Contient clé publique (`e`, `n`) et privée (`d`, `n`) en hex.
# salle_discussion_TCP_chiffre
