# Chatroom TCP chiffree avec RSA maison (modifiable) pour experimenter des vulnerabilites.
import argparse
import json
import math
import os
import secrets
import socket
import threading
from datetime import datetime


# Parametres RSA a modifier pour les experiences
BITS = 1024   # taille de cle (sujet = 1024). Essayer 64 / 128 pour affaiblir
E = 65537     # exposant public. Essayer 3 pour un e trop petit


def is_prime(n, k=20):
    # Test de primalite de Miller-Rabin (probabiliste).
    # On tire k temoins aleatoires: plus k est grand, plus on est sur.
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False

    # Ecriture de n-1 = 2^r * d  (avec d impair)
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Pour chaque temoin a: on calcule a^d mod n puis on carre
    for _ in range(k):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            # aucun carre n'a donne -1 => probablement compose
            return False
    return True


def gen_prime(bits):
    # Tire des entiers aleatoires de 'bits' bits jusqu'a en trouver un premier.
    # | 1  => force impair
    # | (1 << bits-1)  => force le bit de poids fort (bonne taille)
    while True:
        p = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(p):
            return p


def export_keys(pub, priv, name="anon", bits=None, out_dir="."):
    # Sauvegarde les cles en JSON (demande dans le sujet).
    # n et d sont trop gros pour un int JSON classique => on les met en hex.
    e, n = pub
    d, _ = priv
    bits = bits if bits is not None else n.bit_length()
    os.makedirs(out_dir, exist_ok=True)

    # Nom de fichier unique pour ne pas ecraser les anciennes cles
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "anon"
    path = os.path.join(out_dir, "keys_%s_%s.json" % (safe, stamp))

    data = {
        "name": name,
        "algo": "RSA-textbook",
        "bits": bits,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "public": {"e": e, "n": hex(n)},
        "private": {"d": hex(d), "n": hex(n)},
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def keygen(bits=None, e=None, name="anon", out_dir="."):
    # Generation d'une paire RSA:
    #   1) deux premiers p, q
    #   2) n = p*q ,  phi = (p-1)*(q-1)
    #   3) d = inverse de e modulo phi  (donc e*d = 1 mod phi)
    # Retourne pub=(e,n), priv=(d,n) et le chemin du JSON exporte.
    bits = bits if bits is not None else BITS
    e = e if e is not None else E

    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        # e doit etre premier avec phi, sinon pas d'inverse
        if p != q and math.gcd(e, phi) == 1:
            n = p * q
            d = pow(e, -1, phi)
            break

    pub, priv = (e, n), (d, n)
    path = export_keys(pub, priv, name=name, bits=bits, out_dir=out_dir)
    return pub, priv, path


def enc(text, pub):
    # Chiffrement RSA textbook: c = m^e mod n
    # Pas de padding (OAEP etc.) => volontairement faible / etudiable.
    # Si le message est trop long pour n, on le coupe en plusieurs blocs.
    e, n = pub
    data = text.encode()
    size = (n.bit_length() - 1) // 8   # taille max d'un bloc (m < n)
    out = []
    for i in range(0, len(data), size):
        m = int.from_bytes(data[i:i + size], "big")
        c = pow(m, e, n)
        out.append("%x" % c)            # on envoie le chifre en hexa
    return ",".join(out)


def dec(line, priv):
    # Dechiffrement RSA textbook: m = c^d mod n
    # On reconstruit chaque bloc puis on recolle le texte.
    d, n = priv
    size = (n.bit_length() - 1) // 8
    out = b""
    parts = [h for h in line.split(",") if h]
    for i, h in enumerate(parts):
        c = int(h, 16)
        m = pow(c, d, n)
        if i < len(parts) - 1:
            # blocs intermediaires: taille fixe (garde les octets a 0)
            out += m.to_bytes(size, "big")
        else:
            # dernier bloc: taille exacte du message restant
            length = (m.bit_length() + 7) // 8
            out += m.to_bytes(length or 1, "big")
    return out.decode()


def pub_to_line(pub):
    # Met la cle publique sur une seule ligne pour le reseau: "e n"
    e, n = pub
    return "%d %s" % (e, hex(n))


def line_to_pub(line):
    # Inverse de pub_to_line
    e, n = line.strip().split()
    return int(e), int(n, 16)


def send(sock, line):
    # Envoi d'une ligne texte terminee par \n
    sock.sendall((line + "\n").encode())


def run_server(host, port, bits, keys_dir):
    # Le serveur a sa propre paire de cles.
    # Les clients chiffrent vers lui avec sa cle publique.
    # Lui renvoie vers chaque client avec la cle publique de ce client.
    print("[serveur] generation cle RSA (%d bits)..." % bits)
    pub, priv, path = keygen(bits=bits, name="server", out_dir=keys_dir)
    print("[serveur] cles exportees: %s" % path)

    clients = {}  # socket du client -> sa cle publique

    def broadcast(text, sender=None):
        # Affiche en clair cote serveur, puis renvoie chiffre a chaque client
        print(text)
        morts = []
        for sock, cpub in list(clients.items()):
            try:
                send(sock, enc(text, cpub))
            except OSError:
                # client deja parti / connexion cassee
                morts.append(sock)
        for sock in morts:
            clients.pop(sock, None)

    def handle(cli):
        # Un thread = un client. Deroule:
        #  1) echange des cles publiques
        #  2) reception du pseudo chiffre
        #  3) boucle de messages chiffres
        buf = b""

        def read_line():
            # Lit jusqu'au prochain \n (protocole ligne par ligne)
            nonlocal buf
            while b"\n" not in buf:
                chunk = cli.recv(4096)
                if not chunk:
                    return None   # deconnexion
                buf += chunk
            line, buf = buf.split(b"\n", 1)
            return line.decode()

        # handshake
        line = read_line()
        if line is None:
            cli.close()
            return
        cpub = line_to_pub(line)          # cle publique du client
        send(cli, pub_to_line(pub))       # on lui donne la notre

        line = read_line()
        if line is None:
            cli.close()
            return
        # pseudo chiffre avec notre cle publique => on dechiffre avec priv
        name = dec(line.strip(), priv).strip() or "anon"
        clients[cli] = cpub
        broadcast("* %s est la" % name)

        # messages
        while True:
            line = read_line()
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            # On montre le chifre recu puis le clair apres dechiffrement
            print("  [chiffre] %s" % line[:80], flush=True)
            msg = dec(line, priv)         # m = c^d mod n
            print("  [clair]   %s" % msg, flush=True)
            broadcast("[%s] %s" % (name, msg))

        clients.pop(cli, None)
        broadcast("* %s est parti" % name)
        cli.close()

    # Socket d'ecoute TCP
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    print("[serveur] ecoute sur %s:%d" % (host, port))

    # Chaque nouvelle connexion => un thread handle()
    while True:
        cli, addr = srv.accept()
        print("[serveur] connexion de %s:%d" % addr)
        threading.Thread(target=handle, args=(cli,), daemon=True).start()


def run_client(host, port, name, bits, keys_dir):
    # Chaque utilisateur a son nom + sa propre paire de cles.
    if not name:
        name = input("Nom d'utilisateur: ").strip() or "anon"

    print("[client] generation cle RSA (%d bits) pour %s..." % (bits, name), flush=True)
    pub, priv, path = keygen(bits=bits, name=name, out_dir=keys_dir)
    print("[client] cles exportees: %s" % path, flush=True)

    s = socket.create_connection((host, port))
    buf = b""

    def read_line():
        # Meme protocole ligne par ligne que le serveur
        nonlocal buf
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return None
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        return line.decode()

    # Handshake: j'envoie ma pub, je recois celle du serveur, j'envoie mon nom
    send(s, pub_to_line(pub))
    spub = line_to_pub(read_line())       # cle publique du serveur
    send(s, enc(name, spub))              # pseudo chiffre pour le serveur
    print("[client] connecte en tant que %s" % name, flush=True)

    def recv():
        # Thread a part: affiche ce qui arrive (dechiffre avec NOTRE cle privee)
        while True:
            line = read_line()
            if line is None:
                print("[client] deconnecte", flush=True)
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = dec(line, priv)
            except Exception as err:
                print("[client] erreur dec: %s" % err, flush=True)
                continue
            # flush=True important sous Git Bash sinon rien ne s'affiche
            print(msg, flush=True)

    threading.Thread(target=recv, daemon=True).start()

    # Boucle d'envoi: on chiffre avec la cle publique du serveur
    while True:
        msg = input()
        if msg:
            send(s, enc(msg, spub))


p = argparse.ArgumentParser(description="Chatroom TCP + RSA maison")
p.add_argument("mode", choices=["server", "client"],
               help="lancer le serveur ou un client")
p.add_argument("--host", default="127.0.0.1", help="adresse du serveur")
p.add_argument("--port", type=int, default=5555, help="port TCP")
p.add_argument("--name", default="", help="nom d'utilisateur (client)")
p.add_argument("--bits", type=int, default=BITS, help="taille de cle RSA")
p.add_argument("--keys-dir", default="keys", help="dossier d'export JSON")
args = p.parse_args()
os.makedirs(args.keys_dir, exist_ok=True)

if args.mode == "server":
    run_server(args.host, args.port, args.bits, args.keys_dir)
else:
    run_client(args.host, args.port, args.name, args.bits, args.keys_dir)
