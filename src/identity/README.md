## Installation Identity

(normalement `./install.sh` fait tout, mais sinon à la main voici ce qu'il
se passe)


`cargo install --path .` dans le dossier `identity` pour build le binaire dans
`~/.cargo/bin/identity` je crois

(Il faut que `identity` soit accessible depuis la commandline pour les
serveurs web idéalement, donc ajouter `~/.cargo/bin/identity` dans le PATH
somehow)

## Custom protocol

Pour register le protocole `identity://`,
il faut rajouter un fichier
`~/.local/share/applications/identity-protocol.desktop`
avec comme contenu

```
[Desktop Entry]
Name=Identity Prover
Exec=/home/username/.cargo/bin/identity %u
Type=Application
Terminal=true
MimeType=x-scheme-handler/identity;
```
(en remplaçant `username` par la bonne valeur)

Puis mettre à jour avec les commandes suivantes :

```sh
xdg-mime default identity-protocol.desktop x-scheme-handler/identity
update-desktop-database ~/.local/share/applications
```

## Requirements
Il faut juste le paquet `zenity` pour avoir le prompt je crois


## Usage

Mettre votre fichier d'identité `identity.json` dans `~/.identity`

Puis, par exemple :
```
xdg-open "identity://verify?origin=https://example.com&dob_before=726632&license=2"
```

Options de vérification disponibles :
- `req_fname`: Option<String> (prénom = x)
- `req_lname`: Option<String> (nom de famille = x)
- `dob_before`: Option<u64> (age > x)
- `dob_after`: Option<u64> (age < x)
- `dob_equal`: Option<u64> (age = x)
- `req_license`: Option<u64> (license = x)



