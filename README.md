# ING3-Hardening
hardening d'un système GNU/Linux (debian12) en respectant les normes M.I de `ANSSI v2 2022`
- **Nom** : Rapport de durcissement Linux - debian12
- **Auteur** : Adrien MACHNIK [@Drien95]
- **Date** : 28/11/2024
- **Version** : 1.0
- **Documents** : [fr_np_linux_configuration-v2.0](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux)

### R28 | Partitionnement type

Création des partitions:


| Point de montage | Options                                | Taille |
| ---------------- | -------------------------------------- | ------ |
| /boot            | nosuid,nodev,noexec (noauto optionnel) | 512Mb  |
| /boot/efi        | Mode EFI                               | 512Mb  |
Mode LVM

| Point de montage | Options                             | Taille |
| ---------------- | ----------------------------------- | ------ |
| /                | non mentionné                       | 5Gb    |
| /opt             | nosuid,nodev (ro optionnel)         | 1Gb    |
| /tmp             | nosuid,nodev,_noexec*_              | 512Mb  |
| /srv             | nosuid,nodev (noexec,ro optionnels) | 512Mb  |
| /home            | nosuid,nodev,noexec                 | 128Mb  |
| /proc            | hidepid=2                           | 512Mb  |
| /usr             | nodev                               | 8Gb    |
| /var             | nosuid,nodev,_noexec*_              | 2Gb    |
| /var/log         | nosuid,nodev,noexec                 | 2Gb    |
| /var/tmp         | nosuid,nodev,noexec                 | 512Mb  |
Désactiver le mode miroir pour éviter les DL de paquets depuis internet !

### R5 | Configurer un mot de passe pour le chargeur de démarrage

génération du mot de passe : 
`grub-mkpasswd-pbkdf2`

```
sudo nano /etc/grub.d/40_custom
set superusers="admin" 
password_pbkdf2 admin grub.pbkdf2.sha512.10000.XXXXX
```

### R8 | Paramétrer les options de configuration de la mémoire

```
sudo nano /etc/default/grub
```

On rajoute à `GRUB_CMDLINE_LINUX` tous ce qui est listé ci-dessous
```
GRUB_CMDLINE_LINUX="l1tf=full,force page_poison=on pti=on slab_nomerge=yes slub_debug=FZP spec_store_bypass_disable=seccomp spectre_v2=on mds=full,nosmt mce=0 page_alloc.shuffle=1 rng_core.default_quality=500"
```

Puis on update

```
sudo update grub
```


### R9 | Paramétrer les options de configuration du noyau

Dans ce fichier `sudo nano /etc/sysctl.conf` ajouter les commandes ci-dessous :

```
# Restreint l'accès au buffer dmesg
kernel.dmesg_restrict=1

# Cache les adresses noyau dans /proc et autres interfaces
kernel.kptr_restrict=2

# Définit l'espace d'identifiants de processus supporté
kernel.pid_max=65536

# Restreint l'utilisation du sous-système perf
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=2

# Active l'ASLR
kernel.randomize_va_space=2

# Désactive les touches magiques (Magic System Request Key)
kernel.sysrq=0

# Restreint l'usage du BPF noyau aux utilisateurs privilégiés
kernel.unprivileged_bpf_disabled=1

# Déclenche un arrêt complet du système en cas de problème noyau
kernel.panic_on_oops=1

```

Puis on applique les changements
```
 sudo sysctl -p
```


### R11 | Activer et configurer le LSM Yama

Ajouter dans le fichier `sudo nano /etc/default/grub` :

```
GRUB_CMDLINE_LINUX="security=yama"
```
Suite à ce que l'on a déjà fait en R8

Puis on update 
```
sudo update-grub
```

On controle ensuite les persmissions d'accès à `ptrace`

```
sudo nano /etc/sysctl.conf
```

```
# Restriction de l'usage de ptrace
kernel.yama.ptrace_scope=1
```
Suite à ce qu'on a fait en R9

### R12 | Paramétrer les options de configuration du réseau IPv4

Configuration dans `/etc/sysctl.conf`

```
# Sécurise le JIT noyau
net.core.bpf_jit_harden=2

# Désactive le routage entre interfaces
net.ipv4.ip_forward=0

# Rejette les paquets 127/8 venant de l'extérieur
net.ipv4.conf.all.accept_local=0

# Désactive les paquets ICMP redirect (protection contre le détournement de trafic)
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

# Rejette le source routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

# Restreint les réponses ARP globales
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.all.arp_ignore=2

# Bloque les paquets utilisant l'adresse de la boucle locale
net.ipv4.conf.all.route_localnet=0

# Ignore les ARP gratuits (graceful failover)
net.ipv4.conf.all.drop_gratuitous_arp=1

# Filtrage des paquets avec vérification stricte
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# Désactive l'envoi d'ICMP redirects (non nécessaire pour un hôte terminal)
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0

# Ignore les réponses ICMP incorrectes
net.ipv4.icmp_ignore_bogus_error_responses=1

# Augmente la plage des ports éphémères
net.ipv4.ip_local_port_range=32768 65535

# Protection contre les attaques SYN flood
net.ipv4.tcp_syncookies=1

# RFC 1337 - protection contre TIME_WAIT Assassination
net.ipv4.tcp_rfc1337=1
```

### R13 | Désactiver le plan IPv6

#### Sysctl.conf

Rajouter dans `/etc/sysctl.conf`
```
net.ipv6.conf.default.disable_ipv6=1 
net.ipv6.conf.all.disable_ipv6=1
```

#### Grub
Rajouter dans `/etc/default/grub`
```
GRUB_CMDLINE_LINUX=" ipv6.disable=1"
```
Puis
```
sudo update-grub
```

Après examination du ip a on peut voir qu'il n'y a plus de inet6 donc plus d'ipv6

### R14 | Paramétrer les options de configuration des systèmes de fichiers

Dans `/etc/sysctl.conf` rajouter encore une fois

```bash
# Désactive la création de coredump pour les exécutables setuid 
# Notez qu'il est possible de désactiver tous les coredumps avec la 
# configuration CONFIG_COREDUMP=n 
fs.suid_dumpable = 0 
# Disponible à partir de la version 4.19 du noyau Linux, permet d'interdire 
# l'ouverture des FIFOS et des fichiers "réguliers" qui ne sont pas la propriété 
# de l'utilisateur dans les dossiers sticky en écriture pour tout le monde. fs.protected_fifos=2 fs.protected_regular=2 
# Restreint la création de liens symboliques à des fichiers dont l'utilisateur 
# est propriétaire. Cette option fait partie des mécanismes de prévention contre 
# les vulnérabilités de la famille Time of Check- Time of Use (Time of Check
# Time of Use) 
fs.protected_symlinks=1 
# Restreint la création de liens durs à des fichiers dont l'utilisateur est 
# propriétaire. Ce sysctl fait partie des mécanismes de prévention contre les 
# vulnérabilités Time of Check- Time of Use, mais aussi contre la possibilité de 
# conserver des accès à des fichiers obsolètes 
fs.protected_hardinks=1
```

Puis on applique les changements
```bash
 sudo sysctl -p
 ```

### R30 | Désactiver les comptes utilisateur inutilisés

C'est OK

### R31 | Utiliser des mots de passe robustes
**`/etc/security/pwquality.conf`** :

```bash
minlen = 12 
minclass = 4
maxrepeat = 3
```

Dans `/etc/login.defs`
```
PASS_MAX_DAYS 90 
PASS_MIN_DAYS 0 
PASS_MIN_LEN 12 
PASS_WARN_AGE 7
```
### R32 | Éxpirer les sessions utilisateur locales

Dans ` /etc/profile` rajouter à la fin
```bash
# Déconnection pour inactivité au bout de 5 mn 
TMOUT=300 readonly 
TMOUT export TMOUT
```
Ajout de l'expiration des sessions inactive (600 secondes), en ajoutant le fichier **/etc/profile.d/autologout.sh** avec les permissions **0644**

```bash
TMOUT=600 
readonly TMOUT 
export TMOUT 
```

```
$ sudo nano /etc/profile.d/autologout.sh 
# sudo chmod 0644 /etc/profile.d/autologout.sh
```
### R33 | Assurerl'imputabilité des actions d'administration

#### Lister les utilisateurs avec un shell interactif

`awk -F: '/bash$/{print $1}' /etc/passwd`

```bash
root
admloc
```
#### Vérifier les comptes sans mot de passe

`awk -F: '($2 == "") {print $1}' /etc/shadow`

```

```
#### Vérrouillage d'un compte

```bash
# Verrouillage d'un compte 
usermod-L-e 1 {user} 
# Désactivation du shell de login 
usermod-s /bin/false {user}
```

| **Caractéristique**         | **`/usr/sbin/nologin`**                               | **`/bin/false`**         |
| --------------------------- | ----------------------------------------------------- | ------------------------ |
| **Message à l'utilisateur** | `/etc/nologin.txt`                                    | Non                      |
| **Action**                  | Déconnecte après message                              | Déconnecte immédiatement |
| **Raison**                  | comptes système nécessaires à l'exécution de services | Vérouillage d'un compte  |
#### Listing des users

| Users            | **`/usr/sbin/nologin`** | **`/bin/false`** |
| ---------------- | ----------------------- | ---------------- |
| root             |                         | X                |
| daemon           | X                       |                  |
| bin              | X                       |                  |
| sys              | X                       |                  |
| sync             | X                       |                  |
| games            | X                       |                  |
| man              | X                       |                  |
| lp               | X                       |                  |
| mail             | X                       |                  |
| news             | X                       |                  |
| uucp             | X                       |                  |
| proxy            | X                       |                  |
| www-data         | X                       |                  |
| backup           | X                       |                  |
| list             | X                       |                  |
| irc              | X                       |                  |
| _apt_            | X                       |                  |
| nobody           |                         | X                |
| systemd-network  | X                       |                  |
| systemd-timesync | X                       |                  |
| messagebus       | X                       |                  |
| sshd             | X                       |                  |
| admloc           |                         |                  |
| nginx            |                         | X                |
| mysql            |                         | X                |
| TEST             |                         | X                |

#### Journalisation de la création de tout processus

MAJ du source-list apt avec les paquets debian et debian-security

```bash
sudo apt install auditd audispd-plugins
```
J'édite ensuite le fichier des règles `sudoedit /etc/audit/audit.rules` et je rajoute :
```bash
-a exit,always-F arch=b64-S execve,execveat
-a exit,always-F arch=b32-S execve,execveat
```

## Comptes de service
### R34 | Désactiver les comptes de service

#### Listing des comptes de services

`awk -F: '$3 < 1000 {print $1}' /etc/passwd`

| Services         |
| ---------------- |
| root             |
| daemon           |
| bin              |
| sys              |
| sync             |
| games            |
| man              |
| lp               |
| mail             |
| news             |
| uucp             |
| proxy            |
| www-data         |
| backup           |
| list             |
| irc              |
| _apt_            |
| nobody           |
| systemd-network  |
| systemd-timesync |
| messagebus       |
| sshd             |
| admloc           |
| nginx            |
| mysql            |

Désactivation de `nobody`

### R35 | Utiliser des comptes de service uniques et exclusifs

Pour nginx:

```bash
sudo useradd -r -s /bin/false nginx
```
Pour mysql :
```bash
sudo useradd -r -s /bin/false mysql
```
Création de compte systeme sans shell de connexion

### R38 | Créer un groupe dédié à l'usage de sudo

Création d'un nouveau compte administrateur avec le groupe sudo

```bash
useradd -m -G sudo TEST
passwd test
su test
chsh -s $(which bash)
```
### R39 |  Modifier les directives de configuration sudo

Ajouter à `/etc/sudoers`
```bash
Defaults noexec
Defaults requiretty
Defaults use_pty
Defaults umask=0077
Defaults ignore_dot
Defaults env_reset
Defaults:%sudo !noexec
```
#### J'autorise le groupe sudo à utiliser sudo

`%sudo ALL=(ALL:ALL) ALL`
#### Rajout d'un logfile

```bash
Defaults logfile="/var/log/sudo.log"
```
### R41 |Limiter l'utilisation de commandes nécessitant la directive EXEC

C'est OK

### R43 | Préciser les arguments dans les spécifications sudo

C'est OK

### R42 | Bannir les négations dans les spécifications sudo

C'est OK

### R44 | Éditer les fichiers de manière sécurisée avec sudo

`export EDITOR=/bin/nano`

Pour chaque utilisateur, le limiter à nano.
### R50 | Restreindre les droits d'accès aux fichiers et aux répertoires sensibles

Comme le root est désactivé, restreindre à admloc pour le moment les droits d'accès.

Information :
Le schéma d’analyse des fichiers ou répertoires sensibles est le suivant : 
1. les fichiers ou répertoires sensibles système doivent avoir comme propriétaire root afin d’éviter tout changement de droit par un utilisateur non privilégié; 
2. les fichiers ou répertoires sensibles accessibles à un utilisateur différent de root (par exemple, la base des mots de passe d’un serveur Web) doivent avoir comme propriétaire cet utilisateur (par exemple, l’utilisateur associé au serveur Web) qui doit être membre d’un groupe dédié (par exemple, le groupe www-group) et qui aura un droit d’accès en lecture seule à ce fichier ou répertoire; 
3. le reste des utilisateurs ne doit posséder aucun droit sur les fichiers ou répertoires sensibles.

### R52 | Restreindre les accès aux sockets et aux pipes nommées

C'est OK

### R53 | Éviter les fichiers ou répertoires sans utilisateur ou R53 M sans groupe connu

La commandesuivante permet de lister l’ensemble des fichiers qui n’ont plus d’utilisateur ou de groupe associé :

```bash
find /-type f \(-nouser-o-nogroup \)-ls 2>/dev/null
```

Il y en a énormément...

Script pour arranger ça:
```bash
#!/bin/bash
find / -xdev \( ! -nouser -o ! -nogroup \) 2>/dev/null | while read file
do
    # Affiche le fichier et son propriétaire actuel
    echo "Fichier avec propriétaire ou groupe inconnu: $file"
    
    # Correction du propriétaire et groupe (par exemple root)
    sudo chown root:root "$file"
    
    # Affiche la correction effectuée
    echo "Propriétaire et groupe corrigés pour: $file"
done
```


### R54 | Activer le sticky bit sur les répertoires inscriptibles

#### lister l’ensemble des répertoires modifiables par tous et sans sticky bit

`find /-type d \(-perm-0002-a \!-perm-1000 \)-ls 2>/dev/null `

```

```
#### lister l’ensemble des répertoires modifiables par tous et dont le propriétaire n’est pas root

`find /-type d-perm-0002-a \!-uid 0-ls 2>/dev/null`

```

```
#### Exemple de script pour activer le sticky bit (gpt) :

Si vous souhaitez activer automatiquement le sticky bit sur tous les répertoires accessibles en écriture par tous, vous pouvez créer un script comme suit :

```bash
#!/bin/bash
# Recherche des répertoires accessibles en écriture par tous et sans sticky bit 
find / -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | while read dir 
do     
	# Affiche le répertoire concerné     
	echo "Activation du sticky bit sur : $dir"          
	# Active le sticky bit     
	sudo chmod +t "$dir"          
	# Affiche la confirmation     
	echo "Sticky bit activé sur : $dir" 
done
``` 

### R55 | Séparer les répertoires temporaires des utilisateurs

#### pam_mktemp

Ajoutez la ligne suivante dans `/etc/pam.d/common-session`

```bash
session required pam_mktemp.so
```

#### Listing de l’ensemble des fichiers modifiables par tout le monde

` find /-type f-perm-0002-ls 2>/dev/null`

```bash
Beaucoup de résultat...
```

### R56 | Éviter l'usage d'exécutables avec les droits spéciaux setuid et setgid

#### Listing de l’ensemble des fichiers avec les droits spéciaux setuid et setgid présents sur le système 

`find /-type f -perm /6000 -ls 2>/dev/null`

J'ai exactement 18 fichiers dans le listing

à voir avec le prof

### R58 | N'installer que les paquets strictement nécessaires

Je n'ai pas installer GNOME ni d'interface de bureau
j'ai effectué un nettoyage avec `apt-get autoremove`


### R59 | Utiliser des dépôts de paquets de confiance

J'ai configurer mon sourcelist manuellement et je n'ai aucun paquet inutile pour le moment.
Source provenant de debian.org

### R61 | Effectuer des mises à jour régulières

#### MAJ manuelle

```bash
sudo apt update && sudo apt upgrade -y
```

```bash
dpkg -l | grep -i security
```
voir avec le prof car je ne peux pas faire ça

sudo -l

### R62 | Désactiver les services non nécessaires

#### Listing de l’ensemble des services installés sur le système 
```bash
systemctl list-units--type service
```
Je n'ai aucun des services recommandé à désactiver

### R63 | Désactiver les fonctionnalités des services non essentielles

J'ai désactivé ssh et je l'ai paramétré

#### Ajout du groupe **sshusers**

```
# groupadd sshusers
```

#### Ajout des administrateurs dans le groupe sshusers

```
# usermod -aG sshusers _$ADMIN_
```

Configuration SSH dans **/etc/ssh/sshd_config** avec les permissions **0600**

```
Port 22 
Protocol 2 

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr 

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256 

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256 

SyslogFacility AUTH 
LogLevel VERBOSE 
LoginGraceTime 60 
PermitRootLogin no 
StrictModes yes 
MaxAuthTries 4 
MaxSessions 5 
HostbasedAuthentication no 
IgnoreRhosts yes 
PasswordAuthentication no 
PermitEmptyPasswords no 
ChallengeResponseAuthentication no 
UsePAM yes 
AllowAgentForwarding no 
AllowTcpForwarding no 
GatewayPorts no 
X11Forwarding no 
PrintMotd no 
PermitUserEnvironment no 
ClientAliveInterval 15 
ClientAliveCountMax 3 
UseDNS no 
PermitTunnel no 
MaxStartups 10:30:60 
AllowGroups sshusers 
```

```

$ sudoedit /etc/ssh/sshd_config 
# chmod 0600 /etc/ssh/sshd_config
```

À noter que certaines lignes sont continues, _Ciphers, MACs, KexAlgorithms_ doivent être sur une seule ligne.

#### Vérification de la validité de la configuration

```
# /usr/sbin/sshd -t -f /etc/ssh/sshd_config
_Rien_
```

Redémarrage du serviceSSH

 ```
# systemctl reload sshd
```

#### Contrôle

Vérification de la configuration SSH

```
# grep '^[[:blank:]]*[^[:blank:]#;]' /etc/ssh/sshd_config
```

Vérification que le service SSH soit lancé et activé

```
$ systemctl status sshd
```

source : https://ssi-industriel.forge-pages.grandlyon.com/partage/durcissement-serveurs/rules/08_Configuration_SSH/

### R67 | Sécuriser les authentifications distante par PAM

#### /etc/pam.d/su  
Pour limiter l’usage de su pour devenir root aux utilisateurs membres du groupe wheel seulement 
```bash
# Limite l'accès à root via su aux membres du groupe 'wheel'
auth required pam_wheel.so use_uid root_only
``` 
#### /etc/pam.d/passwd 
Pour fixer des règles de complexité des mots de passe : # Au moins 12 caractères de 3 classes différentes parmi les majuscules, 
```bash
# les minuscules, les chiffres et les autres en interdisant la répétition 
# d'un caractère 
password required pam_pwquality.so minlen=12 minclass=3 \ dcredit=0 ucredit=0 lcredit=0 \ 
ocredit=0 maxrepeat=1 
```
#### /etc/pam.d/login et /etc/pam.d/sshd 
Pour bloquer automatiquement des comptes 
```bash
# Blocage du compte pendant 5 min après 3 échecs 
auth required pam_faillock.so deny=3 unlock_time=300
```

### R68 | Protéger les mots de passe stockés

#### yescrypt 

Dans le fichier `/etc/pam.d/common-password` ajouter la directive suivante : 
```bash
password required pam_unix.so obscure yescrypt rounds=11
```

### R69 | Sécuriser les accès aux bases utilisateur distantes

### R70 | Séparer les comptes système et d'administrateur de l'annuaire
