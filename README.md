Rapport debian12 - Hardening
___ 

- **Nom** : Rapport de durcissement Linux - debian12
- **Auteur** : Adrien MACHNIK [@Drien95]
- **Date** : 28/11/2024
- **Version** : 1.0
- **documents** : 
	- [Recommandations de sécurité relatives à un système GNU/Linux - v2.0](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux)
	- [Recommandations pour un usage sécurisé d’(Open)SSH - v1.3](https://cyber.gouv.fr/publications/usage-securise-dopenssh)
___
# Application des recommandations de durcissement GNU/Linux ANSSI V2
___

## R28 | Partitionnement type
___

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

## R5 | Configurer un mot de passe pour le chargeur de démarrage
___

génération du mot de passe : 
`grub-mkpasswd-pbkdf2`

```
sudo nano /etc/grub.d/40_custom
set superusers="admin" 
password_pbkdf2 admin grub.pbkdf2.sha512.10000.XXXXX
```

## R8 | Paramétrer les options de configuration de la mémoire
___

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


## R9 | Paramétrer les options de configuration du noyau
___

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


## R11 | Activer et configurer le LSM Yama
___

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

## R12 | Paramétrer les options de configuration du réseau IPv4
___

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

## R13 | Désactiver le plan IPv6
___

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

## R14 | Paramétrer les options de configuration des systèmes de fichiers
___

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

## R30 | Désactiver les comptes utilisateur inutilisés
___

C'est OK

## R31 | Utiliser des mots de passe robustes
___
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
## R32 | Éxpirer les sessions utilisateur locales
___

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
## R33 | Assurerl'imputabilité des actions d'administration
___

### Lister les utilisateurs avec un shell interactif

`awk -F: '/bash$/{print $1}' /etc/passwd`

```bash
root
admloc
```
### Vérifier les comptes sans mot de passe

`awk -F: '($2 == "") {print $1}' /etc/shadow`

```

```
### Vérrouillage d'un compte

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
### Listing des users

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

### Journalisation de la création de tout processus

MAJ du source-list apt avec les paquets debian et debian-security

```bash
sudo apt install auditd audispd-plugins
```
J'édite ensuite le fichier des règles `sudoedit /etc/audit/audit.rules` et je rajoute :
```bash
-a exit,always-F arch=b64-S execve,execveat
-a exit,always-F arch=b32-S execve,execveat
```

## R34 | Désactiver les comptes de service
___

### Listing des comptes de services

`awk -F: '$3 < 1000 {print $1}' /etc/passwd`

| Services         |
| ---------------- |
| root             |
| daemon           |
| bin              |
| sys              |
| sync             |
| games x          |
| man              |
| lp               |
| mail x           |
| news x           |
| uucp             |
| proxy            |
| www-data x       |
| backup           |
| list             |
| irc              |
| _apt_            |
| nobody x         |
| systemd-network  |
| systemd-timesync |
| messagebus       |
| sshd             |
| admloc           |
| nginx            |
| mysql            |

Désactivation de `nobody`

## R35 | Utiliser des comptes de service uniques et exclusifs
___

Pour nginx:

```bash
sudo useradd -r -s /bin/false nginx
```
Pour mysql :
```bash
sudo useradd -r -s /bin/false mysql
```
Création de compte systeme sans shell de connexion

## R38 | Créer un groupe dédié à l'usage de sudo
___

Création d'un nouveau compte administrateur avec le groupe sudo

```bash
useradd -m -G sudo TEST
passwd test
su test
chsh -s $(which bash)
```
## R39 |  Modifier les directives de configuration sudo
___

Ajouter à `/etc/sudoers`
```bash
#Defaults noexec
Defaults requiretty
Defaults use_pty
Defaults umask=0077
Defaults ignore_dot
Defaults env_reset
```
### J'autorise le groupe sudo à utiliser sudo

`%sudo ALL=(ALL:ALL) ALL`
### Rajout d'un logfile

```bash
Defaults logfile="/var/log/sudo.log"
```
## R41 |Limiter l'utilisation de commandes nécessitant la directive EXEC
___

C'est OK

### R43 | Préciser les arguments dans les spécifications sudo
___

C'est OK

## R42 | Bannir les négations dans les spécifications sudo
___

C'est OK

## R44 | Éditer les fichiers de manière sécurisée avec sudo
___

`export EDITOR=/bin/nano`

Pour chaque utilisateur, le limiter à nano.
## R50 | Restreindre les droits d'accès aux fichiers et aux répertoires sensibles
___

Comme le root est désactivé, restreindre à admloc pour le moment les droits d'accès.

Information :
Le schéma d’analyse des fichiers ou répertoires sensibles est le suivant : 
1. les fichiers ou répertoires sensibles système doivent avoir comme propriétaire root afin d’éviter tout changement de droit par un utilisateur non privilégié; 
2. les fichiers ou répertoires sensibles accessibles à un utilisateur différent de root (par exemple, la base des mots de passe d’un serveur Web) doivent avoir comme propriétaire cet utilisateur (par exemple, l’utilisateur associé au serveur Web) qui doit être membre d’un groupe dédié (par exemple, le groupe www-group) et qui aura un droit d’accès en lecture seule à ce fichier ou répertoire; 
3. le reste des utilisateurs ne doit posséder aucun droit sur les fichiers ou répertoires sensibles.

## R52 | Restreindre les accès aux sockets et aux pipes nommées
___

C'est OK

## R53 | Éviter les fichiers ou répertoires sans utilisateur ou R53 M sans groupe connu
___

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


## R54 | Activer le sticky bit sur les répertoires inscriptibles
___

### lister l’ensemble des répertoires modifiables par tous et sans sticky bit

`find /-type d \(-perm-0002-a \!-perm-1000 \)-ls 2>/dev/null `

```

```
### lister l’ensemble des répertoires modifiables par tous et dont le propriétaire n’est pas root

`find /-type d-perm-0002-a \!-uid 0-ls 2>/dev/null`

```

```
### Exemple de script pour activer le sticky bit (gpt) :

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

## R55 | Séparer les répertoires temporaires des utilisateurs
___

### pam_mktemp

Ajoutez la ligne suivante dans `/etc/pam.d/common-session`

```bash
session required pam_mktemp.so
```

### Listing de l’ensemble des fichiers modifiables par tout le monde

` find /-type f-perm-0002-ls 2>/dev/null`

```bash
Beaucoup de résultat...
```

## R56 | Éviter l'usage d'exécutables avec les droits spéciaux setuid et setgid
___

### Listing de l’ensemble des fichiers avec les droits spéciaux setuid et setgid présents sur le système 

`find /-type f -perm /6000 -ls 2>/dev/null`

J'ai exactement 18 fichiers dans le listing

à voir avec le prof

## R58 | N'installer que les paquets strictement nécessaires
___

Je n'ai pas installer GNOME ni d'interface de bureau
j'ai effectué un nettoyage avec `apt-get autoremove`


## R59 | Utiliser des dépôts de paquets de confiance
___

J'ai configurer mon sourcelist manuellement et je n'ai aucun paquet inutile pour le moment.
Source provenant de debian.org

## R61 | Effectuer des mises à jour régulières
___
### MAJ manuelle

```bash
sudo apt update && sudo apt upgrade -y
```

```bash
dpkg -l | grep -i security
```
voir avec le prof car je ne peux pas faire ça

sudo -l

## R62 | Désactiver les services non nécessaires
___

#### Listing de l’ensemble des services installés sur le système 
```bash
systemctl list-units--type service
```

Désactivation de `games`, `www-data`, `new`, `mail`

## R63 + SSH | Désactiver les fonctionnalités des services non essentielles
___
source : https://ssi-industriel.forge-pages.grandlyon.com/partage/durcissement-serveurs/rules/08_Configuration_SSH/
J'ai désactivé ssh et je l'ai paramétré

### Ajout du groupe **sshusers**

```
# groupadd sshusers
```

### Ajout des administrateurs dans le groupe sshusers

```
# usermod -aG sshusers _$ADMIN_
```

Configuration SSH dans **/etc/ssh/sshd_config** avec les permissions **0600**

```bash
# Limitation au port 22
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

```bash
$ sudoedit /etc/ssh/sshd_config 
# chmod 0600 /etc/ssh/sshd_config
```

À noter que certaines lignes sont continues, _Ciphers, MACs, KexAlgorithms_ doivent être sur une seule ligne.

### Vérification de la validité de la configuration

```
# /usr/sbin/sshd -t -f /etc/ssh/sshd_config
_Rien_
```

Redémarrage du serviceSSH

 ```
# systemctl reload sshd
```

### Contrôle

Vérification de la configuration SSH

```
# grep '^[[:blank:]]*[^[:blank:]#;]' /etc/ssh/sshd_config
```

Vérification que le service SSH soit lancé et activé

```
$ systemctl status sshd
```

source : https://ssi-industriel.forge-pages.grandlyon.com/partage/durcissement-serveurs/rules/08_Configuration_SSH/

## R67 | Sécuriser les authentifications distante par PAM
___
### /etc/pam.d/su  
Pour limiter l’usage de su pour devenir root aux utilisateurs membres du groupe wheel seulement 
```bash
# Limite l'accès à root via su aux membres du groupe 'wheel'
auth required pam_wheel.so use_uid root_only
``` 
### /etc/pam.d/passwd 
Pour fixer des règles de complexité des mots de passe : # Au moins 12 caractères de 3 classes différentes parmi les majuscules, 
```bash
# les minuscules, les chiffres et les autres en interdisant la répétition 
# d'un caractère 
password required pam_pwquality.so minlen=12 minclass=3 \ dcredit=0 ucredit=0 lcredit=0 \ 
ocredit=0 maxrepeat=1 
```
### /etc/pam.d/login et /etc/pam.d/sshd 
Pour bloquer automatiquement des comptes 
```bash
# Blocage du compte pendant 5 min après 3 échecs 
auth required pam_faillock.so deny=3 unlock_time=300
```

## R68 | Protéger les mots de passe stockés
___
### yescrypt 

Dans le fichier `/etc/pam.d/common-password` ajouter la directive suivante : 
```bash
password required pam_unix.so obscure yescrypt rounds=11
```

## R69 | Sécuriser les accès aux bases utilisateur distantes
___

## R70 | Séparer les comptes système et d'administrateur de l'annuaire
___

## R74 | Durcir le service de messagerie locale
___
Suppression de la messagerie

```
sudo apt purge exim4
```

## R79 | Durcir et surveiller les services exposés
___

Nous l'avons déjà fait en amont en encapsulant les services et restreignants leur droits d'accès et de shell. 

# Firewall
___
## 1. Mes interfaces

```bash
ip a
```

- **Interfaces utilisées :**
    
    - `lo` : Interface de loopback (localhost).
    - `ens33` : Interface réseau principale (mon LAN).

## 2. Configurations

Fichier de configuration :
```bash
/etc/nftables.conf
```

- **Chaîne `input` :**
    
    - **Autorise uniquement :**
        - Le trafic provenant de `lo` (trafic local).
        - Le trafic provenant de `ens33` (exemple : machines du réseau local).
    - Par défaut, tout autre trafic est bloqué.
- **Chaîne `forward` :**
    
    - Permet le trafic entre les sous-réseaux si nécessaire (si `ens33` connecte plusieurs réseaux locaux).
    - Bloque tout trafic non sollicité provenant d'Internet, sauf s'il correspond à une connexion établie ou reliée grâce à **conntrack**.
- **Chaîne `output` :**
    
    - Autorise tout trafic sortant de votre machine.

```bash
#!/sbin/nft -f

flush ruleset

table ip filter {
	# Autoriser tout le trafic sortant de la machine
	chain output {
		type filter hook output priority 100; policy accept;
		# Autoriser les requêtes DNS (UDP et TCP) 
		udp dport 53 accept 
		tcp dport 53 accept 
		# Autoriser les requêtes NTP 
		udp dport 123 accept 
		# Autoriser les connexions sortantes vers un serveur Syslog distant 
		udp dport 514 accept 
		tcp dport 514 accept
	}

	# Autoriser localhost et le trafic sur ens33 depuis l'intérieur, bloquer le reste
	chain input {
		type filter hook input priority 0; policy drop;
		iifname "lo" accept       # Autoriser tout le trafic local
		iifname "ens33" accept    # Autoriser le trafic entrant sur ens33 (LAN)
		# Autoriser les connexions SSH 
		tcp dport 22 ct state new,established accept 
		# Autoriser les connexions HTTP/HTTPS 
		tcp dport 80 ct state new,established accept 
		tcp dport 443 ct state new,established accept # Autoriser les connexions Syslog
		udp dport 514 accept tcp dport 514 accept
		log prefix "Firewall DROP INPUT: " drop
	}

	# Autoriser les connexions initiées par la machine et bloquer le reste
	chain forward {
		type filter hook forward priority 0; policy drop;
		iifname "ens33" oifname "ens33" accept                    # Connexions LAN-LAN (si nécessaire)
		iifname "ens33" ct state related,established accept       # Connexions établies ou reliées
		log prefix "Firewall DROP FORWARD: " drop
	}
}

```

Système de log afin de surveiller les paquets avec :
```bash
log prefix "Firewall DROP FORWARD: " drop
log prefix "Firewall DROP INPUT: " drop
```

Appliquer les règles :
```bash
sudo nft -f /etc/nftables.conf
```

Le rendre persistent au démarrage : 
```bash
sudo systemctl enable nftables
```

Vérifications : 
```bash
sudo nft list ruleset
```

![[Pasted image 20241128142412.png]]


# Rsyslog
___
## 1. Installation

On installe et on le boot au démarrage
```bash
sudo apt install rsyslog
sudo systemctl status rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```
Fichier de configuration :
```bash
/etc/rssyslog.conf
```

## 2. Configurations

Je rajoute une règle pour renvoyer mes log de mon iptables dans `firewall.log`

```bash
:msg, contains, "Firewall DROP" /var/log/firewall.log
& stop
```
J'enregistre les modifications : 
```bash
sudo systemctl restart rsyslog
```

# Antivirus 
___
## 1. Clamav

### 1.1. Installation

```bash
sudo apt-get clamav clamav-daemon
```

Importation des templates complètes pour les fichiers de configurations
```bash
clamconf -g freshclam.conf > freshclam.conf
clamconf -g clamd.conf > clamd.conf
clamconf -g clamav-milter.conf > clamav-milter.conf
```
Création d'un log file pour freshclam :
```bash
touch /var/log/freshclam.log
chmod 600 /var/log/freshclam.log
chown clamav /var/log/freshclam.log

```
### 1.2. Configurations
#### 1.2.1. freshclam.conf

Rajout de règles dans `freshclam.conf`
```bash
##
## freshclam.conf - Configuration file for ClamAV's database updater
##

# Supprimer la ligne d'exemple (déjà commentée ici).
# Example

# Emplacement du fichier de log.
UpdateLogFile /var/log/freshclam.log

# Taille maximale du fichier de log (5 Mo dans cet exemple).
LogFileMaxSize 5M

# Activer l'enregistrement de l'heure avec chaque message de log.
LogTime yes

# Activer l'utilisation du syslog pour les logs.
LogSyslog yes

# Définir la priorité de syslog pour les messages.
LogFacility LOG_MAIL

# Réaliser une rotation automatique des logs lorsque la taille max est atteinte.
LogRotate yes

# Activer l'utilisateur sous lequel FreshClam s'exécute après le démarrage en tant que root.
DatabaseOwner clamav

# Vérifier les mises à jour 12 fois par jour.
Checks 12

# Définir les serveurs miroir pour télécharger les bases de données.
DatabaseMirror database.clamav.net

# Activer les mises à jour scriptées (recommandé).
ScriptedUpdates yes

# Tester les bases de données avant de les remplacer (peut être désactivé si manque de RAM).
TestDatabases yes

# Définir le timeout de connexion aux serveurs de bases de données.
ConnectTimeout 30

# Définir le timeout de réception des données des serveurs (0 = désactivé).
ReceiveTimeout 60

# Activer le téléchargement des signatures bytecode pour une meilleure détection.
Bytecode yes

# Envoi de la commande RELOAD à clamd après une mise à jour réussie.
NotifyClamd /etc/clamav/clamd.conf

```

#### 1.2.2. clamd.conf

Pour `clamd.conf` j'ai activé toutes les options de scan de base comme le scan html, http, mail, d'archive...

et j'ai rajouté ça :

```bash
# Activer l'analyse en temps réel
OnAccessEnable yes

# Spécifier les répertoires ou partitions à scanner lors de leur montage
OnAccessMountPath /mnt/partition1 /mnt/partition2

# Optionnel : définir les fichiers exclus (par exemple, fichiers temporaires)
OnAccessExcludePath /mnt/partition1/tmp

# Limiter l'analyse aux utilisateurs spécifiques (par exemple, root uniquement)
OnAccessExcludeUID 0

```

Je ne suis pas réellement allé puis loin car clamav ne fonctionne pas sur ma VM

# USBGuard
___
## 1. Installation

```bash
sudo apt install usbguard
```
Fichier de configuration :
```bash
/etc/usbguard/usbguard-daemon.conf
```
Les règles de configurations sont dans :
```bash
/etc/usbguard/rules.conf
```
Mes bus :
```bash
5: allow id 1d6b:0002 serial "0000:02:03.0" name "EHCI Host Controller" hash "pSuHBvcIETMUGFPlSwdlvEsYG58P+PYrptZLSQr57Kg=" parent-hash "HeMcwU5Di+GYGCjuHSiLNxmkqXZV7uCJ+LeEmwF3BsM=" via-port "usb1" with-interface 09:00:00 with-connect-type ""

6: allow id 1d6b:0001 serial "0000:02:00.0" name "UHCI Host Controller" hash "3QuFY0nRVqo+mgnIkqiXmmirRvxPDeP7P3mintodpys=" parent-hash "42PXRxhXx8adD0H10oXgQnna1ED6vikevkSl6cwgdOI=" via-port "usb2" with-interface 09:00:00 with-connect-type ""

7: allow id 0e0f:0003 serial "" name "VMware Virtual USB Mouse" hash "F4BFfAiFQzjQxG8oQHVYMFiDF2/zhhARDrRSIj6oij8=" parent-hash "3QuFY0nRVqo+mgnIkqiXmmirRvxPDeP7P3mintodpys=" via-port "2-1" with-interface 03:01:02 with-connect-type "unknown"

8: allow id 0e0f:0002 serial "" name "VMware Virtual USB Hub" hash "0cDIzeFX6eYg1fPydeh+aK2a/vRVjjj9bIasbHuN5sE=" parent-hash "3QuFY0nRVqo+mgnIkqiXmmirRvxPDeP7P3mintodpys=" via-port "2-2" with-interface 09:00:00 with-connect-type "unknown"
```

## 2. Configurations

Je pourrais très bien désactiver le bus 5 par exemple :
```bash
block id 1d6b:0002
```
Je rajoute ces règles dans  `/etc/usbguard/rules.conf` 
```bash
# Bloque tous les périphériques USB qui tentent de se connecter via n'importe quelle interface
block with-interface all
# Politique par défaut qui bloque tous les périphériques USB non autorisés
ImplicitPolicyTarget=block
# Je n'autorise que moi même (admloc) à interagir avec le processus d'IPC de USBGuard
IPCAllowedUsers=admloc
```

# Contrôleur d'intégrité 
___
## 1.  AIDE

### 1.1 Initialisation

```bash
sudo apt install aide
```

J'initilise la base de donnée :
```bash
sudo aideinit
```
Résultat : nouveau fichier `aide.db.new` qui remplacera l'ancien
```bash
admloc@debian-ama:~$ sudo ls -l /var/lib/aide/
total 20632
-rw------- 1 root  root  10561626 28 nov.  15:37 aide.db
-rw------- 1 _aide _aide 10561626 28 nov.  15:37 aide.db.new
```
```bash
admmloc@debian-ama:~$ sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

admloc@debian-ama:~$ sudo ls -l /var/lib/aide/
total 10316
-rw------- 1 _aide _aide 10561626 28 nov.  15:37 aide.db
```

### 1.2 Configurations

Rajout des règles de configuration pour surveiller les binaires et les fichiers sensibles : `/etc/shadow | gshadow | passwd

```bash
# Define custom rule sets 
BinFiles = p+i+n+u+g+s+m+c+acl+xattrs+sha256 SensitiveFiles = p+i+n+u+g+s+m+c+sha256 
# Check the binary directories 
/bin BinFiles /sbin BinFiles /usr/bin BinFiles /usr/sbin BinFiles 
# Monitor sensitive files 
/etc/shadow SensitiveFiles 
/etc/gshadow SensitiveFiles 
/etc/passwd SensitiveFiles 
# Optionally, monitor other sensitive locations 
/etc/aide.conf SensitiveFiles
```


# Création d'une partition chiffrée
___
## 1. Le manager de VM - VMWare

Je rajoute un disque de 10Go dans ma VM

![[Pasted image 20241128165842.png]]
![[Pasted image 20241128165849.png]]
![[Pasted image 20241128165901.png]]

![[Pasted image 20241128165909.png]]

## 2. La VM

### 2.1. LVM

Vérification des périphériques de stockages :
```bash
ls /dev | grep "sd"
```
J'ai bien un périphérique en plus `sdb`

![[Pasted image 20241128170134.png]]

Je réalloue ensuite de la mémoire à `vg0` :

```bash
vgextend vg0 /dev/sdb
# pour vérifier que c'est OK
vgdisplay
```

On peut voir que je suis bien passé de 19Go à 29Go :

![[Pasted image 20241128170220.png]]![[Pasted image 20241128170247.png]]
![[Pasted image 20241128170334.png]]

Ensuite j'étend la capacité de mon `/home` de 20% :
```bash
sudo lvextend -l +20%FREE /dev/mapper/vg0-home
# Puis je resize
resize2fs /dev/mapper/vg0-home
```
![[Pasted image 20241128170615.png]]![[Pasted image 20241128170652.png]]

Je crée maintenant un nouveau volume logique (LV) `data` dans mon volume group (VG) existant `vg0` et je lui alloue 2G
```bash
sudo lvcreate -L 2G -n data vg0
```

![[Pasted image 20241128170402.png]]

### 2.2. LUKS
#### 2.2.1. Installation

```bash
sudo apt install cryptsetup
```

#### 2.2.2. Création du volume
Je vais maintenant formater mon volume `dev/vg0/data` avec LUKS pour le chiffrer

```bash
sudo cryptsetup LuksFormat /dev/vg0/data
```

![[Pasted image 20241128171152.png]]

Je crée maintenant un volume déverrouillé `data_crypt` :
```bash
sudo cryptsetup open /dev/vg0/data data_crypt
```

![[Pasted image 20241128171225.png]]

Ensuite je change le fichier de montage `/etc/fstab` et je rajoute ma nouvelle partition montée sur `/mnt/data` :

```bash
/dev/mapper/data_crypt /mnt/data ext4,acl defaults 0 2
```

Je modifie aussi `/etc/crypttab` :
```bash
data_crypt /dev/vg0/data none luks
```

Puis je reboot ma machine pour appliquer les changements : 
```bash
sudo reboot
```
#### 2.2.3. KeyFile
source : [redhat](https://access.redhat.com/solutions/230993)

Préparation du fichier :
```bash
dd if=/dev/random bs=32 count=1 of=/root/random_data_keyfile1
```
Ajout du keyfile au périphérique :
```bash
cryptsetup luksAddKey /dev/vg0/data /root/random_data_keyfile1
```
Ajout du keyfile dans `/etc/crypttab` pour débloquer automatiquement la partition au boot :
```bash
data_crypt      /dev/vg0/data   /root/randon_data_keyfile1      luks
```

Résultat --> ça marche niquel

# ACL
___
source : [ubuntu-fr.of/acl](https://doc.ubuntu-fr.org/acl)

## 1. Fichiers

Création de 4 fichiers dans `/mnt/data/` :
```bash
touch /mnt/data/f_u1
touch /mnt/data/f_u2
touch /mnt/data/f_u3
touch /mnt/data/f_u4
```
Retire les permissions de group/others :
```bash
chmod go= /mnt/data/f_u1
chmod go= /mnt/data/f_u2
chmod go= /mnt/data/f_u3
chmod go= /mnt/data/f_u4
```
![[Pasted image 20241129141425.png]]

## 2. Configurations

Ajout de 3 users :
```bash
sudo useradd u1
sudo useradd u2
sudo useradd u3

# Création d'un groupe partagé u1/u2
sudo groupadd g_u1_u2
sudo usermod -aG g_u1_u2 u1
sudo usermod -aG g_u1_u2 u2

# Création des ACL
sudo setfacl -m u:u2:rw f_u2
sudo setfacl -m u:u1:rw f_u1
sudo setfacl -m g:g_u1_u2:rw f_u3

Affichage des résultats
sudo getfacl f_u*
# file: f_u1
# owner: u1
# group: u1
user::rw-
user:u1:rw-
group::---
mask::rw-
other::---

# file: f_u2
# owner: u2
# group: u2
user::rw-
user:u2:rw-
group::---
mask::rw-
other::---

# file: f_u3
# owner: admloc
# group: g_u1_u2
user::rw-
group::rw-
group:g_u1_u2:rw-
mask::rw-
other::---

# file: f_u4
# owner: root
# group: root
user::rw-
group::---
other::---
```

On dirait que tout est niquel !

Après inspection avec chaque users ça à l'air bon.

# LSM
___
## 1. Capabilities 
### 1.1 Ping

```bash
sudo getcap /bin/ping
/bin/ping cap_net_raw=ep
```

- **`cap_net_raw`** : Cette capacité permet au processus d'ouvrir des sockets bruts, nécessaires pour effectuer des opérations réseau telles que le ping.
- **`+ep`** : Ces options signifient que la capacité est effective (active) pour ce fichier binaire (c'est-à-dire qu'elle est attribuée au programme lorsque celui-ci est exécuté).

### 1.2 Mount

```bash
sudo getcap /bin/mount
# Pas de résultat
```

Suppression du SUID :
```bash
# Supprime le bit suid
sudo chmod u-s /bin/mount
```


