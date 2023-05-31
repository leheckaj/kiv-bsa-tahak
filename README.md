# Pomocné skripty pro předmět KIV/BSA, autor: Jaroslav Lehečka

## Zabezpečení operačního systému Linux

```bash
apt-get install fail2ban
FAIL2BAN !!!!!

mkdir ~/.ssh
#ssh-keygen -t rsa -b 2048
apt-get install curl
curl https://gitlab.com/leheckaj.keys >> ~/.ssh/authorized_keys

echo "PermitRootLogin without-password
AloowUsers root
PasswordAuthentication no" >> /etc/ssh/sshd_config

service sshd restart

ssh -i .ssh/id_rsa root@leheckaj-lin-exam.spos.sgfl.xyz
ssh -i .ssh/id_rsa root@192.168.20.244

```

## LVM Crypted
```bash
Nutné mít dostatečně velké disky - 100MB třeba
apt install cryptsetup lvm2

lsblk
pvcreate /dev/sd{b,c,d}
vgcreate data /dev/sd{b,c,d}

#lvcreate -n encrypted -L 1.5G data
#lvcreate -n share -L 200M data
lvcreate -n encrypted -L 4M data

Kontrola:
lvs
vgs
pvs

cryptsetup -y -v luksFormat /dev/data/encrypted
YES
heslo:123


cryptsetup luksOpen /dev/data/encrypted decrypted

mkfs.ext4 /dev/mapper/decrypted
nebo:
apt-get install xfsprogs
mkfs.xfs /dev/mapper/decrypted

mkdir /mnt/
mount /dev/mapper/decrypted /mnt
lsblk

mount /dev/mapper/decrypted 
cryptsetup luksClose db 

# Vytvoření a přidání klíče
dd if=/dev/urandom of=db.key bs=1M count=1
cryptsetup luksAddKey /dev/data/database db.key
cryptsetup luksOpen $DEVICE $DEV_NAME --key-file $DEST
# zeptá se na heslo
cryptsetup luksAddKey /dev/data/database  db.key 

#ted uz je videt heslo
cryptsetup luksDump /dev/data/database

# Záloha a obnova 
cryptsetup luksHeaderBackup /dev/data/database --header-backup-file /mnt/vgbsa_test.img 
cryptsetup luksHeaderRestore /dev/data/database --header-backup-file /mnt/vgbsa_test.img

# Další 
$ cryptsetup luksRemoveKey /dev/vgbsa/test 
$ cryptsetup luksKillSlot /dev/vgbsa/test 6 
```

## LDAP
```bash
apt install slapd ldap-utils ldapscripts
Admin heslo:123

Vytvoření domény:
dpkg-reconfigure -plow slapd 
Ne
jarda.bsa
123

echo "dn: ou=tests,dc=jarda,dc=bsa
objectClass: organizationalUnit
ou: users" >>ou.ldif 

# Vytvoření organizační jednotky v LDAPu
ldapadd -f ou.ldif -D cn=admin,dc=jarda,dc=bsa -w 123 


# Nový uživatel
echo "dn: uid=pepa,ou=users,dc=jarda,dc=bsa
uid: pepa
cn: pepa
objectClass: account
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
userPassword:: heslo123
shadowLastChange: 14846
shadowMax: 99999
shadowWarning: 7
loginShell: /bin/bash
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/ldap/pepa" > user.ldif 

ldapadd -f user.ldif -D cn=admin,dc=jarda,dc=bsa -w 123 

# Úprava stávajícího
echo "dn: uid=pepa,ou=users,dc=jarda,dc=bsa
changeType: modify
replace: homeDirectory
homeDirectory: /home/ldap/pepa" > modify_user.ldif

ldapmodify -f modify_user.ldif -D cn=admin,dc=jarda,dc=bsa -w 123

# Další user 
změna pepa->tonda, a uid/gid Number: 10002
sed -i 's/pepa/tonda/g' user.ldif
sed -i 's/10001/10002/g' user.ldif

# Vyhledávání
ldapsearch -D cn=admin,dc=jarda,dc=bsa -w 123 -b "dc=jarda,dc=bsa" '(objectClass='account')' cn
ldapsearch -D cn=admin,dc=jarda,dc=bsa -w 123 -b "dc=jarda,dc=bsa" '(objectClass='account')' cn homedirectory 


# Nastavení autentizace
apt install libnss-ldap libpam-ldap
ldapi://localhost:389
dc=jarda,dc=bsa
ldap3
admin jarda bsa
root yes db no
/usr/share/doc/libnss-ldap/examples/nsswitch.ldap
yes

V /etc/pam.d/
soubory common-auth, common-account   ldap required

/etc/init.d/nscd restart

su - tonda
curl https://gitlab.com/leheckaj.keys >> ~/.ssh/authorized_keys
ssh -i ~/.ssh/id_rsa tonda@192.168.20.244

# Debugování
term1: tail -f /var/log/auth.log
term2: su - pepa
```

## SSH TUNNEL
```bash
Vytvoření na Serveru:
vystavení dostupného portu

Vytvoření na KIV-PC:
ssh -R 12345:localhost:10000 root@192.168.20.244
ssh -R 1389:localhost:389 bsa

localhost 1389
dc=admin,dc=jarda,dc=bsa
```

## Certifikační autorita
```bash
CA jednoduse (Easy RSA - 2.0)
apt install easy-rsa -y
mkdir -p /etc/ca 
cp -r /usr/share/easy-rsa/ /etc/ca

cp    vars.example vars
vim vars
-------------------------
Nastavení PKI directory, opensssl directory and command
set_var EASYRSA_REQ_COUNTRY .... atd.

esay rsa key size ......4k klíč nedává java8 
set_var  ca expire --- 2 roky expirace
set_var  cert expire --- 2 roky expirace
-----------------------
./easyrsa

# Init vytváření certifikátu instance
/etc/ca/easyrsa init-pki
===> vytvoří složku /etc/ca/pki/   --- příprava na udělování
/etc/ca/easyrsa build-ca ---- toto držet tajné
Heslo:Heslo123.

Common name: BSA Certificate Authority  nebo cokoliv jiného
Toto /etc/ca/pki/ca.crt je to privátní klíč -> se dává do chromu

./easyrsa build-server-full server.jarda.bsa 
PEM heslo (x2) + heslo certifikační autority

Certifikáty vydávané ven jsou bez hesla:
openssl rsa -in /etc/ca/pki/private/ca.key -out /etc/ca/pki/private/ca.key.in

# Klíč
server.jarda.bsa.key -- sourkomý klič
open x509 -in  /etc/ca/pki/private/server.jarda.bsa.key -text | less
```

## Nginx + CA
```bash
apt install nginx ca-certificates

openssl rsa -in /etc/ca/pki/private/server.jarda.bsa.key -out /etc/ca/pki/private/server.jarda.bsa.key
Heslo123.

vim /etc/nginx/sites-available/default
--------------------------------------
ssl_certificate /etc/ca/pki/issued/server.jarda.bsa.crt;  
ssl_certificate_key /etc/ca/pki/private/server.jarda.bsa.key; 

echo "server{
      listen 8443 default_server;
      
      ssl_certificate /etc/ca/pki/issued/server.jarda.bsa.crt;
      ssl_certificate_key /etc/ca/pki/private/server.jarda.bsa.key; 
      
      root /var/www/html;
      
      index index.html index.htm;
 }" > /etc/nginx/sites-available/defaultSSL


nginx -t
service nginx restart
```

## Apache2 SSL
```bash
apt install apache2
a2enmod ssl
cd /etc/apache2/sites-available/

./easyrsa build-server-full server.jarda.bsa 
openssl rsa -in /etc/ca/pki/private/server.jarda.bsa.key -out /etc/ca/pki/private/server.jarda.bsa.key

echo "
	<VirtualHost _default_:8543>
		DocumentRoot /var/www/html
		ErrorLog /error.log
		CustomLog /access.log combined
		SSLEngine on

		SSLCertificateFile	/etc/ca/pki/issued/server.jarda.bsa.crt
		SSLCertificateKeyFile /etc/ca/pki/private/server.jarda.bsa.key

	</VirtualHost>" > /etc/apache2/sites-enabled/ssl.conf

echo "Listen 8543" >> /etc/apache/ports.conf

a2ensite ssl
service apache2 restart
```

## Stunnel 4
```bash
apt install stunnel4
cp /usr/share/doc/stunnel4/examples/stunnel.conf-sample /etc/stunnel/stunnel.conf

echo "[https]
accept=8443
connect=80
cert=/etc/ca/pki/issued/server.jarda.bsa.crt
key=/etc/ca/pki/private/server.jarda.bsa.key" >> /etc/stunnel/stunnel.conf

service stunnel4 restart
https://leheckaj-lin-exam.spos.sgfl.xyz:8443
curl -k -v https://localhost:8443

ps -aux | grep stunnel vám ukáže PID, který musíte sejmout příkazem kill <pid>
```

## Firewall
```bash
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -s  192.168.20.0/24  -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -s  147.228.0.0/16  -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22  -j DROP

iptables-save > /etc/network/iptables
crontab -e
@reboot iptables-restore /etc/network/iptables
```

## OpenVPN - preshared key
```bash
# Oba pocitace 
wget https://raw.githubusercontent.com/jindrichskupa/kiv-bsa/master/cv05-openvpn/bsa-server-psk.conf 

vim bsa-server-psk.conf 
Vyhodit comp lzo 
nastavit remote
route - navíc u serveru

# Server
Pak vytovrime klic 
openvpn --genkey secret bsa-server-psk.key 
cp ./bsa-server-psk.key /etc/openvpn/
ip a a 192.168.4.160/24 dev enp0s3 

OBA: openvpn --config bsa-server-psk.conf &

openssl rsa -in /etc/ca/pki/private/vpn.jarda.bsa.key -out /etc/ca/pki/private/vpn.jarda.bsa.key
cp pki/ca.crt pki/issued/vpn.jarda.bsa.crt pki/private/vpn.jarda.bsa.key pki/dh.pem /etc/openvpn

.... asi řešit nebudeme
```

## GPG
```bash
openssl genrsa -out key.pem 4096 
openssl rsa -in key.pem -pubout > key.pub 

# Vytvoření souboru k podepsání
dd if=/dev/urandom of=file.bin bs=1M count=5 

# Podpis souboru
openssl dgst -sign key.pem -keyform PEM -sha256 -out file.bin.sign -binary file.bin 

# Ověření
openssl dgst -verify key.pub -keyform PEM -sha256 -signature file.bin.sign --binary file.bin 
```


## Logování
```bash
apt-get install rsyslog

mkdir /var/log/logdir
Otevřeme nastavení:
vim /etc/rsyslog.conf
-----------------------
Při vlastním logování mail zakomentovat:
mail.*
mail.info
mail.error
mail.warn

Přidáme do souboru /etc/rsyslog.conf toto:
---------------------------------------
# rozdeleni logu do adresaru
$template HourlyMailLog,"/var/log/logdir/%$YEAR%/%$MONTH%/%$DAY%/%HOSTNAME%_mail.log"
# formatovani logu
$template SyslFormat,"%timegenerated% %HOSTNAME%  %syslogtag%%msg 
# zapis logu do souboru dle definice a formatu
mail.*                                                  -?HourlyMailLog;SyslFormat
----------------------------------------------------------------------------------

v Linuxu:
systemctl restart rsyslog
echo "Toto je zprava" | logger -p mail.err
cat /var/log/logdir/2023/05/31/lehecka-base_mail.log

https://unix.stackexchange.com/questions/21041/add-new-syslog-facility
```
