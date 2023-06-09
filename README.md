# Pomocné skripty pro předmět KIV/BSA, autor: Jaroslav Lehečka

## Zabezpečení operačního systému Linux

```bash
apt purge man-db
apt-get install --no-install-recommends nginx lvm2...

sudo su -
sudo pkill -9 -f apt

apt-get install fail2ban
FAIL2BAN !!!!!

mkdir ~/.ssh
#ssh-keygen -t rsa -b 2048
apt-get install curl
curl https://gitlab.com/leheckaj.keys >> ~/.ssh/authorized_keys

echo "PermitRootLogin without-password
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
---------------------------------------------------------------------------------
crypttab
---------------------------------------------------------------------------------
lvremove /dev/data/encrypted
vgremove data
pvremove data /dev/vdb

---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
apt install cryptsetup lvm2

lsblk
pvcreate /dev/sd{b,c,d}
vgcreate data /dev/sd{b,c,d}
lvcreate -n encrypted -L 120M data
cryptsetup -y -v luksFormat /dev/data/encrypted
cryptsetup luksAddKey /dev/data/encrypted db.key
cryptsetup luksOpen /dev/data/encrypted decrypted --key-file db.key
mkfs.ext4 /dev/mapper/decrypted
mkdir /mnt/
mount /dev/mapper/decrypted /mnt

lsblk

umount /mnt
cryptsetup luksClose /dev/mapper/decrypted
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
cp -r /usr/share/easy-rsa/* /etc/ca

cp    vars.example vars
vim vars
-------------------------
můžeme, ale nemusíme Nastavení PKI directory, opensssl directory and command
hlavně:
set_var EASYRSA_REQ_COUNTRY .... atd.

esay rsa key size ......4k klíč nedává java8 
set_var  ca expire --- 2 roky expirace
set_var  cert expire --- 2 roky expirace
-----------------------
./easyrsa

# Init vytváření certifikátu instance
./easyrsa init-pki                   ===> vytvoří složku /etc/ca/pki/   --- příprava na udělování
./easyrsa build-ca 	             ---- toto držet tajné 

Heslo:Heslo123.
Common name: BSA Certificate Authority  nebo cokoliv jiného
Toto /etc/ca/pki/ca.crt je to privátní klíč -> se dává do chromu

./easyrsa build-server-full server.jarda.bsa 
PEM heslo (x2) + heslo certifikační autority

Certifikáty vydávané ven jsou bez hesla:
openssl rsa -in /etc/ca/pki/private/ca.key -out /etc/ca/pki/private/ca.key.in

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
      listen 8443 default_server ssl;
      
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

SMAZAT ÚPLNĚ VŠE KOLEM gmailu V TOMTO SOUBORU AKORÁT PŘIDAT TOTO:

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

## OpenVPN - P2P - Server
```bash
wget https://raw.githubusercontent.com/leheckaj/kiv-bsa-tahak/main/bsa-server-psk.conf
Přepsat remote !!!!!

Buď vytvořit klíč: openvpn --genkey --secret bsa-server-psk.key
nebo:
echo "#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
412429f8a9a3fb26b80ccd178d5ba8e4
d962625c17f3ef018d53545bcd8acbce
f70de26192839d7f7252380fd7aefbd1
65ee4998322de93b37ebcb01af3348a1
4019f4ad52505f94034dd632d92a3d27
b90342c0cb844c8d77b54076dad6435f
57fce476cdaff267497f701ad49ee9f6
bdac321a23d5c0ae9b4cbfb3924f390a
14187686798a57b6d0988ecbb4208f50
12fec1833c45153b03ba3f4953b05540
53fc9ec40ecf398269b4ee25b8aec87b
aef8f5702d0ec73abe773edf876bbfd9
bcc38eadedb0d3590b8461648a21ef08
76cca880b240a5f7331787a172959fe2
6bf3bce96725bfcbe05dbcf9dd626902
bc8a48856b063f6dbbade49833f90545
-----END OpenVPN Static key V1-----" > /etc/openvpn/bsa-server-psk.key

ip a a 192.168.4.160/24 dev ens18 

openvpn --config bsa-server-psk.conf &
kilall -9 openvpn

ip a del 192.168.4.160/24 dev ens18 
```

## OpenVPN - P2P - Klient
```bash
wget https://raw.githubusercontent.com/leheckaj/kiv-bsa-tahak/main/bsa-client-psk.conf
Přepsat remote !!!!!

Buď PŘENÉST KLÍČ ZE serveru

nebo:
echo "#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
412429f8a9a3fb26b80ccd178d5ba8e4
d962625c17f3ef018d53545bcd8acbce
f70de26192839d7f7252380fd7aefbd1
65ee4998322de93b37ebcb01af3348a1
4019f4ad52505f94034dd632d92a3d27
b90342c0cb844c8d77b54076dad6435f
57fce476cdaff267497f701ad49ee9f6
bdac321a23d5c0ae9b4cbfb3924f390a
14187686798a57b6d0988ecbb4208f50
12fec1833c45153b03ba3f4953b05540
53fc9ec40ecf398269b4ee25b8aec87b
aef8f5702d0ec73abe773edf876bbfd9
bcc38eadedb0d3590b8461648a21ef08
76cca880b240a5f7331787a172959fe2
6bf3bce96725bfcbe05dbcf9dd626902
bc8a48856b063f6dbbade49833f90545
-----END OpenVPN Static key V1-----" > /etc/openvpn/bsa-server-psk.key

openvpn --config bsa-server-psk.conf &

!!! UMÍSTIT TOTO NA PRVNÍ MÍSTO !!!
nameserver 192.168.20.244 	v /etc/resolv.conf

ping 192.168.4.160

kilall -9 openvpn

ip a del 192.168.4.160/24 dev ens18 
```

## OpenVPN - XXXXX Nejpravděpodobněji funkční verze Multiklient
```bash
https://two-oes.medium.com/how-to-setup-a-vpn-connection-with-openvpn-d2944b5ca768

apt install -y openvpn easy-rs openssl
cd /etc/openvpn/
cp -r /usr/share/easy-rsa /etc/openvpn/
cd /etc/openvpn/easy-rsa/3/

touch vars

chmod +x vars

./easyrsa init-pki
./easyrsa build-ca

./easyrsa gen-req my-server nopass
./easyrsa sign-req server my-server

# openssl verify -CAfile pki/ca.crt pki/issued/my-server.crt

./easyrsa gen-dh
./easyrsa gen-crl

cp pki/ca.crt /etc/openvpn/server/
cp pki/issued/my-server.crt /etc/openvpn/server/
cp pki/private/my-server.key /etc/openvpn/server/
cp pki/dh.pem /etc/openvpn/server/
cp pki/crl.pem /etc/openvpn/server/

systemctl start openvpn@server


./easyrsa gen-req client01 nopass
./easyrsa sign-req client client01
openssl verify -CAfile pki/ca.crt pki/issued/client01.crt
cp pki/ca.crt /etc/openvpn/client/
cp pki/issued/client01.crt /etc/openvpn/client/
cp pki/private/client01.key /etc/openvpn/client/

```


## OpenVPN
```bash
cd /etc/ca

./easyrsa init-pki
./easyrsa build-ca

./easyrsa gen-req vpn.jarda.bsa
./easyrsa sign server vpn.jarda.bsa
openssl rsa -in vpn.jarda.bsa.key -out vpn.jarda.bsa.key
./easyrsa gen-dh
mkdir keys
openvpn --genkey secret keys/ta.key
cp pki/ca.crt pki/issued/vpn.jarda.bsa.crt pki/private/vpn.jarda.bsa.key pki/dh.pem /etc/openvpn
cp keys/ta.key /etc/openvpn/

----------------
----------------
---------------

openssl rsa -in /etc/ca/pki/private/vpn.jarda.bsa.key -out /etc/ca/pki/private/vpn.jarda.bsa.key
cp pki/ca.crt pki/issued/vpn.jarda.bsa.crt pki/private/vpn.jarda.bsa.key pki/dh.pem /etc/openvpn

-------------------------
--------------------------
------------------------
-------------
./easyrsa build-server-full vpn_server nopass
./easyrsa sign-req server vpn_server              /etc/ca/pki/issued/vpn_server.crt
/easyrsa gen-dh                                   /etc/ca/pki/dh.pem
openvpn --genkey tls-crypt-v2-server pki/private/vpn_server.pem
cd /etc/openvpn/server
cd /etc/ca/pki/
cp ca.crt /etc/openvpn/server/
cp dh.pem /etc/openvpn/server/
cp issued/vpn_server.crt /etc/openvpn/server/
cd /etc/ca/pki/private/
cp vpn_server.key /etc/openvpn/server/
cp vpn_server.pem /etc/openvpn/server/
cd /etc/ca/pki/issued/
cp vpn_server.crt /etc/openvpn/server/

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

systemctl start openvpn-server@server.service

cd /etc/ca
./easyrsa gen-req Alice nopass
./easyrsa sign-req client Alice
cd pki
openvpn --tls-crypt-v2 private/vpn_server.pem --genkey tls-crypt-v2-client private/Alice.pem

mkdir /etc/openvpn/client/alice
cd /etc/ca/pki
cp ca.crt /etc/openvpn/client/alice
cp issued/Alice.crt /etc/openvpn/client/alice
cp private/Alice.key /etc/openvpn/client/alice
cp private/Alice.pem /etc/openvpn/client/alice
cd /etc/openvpn/client/alice

killall openvpn
-------------------------------------
https://simplificandoredes.com/en/install-open-vpn-on-linux/
------------------------------------
--------------------------------------
echo "client
dev tun
proto udp
remote 192.168.20.244 1194
remote-cert-tls server
nobind
persist-key
persist-tun
comp-lzo
verb 3
tls-auth ta.key 1

<ca>" > client.conf

cat ca.key >> client.conf

echo "</ca>

<cert>" >> client.conf

sed -ne '
   /-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p      # got the range, ok
   /-END CERTIFICATE-/q                            # bailing out soon as the cert end seen
' vpn.jarda.bsa.crt >> client.conf


echo "</cert>

<key>" >> client.conf

cat vpn.jarda.bsa.key >> client.conf

echo "</key>" >> client.conf







```


## OpenSSL
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

## GPG
```bash
gpg --full-generate-key

apt install rng-tools

apt-get install gnupg
gpg --gen-key
	Jaroslav Lehecka
	jarda@bsa-150.kiv.zcu.cz
P
	Passpharase: Heslo123.


ID:0A70A01AEB498812FFD86DAFE650F5122C482AAF
Selektor e-mail: jarda@bsa-150.kiv.zcu.cz

gpg --armor --output bsa-user.gpg --export jarda@bsa-150.kiv.zcu.cz


echo "DDDDD" > ahoj.txt
gpg -e ahoj.txt
	jarda@bsa-150.kiv.zcu.cz
gpg -d ahoj.txt.gpg


gpg --import
gpg --export
gpg --list-keys
gpg --list-sigs

gpg --sign --encrypt ahoj.txt
gpg --verify ahoj.txt.sig


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






$template errorLogs, "/var/log/errors/%$YEAR%/%$MONTH%/%$DAY%/errors.log"
:programname, endsswith, "error"  ?errorLogs

Tohle do /etc/rsyslog.d/bsa.conf

```



## Vzdálené logování


Vzdálené logování
------------------
```bash

přidám
# provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# naslouchat na 0.0.0.0/514/UDP
$UDPServerAddress 0.0.0.0
$UDPServerRun 514

$RepeatedMsgReduction on
$RepeatedMsgContainsOrigionalMsg on

# odesilat vsechny logy na server 147.228.67.150
*.* @147.228.67.150


watch --interval=1 ls -al R /var/log/logdir

apache 2 přesusnu: Listen 8888 /etc/apache2/ports.conf
sni - server name invocation - ke kterému serveru chci přistupovat - protože už bych během handshaku musel říci kam chci přistupovat

apache co loadne jako první je default ---- to je rozdíl oproti nginx
soft header request, sni - server name
ad logování z apache2


tee -  zapisuje jak do souboru, tak do souboru daného jako parameter -a

vim /usr/local/bin/http_log_error
bin bash hlavička -sheban
cat |/usr/bin/tee -a /var/log/www/error.log  | /usr/bin/logger -t httpd -p local6.err

grep usr 000

do 000-default.conf
errorlog "|/usr/local/bin/http_log_error"
accesslog "|/usr/local/bin/http_log_access" combined

mkdir -p /var/log/www/ && chown www-data:adm /var/log/www
chmod +x /usr/local/bin/http_log_error
chmod +x /usr/local/bin/http_log_access
 
 ls /var/log/www
```





## Bind9 + OpenDKIM

```bash
apt-get install bind9 dnsutils
service bind9 start|stop|restart

domain=jarda.bsa
echo "\$TTL    604800
@   IN  SOA $domain. root.localhost. (

                  2     ; Serial / YYYYMMDDXX
             604800     ; Refresh / seconds
              86400     ; Retry / seconds
            2419200 ; Expire / seconds
             604800 )   ; Negative Cache TTL / explicitni TTL

@         IN      NS                ns
ns        IN      A                 127.0.0.1
mail      IN      A                 127.0.0.1
posta     IN      A		    127.0.0.1
@         IN      MX           10   mail
@         IN      MX           20   posta
txt       IN      TXT               \"ahoj svete\"" > /etc/bind/db.$domain


echo "
zone \"$domain.\" in {
    type master;
    file \"/etc/bind/db.$domain\";
};" >> /etc/bind/named.conf.local

Pro jistotu přidej ručně:
sed '3 i         listen-on { 192.168.0.224; };' /etc/bind/named.conf.options

service bind9 restart

host jarda.bsa 192.168.20.244
```
### Nastavení zón

```bash
zone "jarda.bsa." in {
    type master;
    file "/etc/bind/db.jarda.bsa";
    allow-transfer {147.228.67.0/24;};
};

zone "lubos.bsa." in {
    type slave;
    file "/etc/bind/slave/slave.lubos.bsa";
    masters {147.228.67.41;};
};
```

## DNSSec -  nefunguje
```bsah
Entropie:
apt-get install haveged -y

mkdir /etc/bind/keys
cd /etc/bind/keys
dnssec-keygen -a ECDSAP256SHA256 -fK jarda.bsa
chmod g+r K*.private

ln -s /etc/bind/db.jarda.bsa /var/cache/bind

domain=jarda.bsa
echo "
zone \"$domain.\" in {
    type master;
    file \"/etc/bind/db.$domain\";
    inline-signing yes;
    auto-dnssec maintain;
    key-directory \"/etc/bind/keys\";
};" >> /etc/bind/named.conf.local

service bind9 restart
rndc reload
rndc signing -list jarda.bsa
rndc signing -nsec3param 1 0 10 deadbeef jarda.bsa 
```

## SPF - funguje
```bind
echo "
@  	IN 	TXT 	\"v=spf1 mx a:server.bsa-jindra.bsa ~all\"" >> /etc/bind/db.$domain

ZVYš Seriák!!!!!!!!!!!!!!!!!!!!

SPF odkud je e-mail odkud to může chodit
poslední věc říká co dělat když to nejde odtud
-all :vše zahoď
~all :funguje ale omarkuje
```

## DNSMASQ
```bind
apt -y install dnsmasq

echo "34.171.207.246 private.jarda.bsa
34.171.207.246 public.jarda.bsa" > /etc/dnsmasq.hosts

echo "listen-address=127.0.0.1
listen-address=10.0.10.4
bind-interfaces
log-queries
addn-hosts=/etc/dnsmasq.hosts" >>  /etc/dnsmasq.conf

service dnsmasq restart

dig @localhost ci.example.com +short

dig ci.example.com +short
```
