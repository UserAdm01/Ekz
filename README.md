# Ekz
Экзаменационное задание по ПМ.02. Организация сетевого администрирования
Сценарий.
Вы являетесь системным администратором компании в которой имеется гетерогенная сеть с использованием решений различных производителей. Серверная на основе Windows Server 2019 (Desktop и Core) AltLinux Server, есть клиентские машины на основе Windows 10 Pro и AltLinux. Часть сервисов уже развёрнута на компьютерах организации. В головном офисе компании имеется роутер для подключения к сети провайдера. Провайдер предоставляет подключение к глобальной сети, шлюз по умолчанию, а также выделенные адреса для подключения. В компании имеются сотрудники, которые работают на удалёнке на корпоративных ПК на основе Simply Linux, которые должны иметь доступ к информационной системе компании. Кроме того, в планах руководства есть желание построить корпоративный портал на отказоустойчивой инфраструктуре. Конечной целью является полноценное функционирование инфраструктуры предприятия в пределах соответствующих регионов. Имеющаяся инфраструктура представлена на диаграмме:

Image alt

Таблица адресации:

Image alt

Ваша задача донастроить инфраструктуру организации в соответствии с требованиями руководства компании.
Сервер DC является контроллером домена на нём развёрнуты сервисы Active Directory(домен – Oaklet.org), DNS.

Базовая конфигурация (подготовительные настройки):
FW (name, nameserver, gateway, addressing, nat, dhcp-relay)

set system host-name FW
set interface ethernet eth1 address 172.20.0.1/24
set interface ethernet eth2 address 172.20.2.1/23


set nat source rule 1 outboun-interface eth0
set nat source rule 2 outboun-interface eth0
set nat source rule 1 source address 172.20.0.0/24
set nat source rule 2 source address 172.20.2.0/23
set nat source rule 1 translation address masquerade
set nat source rule 2 translation address masquerade


set service dhcp-relay interface eth1
set service dhcp-relay interface eth2
set service dhcp-relay server 172.20.0.100
set service dhcp-relay relay-options relay-agents-packets discard

DC (DNS)

Add-DnsServerPrimaryZone -NetworkId "172.20.0.0/24" -ReplicationScope Domain
Add-DnsServerPrimaryZone -NetworkId "172.20.2.0/24" -ReplicationScope Domain
Add-DnsServerPrimaryZone -NetworkId "172.20.3.0/24" -ReplicationScope Domain
Add-DnsServerResourceRecordPtr -ZoneName 0.20.172.in-addr.arpa -Name 100 -PtrDomainName dc.Oaklet.org
Add-DnsServerResourceRecordA -Name "FS" -ZoneName "Oaklet.org" -AllowUpdateAny -IPv4Address "172.20.0.200" -CreatePtr
Add-DnsServerResourceRecordA -Name "SRV" -ZoneName "Oaklet.org" -AllowUpdateAny -IPv4Address "172.20.3.100" -CreatePtr

Add-DnsServerResourceRecordCName -Name "www" -HostNameAlias "SRV.Oaklet.org" -ZoneName "Oaklet.org"
Add-DnsServerPrimaryZone -Name first -ReplicationScope "Forest" –PassThru
Add-DnsServerResourceRecordA -Name "app" -ZoneName "first" -AllowUpdateAny -IPv4Address "200.100.100.200"
FS (Disabled Firewall)

powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled false
Add-Computer
    Администратор
    P@ssw0rd
        Oaklet.org
Restart-Computer
SRV (name, addressing)

su -
hostnamectl set-hostname SRV.Oaklet.org
reboot
ЦУС -> Сеть -> Ethernet-интерфейсы
IP: 172.20.3.100/23
Шлюз по умолчанию: 172.20.2.1
DNS-серверы: 172.20.0.100 77.88.8.8
Домены поиска: Oaklet.org
su -
apt-get update
apt-get install -y task-auth-ad-sssd
system-auth write ad Oaklet.org SRV Oaklet 'Администратор' 'P@ssw0rd'
reboot
APP-V (name, addressing, nat)

hostnamectl set-hostname APP-V
mkdir /etc/net/ifaces/enp0s8
cp /etc/net/ifaces/enp0s3/options /etc/net/ifaces/enp0s8


echo 10.116.0.10/14 >> /etc/net/ifaces/enp0s8/ipv4address
systemctl restart network
ip link set up enp0s3
ip link set up enp0s8


echo nameserver 77.88.8.8 > /etc/resolv.conf
apt-get update
apt-get install firewalld -y
systemctl enable --now firewalld


firewall-cmd --permanent --zone=trusted --add-interface=enp0s8
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload


echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf
sysctl -p

APP-L (name, addressing)

hostnamectl set-hostname APP-L
echo 10.116.0.20/14 >> /etc/net/ifaces/enp0s3/ipv4address
echo default via 10.116.0.10 > /etc/net/ifaces/enp0s3/ipv4route
systemctl restart network
ip link set up enp0s3
echo nameserver 77.88.8.8 > /etc/resolv.conf
APP-R (name, addressing)

hostnamectl set-hostname APP-R
echo 10.116.0.30/14 >> /etc/net/ifaces/enp0s3/ipv4address
echo default via 10.116.0.10 > /etc/net/ifaces/enp0s3/ipv4route
systemctl restart network
ip link set up enp0s3
echo nameserver 77.88.8.8 > /etc/resolv.conf
CLI-R (name, addressing)

su -
hostnamectl set-hostname CLI-R
reboot
ЦУС -> Сеть -> Ethernet-интерфейсы
IP: 200.100.100.10/24
Шлюз по умолчанию: 200.100.100.254
DNS-серверы: 77.88.8.8 172.20.0.100


su -
ip link set up enp0s3

Элементы доменной инфраструктуры:
На сервере контроллера домена необходимо развернуть следующую организационную структуру:

Image alt

New-ADOrganizationalUnit -Name ADM
New-ADOrganizationalUnit -Name Sales
New-ADOrganizationalUnit -Name Delivery
New-ADOrganizationalUnit -Name Development

New-ADGroup "ADM" -path 'OU=ADM,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Sales" -path 'OU=Sales,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Delivery" -path 'OU=Delivery,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Frontend" -path 'OU=Development,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Backend" -path 'OU=Development,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose

New-ADUser -Name "Director" -UserPrincipalName "Director@Oaklet.org" -Path "OU=ADM,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Secretary" -UserPrincipalName "Secretary@Oaklet.org" -Path "OU=ADM,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Alice" -UserPrincipalName "Alice@Oaklet.org" -Path "OU=Sales,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Bob" -UserPrincipalName "Bob@Oaklet.org" -Path "OU=Sales,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Polevikova" -UserPrincipalName "Polevikova@Oaklet.org" -Path "OU=Delivery,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Morgushko" -UserPrincipalName "Morgushko@Oaklet.org" -Path "OU=Development,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Radjkovith" -UserPrincipalName "Radjkovith@Oaklet.org" -Path "OU=Development,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true

New-ADUser -Name "smb" -UserPrincipalName "smb@Oaklet.org" -Path "DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true

Add-AdGroupMember -Identity ADM Director, Secretary
Add-AdGroupMember -Identity Sales Alice, Bob
Add-AdGroupMember -Identity Delivery Polevikova
Add-AdGroupMember -Identity Frontend Morgushko
Add-AdGroupMember -Identity Backend Radjkovith

Должны быть настроены следующие GPO:
отключить OneDrive ( имя политики onedrive);
Запретить чтение информации со съёмных носителей ( имя политики removable media);
Отключить использование камер (имя политики camera);
Запретить любые изменения персонализации рабочего стола ( имя политики desktop);
New-GPO -Name "onedrive" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Компоненты Windows -> OneDrive -> Запретить использование OneDrive для хранения файлов (включить)


New-GPO -Name "removable media" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Система -> Доступ к съемным запоминающим устройствам -> Съемные запоминающие устройства всех классов: Запретить любой доступ (включить)
Конфигурация пользователя -> Политики -> Административные шаблоны -> Система -> Доступ к съемным запоминающим устройствам -> Съемные запоминающие устройства всех классов: Запретить любой доступ (включить)


New-GPO -Name "camera" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Компоненты Windows -> Камера -> Разрешить использование камер (Отключить)


New-GPO -Name "desktop" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация пользователя -> Политики -> Административные шаблоны -> Панель управления -> Персонализация


powershell
gpupdate /force
Для обеспечения отказоустойчивости сервер контроллера домена должен выступать DHCP failover для подсети Clients:
Он должен принимать управление в случае отказа основного DHCP сервера;
Install-WindowsFeature DHCP –IncludeManagementTools
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
Restart-Service -Name DHCPServer -Force


Add-DhcpServerv4Scope -Name “Clients-failover” -StartRange 172.20.2.1 -EndRange 172.20.3.254 -SubnetMask 255.255.254.0 -State InActive
Set-DhcpServerv4OptionValue -ScopeID 172.20.2.0 -DnsDomain Oaklet.org -DnsServer 172.20.0.100,77.88.8.8 -Router 172.20.2.1
Add-DhcpServerv4ExclusionRange -ScopeID 172.20.2.0 -StartRange 172.20.2.1 -EndRange 172.20.2.1
Add-DhcpServerv4ExclusionRange -ScopeID 172.20.2.0 -StartRange 172.20.3.100 -EndRange 172.20.3.100
Set-DhcpServerv4Scope -ScopeID 172.20.2.0 -State Active
Организуйте DHCP сервер на базе SRV
Используйте подсеть Clients учётом существующей инфраструктуры в таблице адресации;
Клиенты CLI-L и CLI-W получают адрес и все необходимые сетевые параметры по DHCP, обеспечивая связность с сетью Интернет и подсетью Servers;
Через веб-интерфейс "https://localhost:8080": (вариант для девочек)

Image alt

Вариант для нормальных пацанов:

apt-get install -y dhcp-server
vi /etc/dhcp/dhcpd.conf

ddns-update-style none;
subnet 172.20.2.0 netmask 255.255.254.0 {
        option routers                  172.20.2.1;
        option subnet-mask              255.255.254.0;
        option domain-name              "Oaklet.org";
        option domain-name-servers      172.20.0.100, 77.88.8.8;

        range dynamic-bootp 172.20.3.101 172.20.3.254;
        default-lease-time 21600;
        max-lease-time 43200;
}
vi /etc/sysconfig/dhcpd

    DHCPDARGS=enp0s3
systemctl enable --now dhcpd
Организуйте сервер времени на базе SRV
Данный сервер должен использоваться всеми ВМ внутри региона Office;
Сервер считает собственный источник времени верным;
apt-get install -y chrony

vi /etc/chrony.conf
    allow 172.20.0.0/24
    allow 172.20.2.0/23
    
systemctl enable --now chronyd
DC, FS

Start-Service W32Time
w32tm /config /manualpeerlist:172.20.3.100 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
CLI-W

New-NetFirewallRule -DisplayName "NTP" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
Start-Service W32Time
w32tm /config /manualpeerlist:172.20.3.100 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
Set-Service -Name W32Time -StartupType Automatic
CLI-L

su -
vi /etc/chrony.conf
    pool 172.20.3.100 iburst
    allow 172.20.2.0/23
systemctl restart chronyd

FW

configure
set system ntp server 172.20.3.100
commit
save
Все клиенты региона Office должны быть включены в домен
С клиентов должен быть возможен вход под любой учётной записью домена;
На клиентах должны применятся настроенные групповые политики;
Необходимо обеспечить хранение перемещаемого профиля пользователя Morgushko;
CLI-W

Rename-Computer -NewName CLI-W
Restart-Computer
Add-Computer
    Администратор
    P@ssw0rd
        Oaklet.org
Restart-Computer
CLI-L

su -
hostnamectl set-hostname CLI-L.Oaklet.org
reboot
su - 
apt-get update
apt-get install -y task-auth-ad-sssd
system-auth write ad Oaklet.org CLI-L Oaklet 'Администратор' 'P@ssw0rd'
reboot
DC

New-Item -Path "С:\" -Name "roaming_users" -ItemType "directory"

New-SmbShare -Name "roaming_users" -Path "C:\roaming_users\" -FullAccess Oaklet\Администратор
Средства -> Пользователи и компьютеры Active Directory -> Development -> Morgushko (ПКМ) -> Свойства -> Профиль -> Пусть к профилю: \\DC\roaming_users\%username%
Организуйте общий каталог для ВМ CLI-W и CLI-L на базе FS:
Хранение файлов осуществляется на диске, реализованном по технологии RAID5;
Создать общую папку для пользователей;
Публикуемый каталог D:\opt\share;
Смонтируйте каталог на клиентах /mnt/adminshare и D:\adminshare соответственно;
Разрешите чтение и запись на всех клиентах:
Определить квоту максимальный размер в 20 мб для пользователей домена;
Монтирование каталогов должно происходить автоматически;
diskpart

select disk 1
attrib disk clear readonly
convert dynamic

select disk 2
attrib disk clear readonly
convert dynamic

select disk 3
attrib disk clear readonly
convert dynamic

select disk 4
attrib disk clear readonly
convert dynamic

select disk 5
attrib disk clear readonly
convert dynamic

create volume raid disk=1,2,3,4,5

select volume 0
assign letter=B

select volume 3
assign letter=D
format fs=ntfs
powershell
Install-WindowsFeature -Name "FS-FileServer"
Install-WindowsFeature -Name "FS-Resource-Manager"
Restart-Computer
New-Item -Path "D:\" -Name "opt" -ItemType "directory"
New-Item -Path "D:\opt\" -Name "share" -ItemType "directory"

New-SmbShare -Name "share" -Path "D:\opt\share\" -FullAccess Oaklet\Администратор
Grant-SmbShareAccess -Name "share" -AccountName "Oaklet\smb" -AccessRight Full -Force

New-FsrmQuotaTemplate -Name "20MB" -Size 20MB
New-FsrmQuota -Path "D:\opt\share\" -Template "20MB"
CLI-W

powershell
diskpart
list volume 0 
assign letter=B
New-SmbMapping -LocalPath D: -RemotePath \\FS\share -Username smb -Password P@ssw0rd -Persistent $true

DC

GPO:
Конфигурация пользователя -> Настройка -> Конфигурация Windows -> Сопоставление дисков -> ПКМ -> Создать -> Сопоставленный диск ->:
    Размещение: \\FS\share
    Подпись: adminshare
    Использовать: D
-> Общие параметры:
    Выполнять в контексте безопастности вошедшего пользователя
    Нацеливание на уровень элемента -> Нацеливание:
        Создать элемент -> Группа безопасности -> добавить группы
gpupdate /force   
CLI-W

powershell
gpupdate /force
CLI-L

su -
apt-get install -y cifs-utils

mkdir /mnt/adminshare
chmod 777 /mnt/adminshare

echo '//FS.Oaklet.org/share /mnt/adminshare cifs users,credentials=/etc/samba/sabmacreds,file_mode=0777,dir_mode=0777 0 0' >> /etc/fstab

vi /etc/samba/sabmacreds
username=smb
password=P@ssw0rd

chmod 600 /etc/samba/sabmacreds
chown root: /etc/samba/sabmacreds

mount -a

На файловом сервере FS также хранятся стартовые страницы корпоротивного портала:
для APP-L находится в C:\site\index1.html для APP-L;
для APP-R находится в C:\site\index2.html для APP-R;
Необходимо их загрузить на серверы региона Application вместе с сопутствующими файлами.
APP-V

vi /etc/openssh/sshd_config

    PermitRootLogin yes
systemctl restard sshd.service
APP-L

vi /etc/openssh/sshd_config

    PermitRootLogin yes
systemctl restard sshd.service
APP-R

vi /etc/openssh/sshd_config

    PermitRootLogin yes
systemctl restard sshd.service
FS

Add-WindowsCapability -Online -Name OpenSSH.Client*

scp "C:\site\index1.html" "C:\site\index2.html" root@app.first:/tmp
    yes
    P@ssw0rd
APP-V
scp /tmp/index1.html root@10.116.0.20:/tmp
    yes
    P@ssw0rd
scp /tmp/index2.html root@10.116.0.30:/tmp
    yes
    P@ssw0rd
Реализуйте центр сертификации на базе SRV.
Клиенты СLI-L, CLI-W, CLI-R должны доверять сертификатам;
SRV

Через веб-интерфейс "https://localhost:8080": (вариант для девочек)

Image alt

Вариант для нормальных пацанов:

su - 
mkdir /var/ca
cd /var/ca

openssl req -newkey rsa:4096 -keyform PEM -keyout ca.key -x509 -days 3650 -outform PEM -out ca.cer
    P@ssw0rd
    P@ssw0rd
    Country Name: RU
    Organization Name: Oaklet.org
    Common Name: Oaklet.org CA
vi /etc/openssh/sshd_config

    PermitRootLogin yes
systemctl restart sshd.service
FS

scp root@SRV.Oaklet.org:/var/ca/ca.cer D:\opt\share
    yes
    P@ssw0rd
CLI-W

Import-Certificate -FilePath "D:\ca.cer" -CertStoreLocation cert:\CurrentUser\Root
CLI-L

su -
cp /mnt/adminshare/ca.cer /etc/pki/ca-trust/source/anchors/ && update-ca-trust
CLI-R

ip route add 172.20.0.0/24 via 200.100.100.100
ip route add 172.20.2.0/23 via 200.100.100.100

scp root@SRV.Oaklet.org:/var/ca/ca.cer /etc/pki/ca-trust/source/anchors/ && update-ca-trust
    yes
    P@ssw0rd
Необходимо реализовать следующую инфраструктуру приложения на базе SRV
На нём должно быть активировано внутренне приложение, исполняющееся в контейнере и отвечающее на запросы из браузера клиентов (образ и все необходимые пакеты для работы приложения уже установленны);
Образ приложения расположен по пути: /home/admin/docker;
Доступ к приложению осуществляется по DNS-имени www.Oaklet.org;
SRV

su -

systemctl enable --now docker.service

cd /home/admin/docker

docker build -t  app .
docker run --name app -p 80:5000 -d app
Image alt

На клиенте под управлением Windows должен быть создан шифрованный Bitlocker раздел диска от пользователя уровня ADM.
CLI-W

powershell
logoff
    CLI-W\user
    P@ssw0rd
Управление дисками -> Диск 0 -> ПКМ -> Сжать том -> Размер сжимаемого пространства: 5120 -> Сжать
ПКМ -> Создать простой том -> U:
logoff
    Director
    P@ssw0rd

# Должен быть в группе Администраторы Домена
Enable-BitLocker -MountPoint U: -PasswordProtector
В общих локальных документах должен быть создан текстовый файл с записью внутри: “Секретное содержимое”, зашифрованный EFS.
CLI-W

New-Item -Path "C:\Users\Public\Documents\file.txt" -ItemType "file" -Value "Секретное содержимое"

cipher /e C:\Users\Public\Documents\file.txt
Сетевая связность:
Реализуйте связность конпонентов инфраструктуры с применением технологии VPN.
Соединяются регионы Office и Application;
Соединение должно быть защищено;
При повторном запуске – восстанавливаться;
Все хосты регионов должны взаимодействовать друг с другом;
FW

sudo su
mkdir /etc/wireguard/keys
cd /etc/wireguard/keys
wg genkey | tee srv-sec.key | wg pubkey > srv-pub.key
wg genkey | tee cli-sec.key | wg pubkey > cli-pub.key

cat srv-sec.key cli-pub.key >> /etc/wireguard/wg0.conf

vi /etc/wireguard/wg0.conf
  [Interface]
  Address = 10.20.30.1/30
  ListenPort = 12345
  PrivateKey = srv-sec.key
  
  [Peer]
  PublicKey = cli-pub.key
  AllowedIPs = 10.20.30.0/30

systemctl enable --now wg-quick@wg0

scp srv-pub.key cli-sec.key root@200.100.100.200:/tmp
reboot
APP-V

apt-get install -y wireguard-tools wireguard-tools-wg-quick
cd /tmp

mkdir /etc/wireguard

cat cli-sec.key srv-pub.key >> /etc/wireguard/wg0.conf

vi /etc/wireguard/wg0.conf
  [Interface]
  Address = 10.20.30.2/30
  PrivateKey = cli-sec.key

  [Peer]
  PublicKey = srv-pub.key
  Endpoint = 200.100.100.100:12345
  AllowedIPs = 10.20.30.0/30, 172.20.0.0/24, 172.20.2.0/23
  PersistentKeepalive = 10
firewall-cmd --permanent --add-port=12345/{tcp,udp}
firewall-cmd --permanent --add-interface=wg0 --zone=public
firewall-cmd --reload
systemctl enable --now wg-quick@wg0
CLI-R должен получать удалённый доступ к каналам инфраструктуры, в частности к DNS серверу.
Выполнен ранее

Работа приложения:
В регионе APP должен хостится корпоративный портал. Он развёртывается на APP-L и APP-R.
APP-L

apt-get update
apt-get install -y nginx

systemctl enable --now nginx

mkdir -p /var/www/html
cp /opt/index1.html /var/www/html

mv /var/www/html/index1.html /var/www/html/index.html
vi /etc/nginx/sites-available.d/default.conf
    listen 80 default_server;

ln -s /etc/nginx/sites-available.d/default.conf /etc/nginx/sites-enabled.d/default.conf
nginx -t 
systemctl restart nginx
APP-R

apt-get update
apt-get install -y nginx

systemctl enable --now nginx

mkdir -p /var/www/html
cp /opt/index2.html /var/www/html

mv /var/www/html/index2.html /var/www/html/index.html
vi /etc/nginx/sites-available.d/default.conf
    listen 80 default_server;

ln -s /etc/nginx/sites-available.d/default.conf /etc/nginx/sites-enabled.d/default.conf
nginx -t 
systemctl restart nginx
Корпоративный портал должен быть доступен по адресу app.first.
Клиентами должны быть CLI-L, CLI-W, CLI-R.
Доступ должен осуществляться по внешнему каналу, внутренний прямой доступ к вебслужбам на на хостах APP-L и APP-R запрещён.
Доступ к порталу должен осуществляться по защищённому каналу. Незащищённые HTTP-соединения автоматически переводятся на защищённый канал. Перевод осуществляется с сохранением параметров запроса.
В любом из сценариев высокой доступности простой не должен составлять более 20 секунд.
Портал должен быть доступен при отказе одного из APP-L(R) хостов.
APP-V

mkdir cert
cd cert

openssl genrsa -out app.key 4096
openssl req -new -key app.key -out app.req -sha256
    Country Name: RU
    Organization Name: Oaklet.org
    Common Name: app.first
scp app.req root@172.20.3.100:/var/ca
SRV

su -
cd /var/ca
openssl x509 -req -in app.req -CA ca.cer -CAkey ca.key -set_serial 100 -extentions app -days 1460 -outform PEM -out app.cer -sha256
    P@ssw0rd
APP-V

scp root@172.20.3.100:/var/ca/app.cer ./
mkdir -p /etc/pki/nginx/private

cp app.cer /etc/pki/nginx/
cp app.key /etc/pki/nginx/private
apt-get install -y nginx
systemctl enable --now nginx

vi /etc/nginx/sites-available.d/proxy.conf
Image alt

ln -s /etc/nginx/sites-available.d/proxy.conf /etc/nginx/sites-enabled.d/proxy.conf

nginx -t
systemctl restart nginx 
firewall-cmd --permanent --add-service={http,https}
firewall-cmd --reload
CLI-W

Image alt

CLI-L

Image alt
