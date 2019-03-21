#!/bin/bash

# JShielder v2.3
# Deployer for Ubuntu Server 18.04 LTS
#
# Jason Soto
# www.jasonsoto.com
# www.jsitech-sec.com
# Twitter = @JsiTech

# Based from JackTheStripper Project
# Credits to Eugenia Bahit

# A lot of Suggestion Taken from The Lynis Project
# www.cisofy.com/lynis
# Credits to Michael Boelen @mboelen


source helpers.sh

##############################################################################################################

f_banner(){
echo
echo "

     ¦¦+¦¦¦¦¦¦¦+¦¦+  ¦¦+¦¦+¦¦¦¦¦¦¦+¦¦+     ¦¦¦¦¦¦+ ¦¦¦¦¦¦¦+¦¦¦¦¦¦+
     ¦¦¦¦¦+----+¦¦¦  ¦¦¦¦¦¦¦¦+----+¦¦¦     ¦¦+--¦¦+¦¦+----+¦¦+--¦¦+
     ¦¦¦¦¦¦¦¦¦¦+¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦+  ¦¦¦     ¦¦¦  ¦¦¦¦¦¦¦¦+  ¦¦¦¦¦¦++
¦¦   ¦¦¦+----¦¦¦¦¦+--¦¦¦¦¦¦¦¦+--+  ¦¦¦     ¦¦¦  ¦¦¦¦¦+--+  ¦¦+--¦¦+
+¦¦¦¦¦++¦¦¦¦¦¦¦¦¦¦¦  ¦¦¦¦¦¦¦¦¦¦¦¦¦+¦¦¦¦¦¦¦+¦¦¦¦¦¦++¦¦¦¦¦¦¦+¦¦¦  ¦¦¦
+----+ +------++-+  +-++-++------++------++-----+ +------++-+  +-+

Pour debian 9 traduis en français
Developed By Jason Soto @Jsitech"
echo
echo

}

##############################################################################################################

#  Vérifier si en cours d'exécution avec l'utilisateur root

clear
f_banner


check_root() {
if [ "$USER" != "root" ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
else
      clear
      f_banner
      cat templates/texts/welcome
fi
}

##############################################################################################################

# Installation de dépendances
# Pré requis requis seront mis en place ici
install_dep(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Définition de conditions préalables"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt install spinner #install spinner not default debian
   apt install e2fslibs # install for chattr
   apt -y install lsb-release apt-transport-https ca-certificates #install php 7.3
   wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
   echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php7.3.list
   say_done
}

##############################################################################################################

#  Configurer le nom d'hôte
config_host() {
echo -n " Voulez-vous définir un nom d’hôte? (y/n): "; read config_host
if [ "$config_host" == "y" ]; then
    serverip=$(__get_ip)
    echo " Tapez un nom pour identifier ce serveur:"
    echo -n " (Par exemple: myserver): "; read host_name
    echo -n " Tapez le nom de domaine ?: "; read domain_name
    echo $host_name > /etc/hostname
    hostname -F /etc/hostname
    echo "127.0.0.1    localhost.localdomain      localhost" >> /etc/hosts
    echo "$serverip    $host_name.$domain_name    $host_name" >> /etc/hosts
    #Creating Legal Banner for unauthorized Access
    echo ""
    echo "Créer des bannières légales pour un accès non autorisé"
    spinner
    cat templates/motd > /etc/motd
    cat templates/motd > /etc/issue
    cat templates/motd > /etc/issue.net
    sed -i s/server.com/$host_name.$domain_name/g /etc/motd /etc/issue /etc/issue.net
    echo "OK "
fi
    say_done
}

##############################################################################################################

# Configurer le fuseau horaire
config_timezone(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Nous allons maintenant configurer le fuseau horaire"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
   say_done
}

##############################################################################################################

# Système de mise à jour, outil d’installation sysv-rc-conf
update_system(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Mise à jour du système"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt update
   apt upgrade -y
   apt dist-upgrade -y
   say_done
}

##############################################################################################################

#  Définir un UMASK plus restrictif
restrictive_umask(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Définir UMASK sur une valeur plus restrictive (027)"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   cp templates/login.defs /etc/login.defs
   # sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc
   echo ""
   echo "OK"
   say_done
}

#############################################################################################################

#Désactivation des systèmes de fichiers inutilisés

unused_filesystems(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Désactivation des systèmes de fichiers inutilisés"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done
}

##############################################################################################################

uncommon_netprotocols(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m  Désactivation des protocoles de réseau inhabituels"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done

}

##############################################################################################################

# Créer un utilisateur privilégié
admin_user(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Nous allons maintenant créer un nouvel utilisateur"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Tapez le nouveau nom d'utilisateur: "; read username
    adduser $username
    say_done
}

##############################################################################################################

# Instruction pour générer des clés RSA
rsa_keygen(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Instructions pour générer une paire de clés RSA"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    serverip=$(__get_ip)
    echo " *** SI VOUS N'AVEZ PAS UNE CLE PUBLIQUE RSA, GENEREZ UN ***"
    echo "     Suivez les instructions et appuyez sur Entrée quand c'est fait"
    echo "     Recevoir une nouvelle instruction"
    echo " "
    echo "    LANCE LES COMMANDES SUIVANTES"
    echo -n "     a) ssh-keygen -t rsa -b 4096 "; read foo1
    echo -n "     b) cat /home/$username/.ssh/id_rsa.pub >> /home/$username/.ssh/authorized_keys "; read foo2
    say_done
}
##############################################################################################################

# Déplacer la clé publique générée
rsa_keycopy(){
    echo " Exécuter la commande suivante pour copier la clé"
    echo " Appuyez sur ENTER une fois terminé "
    echo " ssh-copy-id -i $HOME/.ssh/id_rsa.pub $username@$serverip "
    say_done
}
##############################################################################################################

#Sécurisation du dossier /tmp
secure_tmp(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Sécurisation du dossier /tmp"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " Avez-vous créé une partition séparée / tmp lors de l’installation initiale?(y/n): "; read tmp_answer
  if [ "$tmp_answer" == "n" ]; then
      echo "Nous allons créer un système de fichiers pour le répertoire / tmp et définir les autorisations appropriées "
      spinner
      dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000
      mkdir /tmpbackup
      cp -Rpf /tmp /tmpbackup
      mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
      chmod 1777 /tmp
      cp -Rpf /tmpbackup/* /tmp/
      rm -rf /tmpbackup
      echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
      sudo mount -o remount /tmp
      say_done
  else
      echo "Bien joué, n'oubliez pas de définir les permissions appropriées dans /etc/fstab"
      echo ""
      echo "Example:"
      echo ""
      echo "/dev/sda4   /tmp   tmpfs  loop,nosuid,noexec,rw  0 0 "
      say_done
  fi
}

##############################################################################################################

# SSH sécurisé
secure_ssh(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Sécurisation de SSH"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Securing SSH..."
    spinner
    sed s/USERNAME/$username/g templates/sshd_config > /etc/ssh/sshd_config; echo "OK"
    chattr -i /home/$username/.ssh/authorized_keys
    service ssh restart
    say_done
}

##############################################################################################################

# Définir les règles IPTABLES
set_iptables(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Définition des règles IPTABLE"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Définition des règles Iptables..."
    spinner
    sh templates/iptables.sh
    cp templates/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
    say_done
}

##############################################################################################################

# Installer fail2ban
    # Pour supprimer une règle Fail2Ban, utilisez:
    # iptables -D fail2ban-ssh -s IP -j DROP
install_fail2ban(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de Fail2Ban"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install sendmail
    apt install fail2ban
    say_done
}

##############################################################################################################

# Installer, configurer et optimiser MySQL
install_secure_mysql(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installer, Configurer et Optimiser MySQL"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install mysql-server
    echo ""
    echo -n " configuration de MySQL............ "
    spinner
    cp templates/mysql /etc/mysql/mysqld.cnf; echo " OK"
    mysql_secure_installation
    cp templates/usr.sbin.mysqld /etc/apparmor.d/local/usr.sbin.mysqld
    service mysql restart
    say_done
}

##############################################################################################################

# Installer Apache
install_apache(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installation du serveur Web Apache"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install apache2
  say_done
}

##############################################################################################################

# Installer Nginx avec ModSecurity
install_nginx_modsecurity(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Téléchargement et compilation de Nginx avec ModSecurity"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt -y install git build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-prefork-dev libxml2-dev libcurl4-openssl-dev
  mkdir src
  cd src/
  git clone https://github.com/SpiderLabs/ModSecurity
  cd ModSecurity
  ./autogen.sh
  ./configure --enable-standalone-module
  make
  cd ..
  wget http://nginx.org/download/nginx-1.9.7.tar.gz
  tar xzvf nginx-1.9.7.tar.gz
  cp ../templates/ngx_http_header_filter_module.c nginx-1.9.7/src/http/ngx_http_header_filter_module.c
  cd nginx-1.9.7/
  ./configure --user=www-data --group=www-data --with-pcre-jit --with-debug --with-http_ssl_module --add-module=/root/JShielder/UbuntuServer_14.04LTS/src/ModSecurity/nginx/modsecurity
  make
  make install
  #Remplacement de Nginx conf avec des configurations sécurisées
  cp ../../templates/nginx /usr/local/nginx/conf/nginx.conf
  #Jason Giedymin Nginx Init Script
  wget https://raw.github.com/JasonGiedymin/nginx-init-ubuntu/master/nginx -O /etc/init.d/nginx
  chmod +x /etc/init.d/nginx
  update-rc.d nginx defaults
  mkdir /usr/local/nginx/conf/sites-available
  mkdir /usr/local/nginx/conf/sites-enabled
  say_done
}
  ##############################################################################################################

  #Configuration de l'hôte virtuel
  set_nginx_vhost(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Configurer un hôte virtuel"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo " Configurer un hôte virtuel"
  echo " Tapez un nom pour identifier l'hôte virtuel"
  echo -n " (Par exemple: myserver.com) "; read vhost
  touch /usr/local/nginx/conf/sites-available/$vhost
  cd ../..
  cat templates/nginxvhost >> /usr/local/nginx/conf/sites-available/$vhost
  sed -i s/server.com/$vhost/g /usr/local/nginx/conf/sites-available/$vhost
  ln -s /usr/local/nginx/conf/sites-available/$vhost /usr/local/nginx/conf/sites-enabled/$vhost
  say_done
}


##############################################################################################################

#Configuration de l'hôte virtuel
set_nginx_vhost_nophp(){
clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m Configurer l'hôte virtuel pour Nginx"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo "  Configurer un hôte virtuel "
echo " Tapez un nom pour identifier l'hôte virtuel"
echo -n " (For Example: myserver.com) "; read vhost
touch /usr/local/nginx/conf/sites-available/$vhost
cd ../..
cat templates/nginxvhost_nophp >> /usr/local/nginx/conf/sites-available/$vhost
sed -i s/server.com/$vhost/g /usr/local/nginx/conf/sites-available/$vhost
ln -s /usr/local/nginx/conf/sites-available/$vhost /usr/local/nginx/conf/sites-enabled/$vhost
say_done
}


##############################################################################################################

# Définir les règles OWASP de Nginx Modsecurity
set_nginx_modsec_OwaspRules(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Définition des règles OWASP pour ModSecurity sur Nginx"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  cd src/
  wget https://github.com/SpiderLabs/owasp-modsecurity-crs/tarball/master -O owasp.tar.gz
  tar -zxvf owasp.tar.gz
  owaspdir=$(ls -la | grep SpiderLabs | cut -d ' ' -f18)
  cp ModSecurity/modsecurity.conf-recommended /usr/local/nginx/conf/modsecurity.conf
  cp ModSecurity/unicode.mapping /usr/local/nginx/conf/
  cd $owaspdir/
  cat modsecurity_crs_10_setup.conf.example >> /usr/local/nginx/conf/modsecurity.conf
  cd base_rules/
  cat *.conf >> /usr/local/nginx/conf/modsecurity.conf
  cp *.data /usr/local/nginx/conf/
  cd ../../..
  service nginx restart
  say_done
}


##############################################################################################################

# Installer, configurer et optimiser PHP
install_secure_php(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installer, Configurer et Optimiser PHP"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install -y php php-cli php-pear
    apt install -y php-mysql python-mysqldb libapache2-mod-php7.3
    echo ""
    echo -n " Remplacement de php.ini..."
    spinner
    cp templates/php /etc/php/7.3/apache2/php.ini; echo " OK"
    cp templates/php /etc/php/7.3/cli/php.ini; echo " OK"
    service apache2 restart
    say_done
}

##############################################################################################################
# Installer, configurer et optimiser PHP pour Nginx
install_php_nginx(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installer, Configurer et Optimiser PHP/PHP-FPM"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install php-fpm php php-cli php-pear
  apt install php-mysql python-mysqldb
  echo ""
  echo -n " Remplacement de php.ini..."
  spinner
  cp templates/php /etc/php/7.0/cli/php.ini; echo " OK"
  cp templates/phpnginx /etc/php/7.0/fpm/php.ini; echo "OK"
  service php-fpm restart
  service nginx restart
  say_done
}

##############################################################################################################

# Installer ModSecurity
install_modsecurity(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de ModSecurity"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install libxml2 libxml2-dev libxml2-utils
    apt install libaprutil1 libaprutil1-dev
    apt install libapache2-mod-security2
    service apache2 restart
    say_done
}

##############################################################################################################

# Configurer OWASP pour ModSecurity
set_owasp_rules(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Configuration des règles OWASP pour ModSecurity"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

    #for archivo in /usr/share/modsecurity-crs/base_rules/*
     #   do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    #done

    #for archivo in /usr/share/modsecurity-crs/optional_rules/*
    #    do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    #done
    spinner
    echo "OK"

    sed s/SecRuleEngine\ DetectionOnly/SecRuleEngine\ On/g /etc/modsecurity/modsecurity.conf-recommended > salida
    mv salida /etc/modsecurity/modsecurity.conf

    echo 'SecServerSignature "AntiChino Server 1.0.4 LS"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Powered-By "Plankalkül 1.0"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Mamma "Mama mia let me go"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf

    a2enmod headers
    service apache2 restart
    say_done
}

##############################################################################################################

# Configure and optimize Apache
secure_optimize_apache(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Configurer et optimiser Apache"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    cp templates/apache /etc/apache2/apache2.conf
    echo " -- Activer ModRewrite"
    spinner
    a2enmod rewrite
    service apache2 restart
    say_done
}

##############################################################################################################

# Installer ModEvasive
install_modevasive(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de ModEvasive"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Tape un Email pour recevoir des alertes "; read inbox
    apt install libapache2-mod-evasive
    mkdir /var/log/mod_evasive
    chown www-data:www-data /var/log/mod_evasive/
    sed s/MAILTO/$inbox/g templates/mod-evasive > /etc/apache2/mods-available/mod-evasive.conf
    service apache2 restart
    say_done
}

##############################################################################################################

#  Installer Mod_qos/spamhaus
install_qos_spamhaus(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de Mod_Qos/spamhaus"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt -y install libapache2-mod-qos
    cp templates/qos /etc/apache2/mods-available/qos.conf
    wget http://ftp.us.debian.org/debian/pool/main/m/mod-spamhaus/libapache2-mod-spamhaus_0.7-1_amd64.deb #spamhaus not maintained next change limapapche2-mod-defensible maybe
    dpkg -i libapache2-mod-spamhaus_0.7-1_amd64.deb
    cp templates/spamhaus /etc/apache2/mods-available/spamhaus.conf
    service apache2 restart
    say_done
}

##############################################################################################################

# Configurez fail2ban
config_fail2ban(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Configuration de Fail2Ban"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Configuration de Fail2Ban......"
    spinner
    sed s/MAILTO/$inbox/g templates/fail2ban > /etc/fail2ban/jail.local
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.conf
    /etc/init.d/fail2ban restart
    say_done
}

##############################################################################################################

# Installer des paquets supplémentaires
additional_packages(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de packages supplémentaires"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Install tree............."; apt install tree
    echo "Install Python-MySQLdb..."; apt install python-mysqldb
    echo "Install WSGI............."; apt install libapache2-mod-wsgi
    echo "Install PIP.............."; apt install python-pip
    echo "Install Vim.............."; apt install vim
    echo "Install Nano............."; apt install nano
    echo "Install pear............."; apt install php-pear
    echo "Install DebSums.........."; apt install debsums
    echo "Install apt-show-versions"; apt install apt-show-versions
    echo "Install PHPUnit..........";
    pear config-set auto_discover 1
    mv phpunit-patched /usr/share/phpunit
    echo include_path = ".:/usr/share/phpunit:/usr/share/phpunit/PHPUnit" >> /etc/php/7.2/cli/php.ini
    echo include_path = ".:/usr/share/phpunit:/usr/share/phpunit/PHPUnit" >> /etc/php/7.2/apache2/php.ini
    service apache2 restart
    say_done
}

##############################################################################################################

#Ajuster et sécuriser le noyau
tune_secure_kernel(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Optimisation et sécurisation du noyau Linux"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Sécuriser le noyau Linux"
    spinner
    echo "* hard core 0" >> /etc/security/limits.conf
    cp templates/sysctl.conf /etc/sysctl.conf; echo " OK"
    cp templates/ufw /etc/default/ufw
    sysctl -e -p
    say_done
}

##############################################################################################################

# Installez RootKit Hunter
install_rootkit_hunter(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de RootKit Hunter"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Rootkit Hunter est un outil d’analyse permettant de s’assurer que vous n’avez plus d’outil méchant. Cet outil analyse les rootkits, les backdoors et les exploits locaux en exécutant des tests tels que:
          - Comparaison de hash MD5
          - Rechercher les fichiers par défaut utilisés par les rootkits
          - Mauvaises autorisations sur les fichiers pour les fichiers binaires
          - Recherchez les chaînes suspectes dans les modules LKM et KLD
          - Rechercher des fichiers cachés
          - Analyse facultative dans les fichiers texte et binaires"
    sleep 1
    cd rkhunter-1.4.6/
    sh installer.sh --layout /usr --install
    cd ..
    rkhunter --update
    rkhunter --propupd
    echo ""
    echo " ***Pour exécuter RootKit Hunter ***"
    echo "     rkhunter -c --enable all --disable none"
    echo "     Detailed report on /var/log/rkhunter.log"
    say_done
}

##############################################################################################################

# Réglage
tune_nano_vim_bashrc(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Réglage bashrc, nano et Vim"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

# Tune .bashrc
    echo "Réglage .bashrc......"
    spinner
    cp templates/bashrc-root /root/.bashrc
    cp templates/bashrc-user /home/$username/.bashrc
    chown $username:$username /home/$username/.bashrc
    echo "OK"


# Tune Vim
    echo "Réglage Vim......"
    spinner
    tunning vimrc
    echo "OK"


# Tune Nano
    echo "Réglage Nano......"
    spinner
    tunning nanorc
    echo "OK"
    say_done
}

##############################################################################################################

# Ajouter un travail quotidien de mise à jour
daily_update_cronjob(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m 
Ajout du travail périodique de mise à jour du système"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Création du cron journalier"
    spinner
    job="@daily apt update; apt dist-upgrade -y"
    touch job
    echo $job >> job
    crontab job
    rm job
    say_done
}

##############################################################################################################

# Installez PortSentry
install_portsentry(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation PortSentry"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install portsentry
    mv /etc/portsentry/portsentry.conf /etc/portsentry/portsentry.conf-original
    cp templates/portsentry /etc/portsentry/portsentry.conf
    sed s/tcp/atcp/g /etc/default/portsentry > salida.tmp
    mv salida.tmp /etc/default/portsentry
    /etc/init.d/portsentry restart
    say_done
}

##############################################################################################################

# Installez et Configurez Artillery
install_artillery (){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Clonage et repro installation Artillery"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    git clone https://github.com/BinaryDefense/artillery
    cd artillery/
    python setup.py
    cd ..
    echo ""
    echo "Établir des règles iptables pour l'artillerie"
    spinner
    for port in 22 1433 8080 21 5900 53 110 1723 1337 10000 5800 44443 16993; do
      echo "iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT" >> /etc/init.d/iptables.sh
    done
    echo ""
    echo "Artillery configuration file is /var/artillery/config"
    say_done  
}
##############################################################################################################

# Étapes de durcissement supplémentaires
additional_hardening(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m exécution d'étapes de durcissement supplémentaires"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "exécution d'étapes de durcissement supplémentaires...."
    spinner
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #Remove AT and Restrict Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " Securisation de Cron "
    spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
    echo -n " Voulez-vous désactiver la prise en charge USB pour ce serveur? (y/n): " ; read usb_answer
    if [ "$usb_answer" == "y" ]; then
       echo ""
       echo "Désactiver le support USB"
       spinner
       echo "blacklist usb-storage" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u
       echo "OK"
       say_done
    else
       echo "OK"
       say_done
    fi
}

##############################################################################################################

# Installez Unhide
install_unhide(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de UnHide"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Unhide est un outil d'investigation permettant de rechercher des processus cachés et des ports TCP/UDP à l'aide de rootkits /LKM ou d'une autre technique cachée."
    sleep 1
    apt -y install unhide
    echo ""
    echo " Unhide est un outil de détection de processus cachés "
    echo " Pour plus d'informations sur l'outil, utilisez les pages de manuel  "
    echo " man unhide "
    say_done
}

##############################################################################################################

# Installer Tiger
# Tiger is and Audit et système de détection d'intrusion
install_tiger(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installation de Tiger"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Tiger est un outil de sécurité qui peut être utilisé à la fois comme audit de sécurité et comme système de détection d'intrusion "
    sleep 1
    apt -y install tiger
    echo ""
    echo " Pour plus d'informations sur l'outil, utilisez le manuel "
    echo " man tiger "
    say_done
}

##############################################################################################################

# Installer PSAD
# PSAD surveille activement les journaux du pare-feu pour déterminer si une analyse ou une attaque est en cours.
install_psad(){
clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m Install PSAD"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo " PSAD est un logiciel qui surveille activement les journaux du pare-feu afin de déterminer si une analyse
       ou événement d'attaque est en cours. Il peut alerter et prendre des mesures pour dissuader la menace
       REMARQUE:
       SI VOUS UTILISEZ UNIQUEMENT CETTE FONCTION, VOUS DEVEZ ACTIVER LA CONNEXION POUR iptables.
       iptables -A INPUT -j LOG
       iptables -A FORWARD -j LOG

       "
echo ""
echo -n " Voulez-vous installer PSAD (Recommandé)? (y/n): " ; read psad_answer
if [ "$psad_answer" == "y" ]; then
     echo -n "Tapez une adresse email pour recevoir les alertes PSAD: " ; read inbox1
     apt install psad
     sed -i s/INBOX/$inbox1/g templates/psad.conf
     sed -i s/CHANGEME/$host_name.$domain_name/g templates/psad.conf  
     cp templates/psad.conf /etc/psad/psad.conf
     psad --sig-update
     service psad restart
     echo "Installation et configuration terminées "
     echo "Exécuter le statut psad du service, pour les événements détectés"
     echo ""
     say_done
else
     echo "OK"
     say_done
fi
}

##############################################################################################################


# Désactiver les compilateurs
disable_compilers(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Désactivation des compilateurs"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Désactivation des compilateurs....."
    spinner
    chmod 000 /usr/bin/as >/dev/null 2>&1
    chmod 000 /usr/bin/byacc >/dev/null 2>&1
    chmod 000 /usr/bin/yacc >/dev/null 2>&1
    chmod 000 /usr/bin/bcc >/dev/null 2>&1
    chmod 000 /usr/bin/kgcc >/dev/null 2>&1
    chmod 000 /usr/bin/cc >/dev/null 2>&1
    chmod 000 /usr/bin/gcc >/dev/null 2>&1
    chmod 000 /usr/bin/*c++ >/dev/null 2>&1
    chmod 000 /usr/bin/*g++ >/dev/null 2>&1
    spinner
    echo ""
    echo " Si vous souhaitez les utiliser, il suffit de modifier les autorisations"
    echo " Example: chmod 755 /usr/bin/gcc "
    echo " OK"
    say_done
}

##############################################################################################################

# Restrict Access to Apache Config Files
apache_conf_restrictions(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Restreindre l'accès aux fichiers de configuration Apache"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Restreindre l'accès aux fichiers de configuration Apache......"
    spinner
     chmod 750 /etc/apache2/conf* >/dev/null 2>&1
     chmod 511 /usr/sbin/apache2 >/dev/null 2>&1
     chmod 750 /var/log/apache2/ >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-available/* >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-enabled/* >/dev/null 2>&1
     chmod 640 /etc/apache2/apache2.conf >/dev/null 2>&1
     echo " OK"
     say_done
}

##############################################################################################################

# Configurations de sécurité supplémentaires
# Activer les mises à jour de sécurité sans surveillance
  unattended_upgrades(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Activer les mises à jour de sécurité sans assistance"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " Souhaitez-vous activer les mises à jour de sécurité sans surveillance?(y/n): "; read unattended
  if [ "$unattended" == "y" ]; then
      dpkg-reconfigure -plow unattended-upgrades
  else
      clear
  fi
}

##############################################################################################################

# Activer la comptabilité des processus
enable_proc_acct(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Activer la comptabilisation des processus"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install acct
  touch /var/log/wtmp
  echo "OK"
}

##############################################################################################################

#Install PHP Suhosin Extension
#install_phpsuhosin(){
#  clear
#  f_banner
#  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#  echo -e "\e[93m[+]\e[00m Installing PHP Suhosin Extension"
#  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#  echo ""
#  echo 'deb http://repo.suhosin.org/ ubuntu-trusty main' >> /etc/apt/sources.list
#  #Suhosin Key
#  wget https://sektioneins.de/files/repository.asc
#  apt-key add repository.asc
#  apt update
#  apt install php-suhosin-extension
# phpenmod suhosin
#  service apache2 restart
#  echo "OK"
#  say_done
#}

##############################################################################################################

#Installer et activer auditd

install_auditd(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installation de auditd"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install auditd

  # Utilisation de la configuration du benchmark CIS
  
  # S'assurer que l'audit des processus démarrant avant auditd est activé
  echo ""
  echo "Activation de l'audit pour les processus démarrant avant auditd "
  spinner
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub

  echo ""
  echo " Configuration des règles Auditd"
  spinner

  cp templates/audit-CIS.rules /etc/audit/rules.d/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/rules.d/audit.rules

  echo " " >> /etc/audit/rules.d/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/rules.d/audit.rules
  echo "-e 2" >>/etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
  echo "OK"
  say_done
}
##############################################################################################################

#Installer et activer sysstat

install_sysstat(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installer et activer sysstat"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install sysstat
  sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
  service sysstat start
  echo "OK"
  say_done
}

##############################################################################################################

#Installer ArpWatch

install_arpwatch(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m ArpWatch Installation"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "ArpWatch est un outil de surveillance du trafic ARP sur System. Il génère un journal du couplage observé entre IP et MAC."
  echo ""
  echo -n " Voulez-vous installer ArpWatch sur ce serveur? (y/n): " ; read arp_answer
  if [ "$arp_answer" == "y" ]; then
     echo "Installing ArpWatch"
     spinner
     apt install -y arpwatch
     systemctl enable arpwatch.service
     service arpwatch start
     echo "OK"
     say_done
  else
     echo "OK"
     say_done
  fi
}

##############################################################################################################

set_grubpassword(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Mot de passe du chargeur d'amorçage GRUB"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "Il est recommandé de définir un mot de passe sur le chargeur de démarrage GRUB pour éviter de modifier la configuration de démarrage (par exemple, démarrage en mode utilisateur unique sans mot de passe)"
  echo ""
  echo -n " Voulez-vous définir un mot de passe pour le chargeur d'amorçage GRUB? (y/n): " ; read grub_answer
  if [ "$grub_answer" == "y" ]; then
    grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
    grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
    echo " set superusers="root" " >> /etc/grub.d/40_custom
    echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
    rm grubpassword.tmp
    update-grub
    echo " À chaque démarrage, entrez l'utilisateur root et le mot de passe que vous venez de définir "
    echo "OK"
    say_done
  else
    echo "OK"
    say_done
  fi

echo -e ""
echo -e "Sécuriser les paramètres de démarrage"
spinner
sleep 2
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
say_done

}    

##############################################################################################################

file_permissions(){
 clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Définition des autorisations de fichier sur les fichiers système critiques"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  sleep 2
  chmod -R g-wx,o-rwx /var/log/*

  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config

  chown root:root /etc/passwd
  chmod 644 /etc/passwd

  chown root:shadow /etc/shadow
  chmod o-rwx,g-wx /etc/shadow

  chown root:root /etc/group
  chmod 644 /etc/group

  chown root:shadow /etc/gshadow
  chmod o-rwx,g-rw /etc/gshadow

  chown root:root /etc/passwd-
  chmod 600 /etc/passwd-

  chown root:root /etc/shadow-
  chmod 600 /etc/shadow-

  chown root:root /etc/group-
  chmod 600 /etc/group-

  chown root:root /etc/gshadow-
  chmod 600 /etc/gshadow-


  echo -e ""
  echo -e "Définir Sticky bit sur tous les répertoires"
  sleep 2
  spinner

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

  echo " OK"
  say_done

}
##############################################################################################################

# Redemarrage du serveur
reboot_server(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m étape finale"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    sed -i s/USERNAME/$username/g templates/texts/bye
    sed -i s/SERVERIP/$serverip/g templates/texts/bye
    cat templates/texts/bye
    echo -n " Avez-vous pu vous connecter via le serveur SSH au serveur en utilisant $username? (y/n): "; read answer
    if [ "$answer" == "y" ]; then
        reboot
    else
        echo "Le serveur ne redémarrera pas"
        echo "Bye."
    fi
}

##################################################################################################################

clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m CHOISISSEZ L’OPTION SOUHAITE"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. Déploiement de LAMP"
echo "2. Déploiement du proxy inverse avec Apache"
echo "3. Déploiement de LEMP "
echo "4. Déploiement du proxy inverse avec Nginx (ModSecurity)"
echo "5. Utiliser le script SecureWPDeployer ou JSDeployer"
echo "6. xécution personnalisée (Exécuter uniquement les options souhaitées) "
echo "7. Durcissement de référence du CIS"
echo "8. Exit"
echo

read choice

case $choice in

1)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_apache
install_secure_php
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

2)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_apache
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

3)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_nginx_modsecurity
set_nginx_vhost
set_nginx_modsec_OwaspRules
install_php_nginx
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

4)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_nginx_modsecurity
set_nginx_vhost_nophp
set_nginx_modsec_OwaspRules
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
reboot_server
;;

5)
check_root
install_dep
config_host
config_timezone
update_system
restrictive_umask
unused_filesystems
uncommon_netprotocols
admin_user
rsa_keygen
rsa_keycopy
secure_ssh
set_iptables
install_fail2ban
install_secure_mysql
install_apache
install_secure_php
install_modsecurity
set_owasp_rules
secure_optimize_apache
install_modevasive
install_qos_spamhaus
config_fail2ban
additional_packages
tune_secure_kernel
install_rootkit_hunter
tune_nano_vim_bashrc
daily_update_cronjob
install_artillery
additional_hardening
install_unhide
install_tiger
install_psad
disable_compilers
secure_tmp
apache_conf_restrictions
unattended_upgrades
enable_proc_acct
install_auditd
install_sysstat
install_arpwatch
set_grubpassword
file_permissions
;;

6)

menu=""
until [ "$menu" = "34" ]; do

clear
f_banner
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m SELECT THE DESIRED OPTION"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1.  Configurer le nom d'hôte, créer des bannières légales, mettre à jour les fichiers hôtes"
echo "2.  Configurer le fuseau horaire"
echo "3.  Mise à jour système"
echo "4.  Créer un utilisateur administrateur "
echo "5.  Instructions pour générer et déplacer une paire de clés privée/publique"
echo "6.  Configuration SSH sécurisée"
echo "7.  Définir des règles IPTable restrictives"
echo "8.  Installer et configurer Fail2Ban"
echo "9.  Installer, optimiser et sécuriser Apache"
echo "10. Installez Nginx avec ModSecurity Module et définissez OwaspRules"
echo "11. Configurez Nginx Vhost avec PHP"
echo "12. Set Nginx Vhost"
echo "13. Installer et sécuriser PHP pour Apache Server"
echo "14. Installer et sécuriser PHP pour Nginx Server"
echo "15. Installez ModSecurity (Apache) et définissez les règles Owasp "
echo "16. Installez ModEvasive"
echo "17. Installez ModQos et SpamHaus"
echo "18. Ajuster et sécuriser le noyau Linux"
echo "19. Installez RootKit Hunter"
echo "20. Réglages Vim, Nano, Bashrc"
echo "21. Installez PortSentry"
echo "22. tty sécurisé, root home, config grub, cron"
echo "23. Installez Unhide"
echo "24. Installez Tiger"
echo "25. Désactiver les compilateurs"
echo "26. Activer les mises à niveau non prises en charge"
echo "27. Activer la comptabilité des processus"
echo "28. Installer PHP Suhosin (Désactivé pour le moment)"
echo "29. Installer et sécuriser MySQL "
echo "30. Valeur UMASK plus restrictive (027)"
echo "31. Répertoire sécurisé /tmp"
echo "32. Installer PSAD IDS"
echo "33. Définir le mot de passe du chargeur d'amorçage GRUB"
echo "34. Exit"
echo " "

read menu
case $menu in

1)
config_host
;;

2)
config_timezone
;;

3)
update_system
;;

4)
admin_user
;;

5)
rsa_keygen
rsa_keycopy
;;

6)
echo "key Pair must be created "
echo "What user will have access via SSH? " ; read username
rsa_keygen
rsa_keycopy
secure_ssh
;;

7)
set_iptables
;;

8)
echo "Type Email to receive Alerts: " ; read inbox
install_fail2ban
config_fail2ban
;;

9)
install_apache
secure_optimize_apache
apache_conf_restrictions
;;

10)
install_nginx_modsecurity
set_nginx_modsec_OwaspRules
;;

11)
set_nginx_vhost
;;


12)
set_nginx_vhost_nophp
;;

13)
install_secure_php
;;

14)
install_php_nginx
;;

15)
install_modsecurity
set_owasp_rules
;;

16)
install_modevasive
;;

17)
install_qos_spamhaus
;;

18)
tune_secure_kernel
;;

19)
install_rootkit_hunter
;;

20)
tune_nano_vim_bashrc
;;

21)
install_portsentry
;;

22)
additional_hardening
;;

23)
install_unhide
;;

24)
install_tiger
;;

25)
disable_compilers;
;;

26)
unattended_upgrades
;;

27)
enable_proc_acct
;;

#28)
#install_phpsuhosin
#;;

29)
install_secure_mysql
;;

30)
restrictive_umask
;;

31)
secure_tmp
;;

32)
install_psad
;;

33)
set_grubpassword
;;

34)
break ;;

*) ;;

esac
done
;;

7)
chmod +x jshielder-CIS.sh
./jshielder-CIS.sh
;;

8)
exit 0
;;

esac
##############################################################################################################
