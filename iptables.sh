###################################
# IPtables por Kum Traceroute     #
# Contato: +55 (14) 98820-8320    #
###################################

firewall_version() {
  echo "[+] IPTables Kull 1.0.1"
}

firewall_help() {
  firewall_version
  echo "[+] Uso: firewall <opção>"
  echo " :: help        :: mostra essa página de ajuda"
  echo " :: status      :: mostra se o iptables está ativo ou desativo"
  echo " :: start       :: inicia as regras"
  echo " :: stop        :: apaga e retorna as políticas padrões ao normal"
  echo " :: start_quiet :: inicia as regras em modo quiet"
  echo " :: stop_quiet  :: apaga e retorna as políticas padrões ao normal em modo quiet"
  echo "Veja https://github.com/kumroute/ para mais informações"
}

firewall_up () {
  
  # INTERFACE WLAN
  ext="wlp8s0"

  # PORTAS DO PORT KNOCK
  pk1=100
  pk2=201
  pk3=302

  # PORTAS PROTEGIDAS PELO PORTKNOCK
  porta_serv[0]=2222

  # PORTAS PARA LIVRE USO INPUT TCP
  # porta_in_tcp[0]=
  # PORTAS PARA LIVRE USO INPUT UDP
  # porta_in_udp[0]=

  # PORTAS PARA LIVRE USO OUTPUT TCP
  porta_out_tcp[0]=80
  porta_out_tcp[1]=443
  # PORTAS PARA LIVRE USO OUTPUT UDP
  porta_out_udp[0]=53

  # TIRANDO TUDO
  iptables -F
  iptables -X
  iptables -Z

  # POLITICAS PADROES
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  ####### REGRAS DE INPUT #################

  # CONEXOES ESTABELECIDAS E RELACIONADAS
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # LOOP BACK, LOCALHOST
  iptables -A INPUT -i lo -j ACCEPT

  # BLOQUEAR PACOTES FRAGMENTADOS
  iptables -A INPUT -f -j DROP

  # PROTECAO PING DA MORTE
  # iptables -t filter -A INPUT -p icmp --icmp-type 0 -m limit --limit 1/s -j RETURN

  # PROTECAO SYN FLOOD, LIMITANDO PACOTES COM SYN - INICIO DE CONEXAO
  iptables -t filter -A INPUT -p tcp --syn -m limit --limit 2/s -j ACCEPT

  # LIBERA ECHO-REPLY - PONG - REPOSTA DE PING
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

  # PROTECAO CONTRA IP SPOOFING
  iptables -A INPUT -s 172.16.0.0/16 -i $ext -j DROP
  iptables -A INPUT -s 192.168.0.0/24 -i $ext -j DROP

  ## PROTECAO PARA OS SERVICOS - PORT KNOCK
  # "FUNCOES" DAS FASES
  iptables -N INTO-FASE2
  iptables -A INTO-FASE2 -m recent --name FASE1 --remove
  iptables -A INTO-FASE2 -m recent --name FASE2 --set
  iptables -A INTO-FASE2 -j LOG --log-prefix "FIREWALL: segunda fase portknock :  "
  iptables -N INTO-FASE3
  iptables -A INTO-FASE3 -m recent --name FASE2 --remove
  iptables -A INTO-FASE3 -m recent --name FASE3 --set
  iptables -A INTO-FASE3 -j LOG --log-prefix "FIREWALL: terceira fase portknock :  "
  ## PORTAS DO PORT KNOCK
  iptables -A INPUT -m recent --update --name FASE1
  iptables -A INPUT -p tcp --dport $pk1 -m recent --set --name FASE1
  iptables -A INPUT -p tcp --dport $pk2 -m recent --rcheck --seconds 60 --name FASE1 -j INTO-FASE2
  iptables -A INPUT -p tcp --dport $pk3 -m recent --rcheck --seconds 60 --name FASE2 -j INTO-FASE3
  i=0 ; while [ ${porta_serv[$i]} ] ; do
  iptables -A INPUT -p tcp --dport ${porta_serv[$i]} -m recent --rcheck --seconds 600 --name FASE3 -j ACCEPT
  i=$[i+1] ; done

  # PROTECAO CONTRA PORTSCAN
  iptables -N SCANNER
  iptables -A SCANNER -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i $ext -j SCANNER
  iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i $ext -j SCANNER

  # LIBERAR PORTAS PARA LIVRE USO
  i=0 ; while [ ${porta_in_tcp[$i]} ] ; do
  iptables -A INPUT -p tcp --dport ${porta_in_tcp[$i]} -j ACCEPT
  i=$[i+1] ; done
  i=0 ; while [ ${porta_in_udp[$i]} ] ; do
  iptables -A INPUT -p udp --dport ${porta_in_udp[$i]} -j ACCEPT
  i=$[i+1] ; done

  #########################################

  ####### REGRAS DE OUTPUT ################

  # CONEXOES ESTABELECIDAS E RELACIONADAS
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # LIBERA LOOPBACK, LOCALHOST
  iptables -A OUTPUT -o lo -j ACCEPT

  # LIBERA REQUEST ECHO - PING
  iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT

  # LIBERAR PORTAS PARA LIVRE USO
  i=0 ; while [ ${porta_out_tcp[$i]} ] ; do
  iptables -A OUTPUT -p tcp --dport ${porta_out_tcp[$i]} -j ACCEPT
  i=$[i+1] ; done
  i=0 ; while [ ${porta_out_udp[$i]} ] ; do
  iptables -A OUTPUT -p udp --dport ${porta_out_udp[$i]} -j ACCEPT
  i=$[i+1] ; done

  #########################################

}

firewall_down() {
  iptables -F
  iptables -X
  iptables -Z
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
}

if [ "$1" == "start" ] ; then
  firewall_version
  echo "[+] Trocando políticas padrões"
  echo "[+] Carregando regras de input"
  echo " :: Carregando proteção contra synflood"
  echo " :: Carregando proteção contra ip spoofing"
  echo " :: Carregando portknock para os serviços"
  echo " :: Carregando proteção contra portscan"
  echo " :: Liberando portas para livre uso"
  echo "[+] Carregando regras de output"
  echo " :: Liberando o retorno de serviços iniciados"
  echo " :: Liberando acesso à servidores web"
  firewall_up
fi

if [ "$1" == "stop" ] ; then
  firewall_version
  echo "[+] Apagando as regras"
  echo "[+] Trocando políticas padrões"
  firewall_down
fi

if [ "$1" == "start_quiet" ] ; then
  firewall_up
fi

if [ "$1" == "stop_quiet" ] ; then
  firewall_down
fi

if [ "$1" == "help" ] || [ ! $1 ] ; then
  firewall_help
fi

if [ "$1" == "status" ] ; then
  firewall_version
  var=$(iptables -S | head -1)
  if [ "$var" == "-P INPUT ACCEPT" ] ; then
    echo " :: is inactive"
  else
    echo " :: is active"
  fi
fi

