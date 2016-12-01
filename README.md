Criado por Kum Traceroute em 30/11/2016

Configuração :
  # entre na pasta iptables-kull
  caminho=$(pwd)
  echo "alias nmap='sudo $caminho/cnmap.sh'" >> .bashrc
  echo "alias firewall='sudo $caminho/iptables.sh'" >> .bashrc
  sed -i 's/kumroute/seu_nome_de_usuário/g'
  sed -i 's/wlp8s0/sua_interface_wlan/g'
  # feche e abra outro terminal, e estará pronto para uso

Página de ajuda :
  # execute :
  firewall help

Porque utilizar o Kull ?
  => Ele faz PortKnock nas portas em que você especificou no array $porta_serv[]
  => Ele libera as portas que você especificou no array $porta_in_tcp[] e $porta_in_udp[], sendo portas TCP e UDP respectivamente
  => O mesmo é feito com os arrays $porta_out_tcp[] e $porta_out_udp[]
  => Ele bloqueia pacotes fragmentados
  => Ele limita os pacotes TCP contendo o bit SYN para somente 2 por segundo, fazendo uma proteção contra SYN flood
  => Ele bloqueia IP spoofing
  => Ele bloqueia o ping de chegar em sua máquina, porém você pode utilizá-lo nos outros

Qualquer duvida, erros ou bugs :
Contato : +55 (14) 98820-8320