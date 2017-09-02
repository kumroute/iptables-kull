# IPTables Kull  
## Instalação e uso  

```  
git clone https://github.com/kumroute/iptables-kull  
cd iptables-kull  
bash iptables.sh  
```  

#### Sobre o arquivo config  

=> O arquivo config podem ter quatro divisões :  
  * [Options] : essa é uma seção especial para os protocolos (em especial o ICMP)  
    * Sintaxe: \<protocolo>\_<input/output>: <allow/deny/drop>  
    * Sintaxe especial: ping\_<reply/request>\_<input_output>: <allow/deny/drop>  
  * [Kernel] : as opções aqui são/devem ser arquivos do diretório /proc/sys/net/ipv4  
    * Caso a ação for yes, o arquivo terá seu valor=1 e se for no = 0  
  * [Port] : configurações de porta, pode estar protegido por portknock ou não  
    * Caso esteja: ports_portknock: <portas> | Ex. ports_portknock: 111,222,333  
      * E após isso especificar que porta quer proteger, Ex. portknock: 21,22  
    * Caso não esteja, a sintaxe é essa: \<allow/deny/drop>\_<input/output>\_\<protocolo>: \<portas>  
    * Nova opção: redirect-$protocolo: $porta, $ip:$porta  
      * Se $protocolo não for especificado, será considerado como tcp  
  * [Protect] : é um caso especial, são algumas proteções que o Kull permite que você use, eis uma lista :  
    * (syn/udp)-flood-(input/forward): <yes/no>  
      * Para syn/udp, o padrão é syn  
      * Para input/forward, o padrão é input  
    * ip-spoofing: <yes/no>  
    * port-scan: <yes/no>  
    * death-ping: <yes/no>  
    * block-fragments: <yes/no>  
    * block-mac: \<mac address>  
    * block-ip: \<ip address>  

* Não se esqueça de dar uma olhada no exemplo ;D

#### Opções extras para o IPTables Kull :  

```  
bash iptables.sh start quiet  
bash iptables.sh stop quiet  
```  
* Esconde os printf em sua tela  

```  
bash iptables.sh start input
```  
* Carrega somente as regras de input, útil para utilizar o nmap, por ex.  

IPTables Kull, exemplo de configuração em config  
Qualquer duvida, erros ou bugs :  
Contato : +55 (14) 98820-8320  

