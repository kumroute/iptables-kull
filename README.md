# IPTables Kull  
## Instalação e uso  

```  
git clone https://github.com/kumroute/iptables-kull  
cd iptables-kull  
bash iptables.sh  
```  

#### Sobre o arquivo config  

1. O arquivo config podem ter quatro divisões :  
  * [Options] : essa é uma seção especial para os protocolos (em especial o ICMP)  
    1. Sintaxe: <protocolo>_<input/output>: <allow/deny/drop>  
    2. Sintaxe especial: ping_<reply/request>_<input_output>: <allow/deny/drop>  
  * [Kernel] : as opções aqui são/devem ser arquivos do diretório /proc/sys/net/ipv4  
    1. Caso a ação for yes, o arquivo terá seu valor=1 e se for no = 0  
  * [Port] : configurações de porta, pode estar protegido por portknock ou não  
    1. Caso esteja: ports_portknock: <portas> | Ex. ports_portknock: 111,222,333  
      * E após isso especificar que porta quer proteger, Ex. portknock: 21,22  
    2. Caso não esteja, a sintaxe é essa: <allow/deny/drop>_<input/output>_<protocolo>: <portas>  
  * [Protect] : é um caso especial, são algumas proteções que o Kull permite que você use, eis uma lista :  
    1. syn-flood: <yes/no>  
    2. ip-spoofing: <yes/no>  
    3. port-scan: <yes/no>  
    4. death-ping: <yes/no>  
    5. block-fragments: <yes/no>  

* Não se esqueça de dar uma olhada no exemplo ;D

Opções extras para o IPTables Kull :  

- bash iptables.sh start quiet  
- bash iptables.sh stop quiet  
1. Esconde os printf em sua tela  

- bash iptables.sh start input
1. Carrega somente as regras de input, útil para utilizar o nmap, por ex.  

IPTables Kull, exemplo de configuração em config  
Qualquer duvida, erros ou bugs :  
Contato : +55 (14) 98820-8320  

