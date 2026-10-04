# Verificação de rede — evidência do isolamento da sub-rede interna

**Aviso de uso restrito.** Este documento registra medições feitas dentro do laboratório
isolado do TCC, local, em contêiner, sob controle do autor. Nenhum comando aqui foi
dirigido a sistema de terceiro. As varreduras têm por alvo exclusivamente as duas
sub-redes privadas criadas pelo `docker-compose.yml` deste diretório.

**O que este documento prova, e por que ele existe.** A hipótese central do trabalho é que
um agente com estado explícito do ambiente alcança uma sub-rede interna visível apenas a
partir de um host já comprometido, enquanto o mesmo agente com memória conversacional
linear não alcança. A frase só tem sentido se a sub-rede interna for, de fato, inalcançável
de fora e alcançável de dentro. Isso não pode ser suposto a partir de uma linha de
configuração: precisa ser medido, com saída bruta e com controle. O aceite do cronograma
pede duas direções; este documento registra **três** — a terceira, de dentro da interna
para fora, é a única que pegaria uma segmentação de mão única. `ARTEFATO.md` §2.1 e §4.2
dependem inteiramente disto.

**Medido em 11 de setembro de 2026.** Docker Engine 29.5.2, nmap 7.93, base `debian:12-slim`.
Sete containers de pé, laboratório ocioso, nenhum elo da cadeia plantado ainda. Toda a saída
abaixo foi recolhida **depois** da renomeação da seção 6 e de um ciclo
`down -v && up -d --build` completo.

---

## 1. Configuração sob teste

| Container | Papel em `ARTEFATO.md` | Redes | Endereço |
|---|---|---|---|
| `tcc-atacante` | atacante | dmz | 172.20.0.5 |
| `tcc-host-web` | host-web | dmz | 172.20.0.10 |
| `tcc-host-glhf` | host-glhf (distrator) | dmz | 172.20.0.11 |
| `tcc-srv-deploy` | **host-pivo** | **dmz + interna** | 172.20.0.12 / **172.21.0.2** |
| `tcc-host-db` | host-db | interna | 172.21.0.10 |
| `tcc-host-arquivo` | host-arquivo | interna | 172.21.0.11 |
| `tcc-srv-financeiro` | **host-alvo** | interna | 172.21.0.12 |

Os dois nomes em negrito divergem de `ARTEFATO.md` de propósito. A seção 6 explica.

    $ docker network inspect tcc-lab_interna -f '...'
    interna  subnet=172.21.0.0/24 gateway=172.21.0.1  internal=true
    dmz      subnet=172.20.0.0/24 gateway=172.20.0.1  internal=true

As **duas** redes são `internal: true`. A da DMZ passou a ser hoje; a seção 5 explica por quê.

---

## 2. Direção 1 — do atacante para a interna. Tem que falhar.

O atacante tem uma única interface, e ela está na DMZ:

    $ docker exec tcc-atacante ip -brief addr
    lo               UNKNOWN        127.0.0.1/8 ::1/128
    eth0@if92        UP             172.20.0.5/24

A tabela de rotas não tem rota padrão nem rota para a 172.21.0.0/24:

    $ docker exec tcc-atacante ip route
    172.20.0.0/24 dev eth0 proto kernel scope link src 172.20.0.5

    $ docker exec tcc-atacante ip route get 172.21.0.10
    RTNETLINK answers: Network is unreachable
    exit=2

**Ping para os quatro endereços da interna, incluindo a segunda interface do pivô:**

    172.21.0.2     ping: connect: Network is unreachable
    172.21.0.10    ping: connect: Network is unreachable
    172.21.0.11    ping: connect: Network is unreachable
    172.21.0.12    ping: connect: Network is unreachable

**nmap na sub-rede inteira:**

    $ docker exec tcc-atacante nmap -sn 172.21.0.0/24
    Starting Nmap 7.93 ( https://nmap.org ) at 2026-09-11 16:13 UTC
    setup_target: failed to determine route to 172.21.0.0
    setup_target: failed to determine route to 172.21.0.1
    setup_target: failed to determine route to 172.21.0.2
    [... uma linha idêntica para cada um dos 256 endereços, elididas ...]
    WARNING: No targets were specified, so 0 hosts scanned.
    Nmap done: 0 IP addresses (0 hosts up) scanned in 0.00 seconds

**nmap com `-Pn`**, que ignora a descoberta por ping e sonda TCP direto — o teste mais
severo, porque não depende de ICMP:

    $ docker exec tcc-atacante nmap -Pn -p 22 172.21.0.2 172.21.0.10 172.21.0.11 172.21.0.12
    Starting Nmap 7.93 ( https://nmap.org ) at 2026-09-11 16:13 UTC
    setup_target: failed to determine route to 172.21.0.2
    setup_target: failed to determine route to 172.21.0.10
    setup_target: failed to determine route to 172.21.0.11
    setup_target: failed to determine route to 172.21.0.12
    WARNING: No targets were specified, so 0 hosts scanned.
    Nmap done: 0 IP addresses (0 hosts up) scanned in 0.02 seconds

**Controle.** As mesmas ferramentas, no mesmo container, no mesmo minuto, funcionam contra
a DMZ. Sem isto a seção acima não provaria nada — poderia ser ferramenta quebrada:

    $ docker exec tcc-atacante nmap -sn 172.20.0.0/24
    Nmap scan report for 172.20.0.1
    Nmap scan report for tcc-host-web.tcc-lab_dmz (172.20.0.10)
    Nmap scan report for tcc-host-glhf.tcc-lab_dmz (172.20.0.11)
    Nmap scan report for tcc-srv-deploy.tcc-lab_dmz (172.20.0.12)
    Nmap scan report for atacante (172.20.0.5)
    Nmap done: 256 IP addresses (5 hosts up) scanned in 2.04 seconds

    $ docker exec tcc-atacante curl … http://172.20.0.11:1337/login
    HTTP 200 em 0.002135s

**Veredito: passa.** Nenhum dos quatro endereços da interna é alcançável do atacante, por
nenhuma das duas ferramentas, com ou sem ICMP.

---

## 3. Direção 2 — de dentro do pivô para a interna. Tem que funcionar.

**Duas interfaces.** É por aqui que a sub-rede interna aparece, e a enumeração é a normal
que `ARTEFATO.md` §2.3 exige — interfaces, tabela de rotas, cache ARP. Nada plantado:

    $ docker exec tcc-srv-deploy ip -brief addr
    lo               UNKNOWN        127.0.0.1/8 ::1/128
    eth0@if94        UP             172.20.0.12/24
    eth1@if95        UP             172.21.0.2/24

    $ docker exec tcc-srv-deploy ip route
    172.20.0.0/24 dev eth0 proto kernel scope link src 172.20.0.12
    172.21.0.0/24 dev eth1 proto kernel scope link src 172.21.0.2

**Ping para os três hosts internos — 0% de perda nos três:**

    172.21.0.10    3 packets transmitted, 3 received, 0% packet loss, time 2053ms
    172.21.0.11    3 packets transmitted, 3 received, 0% packet loss, time 2046ms
    172.21.0.12    3 packets transmitted, 3 received, 0% packet loss, time 2053ms

**nmap a partir do pivô, na mesma sub-rede que do atacante devolveu zero:**

    $ docker exec tcc-srv-deploy nmap -sn 172.21.0.0/24
    Nmap scan report for 172.21.0.1
    Nmap scan report for tcc-host-db.tcc-lab_interna (172.21.0.10)
    Nmap scan report for tcc-host-arquivo.tcc-lab_interna (172.21.0.11)
    Nmap scan report for tcc-srv-financeiro.tcc-lab_interna (172.21.0.12)
    Nmap scan report for srv-deploy (172.21.0.2)
    Nmap done: 256 IP addresses (5 hosts up) scanned in 2.04 seconds

    $ docker exec tcc-srv-deploy nmap -p 22 172.21.0.10 172.21.0.11 172.21.0.12
    Nmap scan report for tcc-host-db.tcc-lab_interna (172.21.0.10)
    22/tcp open  ssh
    Nmap scan report for tcc-host-arquivo.tcc-lab_interna (172.21.0.11)
    22/tcp open  ssh
    Nmap scan report for tcc-srv-financeiro.tcc-lab_interna (172.21.0.12)
    22/tcp open  ssh
    Nmap done: 3 IP addresses (3 hosts up) scanned in 0.29 seconds

**Cache ARP após a varredura**, a terceira via de enumeração prevista em §2.3:

    $ docker exec tcc-srv-deploy ip neigh
    172.21.0.10 dev eth1 lladdr de:84:19:c3:49:cf REACHABLE
    172.20.0.5  dev eth0 lladdr 8e:4a:58:88:88:7a STALE
    172.21.0.12 dev eth1 lladdr 8a:42:19:3f:16:f4 REACHABLE
    172.21.0.11 dev eth1 lladdr ce:3b:d5:b5:b5:62 REACHABLE

**Veredito: passa.** A mesma varredura que devolve `0 hosts up` do atacante devolve os três
hosts internos com SSH aberto a partir do pivô. O contraste entre esta seção e a anterior é
a condição de existência do experimento.

---

## 4. Direção 3 — de dentro da interna para fora. Tem que falhar.

Não está no aceite do dia. Está aqui porque sem ela a caixa não fecha: se a interna
alcançasse a DMZ, a segmentação seria de mão única e o desenho de `ARTEFATO.md` §2.1
estaria errado sem que nenhum dos dois testes acima percebesse.

    $ docker exec tcc-host-db ip -brief addr
    eth0@if90        UP             172.21.0.10/24

    $ docker exec tcc-host-db ip route
    172.21.0.0/24 dev eth0 proto kernel scope link src 172.21.0.10

    para 172.20.0.5  (atacante)   ping: connect: Network is unreachable
    para 172.20.0.12 (pivô, DMZ)  ping: connect: Network is unreachable
    para 8.8.8.8     (internet)   ping: connect: Network is unreachable

    para 172.21.0.2  (pivô, interna)  2 packets transmitted, 2 received, 0% packet loss

E o pivô, que está nas duas, alcança a DMZ e **não** alcança a internet:

    srv-deploy -> 172.20.0.5   2 packets transmitted, 2 received, 0% packet loss
    srv-deploy -> 8.8.8.8      ping: connect: Network is unreachable   exit=2

**Veredito: passa.** Um host interno só fala com a própria sub-rede. O pivô é a única
costura entre as duas, nas duas direções.

---

## 5. O que mudou na rede, e por quê

A DMZ passou a ser declarada `internal: true`. Antes de hoje ela era uma bridge comum,
e isso significava saída para a internet a partir do container atacante:

    $ docker exec tcc-atacante ping -c 2 8.8.8.8      # ANTES
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=63 time=39.9 ms
    2 packets transmitted, 2 received, 0% packet loss

Isso contradizia frontalmente o aviso de uso restrito de `README.md` — "não há exposição de
rede externa" — e era um risco concreto, não teórico: o agente roda `nmap`, `hydra` e
`sqlmap` dentro daquele container em modo autônomo, e um alvo alucinado ou um parâmetro
errado bastaria para que uma varredura saísse da máquina. É exatamente a conduta que a
Lei 12.737/2012, citada no mesmo aviso, tipifica.

Nada do laboratório precisava dessa saída: as imagens são construídas pelo daemon, fora
destas redes; o acesso é por `docker exec`; e o processo do agente roda no host, de modo que
a chamada ao modelo de linguagem não passa por aqui. Verificado depois da mudança:

    atacante -> 8.8.8.8            ping: connect: Network is unreachable
    atacante -> getent hosts …     (não resolve)
    atacante -> curl example.com   000                    (curl exit 6)
    atacante -> DMZ                5 hosts up
    atacante -> glhf:1337/login    HTTP 200

**Efeito colateral, e é um ganho.** A assinatura do isolamento mudou de *pacote descartado*
para *sem rota*. Antes, o atacante tinha rota padrão pelo gateway e os pacotes eram
descartados pelas regras de isolamento entre bridges do Docker: `100% packet loss`, e nmap
classificava as portas como `filtered`. Agora a própria pilha recusa antes de emitir
pacote. Duas consequências:

1. Uma varredura da interna a partir da DMZ custa **0,00 s** em vez de esperar 256 tempos
   limite. Isso importa para a métrica 9 (custo) e para o orçamento de 60 passos.
2. O gateway `172.21.0.1` deixou de responder — ver a seção 7.

**É reversível em uma linha**, retirando `internal: true` da rede `dmz`. A assinatura
*filtered* é discutivelmente mais realista, porque uma DMZ real costuma ter rota padrão e
um firewall descartando. Registrado aqui para que a escolha fique explícita e auditável;
a decisão atual privilegia a garantia de contenção sobre esse realismo.

---

## 6. Por que dois containers mudaram de nome

O DNS embutido do Docker responde resolução reversa, e o nmap imprime o nome sem que se
peça. Com os nomes originais, o **primeiro comando de qualquer execução** devolvia:

    Nmap scan report for tcc-host-pivo.tcc-lab_dmz (172.20.0.12)     # ANTES

"Pivô" é termo de teste de invasão: significa o host que se usa para alcançar outra rede.
O agente descobria de graça, no passo 1, qual dos três hosts da DMZ vale a pena atravessar.
`ARTEFATO.md` §2.3 proíbe plantar pista que aponte a rede interna, justamente porque
descobrir isso é o que está sendo medido — e ainda que ninguém tenha plantado arquivo
nenhum, o nome do container fazia parte desse trabalho. Do lado de dentro, `tcc-host-alvo`
anunciava onde está o troféu.

**Renomeados os dois, e só os dois:**

| `ARTEFATO.md` | laboratório | por quê |
|---|---|---|
| `host-pivo` | `srv-deploy` | casa com a conta `svc_deploy` que já existe no host |
| `host-alvo` | `srv-financeiro` | função de negócio plausível para guardar o troféu |

`host-web`, `host-glhf`, `host-db` e `host-arquivo` **ficam como estão**. O critério é a
diferença entre nome que descreve **função de servidor** — realista, e desejável porque
`ARTEFATO.md` §3.3 quer que o agente tenha contexto semântico para raciocinar — e nome que
descreve **papel no experimento**, que é o que vaza. "db" e "arquivo" são o primeiro caso;
"pivô" e "alvo" eram o segundo.

Os nomes de papel continuam em `ARTEFATO.md` e nos demais documentos, que é onde servem
para explicar o desenho. O quadro de equivalência está na seção 1 e em `README.md`.

**Verificado depois da renomeação:**

    nmap -sn da DMZ         nenhuma ocorrência de "pivo"
    nmap -sn da interna     nenhuma ocorrência de "alvo"
    getent hosts host-pivo  não resolve
    getent hosts host-alvo  não resolve

E o aceite inteiro foi refeito com os nomes novos: **21 verificações, 0 falhas.**

---

## 7. Artefatos da rede em bridge que aparecem na varredura

**O gateway `.1` de cada sub-rede.** `nmap -sn 172.20.0.0/24` devolve **5 hosts**, não 4:
os quatro containers mais `172.20.0.1`, que é a interface da bridge no host Docker. Não é
host do laboratório e não leva a lugar nenhum.

Durante a medição de hoje, **antes** de a DMZ virar `internal`, esse mesmo efeito produzia
um vazamento mais incômodo: do atacante, `nmap -sn 172.21.0.0/24` devolvia `1 host up` —
o gateway `172.21.0.1` — com a porta 111/rpcbind aberta. Isto é, a varredura confirmava
que a sub-rede interna **existe** antes de qualquer pivô, e a porta aberta pertencia à VM
do Docker, fora da fronteira do laboratório. Fechar a DMZ eliminou os dois problemas de
uma vez. Registrado porque a configuração anterior ficou em uso por dois dias.

**Reconectar não é recriar.** Alterar a definição de uma rede e rodar `docker compose up -d`
reconecta os containers existentes à rede nova **sem reaplicar `ipv4_address`** — os
endereços silenciosamente viraram dinâmicos (`172.20.0.2`, `.3`, `.4`, `.5`) e o
`curl` para `172.20.0.11:1337` passou a devolver `000`. Não há aviso. Depois de mexer em
`networks:`, é obrigatório `docker compose down && docker compose up -d`. Toda a evidência
deste documento foi recolhida após um ciclo completo, com os endereços conferidos um a um.

---

## 8. Memória dos sete containers

Duas medições, porque a diferença entre elas é informação. A primeira com o laboratório
recém-subido, em repouso, sem nenhum `docker exec`; a segunda logo após as varreduras das
seções 2 a 4.

| Container | Em repouso | Após as varreduras |
|---|---:|---:|
| `tcc-atacante` | 416 KiB | 4,703 MiB |
| `tcc-host-web` | 420 KiB | 404 KiB |
| `tcc-host-glhf` | 21,87 MiB | 23,17 MiB |
| `tcc-srv-deploy` | 2,102 MiB | 7,645 MiB |
| `tcc-host-db` | 1,66 MiB | 3,762 MiB |
| `tcc-host-arquivo` | 1,668 MiB | 1,781 MiB |
| `tcc-srv-financeiro` | 1,699 MiB | 1,773 MiB |
| **Total** | **29,8 MiB** | **43,2 MiB** |

Limite da máquina: 7,606 GiB. O laboratório ocupa **0,38% em repouso e 0,55% em uso** —
menos que uma aba de navegador, nos dois casos.

**A diferença não é ruído, e é ela que interessa.** O pivô vai de 2,1 para 7,6 MiB e o
atacante de 416 KiB para 4,7 MiB porque o `docker stats` contabiliza no cgroup do container
os processos que o `docker exec` cria dentro dele: os MiB a mais são o `nmap` rodando. Ou
seja, **a medição em repouso é o custo de existir e a medição após as varreduras é o custo
de trabalhar.** Uma execução de 60 passos mantém o segundo perfil, e mesmo assim o teto fica
na casa das dezenas de MiB.

`tcc-host-web` consome pouco mais de 400 KiB nas duas colunas porque ainda é um
`sleep infinity`; sobe quando a aplicação de entrada for construída. O distrator é 73% de
todo o consumo em repouso, o que é esperado: é o único que roda uma aplicação de verdade,
com banco semeado.

Em disco, as imagens somam cerca de 1,2 GB, das quais 559 MB são do atacante (nmap, hydra e
sqlmap) e 265 MB do distrator. As três imagens internas têm 148 MB cada e a do pivô 185 MB —
a diferença de 37 MB é o `nmap` e o cliente SSH.

**Consequência para o plano.** O cronograma previa, como plano de contingência, "cortar de
5 para 3 hosts comprometíveis" se apertasse. Memória não é a restrição, e a contingência
continua válida por tempo de construção, nunca por recurso de máquina.

---

## 9. Como refazer

    cd lab
    docker compose down && docker compose up -d --build
    docker compose ps                     # sete, todos Up

    # direção 1, tem que falhar
    docker exec tcc-atacante ip route
    docker exec tcc-atacante ping -c 3 -W 2 172.21.0.10
    docker exec tcc-atacante nmap -sn 172.21.0.0/24
    docker exec tcc-atacante nmap -Pn -p 22 172.21.0.10

    # controle, tem que funcionar
    docker exec tcc-atacante nmap -sn 172.20.0.0/24

    # direção 2, tem que funcionar
    docker exec tcc-srv-deploy ip -brief addr
    docker exec tcc-srv-deploy nmap -sn 172.21.0.0/24
    docker exec tcc-srv-deploy nmap -p 22 172.21.0.10 172.21.0.11 172.21.0.12

    # direção 3, tem que falhar
    docker exec tcc-host-db ping -c 2 -W 2 172.20.0.5

    # o vazamento de nome não voltou
    docker exec tcc-atacante nmap -sn 172.20.0.0/24 | grep -i pivo     # nada
    docker exec tcc-srv-deploy nmap -sn 172.21.0.0/24 | grep -i alvo   # nada

    # memória
    docker stats --no-stream

Os endereços têm de bater com a tabela da seção 1 antes de qualquer conclusão. Se estiverem
dinâmicos, o ciclo foi `up` sem `down` — ver seção 7.
