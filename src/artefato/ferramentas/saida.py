"""O que a saida de um comando executado revela.

Terceiro caso do mesmo padrao encontrado em 18 de setembro: o agente paga um
passo, obtem informacao, e o grafo nao a retem. §E13 foram as rotas, §E14 foi a
propria execucao, e aqui e o que o comando devolveu. Sem isto o agente roda
`find` e nao ve o resultado -- e, como o historico e descartado, ele nao tem
onde mais guardar.

**Este modulo nao decide QUANDO aplicar.** Pagina HTML comum tem caminho
(`/static/estilo.css`), e varrer todo corpo de resposta registraria rota de site
como arquivo do servidor. Quem aplica e o laco, e so quando o arnes SABE que um
comando executou: o oraculo confirmou (D55/D56) ou o ssh autenticou, caso em que
um comando rodou por definicao.

**Tres extracoes, e nao seis.** O prompt medido tem seis linhas vindas de saida
de comando; aqui estao `execucao:`, os caminhos e -- desde 21 de setembro --
`interfaces:`, a que revela a segunda interface do pivo e portanto a existencia
da sub-rede interna.

**`interfaces:` e a peca mais delicada do modulo**, e nao pelo parser: pelo que
o grafo faz com ela. Saber que a 172.21.0.0/24 existe NAO e alcanca-la. Se
comprometer o pivo contasse como alcance, o braco B tambem a alcancaria ao fazer
SSH nele, e o criterio de `ARTEFATO.md` §4.4 seria satisfeito pelos dois por
acidente. A separacao vive em `grafo/__init__.py`: `subredes` e conhecimento,
`subredes_alcancadas` e conquista, e so a segunda e a metrica 1.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .fatos import Host as HostObservado
from .fatos import Associacao, usuario_plausivel

# `uid=0(root) gid=0(root) groups=0(root)`, da saida de `id`. So esta forma e
# reconhecida: `whoami` devolve o nome solto, sem estrutura, e adivinhar que uma
# palavra qualquer e um usuario seria inventar.
IDENTIDADE = re.compile(r"\buid=(\d+)\(([^)]+)\)")

# Caminho absoluto. A ancora negativa antes da barra e o que separa caminho de
# ruido, e ela ganhou os tres casos que a saida REAL do laboratorio traz:
#
#   rtt min/avg/max/mdev = 0.075/0.075/0.075/0.000 ms
#        ^^^^ vem colado a letra          ^^^^ vem colado a digito
#   http://172.20.0.10:8080/diagnostico
#          ^^ vem colado a `:` e a `/`
#
#   </title>  </head>  </body>
#   ^ tag HTML de fechamento -- veio de ler o `app.py` do alvo, que traz o
#     template inteiro dentro de uma string
#
# Sem ela, uma linha de estatistica do `ping` viraria quatro arquivos, e ler o
# fonte de uma aplicacao web encheria o grafo de `/title`, `/head`, `/body`.
# Na `dmz-04`, 11 dos 38 caminhos guardados eram tags -- quase um terco do que o
# agente lia, e ocupando o teto que D58 reserva para caminho de verdade.
#
# O preco e `</dev/null` na forma de redirecionamento de ENTRADA deixar de ser
# lido como caminho. E ruido de qualquer jeito, e a forma `2>/dev/null`, que e a
# comum, nao e afetada.
# O `*` entrou em 29 de setembro, com D172. O MOTD do Debian, que toda sessao
# SSH imprime, traz `individual files in /usr/share/doc/*/copyright.` -- e o
# `*` cortava o caminho em dois, dando `/usr/share/doc` (certo) e
# `/copyright.` (que nao existe em host nenhum). Curinga antes da barra e
# padrao de glob, nunca inicio de caminho.
#
# O `~` entrou com D179, mesma familia e mesmo dia. `ls -la ~/.ssh/id_ed25519`
# gravava `/.ssh/id_ed25519` -- caminho que nao existe, e justo o do arquivo de
# que o elo 5 depende. Medido no corpus: `/.bashrc` em 17 execucoes e
# `/.profile` em 14, nenhum deles existente. O til e atalho para o diretorio
# do usuario, e qual diretorio e isso o texto nao diz: **perder o achado e
# menos grave que inventar o caminho** (D04).
CAMINHO = re.compile(r"(?<![\w:/.<*?~])(/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)")

# Uma entrada de `ls -l`. A coluna de permissao e inconfundivel -- tipo, depois
# nove letras de modo, opcionalmente `.` ou `+` de atributo estendido -- e e ela
# que separa listagem de qualquer outro texto.
#
# **So a forma `-l` e lida.** Sem ela, `ls` devolve um nome solto por linha, e
# nome solto nao se distingue de prosa: tentar adivinhar inventaria caminho. O
# agente tem `find`, que devolve caminho absoluto e ja funciona.
#
# O nome vai ate o FIM da linha, nao ate o primeiro espaco: `notas do time.txt`
# e um arquivo so.
ENTRADA = re.compile(
    r"^[-dlcbps][rwxsStT-]{9}[.+]?\s+\d+\s+\S+\s+\S+\s+\d+\s+"
    r"\S+\s+\S+\s+\S+\s+(\S.*?)\s*$")

# Link simbolico no `ls -l`: `bin -> usr/bin`. O alvo sai do nome, senao o grafo
# guarda `/bin -> usr/bin`, que nao e caminho que exista -- e o agente que
# tentasse usa-lo montaria um comando quebrado.
ALVO_DO_LINK = re.compile(r"\s+->\s+.*$")

# Endereco IPv4 de uma interface, na saida de `ip addr`. As duas formas que o
# agente escreve trazem a MESMA linha, e por isso uma expressao so atende as
# duas:
#
#   ip -o addr  "2: eth0    inet 172.21.0.2/24 brd ... scope global eth0\..."
#   ip addr     "    inet 172.21.0.2/24 brd ... scope global eth0"
#
# **A ancora e `scope global`**, e ela faz o trabalho de excluir o loopback
# sozinha: `lo` sai como `scope host`. Filtrar por `127.` seria endereco fixo no
# codigo, que e o que D04 manda evitar -- e nao pegaria outro loopback.
#
# `inet6` nao casa porque a expressao exige quatro octetos decimais. O grafo
# modela IPv4; reconhecer IPv6 sem o resto do artefato saber lidar com ele
# gravaria fato que nada consome.
#
# **O nome para na barra invertida**, e isso nao e detalhe cosmetico: a forma
# `-o` junta numa linha so o que a forma longa quebra em varias, e usa `\` como
# emenda. Sem excluir a barra o nome sai `eth0\`, e as duas formas -- que sao a
# MESMA informacao -- dariam resultados diferentes.
ENDERECO_DE_INTERFACE = re.compile(
    r"\binet (\d+\.\d+\.\d+\.\d+)/(\d+)\b.*?\bscope global\b\s*([^\s\\]+)?")

# A MESMA INFORMACAO PELA OUTRA PORTA: a tabela de rotas (D142).
#
#   172.21.0.0/24 dev eth1 proto kernel scope link src 172.21.0.2
#
# Ate 25 de setembro so a forma do `ip addr` era reconhecida, e o agente que
# rodasse `ip route` -- que e o comando irmao, e igualmente natural -- lia
# "nenhum fato novo" depois de ter a resposta na tela. Pior que perder o fato:
# o resumo AFIRMA que nao houve fato, e `CONTEXTO.md` §9 impede o agente de
# conferir, porque a saida bruta nunca chega a ele.
#
# **Isto e leitura, nao sintese.** A linha declara a sub-rede COM o prefixo, o
# nome da interface e o endereco local -- os mesmos tres fatos do `ip addr`, e
# a sub-rede aqui vem escrita em vez de calculada.
#
# `proto kernel scope link` restringe as rotas de interface direta. Sem isso a
# expressao casaria tambem as rotas via gateway, que falam de uma rede que o
# host ALCANCA e nao de uma em que ele ESTA -- e registrar aquilo como interface
# poria um fato falso no grafo.
# LINHA DO `/etc/hosts` (D155): endereco IPv4, espaco em branco, um ou mais
# nomes. Ancorada no comeco da linha para nao casar endereco no meio de prosa.
#
# ENTROU DEPOIS de D142 ter recusado, e a recusa estava errada pelo motivo
# errado. Escrevi que absorver este arquivo "exigiria inventar a mascara" -- mas
# `grafo._subrede_de` DEDUZ /24 de qualquer endereco solto, sempre deduziu, e a
# docstring dela diz por que: "o agente descobre a sub-rede interna ao enumerar
# o pivo, e nesse instante ela tem de existir no grafo sem ninguem ter declarado
# nada". Eu apliquei ao parser uma regra que o grafo ao lado nao segue.
#
# O PRECO DA RECUSA foi medido: no passo 16 do braco B do par 2 o agente leu
# este arquivo no pivo -- que nomeia `172.21.0.2 srv-deploy` -- e o arnes
# respondeu "nenhum fato novo". Ele leu a resposta e nos a jogamos fora.
#
# Vira HOST OBSERVADO, nao interface: o arquivo da endereco e nome, que e
# exatamente a forma que `Grafo.absorver_hosts` ja recebe do nmap. Interface
# exigiria prefixo, e esse o arquivo de fato nao tem.
LINHA_DE_ETC_HOSTS = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)[ \t]+(\S+)", re.MULTILINE)

# A ASSINATURA DE UM `/etc/hosts`: a linha de loopback com nome, que todo arquivo
# desses tem na primeira linha. E o que separa o arquivo de uma prosa que comeca
# com endereco.
LOOPBACK_NOMEADO = re.compile(r"^127\.\d+\.\d+\.\d+[ \t]+\S", re.MULTILINE)

# LINHA SO DE ENDERECOS (D155), que e o que `hostname -I` devolve:
#
#   172.20.0.12 172.21.0.2
#
# Sao os enderecos DA PROPRIA maquina, sem nome e sem prefixo. Precisa de padrao
# proprio porque `LINHA_DE_ETC_HOSTS` leria o SEGUNDO endereco como nome do
# primeiro -- e "172.21.0.2" viraria o nome de "172.20.0.12", fato falso no
# grafo. A guarda esta no laco: nome que e endereco nao vira nome.
#
# A linha INTEIRA tem de ser so enderecos e espaco. Sem a ancora de fim, a
# primeira linha de um `/etc/hosts` casaria aqui tambem.
LINHA_SO_DE_ENDERECOS = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+(?:[ \t]+\d+\.\d+\.\d+\.\d+)*)[ \t]*$", re.MULTILINE)

# ENDERECO PROPRIO NO `/proc/net/fib_trie` (D155). O arquivo e uma arvore:
#
#        +-- 172.21.0.0/24 2 0 2
#           +-- 172.21.0.0/30 2 0 2
#              |-- 172.21.0.0
#                 /24 link UNICAST
#              |-- 172.21.0.2
#                 /32 host LOCAL      <- ESTE, o endereco da maquina
#
# Le-se o par `|-- <ip>` seguido de `/32 host LOCAL`, que sao os enderecos do
# proprio host. As linhas `/24 link UNICAST` declaram a rede COM prefixo, e eu
# as deixo de fora de proposito: elas trazem o endereco de REDE, nao o do host,
# e `Interface` precisa do endereco do host. A deducao /24 que o grafo faz
# concorda com o que essas linhas declaram -- CONFERIDO na saida real do pivo,
# nao suposto.
ENDERECO_LOCAL_NO_FIB = re.compile(
    r"\|--\s+(\d+\.\d+\.\d+\.\d+)\s*\n\s*/32\s+host\s+LOCAL")

ROTA_DE_INTERFACE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)/(\d+)\s+dev\s+(\S+)\b.*?"
    r"\bproto kernel\b.*?\bscope link\b.*?\bsrc\s+(\d+\.\d+\.\d+\.\d+)",
    re.MULTILINE)


# Cabecalho de bloco do `ls` com varios diretorios: uma linha que so tem o
# caminho e dois pontos. Quem lista varios diretorios de uma vez recebe a saida
# em blocos, e cada bloco declara a sua propria base -- ler isso nao e adivinhar
# de onde veio um nome, e ler o que a saida afirma.
CABECALHO_DE_BLOCO = re.compile(r"^(/[^\s:]*):$")

# Linha em que a saida NEGA a existencia do caminho que ela mesma cita:
# `cat: /root/trofeu.txt: No such file or directory`. Sem isto o grafo gravava
# o caminho como visto, e mandava o agente de volta a um lugar que nao existe --
# pior do que perder o fato, porque um fato falso ele acredita.
#
# So a NAO-EXISTENCIA derruba o caminho. `Permission denied` afirma o contrario:
# o caminho existe e falta permissao, que e informacao util -- diz onde insistir
# com outro uid.
INEXISTENTE = re.compile(r"No such file or directory|not found", re.IGNORECASE)
# ⚠️ D251. O CAMINHO QUE A PROPRIA SAIDA DECLARA AUSENTE NAO E PROVA.
#
# `INEXISTENTE` acima recusa a LINHA que fala de ausencia, e isso resolve o caso
# de uma linha. Nao resolve o caso de DUAS, que e o que o agente produz:
#
#     ---/var/log/sulog---                              <- eco do candidato
#     cat: /var/log/sulog: No such file or directory     <- a refutacao
#
# O agente escreve `for f in <lista>; do echo ---$f---; cat "$f"; done` com uma
# lista de candidatos que ele QUER testar. O `echo` imprime cada um exista ou
# nao, a guarda por linha recusa a segunda linha e aceita a primeira, e o
# candidato entra como caminho PROVADO. A saida contem a refutacao e o arnes a
# joga fora.
#
# Medido (§E114): no passo 74 do braco A do par 4 o agente listou nove
# candidatos de `/etc/login.defs` e os nove entraram provados, nenhum existindo.
# E no passo 66 do braco A do par 8 ele AGIU sobre um deles, com estas palavras:
# *"o caminho /var/app/images aparece listado como visto porem nunca
# explorado"* -- leu o proprio eco de volta como descoberta.
#
# As tres formas sao as que este laboratorio produz de verdade, conferidas nele:
#     cat: /var/log/sulog: No such file or directory
#     ls: cannot access '/etc/ttytype': No such file or directory
#     stat: cannot statx '/bin/fakeshell': No such file or directory
#
# ⚠️ **E o contraexemplo que define a forma da expressao** e a reclamacao do
# `hydra`: `[ERROR] passwords not found: /usr/share/wordlists/rockyou.txt`. Ali o
# caminho vem DEPOIS do texto, e ele EXISTE -- o agente acabou de baixa-lo. Uma
# expressao que casasse isso tiraria da prova um caminho verdadeiro, que e o
# defeito oposto e igualmente grave. Por isso o caminho tem de vir ANTES do
# `:`, nao depois.
DECLARADO_AUSENTE = re.compile(
    r"'?(/[^\s':]+)'?:\s*(?:No such file or directory|not found)",
    re.IGNORECASE)


def _declarados_ausentes(texto: str) -> set[str]:
    """Os caminhos que a propria saida diz que nao existem. Funcao pura.

    Separada para ser testavel sem laboratorio (D25) e para ser a unica fonte da
    regra -- a licao de `autenticou` em `ferramentas/ssh.py`: regra repetida em
    dois lugares e regra que vai divergir.

    Devolve conjunto, nao lista: a pergunta e de pertinencia, e o mesmo caminho
    costuma aparecer varias vezes na mesma saida.
    """
    return set(DECLARADO_AUSENTE.findall(texto or ""))

# Linha em que o shell diz que o BINARIO nao existe. Caso distinto do de cima,
# e a distincao e o fato que interessa ao agente: `INEXISTENTE` responde "o
# arquivo que voce pediu nao esta la", esta responde "o comando que voce
# escreveu nao roda aqui". Sem separar as duas, um `ip` que nunca executou vira
# "nenhum fato novo", e o agente nao consegue distinguir *rodei e nao achei* de
# *nao consegui rodar* -- passo 10 da `teto-03`.
#
# As duas formas que o laboratorio produz, capturadas do `tcc-host-web`:
#
#   /bin/sh.real: 1: ip: not found          (dash)
#   bash: line 1: ip: command not found     (bash)
#
# **Quem separa binario de arquivo e a exigencia de `<nome>:` colado ao `not
# found`**, e nao a ancora de fim de linha. O `hydra` escreve `File for
# passwords not found: /usr/share/wordlists/rockyou.txt`: ali o texto antes de
# `not found` e " passwords ", sem dois-pontos, entao a linha nao casa de jeito
# nenhum. Medido, porque a primeira versao deste comentario atribuia o merito a
# ancora e estava errada.
#
# O que a ANCORA faz e recusar linha com texto depois -- `sh: ip: not found,
# try: apt install iproute2` e prosa, nao mensagem de shell. Ela aceita `<` para
# nao morrer se a saida vier embrulhada em HTML (`...not found</pre>`), que e o
# formato que a aplicacao do `host-web` poderia passar a devolver; hoje ela
# devolve texto puro, verificado em 22 de setembro contra o laboratorio no ar.
# Sem essa folga a deteccao sumiria EM SILENCIO no dia em que o template
# mudasse.
#
# O nome sai da ULTIMA secao do caminho: o agente costuma escrever
# `/usr/bin/ip`, e o que ele precisa reconhecer noutro host e `ip`.
COMANDO_INEXISTENTE = re.compile(
    r"(?:^|:\s)\s*([\w./+-]+):\s+(?:command\s+)?not found\s*(?=<|$)",
    re.IGNORECASE | re.MULTILINE)


@dataclass
class Interface:
    """Uma interface de rede do host, como `ip addr` a reporta.

    `subrede` e CALCULADA do endereco e do prefixo, nao lida -- o `ip addr` nao
    a imprime. A conta usa `ipaddress` da biblioteca padrao, entao vale para
    qualquer prefixo: reproduzir este trabalho noutra faixa nao exige mexer
    aqui.
    """

    nome: str
    endereco: str
    subrede: str


def _subrede_de(endereco: str, prefixo: str) -> str | None:
    """`172.21.0.2` + `24` -> `172.21.0.0/24`. `None` quando nao da conta."""
    try:
        return str(ipaddress.ip_network(f"{endereco}/{prefixo}", strict=False))
    except ValueError:
        # Prefixo fora da faixa ou endereco malformado. Nao se inventa
        # sub-rede a partir de texto que nao e endereco.
        return None


@dataclass
class ContaDeConfig:
    """Uma conta que um arquivo de configuracao de `ssh` DECLARA (D186).

    `alias` e o nome do bloco, guardado por ser o que o arquivo chama de host --
    util para quem le a medicao, e nao usado como endereco. `endereco` so existe
    quando o `HostName` E um IPv4: nome de maquina nao vira endereco, pela mesma
    razao que D155 nao deixa texto virar host.
    """

    usuario: str
    alias: str
    endereco: str | None = None
    identidade: str | None = None


# D186. A CONTA QUE UM CONFIG DE `ssh` DECLARA.
#
# **O defeito que isto conserta, com o passo que o provou.** No passo 18 da
# execucao de 29 de setembro o agente rodou exatamente o comando certo --
# `cat /home/svc_deploy/.ssh/*` no `172.21.0.10` -- e o resumo respondeu
# **"nenhum fato novo"**. O arquivo continha `User svc_backup` e
# `HostName 172.21.0.11`, que e o salto do elo 5 que D181 acabou de tornar
# descobrivel NO LABORATORIO. O agente nao ve saida crua: ele ve o grafo e o
# resumo. Sem regra aqui, o laboratorio nomeia o proximo alvo e o arnes engole.
#
# ⚠️ **E a assimetria de raiz, registrada em §E76 e NAO consertada aqui:** o
# arnes extrai credencial do corpo de uma resposta HTTP (`Curl._credenciais`) e
# NUNCA da saida de um comando -- `FatosDeShell` nao tinha campo de credencial.
# O `config.ini` lido pela injecao web virou a `c01`; o mesmo arquivo lido por
# `ssh` nao viraria nada. Esta entrada abre a porta SO para o config de `ssh`,
# que e o que bloqueia o elo 5, e deixa a assimetria declarada.
#
# **A assinatura e forte de proposito.** `Host` aparece em prosa -- "Host key
# verification failed." e a linha que o proprio laboratorio produz. Exigir
# `User` E `HostName` dentro do mesmo bloco mantem a prosa fora: um arquivo de
# configuracao de verdade tem os tres, uma frase de erro nao tem nenhum.
CHAVE_DE_CONFIG = re.compile(r"^\s*(Host|HostName|User|IdentityFile)\s+(\S+)\s*$",
                             re.IGNORECASE)
IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _contas_de_config(texto: str) -> list[ContaDeConfig]:
    achadas: list[ContaDeConfig] = []
    bloco: dict[str, str] = {}

    def fechar() -> None:
        # ⚠️ Os DOIS campos, nunca um. Bloco com `Host` e `User` mas sem
        # `HostName` nao diz onde a conta serve; com `HostName` e sem `User` nao
        # diz quem ela e. Emitir com um so seria fato pela metade, que o agente
        # completaria adivinhando -- o defeito que D181 acabou de tirar do
        # laboratorio.
        # ⚠️ D244: a mesma guarda do `curl.py`, e aqui pela mesma razao. A
        # assinatura `Host`+`User`+`HostName` e forte, mas um TEMPLATE de script
        # com `User "$4"` a satisfaria -- e o defeito de §E100 entrou exatamente
        # por conteudo de script lido como configuracao.
        if (bloco.get("host") and bloco.get("hostname")
                and usuario_plausivel(bloco.get("user"))):
            destino = bloco["hostname"]
            achadas.append(ContaDeConfig(
                usuario=bloco["user"], alias=bloco["host"],
                endereco=destino if IPV4.match(destino) else None,
                identidade=bloco.get("identityfile")))

    for linha in (texto or "").splitlines():
        m = CHAVE_DE_CONFIG.match(linha)
        if not m:
            continue
        palavra = m.group(1).lower()
        if palavra == "host":
            fechar()
            bloco = {"host": m.group(2)}
            continue
        if bloco:
            bloco[palavra] = m.group(2)
    fechar()
    return achadas


@dataclass
class FatosDeShell:
    """O que se extraiu da saida de um comando. Campo ausente e `None`."""

    usuario: str | None = None
    uid: int | None = None
    # Na ordem em que apareceram, sem repetir. A ordem importa: uma busca
    # estreita feita antes de uma ampla fica na frente, e e a que tem valor.
    caminhos: list[str] = field(default_factory=list)
    # Na ordem em que o `ip addr` as lista, que e a ordem do indice da
    # interface -- estavel entre execucoes.
    interfaces: list[Interface] = field(default_factory=list)
    # Hosts que a saida NOMEIA, na ordem em que aparecem (D155). Vem do
    # `/etc/hosts`, que e configuracao: ele declara um mapeamento, e nao prova
    # que o host esta vivo. Entra como host sem servico -- `enumerado` fica
    # falso, porque ler o arquivo nao olhou porta nenhuma -- e a varredura
    # continua sendo o que estabelece atividade.
    hosts: list["HostObservado"] = field(default_factory=list)
    # Binarios que o shell disse nao existir NESTE host, na ordem em que
    # apareceram e sem repetir. Nao e ausencia global: `ip` falta no `host-web`
    # e existe no pivo, e e justamente essa diferenca que o agente precisa
    # enxergar.
    ausentes: list[str] = field(default_factory=list)
    # Contas que um arquivo de configuracao de `ssh` DECLARA (D186). Mesma
    # natureza dos `hosts` acima: e declaracao, nao prova. O host entra sem
    # servico e a credencial entra sem valida em lugar nenhum -- quem estabelece
    # que a conta funciona e o agente tentando.
    contas: list[ContaDeConfig] = field(default_factory=list)
    # D197. CAMINHOS QUE A SAIDA MENCIONA SEM PROVAR, na ordem em que apareceram.
    #
    # `caminhos` afirma *este host tem este caminho*. `mencionados` afirma outra
    # coisa, mais fraca e verdadeira: *um arquivo deste host cita este caminho*.
    # Confundir as duas foi o defeito que custou 6 passos no braco A do par 1.
    mencionados: list[str] = field(default_factory=list)

    # D245. Os pares (endereco, caminho) que uma linha de arquivo AFIRMA --
    # `uma linha lida aqui associa aquele endereco a este caminho`. Lista
    # separada de `mencionados` porque afirma MAIS: nao so que um arquivo
    # daqui fala do caminho, mas de QUEM o caminho e. Nao afirma
    # existencia (§E99, corrigida): e verdade sobre o texto lido.
    associados: list[Associacao] = field(default_factory=list)

    @property
    def root(self) -> bool | None:
        """`None` quando nao se sabe -- nunca falso por omissao."""
        return None if self.uid is None else self.uid == 0


# `/proc` e `/sys` sao interfaces do KERNEL, nao configuracao do host: nenhum
# passo de `lab/cadeia.md` os envolve e nenhum deles e achado. Guardá-los gasta
# a memoria de caminhos do grafo com o que nao e fato do ambiente (D112).
#
# No passo 5 da `diag-04` o agente rodou `find / -iname "*flag*"` procurando o
# trofeu e levou doze entradas assim para o grafo:
#
#   /proc/fs/cifs/SecurityFlags
#   /proc/sys/net/ipv4/fib_notify_on_flag_change
#   /proc/kpageflags
#   /sys/devices/platform/serial8250/tty/ttyS2/flags
#
# Doze das quarenta vagas POR HOST. No passo 11 o teto encheu, e do passo 11 ao
# 45 nada mais entrou -- inclusive o `config.ini` que tem a credencial.
#
# **Por COMPONENTE, nao por prefixo de texto.** `/procedimentos/backup.sh` nao
# e `/proc`, e uma comparacao por prefixo o comeria em silencio.
KERNEL = frozenset({"proc", "sys"})


def _do_kernel(caminho: str) -> bool:
    partes = caminho.split("/")
    return len(partes) > 1 and partes[1] in KERNEL


# D172. MATERIAL DE CHAVE RASPADO COMO CAMINHO.
#
# Base64 usa a barra no alfabeto, e `CAMINHO` nao sabe disso: a linha de um
# `known_hosts` --
#
#   172.20.0.12 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI.../P/iGJ3qI8Y2Vd/CyXbaDsO0k2Y
#
# -- entrega ao grafo dois "caminhos" que nunca existiram. **Nao e hipotese:**
# na `coleta-A-01` o agente gastou os passos 19, 24, 32, 36 e 37 tentando
# `cat`, `ls`, `file`, `find` e ate `nc -U` naqueles dois nomes. Cinco passos de
# oitenta, atras de um fato que o arnes inventou.
#
# **A regra e sobre o SEGMENTO, nao sobre a linha.** Pular a linha inteira
# perderia caminho legitimo que estivesse nela; e pular pelo marcador
# `ssh-ed25519` deixaria passar chave PRIVADA em PEM, que nao tem marcador
# nenhum no meio do blob.
#
# Oito caracteres de [A-Za-z0-9] com maiuscula, minuscula E digito, sem ponto,
# hifen ou sublinhado. Nome de arquivo real quase nunca tem essa forma -- e a
# escolha e a de D04: **perder achado e menos grave que inventar fato.** O
# preco esta medido em §E67, contra o laboratorio no ar: dos caminhos do corpus
# inteiro que esta regra descarta, ZERO existem de verdade.
#
# ⚠️ **O limiar era DEZ e passou a OITO em 29 de setembro (D184), com a medicao
# que decidiu.** Com dez, `/Wg0n2cou1` -- nove caracteres, saido do
# `known_hosts` pelo mesmo mecanismo que D172 descreve -- entrou no grafo da
# execucao daquele dia e custou o passo 29, gasto num `ls` e num `cat` de um
# nome que nunca existiu. Contra os 2.424 caminhos do corpo inteiro, descer de
# dez para oito descarta **exatamente um caminho: aquele.** Nenhum caminho real
# se perde, e por isso a mudanca nao e troca de um risco por outro.
CHAVE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[A-Za-z0-9]{8,}$")

# D184. PONTO FINAL DE FRASE NAO E PARTE DO CAMINHO.
#
# `CAMINHO` casa `[A-Za-z0-9._-]`, entao o ponto que termina uma frase entra no
# nome: um texto que diz "veja /etc/profile." entrega `/etc/profile.`, que nao
# existe, em vez de `/etc/profile`, que existe. No corpo inteiro sao **48
# caminhos terminados em ponto**, entre eles `/etc/profile.` 18 vezes e
# `/copyright.` 23.
#
# ⚠️ **Isto nao transforma todo falso em verdadeiro, e a diferenca importa.**
# `/etc/profile.`, `/bin/ip.` e `/etc/pam.d.` passam a nomear o arquivo certo;
# `/copyright.` continua sendo mencao de texto e segue inexistente, so sem a
# pontuacao. A justificativa nao e "conserta tudo": e que o ponto final **nunca**
# faz parte destes nomes, entao mante-lo e sempre errado.
# D190. E O BANNER DE SHELL DO PROPRIO AGENTE, pelo mesmo mecanismo.
#
# O agente escreve `for f in ...; do echo ---$f---; cat $f; done` para separar
# blocos. Com `$f` expandindo para o caminho, a linha fica
# `---/opt/diagnostico/config.ini---`, e `-` e caractere valido de `CAMINHO`:
# entra `/opt/diagnostico/config.ini---`, que nao existe. **O arquivo corrompido
# e o que guarda a credencial da cadeia.** Medido no braco A de 30 de setembro,
# onde as duas formas conviviam no grafo (11 passos usaram separador).
#
# ⚠️ **SO CORRIDA DE DOIS OU MAIS, e o contraexemplo e o que fixa a regra:**
# `/etc/passwd-` e `/etc/group-` EXISTEM no laboratorio -- sao os backups do
# Debian, e justamente o que interessa a um atacante. `rstrip("-")` cego
# destruiria achado legitimo. Contra os 2.522 caminhos do corpo: 16 terminam em
# traco, e a regra de dois-ou-mais conserta 13 sem perder nenhum real.
FIM_DE_BANNER = re.compile(r"-{2,}$")


# D194, MECANISMO 1. PREFIXO DE REDE, e nao caminho.
#
# `/proc/net/fib_trie` imprime o comprimento do prefixo em LINHA PROPRIA e
# indentado -- `              /8 host LOCAL` --, e o caractere antes da barra e
# espaco, que nao esta na negativa de `CAMINHO`. Reproduzido contra o
# `tcc-host-web`: o arquivo entrega exatamente `/8`, `/32` e `/24`, que sao os
# tres falsos que apareceram na execucao de 30 de setembro.
#
# ⚠️ **A regra e sobre o caminho INTEIRO, nunca sobre o segmento:** `/proc/1` e o
# PID 1 e `/var/log/journal/8` existe. Barra mais digitos e SOZINHO nao e nome de
# arquivo em nenhum dos sete conteineres.
SO_DIGITOS = re.compile(r"^/[0-9]+$")

# D194, MECANISMO 2. A TABELA DE MONTAGEM DESCREVE A MAQUINA HOSPEDEIRA.
#
# `mount` rodado dentro do conteiner imprime as opcoes do overlayfs, e elas
# apontam para o armazenamento do Docker no HOST -- `/var/lib/desktop-containerd/
# daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1589/fs`. Nada disso
# existe dentro do conteiner. Sao 70 caminhos falsos no corpo.
#
# ⚠️ **Tira-se a OPCAO, nao a linha:** o ponto de montagem na mesma linha e fato
# verdadeiro e util (`tmpfs on /run/lock ...`). Pular a linha inteira perderia
# achado legitimo, que e D04 ao contrario.
OPCAO_DE_OVERLAY = re.compile(r"\b(?:lower|upper|work)dir=[^,)\s]*")

# D194, MECANISMO 4. O PRIMEIRO CAMPO DO `df` E O DISPOSITIVO.
#
# `/dev/sdd       1007G   21G  935G   3% /etc/hosts` -- o primeiro campo lastreia
# o sistema de arquivos e nao existe dentro do conteiner; o ULTIMO e o ponto de
# montagem, que e caminho de verdade.
#
# ⚠️ **Tira-se so a primeira coluna, e o contraexemplo esta na mesma saida:**
# `/dev/shm` aparece como ponto de MONTAGEM e e caminho legitimo. Uma regra que
# apagasse `/dev/...` inteiro comeria achado -- e `/dev/null` e `/dev/shm` sao
# dos mais uteis a quem opera. Cobre `df` e `df -h`: contagem de blocos ou
# tamanho com sufixo.
DF_LINHA = re.compile(
    r"^\S+(\s+[\d.,]+[KMGTPE]?i?B?\s+[\d.,]+[KMGTPE]?i?B?"
    r"\s+[\d.,]+[KMGTPE]?i?B?\s+\d+%\s+\S+)\s*$")

# E A ORIGEM DA LINHA DO `mount`, pelo mesmo motivo e no mesmo formato de saida:
#
#   /dev/sdd on /etc/hosts type ext4 (rw,relatime)
#   ^^^^^^^^    ^^^^^^^^^^
#   dispositivo  ponto de montagem
#
# A origem e dispositivo do HOST ou, em montagem por vinculo, caminho do HOST --
# **nunca caminho deste conteiner**. O ponto de montagem e; ele fica.
ORIGEM_DE_MONTAGEM = re.compile(r"^\S+( on /\S* type \S+)")

# D234. A MESMA ORIGEM, NA OUTRA GRAFIA: `/proc/mounts` e `/etc/mtab`.
#
# ⚠️ **A guarda acima cobria a forma que eu imaginei, e o mundo entregou a
# outra.** `ORIGEM_DE_MONTAGEM` casa a saida do COMANDO `mount`
# (`/dev/sdd on /etc/hosts type ext4`). O `/proc/mounts` afirma o MESMO fato com
# outra sintaxe, sem ` on ` e sem ` type `:
#
#   /dev/sdd /etc/hosts ext4 rw,relatime 0 0
#   proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
#
# **E foi exatamente por essa via que o agente passou.** A justificativa do
# passo 74 da `coleta-B-01` de 1 de outubro: *"df/mount falharam repetidamente
# por reset; ler /proc/mounts diretamente (sem invocar binario externo) e uma
# forma mais leve de descobrir volumes extras"*. O `mount` levava
# `kex_exchange_identification: Connection reset`, entao ele trocou de grafia --
# e a guarda nao o seguiu. Familia de D109, D211 e D230.
#
# **O preco, medido no registro.** `/dev/sdd` entrou no grafo do `srv-deploy`; o
# campo `fatos` do braco B o entregou ao agente no passo 74, dentro de
# `caminhos vistos`; e ele gastou SEIS dos seus ultimos sete passos atras dele:
#
#   p75  "/proc/mounts revelou um novo dispositivo /dev/sdd nunca visto antes"
#   p76  "este dispositivo novo pode ser um volume extra onde o trofeu esta"
#   p78  "/dev/sdd provavelmente monta em /mnt, local plausivel do trofeu"
#
# `/dev/sdd` e o disco virtual do Docker/WSL e **nao existe dentro do
# conteiner** -- `ls /dev/sd*` responde "No such file or directory", e
# `conferir_caminhos.py` (D184) o acusou como ausente. Mesma classe de §E86, que
# descartou o par de 30 de setembro: fato falso NOSSO custando passos do braco
# que a hipotese diz que perde.
#
# Tira-se o PRIMEIRO CAMPO, nunca a linha: o ponto de montagem e caminho deste
# conteiner e continua entrando -- medido, 36 de 36 linhas do `/proc/mounts` do
# pivo, com `/etc/hosts`, `/etc/hostname` e `/etc/resolv.conf` preservados.
#
# ⚠️ **Os dois ultimos campos serem NUMEROS e o que segura a cerca.** O formato
# tem seis campos exatos (`origem ponto tipo opcoes dump passe`), e e isso que
# distingue a linha de uma frase qualquer com barras e numeros. Conferido contra
# cinco contraexemplos, nenhum casa -- entre eles
# `/etc/passwd /etc/shadow sao dois arquivos 1 2`.
ORIGEM_EM_PROC_MOUNTS = re.compile(
    r"^\S+(\s+/\S*\s+\S+\s+\S+\s+\d+\s+\d+)\s*$")

# D197. Endereco IPv4 solto na linha. Deliberadamente simples, como o
# `FORA_DE_ESCOPO` do laco: quatro grupos de digitos. Serve de sinal de que a
# linha descreve OUTRA maquina, nao de validacao de endereco.
ENDERECO_NA_LINHA = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# D198. `href` E `src` SAO ROTA DE SERVIDOR, nao caminho de sistema de arquivos.
#
# **O caso que provou.** No braco B do par 1 o agente usou a injecao no `.10`
# para rodar `python3 -c "import urllib..."` e baixar a pagina da GLHF. O HTML
# voltou pelo corpo, e **21 caminhos falsos** entraram no grafo em dois hosts --
# `/static/css/bootstrap.min.css`, `/login`, `/register`,
# `/download/rockyou.txt`. O python rodou mesmo no `.10`, entao nao e atribuicao
# errada de host (D175): e HTML lido como sistema de arquivos.
#
# ⚠️ **E o braco B VE esses caminhos.** A memoria linear carrega as cadeias, nao
# so a contagem -- eu supus o contrario e conferi antes de decidir. O braco que a
# hipotese diz que FALHA foi o mais contaminado, 21 contra 3. Defeito cujo
# sintoma e o resultado desejado e a pior classe deste projeto (D125), e por isso
# este nao e declaravel: e conserto.
#
# Tira-se o VALOR DO ATRIBUTO, nunca a linha: caminho de verdade fora de atributo
# -- um rastro de pilha vazado numa pagina de erro, que e dos achados mais uteis
# que um alvo entrega -- continua entrando. `D188` cobre a rota que o `curl` ja
# conhecia; esta cobre a que so existe no texto da pagina.
# D212, MECANISMO 1. LINHA DE COMENTARIO de script ou configuracao.
#
# **Observado ao vivo no passo 75 da `coleta-B-01`**, pelo vigia: seis caminhos
# falsos no `host-db`, todos do `.bashrc` PADRAO DO DEBIAN. O `.bashrc` e um dos
# primeiros arquivos que qualquer agente le, entao isto dispara em quase toda
# execucao, em quase todo host.
#
#   # see /usr/share/doc/bash/examples/startup-files    <- COMENTARIO
#   #[ -x /usr/bin/lesspipe ] && eval ...               <- LINHA COMENTADA
#
# Comentario **fala** de um caminho; nao prova que ele existe. E a distincao que
# D197 criou: `caminhos` afirma *este host tem isto*, `mencionados` afirma *um
# arquivo daqui fala disto*. Aqui a mencao se guarda, com o nome certo.
#
# ⚠️ **A cerquilha tem de estar no COMECO da linha.** `/tmp/a#b` e nome de
# arquivo com cerquilha no meio, e o agente escreveu coisa parecida no corpo.
#
# ⚠️ **E `--` TAMBEM E COMENTARIO (D237), que a cerquilha nao cobria.** Lua e SQL
# comentam com dois tracos, e isso custou dois fatos falsos no braco A do par 2
# da coleta:
#
#   1. o agente rodou `find / -iname "*flag*" -exec cat {}`
#   2. casou com `/usr/share/nmap/scripts/http-cookie-flags.nse` -- o NOME tem
#      "flag", e o arquivo e um script do nmap, nao um trofeu
#   3. o `cat` despejou o FONTE, cujos comentarios de documentacao dizem
#      `-- |   /admin/:` e `-- <table key="/mail/">` -- exemplo de saida do
#      script, nao caminho do pivo
#   4. `/admin` e `/mail` entraram como caminho PROVADO do `srv-deploy`
#
# `conferir_caminhos.py` (D184) os acusou como ausentes. Sexta aparicao da
# familia D109/D211/D230/D234: a guarda cobria a sintaxe que eu imaginei.
#
# ⚠️ **O `(?!-)` nao e enfeite, e dois contraexemplos o exigem.** `ls -l` de
# arquivo sem permissao nenhuma comeca com DEZ tracos e traz o nome na mesma
# linha (`---------- 1 root root 0 Jan 1 00:00 /tmp/trancado`), e cabecalho de
# `diff` comeca com tres (`--- a/src/arquivo.py`). Os dois perderiam caminho
# legitimo com a guarda larga; com `(?!-)` nenhum dos dois casa. Conferido
# contra oito formas.
# ⚠️ **AS QUATRO SINTAXES DE 2 DE OUTUBRO, e por que so quatro.** D237 tapou `--`
# e nao conferiu as outras: medido depois, **oito de dez** sintaxes de comentario
# entravam como caminho PROVADO. Setima aparicao de D109/D211/D230/D234/D237 --
# *a guarda cobria a sintaxe que eu imaginei*.
#
# Entram so as ALCANCAVEIS neste laboratorio, que le shell, config, Python, Lua
# (`.nse`) e HTML: `//`, `;`, `/*` e `<!--`. Ficam fora `%` (TeX), `'` (VB),
# `rem` (BAT) e `"` (vimrc) -- mundos que este laboratorio nao tem, e tres delas
# aparecem em saida comum de comando, onde a guarda custaria mais do que paga.
#
# ⚠️ **O `\s` depois de `//` e de `/*` nao e enfeite, e cada um tem contraexemplo
# medido.** Sem ele, `//usr/lib/x86_64-linux-gnu/libc.so.6` -- caminho POSIX com
# barra dupla, legitimo -- seria rebaixado, e `/*.conf: No such file or directory`
# tambem, porque `/*` ali e GLOB e nao abertura de bloco. Comentario de verdade
# traz espaco depois do marcador; glob e caminho nao. Conferido contra 21 formas.
#
# `<!--` nao precisa de `\s`: nao existe caminho de sistema de arquivos que
# comece assim.
#
# ⚠️ **LIMITE DECLARADO: a guarda e de LINHA.** Corpo de comentario de varias
# linhas nao e coberto -- a continuacao de `<!--` nao tem marcador nenhum, e a de
# `/*` comeca com ` * `, que aparece em `crontab`. Isso fica declarado em vez de
# resolvido: D212 e linha a linha por desenho, e uma guarda de ESTADO (dentro de
# bloco / fora de bloco) e mudanca de outra ordem.
#
# O `(?!-)` de D237 continua, e dois contraexemplos o exigem: `ls -l` de arquivo
# sem permissao nenhuma comeca com DEZ tracos e traz o nome na mesma linha
# (`---------- 1 root root 0 Jan 1 00:00 /tmp/trancado`), e cabecalho de `diff`
# comeca com tres (`--- a/src/arquivo.py`).
LINHA_DE_COMENTARIO = re.compile(r"^\s*(#|--(?!-)|//\s|/\*\s|<!--|;\s)")

# D212, MECANISMO 2. TESTE DE EXISTENCIA -- o script PERGUNTA se o caminho existe.
#
#   if [ -r /etc/debian_chroot ]; then
#   test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
#
# Um teste e a prova do CONTRARIO: quem escreveu o script nao sabia se o caminho
# estaria la. Nos dois casos acima o arquivo testado **nao existe** nos
# conteineres do laboratorio -- conferido.
#
# ⚠️ **REGIAO, NUNCA A LINHA, e esta e a quarta vez hoje que a licao aparece.**
# Na segunda linha acima, `/run/systemd/system` e testado (mencao) e
# `/sbin/e2scrub_all` e EXECUTADO (prova) -- as duas coisas na mesma linha. Uma
# regra de linha perderia a segunda. Mesma licao de D198, D204 e D211.
TESTE_DE_EXISTENCIA = re.compile(
    r"(?:\[\[?|\btest)\s+-[a-zA-Z]{1,2}\s+(/[^\s\]]+)")

# D212, MECANISMO 3. CARREGAMENTO de arquivo por script -- `. /p` ou `source /p`.
#
# No `.bashrc` real do laboratorio cada caminho aparece DUAS vezes: uma no teste
# e outra no corpo do `if`. E prova vence mencao (D197), entao sem esta regra os
# tres do `.bashrc` continuavam entrando como prova:
#
#   if [ -f /usr/share/bash-completion/bash_completion ]; then
#     . /usr/share/bash-completion/bash_completion
#
# Carregar um arquivo DENTRO de um `if` nao prova que ele existe -- e o que o
# script faria SE existisse. Mesma categoria do teste.
#
# ⚠️ O ponto exige espaco depois: `./configure` e programa no diretorio atual e
# nao casa, porque o `/` vem colado no ponto.
CARREGAMENTO = re.compile(r"^\s*(?:\.|source)\s+(/[^\s;&|]+)")

# D212, MECANISMO 4. SUBSTITUICAO DE COMANDO -- `$(cat /p)` ou `` `cat /p` ``.
#
# O ultimo falso do `.bashrc` real vinha daqui:
#
#   debian_chroot=$(cat /etc/debian_chroot)
#
# O script LE o arquivo; nao prova que ele existe -- e a linha esta dentro do
# `if` que acabou de testar a existencia. Mesma categoria das tres acima.
SUBSTITUICAO = re.compile(r"\$\([^()]*\)|`[^`]*`")

# D211, MECANISMO 1. LINHA DE DESPEJO HEXADECIMAL do `od -t x1z`.
#
# **Reproduzido contra o laboratorio.** No passo 23 da `piloto-B-01-preD199` o
# agente rodou `od -A x -t x1z -v scan_172_21.txt`. Esse formato imprime a
# renderizacao ASCII entre `>` e `<`, e **corta o arquivo em pedacos de 16
# bytes**:
#
#   000000 65 73 20 2f 70 72 6f 63  >escaneando /proc<   <- o corte cai aqui
#   000010 2f 6e 65 74 2f 75 64 70  >/net/udp6 e /pro<
#   -> colhia ['/net/udp6', '/pro']
#
# Um caminho real virando dois falsos. Duas causas somadas: o `lookbehind` do
# `CAMINHO` exclui `<` mas **nao** `>` -- assimetria acidental --, e o corte
# parte o caminho ao meio.
#
# ⚠️ **A LINHA INTEIRA sai, e aqui isso e o certo** -- ao contrario de D198 e
# D204, onde se tira a regiao e nunca a linha. O motivo: numa linha de `od`
# TODO caminho e fragmento cortado em 16 bytes. Nao existe caminho legitimo ali
# para preservar.
DESPEJO_HEX = re.compile(r"^\s*[0-9a-f]{6,8}\s+(?:[0-9a-f]{2}\s+){2,}")

# D211, MECANISMO 2. LINHA DE BASE64 -- corpo de chave privada, certificado, PEM.
#
# **Reproduzido com a saida real do `host-web`.** No passo 23 o agente rodou
# `grep -rli "pass|secret|token|key" /opt /etc /home /root | xargs cat`, que
# acha CHAVES PRIVADAS e despeja o corpo delas. O base64 quebra em linhas de
# ~64 caracteres, e naquela saida **13 linhas comecaram com `/`**:
#
#   /1eE5+VU0fMHbZDkVeL0LOAecpPGH3uCEXaf4J0Pu4jXCHqz9UPMNRawNWEcBRTZ
#
# No comeco da linha nao ha caractere anterior para o `lookbehind` rejeitar, e o
# `+` corta o resto -- sobra `/1eE5`. Os cinco falsos da `coleta-B-01` sao isso,
# e **custaram 7 dos 80 passos do braco B** (§E86).
#
# A guarda `CHAVE` de D184 nao pega por dois motivos independentes: quatro dos
# cinco tem menos de 8 caracteres, e o quinto -- `jStbjsIJIRaQC` -- passa porque
# `CHAVE` exige DIGITO e ele nao tem nenhum.
#
# ⚠️ **Por que a regra e de LINHA e nao de segmento.** Julgar o segmento vira
# adivinhacao sobre tamanho e mistura de letras, e um dia recusa caminho real --
# `/var/lib/AccountsService` tem maiuscula, minuscula e nenhum separador. A
# linha, nao: uma linha que e **so** alfabeto base64 e tem 40 caracteres ou mais
# nao e listagem de diretorio. Caminho real quase sempre traz `-`, `_` ou `.`,
# que estao **fora** do alfabeto base64.
SO_BASE64 = re.compile(r"^[A-Za-z0-9+/=]{40,}$")
# E o HASH CRYPT, o outro portador de base64 com `/` dentro.
#
# ⚠️ **SAI A REGIAO, NUNCA A LINHA, e esta foi a terceira vez que o
# contraexemplo me corrigiu.** A primeira versao apagava a linha que contivesse
# `$6$` -- e saida de `grep -r` e `caminho:conteudo`, entao
# `/etc/shadow:root:$6$abc$def` perdia o `/etc/shadow`, que e caminho de
# verdade. Mesma licao que D198 ja tinha escrito e que D204 repetiu.
#
# Vai de `$6$` (ou outro identificador de crypt) ate o proximo espaco ou
# dois-pontos, que e onde o campo do `shadow` termina.
HASH_CRYPT = re.compile(r"\$(?:1|2[aby]?|5|6|y|7|gy)\$[^\s:]*")
# E o delimitador de PEM, que e o sinal explicito. Segundo sinal para o mesmo
# fato, na disciplina de D65/D68.
LIMITE_PEM = re.compile(r"^-{3,}(?:BEGIN|END) ")

# D211, MECANISMO 3. O NOME MULTI-ARQUITETURA DO DPKG, que tem `:` DENTRO.
#
# `:` nao esta no alfabeto do caminho, entao a expressao parava nele e
# `/var/lib/dpkg/info/libc6:amd64.list` virava `/var/lib/dpkg/info/libc6` --
# que nao existe. Dezenove casos na `coleta-A-01`.
#
# ⚠️ **E o conserto NAO e descartar o prefixo, e sim ler o nome inteiro.**
# Conferido contra o laboratorio: `/var/lib/dpkg/info/libc6:amd64.list` EXISTE,
# com os dois-pontos no nome -- e convencao multi-arquitetura do Debian. Ler o
# nome completo troca dezenove caminhos FALSOS por dezenove VERDADEIROS, o que e
# estritamente melhor que perder os dois lados.
#
# ⚠️ **A primeira versao desta regra descartava o prefixo, e quebrou o
# contraexemplo que eu havia escrito para proteger.** Saida de `grep -r` e
# `caminho:conteudo`, e `/etc/shadow:root:$6$...` perdia o `/etc/shadow`. A lista
# de arquiteturas e estreita de proposito: ela distingue nome de arquivo de
# separador de `grep`, que nenhuma regra de forma generica distingue.
#
# Conhecimento de FERRAMENTA, nao do laboratorio -- mesma categoria dos formatos
# do nmap, dos modulos do hydra e dos codigos de saida do ssh.
ARQUITETURAS = ("amd64", "i386", "arm64", "armhf", "armel", "ppc64el",
                "s390x", "riscv64", "all")
SUFIXO_MULTIARCH = re.compile(
    r":(?:" + "|".join(ARQUITETURAS) + r")(?:[A-Za-z0-9._-]*)")

# D204. CABECALHO HTTP CUJO VALOR E UMA ROTA, nao um caminho de sistema de
# arquivos. Mesma familia de D188 e D198, terceiro portador: ali eram o grafo e
# o atributo de marcacao; aqui e o cabecalho da resposta.
#
# **Reproduzido contra a GLHF no ar**, e e o `/login` falso da `coleta-A-01`:
#
#   $ curl -s -i http://172.20.0.11:1337/
#   HTTP/1.1 302 FOUND
#   Location: /login          <- virava caminho do 172.20.0.12
#
# O agente salvou a resposta num arquivo e leu o arquivo depois; a colheita nao
# tem como saber que aquele texto e uma resposta HTTP, entao a regra tem de
# morar na linha.
#
# ⚠️ **A LISTA E EXATA, e isso e o conserto.** `cat: /etc/shadow: Permission
# denied` tambem tem a forma `Nome: valor`, e ali `/etc/shadow` e caminho de
# verdade -- o arquivo existe, o que faltou foi permissao. Uma regra que
# casasse qualquer `Nome:` apagaria esse achado. So entram os quatro cabecalhos
# cujo valor e, por definicao de protocolo, um URI. Mesma disciplina de D192,
# que trocou `startswith` por pertinencia exata depois de a bateria cobrar.
CABECALHO_DE_ROTA = re.compile(
    r"^(\s*(?:Location|Content-Location|Refresh|Link)\s*:)\s*\S.*$",
    re.IGNORECASE)

ATRIBUTO_DE_URL = re.compile(r"""\b(?:href|src|action|data-url)\s*=\s*["'][^"']*["']""",
                             re.IGNORECASE)


def _sem_pontuacao_final(caminho: str) -> str:
    # ⚠️ EM LACO, e nao em duas linhas, porque a ORDEM importa e nao e conhecida.
    # `---/etc/profile.---` tem o ponto ATRAS dos tracos: tirar o ponto primeiro
    # nao o alcanca, e tirar so uma vez deixa `/etc/profile.` de pe. Foi o teste
    # da ordem que pegou, e ele foi escrito porque a ordem interna de duas
    # limpezas numa funcao so e acidente esperando acontecer.
    limpo = caminho
    while True:
        antes = limpo
        limpo = FIM_DE_BANNER.sub("", limpo.rstrip("."))
        if limpo == antes:
            return limpo or caminho


def _material_de_chave(caminho: str) -> bool:
    return any(CHAVE.match(s) for s in caminho.split("/") if s)


def analisar_saida(texto: str, base: str | None = None) -> FatosDeShell:
    """Le a saida de um comando e devolve o que ela afirma.

    Nao interpreta significado: `uid=0(root)` e leitura de um formato, e um
    token que comeca com barra e um caminho. O que o arquivo contem, se o
    comando teve sucesso, ou se aquilo e util -- nada disso e decidido aqui.

    Os nomes de uma listagem sao RELATIVOS, e sem uma base eles nao viram
    caminho -- o parser nao adivinha de onde vieram. **Duas fontes dao base, e
    so essas duas:**

    1. `base`, o diretorio que o comando pediu para listar. Quem sabe isso e
       quem montou o comando, e ele a extrai com
       `laco.proposta.diretorio_listado`.
    2. O **cabecalho de bloco** da propria saida (D59): `ls` com varios
       diretorios imprime `/opt:` antes de cada bloco, e ali a saida DECLARA a
       base. Cada cabecalho troca a base corrente, e por isso `base` pode vir
       `None` num comando com varios diretorios sem que a listagem se perca.

    Sem nenhuma das duas, nome relativo nao vira caminho.
    """
    f = FatosDeShell()

    m = IDENTIDADE.search(texto or "")
    if m:
        f.uid, f.usuario = int(m.group(1)), m.group(2)

    # Interfaces, linha a linha. O nome vem do fim da propria linha do `inet`
    # (`... scope global eth0`), que as duas formas de `ip addr` trazem -- e nao
    # do cabecalho da interface, que so a forma longa tem.
    vistas: set[str] = set()
    for linha in (texto or "").splitlines():
        achado = ENDERECO_DE_INTERFACE.search(linha)
        if not achado:
            continue
        endereco, prefixo, nome = achado.groups()
        subrede = _subrede_de(endereco, prefixo)
        if subrede is None or endereco in vistas:
            continue
        vistas.add(endereco)
        f.interfaces.append(
            Interface(nome=nome or "?", endereco=endereco, subrede=subrede))

    # E PELA TABELA DE ROTAS (D142), depois do `ip addr` e nao antes: quando o
    # agente roda `ip -o a; ip route` numa tacada so, as duas formas descrevem
    # as mesmas interfaces, e `vistas` faz a segunda passar batida. A ordem
    # importa porque o `ip addr` e a fonte mais rica -- traz o nome mesmo em
    # interface sem rota --, entao ele fica com a primeira palavra.
    for achado in ROTA_DE_INTERFACE.finditer(texto or ""):
        rede, prefixo, nome, endereco = achado.groups()
        if endereco in vistas:
            continue
        # A sub-rede vem ESCRITA na linha, e ainda assim passa por
        # `_subrede_de`: normalizar pela biblioteca padrao faz `172.21.0.0/24`
        # e `172.21.0.5/24` virarem a mesma coisa, e a comparacao com o que o
        # `ip addr` calcula deixa de depender de o texto vir na forma canonica.
        subrede = _subrede_de(rede, prefixo)
        if subrede is None:
            continue
        vistas.add(endereco)
        f.interfaces.append(
            Interface(nome=nome, endereco=endereco, subrede=subrede))

    # HOSTS NOMEADOS PELO `/etc/hosts` (D155). Tres guardas, e cada uma existe
    # porque o arquivo real do laboratorio a exercita:
    #
    #   127.0.0.1  localhost                 -> loopback, mesma regra do
    #                                            `scope host` das interfaces
    #   ::1        localhost ip6-localhost   -> IPv6, e o grafo e IPv4
    #   172.21.0.2 srv-deploy                -> ESTE e o fato que importa
    #
    # O endereco passa por `ipaddress` em vez de por expressao: `999.1.2.3` casa
    # com quatro grupos de digitos e nao e endereco, e inventar host a partir
    # disso poria fato falso no grafo.
    nomeados: set[str] = set()

    def _nomear(bruto: str, nome: str | None) -> None:
        """Poe o host, se o endereco for endereco e nao for loopback."""
        try:
            ip = ipaddress.ip_address(bruto)
        except ValueError:
            return
        if ip.is_loopback or bruto in nomeados:
            return
        nomeados.add(bruto)
        f.hosts.append(HostObservado(endereco=bruto, nome=nome))

    # SO ABSORVE NOME DE UM TEXTO QUE **E** UM `/etc/hosts`, e o marcador e a
    # linha de loopback que todo arquivo desses tem. Sem esta guarda, a prosa
    # `172.21.0.2 esta no ar hoje` produzia um host chamado "esta" -- flagrado
    # pelo teste desta propria entrada, e e exatamente o fato inventado que D04
    # proibe. Nao ha como distinguir nome de hospedeiro de palavra qualquer:
    # "esta", "no" e "hoje" sao todos nomes validos de host.
    #
    # O PRECO, declarado: `grep 172.21 /etc/hosts` ou `tail -2 /etc/hosts` nao
    # trazem a linha de loopback, e por este caminho o fato nao entra. Perder
    # achado e menos grave que inventar fato (D04), e os outros quatro caminhos
    # -- `ip a`, `ip route`, `hostname -I`, `fib_trie` -- seguem valendo.
    if LOOPBACK_NOMEADO.search(texto or ""):
        for achado in LINHA_DE_ETC_HOSTS.finditer(texto or ""):
            bruto, nome = achado.groups()
            # NOME QUE E ENDERECO NAO E NOME. `hostname -I` devolve
            # `172.20.0.12 172.21.0.2`, e sem esta guarda o segundo viraria nome
            # do primeiro. Os dois entram pelo laco seguinte, como endereco.
            try:
                ipaddress.ip_address(nome)
            except ValueError:
                _nomear(bruto, nome)

    # ENDERECOS DA PROPRIA MAQUINA, por dois caminhos (D155): `hostname -I`, que
    # os lista numa linha, e o `/proc/net/fib_trie`, que os marca `/32 host
    # LOCAL`. Sem nome: nenhum dos dois informa nome, e inventar um seria fato
    # falso. O grafo deduz a sub-rede do endereco, como faz com todo host.
    for achado in LINHA_SO_DE_ENDERECOS.finditer(texto or ""):
        for bruto in achado.group(1).split():
            _nomear(bruto, None)
    for achado in ENDERECO_LOCAL_NO_FIB.finditer(texto or ""):
        _nomear(achado.group(1), None)

    # Binario ausente. Roda sobre o texto inteiro porque a expressao ja ancora
    # em linha (`MULTILINE`), e a saida real repete a linha uma vez por
    # invocacao -- `ip -o a; ip route` devolve duas. O dicionario preserva a
    # ordem e descarta a repeticao.
    faltando: dict[str, None] = {}
    for achado in COMANDO_INEXISTENTE.finditer(texto or ""):
        # `/usr/bin/ip` -> `ip`. O nome do binario e o que o agente digita.
        faltando.setdefault(achado.group(1).rsplit("/", 1)[-1], None)
    f.ausentes = list(faltando)

    vistos: dict[str, None] = {}
    # D197. O que a saida MENCIONA, separado do que ela PROVA.
    citados: dict[str, None] = {}
    # D245: os PARES (endereco, caminho) que uma linha de arquivo afirma.
    # Chave composta para deduplicar: o mesmo par pode vir de duas linhas.
    associados: dict[tuple[str, str], None] = {}
    # Linha a linha, e nao no texto inteiro, porque a negativa vale so para a
    # linha dela: uma linha boa no meio de erros continua valendo.
    for linha in (texto or "").splitlines():
        if INEXISTENTE.search(linha):
            continue
        # D194: as opcoes de overlay saem ANTES da colheita, e so elas -- o
        # ponto de montagem na mesma linha continua entrando.
        linha = OPCAO_DE_OVERLAY.sub("", linha)
        # D194: e a primeira coluna do `df` tambem, pelo mesmo criterio -- o
        # ponto de montagem, que e o ultimo campo, fica.
        linha = DF_LINHA.sub(r"\1", linha)
        linha = ORIGEM_DE_MONTAGEM.sub(r"\1", linha)
        # D234: e a MESMA origem na grafia do `/proc/mounts`, que foi a via por
        # onde o agente passou quando o `mount` vivia levando reset.
        linha = ORIGEM_EM_PROC_MOUNTS.sub(r"\1", linha)
        # D198: e os valores de `href`/`src`, que sao rota e nao arquivo.
        linha = ATRIBUTO_DE_URL.sub("", linha)
        # D204: e o valor de `Location:` e parentes, pelo mesmo motivo. Some o
        # VALOR e fica o nome do cabecalho -- a licao de D198, "tira-se o
        # atributo, nunca a linha", vale igual aqui.
        linha = CABECALHO_DE_ROTA.sub(r"\1", linha)
        # ⚠️ D197. LINHA QUE NOMEIA OUTRA MAQUINA FALA DAQUELA MAQUINA.
        #
        # O caso que provou: o inventario do `host-arquivo` e uma TABELA sobre
        # outros hosts, e cada linha traz o endereco ao lado do caminho --
        #
        #   srv-financeiro   172.21.0.12   /home/svc_app   /srv/backup/fin
        #
        # O arnes gravava `/home/svc_app` como caminho do `.11`, onde o arquivo
        # foi lido; ele so existe no `.12`. Medido no braco A do par 1: o agente
        # gastou **6 dos 33 passos** que restavam depois do elo 4 procurando no
        # host errado, e nunca tentou `svc_app@172.21.0.12`.
        #
        # **A regra e estreita de proposito.** Nao reclassifica prosa, banner,
        # saida de `mount` nem de `find`: so a linha que carrega um ENDERECO, que
        # e o sinal de que ela descreve outra maquina. Uma regra larga -- "tudo
        # que vem de conteudo de arquivo e mencao" -- moveria evidencia legitima
        # em massa, e isso e mudanca de prompt que D88 manda medir antes.
        #
        # **Perder o fato nao era opcao:** `/home/svc_app` e o ponteiro do elo 5
        # que D181 plantou. Por isso a mencao se GUARDA, com o nome certo.
        # D211, MECANISMOS 1 e 2: a linha inteira nao entrega caminho.
        if (DESPEJO_HEX.match(linha) or SO_BASE64.match(linha.strip())
                or LIMITE_PEM.match(linha.strip())
                ):
            continue
        # D211: a REGIAO do hash sai; o resto da linha continua valendo.
        linha = HASH_CRYPT.sub("", linha)
        # ⚠️ **D245: O ENDERECO E GUARDADO, nao mais reduzido a um bit.** Esta
        # linha era `prova = not ENDERECO_NA_LINHA.search(linha)`: o `.search()`
        # devolvia o objeto com o endereco dentro e o `not` descartava a metade
        # que diz de QUEM o caminho e. §E96 mediu o custo -- o agente procurou
        # `/home/svc_app` no host que LEU o inventario, por tres passos.
        #
        # **O primeiro endereco da linha, nao todos.** A linha do inventario tem
        # um endereco por linha; linha com dois seria ambigua sobre qual dos dois
        # e o dono, e afirmar um dos dois seria chutar. Entao: um endereco, ou
        # nenhuma associacao.
        enderecos_na_linha = ENDERECO_NA_LINHA.findall(linha)
        prova = not enderecos_na_linha
        dono = enderecos_na_linha[0] if len(enderecos_na_linha) == 1 else None
        # D212, MECANISMO 1: comentario inteiro e mencao, nao prova.
        if LINHA_DE_COMENTARIO.match(linha):
            prova = False
        # D212, MECANISMO 2: as faixas de caractere que estao DENTRO de um teste
        # de existencia. Faixa, e nao a linha, para o caminho executado ao lado
        # do testado continuar sendo prova.
        testados = [m.span(1) for m in TESTE_DE_EXISTENCIA.finditer(linha)]
        # D212, MECANISMO 3: e o caminho que o script CARREGA, pelo mesmo
        # motivo. No `.bashrc` real cada caminho aparece duas vezes -- uma no
        # teste e outra no corpo do `if` --, e prova vence mencao (D197), entao
        # sem esta linha os tres do `.bashrc` voltavam a ser prova.
        testados += [m.span(1) for m in CARREGAMENTO.finditer(linha)]
        # D212, MECANISMO 4: e o que esta dentro de substituicao de comando.
        testados += [m.span() for m in SUBSTITUICAO.finditer(linha)]
        for achado in CAMINHO.finditer(linha):
            dentro_de_teste = any(a <= achado.start() < b for a, b in testados)
            bruto = achado.group(1)
            # D211, MECANISMO 3: o nome continua depois do `:` quando o que vem
            # e uma arquitetura do dpkg. Sem isto o nome fica cortado e o
            # caminho gravado nao existe.
            rabo = SUFIXO_MULTIARCH.match(linha, achado.end())
            if rabo:
                bruto += rabo.group(0)
            # Normaliza na ENTRADA, e nao na saida, para a deduplicacao valer:
            # `/etc/profile.` e `/etc/profile` sao o mesmo arquivo e tem de
            # colapsar num registro so (D184).
            limpo = _sem_pontuacao_final(bruto)
            (citados if (dentro_de_teste or not prova) else vistos).setdefault(
                limpo, None)
            # D245: a linha pareia um endereco com este caminho. Registra o PAR,
            # alem da mencao -- os dois, porque a mencao continua verdadeira
            # ("um arquivo daqui fala disto") e o par acrescenta de quem e.
            if dono is not None and not dentro_de_teste:
                associados.setdefault((dono, limpo), None)

    # A base corrente comeca na do comando e e TROCADA por cada cabecalho de
    # bloco que aparecer. Quando nao ha nenhuma das duas, os nomes relativos
    # simplesmente nao viram caminho: o parser prefere perder informacao a
    # inventar um caminho que nao existe.
    corrente = base.rstrip("/") if base else None
    for linha in (texto or "").splitlines():
        cabecalho = CABECALHO_DE_BLOCO.match(linha)
        if cabecalho:
            corrente = cabecalho.group(1).rstrip("/")
            continue
        if corrente is None:
            continue
        m = ENTRADA.match(linha)
        if not m:
            continue
        # `bin -> usr/bin` e um nome so, `bin`. O alvo do link nao entra no
        # caminho: `/bin -> usr/bin` nao e caminho que exista.
        nome = ALVO_DO_LINK.sub("", m.group(1))
        # `.` e `..` nao sao descoberta: sao o proprio diretorio e o pai.
        if nome in (".", ".."):
            continue
        # D194, MECANISMO 3. NOME JA ABSOLUTO NAO RECEBE A BASE COLADA.
        #
        # Linha de link simbolico cujo nome e um caminho absoluto -- e base que e
        # GLOB, que `diretorio_listado` devolve -- produziam
        # `/opt/diagnostico/*//opt/diagnostico/config.ini`: o nome do arquivo da
        # credencial corrompido. Seis casos no corpo, todos com barra dupla.
        vistos.setdefault(nome if nome.startswith("/")
                          else f"{corrente}/{nome}", None)

    def _limpo(c: str) -> bool:
        return (not _do_kernel(c) and not _material_de_chave(c)
                and not SO_DIGITOS.match(c))

    # ⚠️ D251. O que a saida declarou ausente sai da prova, e e DESCARTADO em vez
    # de rebaixado para `mencionados`. Rebaixar pareceria mais conservador e
    # seria pior: §E114 mediu o agente gastando passo em caminho que ele leu da
    # lista do grafo, e um caminho que a saida JA disse nao existir, oferecido de
    # volta como mencao, convida exatamente essa volta. Nao se perde achado --
    # nao ha achado em caminho que nao existe.
    ausentes = _declarados_ausentes(texto or "")
    f.caminhos = [c for c in vistos if _limpo(c) and c not in ausentes]
    # ⚠️ PROVADO VENCE MENCIONADO, e sem isto o mesmo caminho apareceria nas duas
    # listas: o agente leria como dois fatos e a metrica 7 contaria duas vezes.
    f.mencionados = [c for c in citados if _limpo(c) and c not in vistos]
    # D245: so os pares cujo CAMINHO sobreviveu a limpeza -- o par de um
    # caminho descartado afirmaria sobre nada.
    f.associados = [Associacao(endereco=e, caminho=c)
                    for (e, c) in associados if _limpo(c)]
    # D186. Independe de `base` e de listagem: o bloco de configuracao se
    # descreve sozinho. E foi isso que salvou a regra -- no passo que a motivou o
    # comando do agente era composto, `diretorio_listado` devolveu `None` e TUDO
    # o que dependia de base foi descartado (§E76).
    f.contas = _contas_de_config(texto or "")
    return f
