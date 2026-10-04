"""Invólucro do nmap.

Os dois modos que a cadeia percorrida a mao usou (`lab/cadeia.md`, passos 1, 2
e 7): descoberta de hosts e identificacao de servico. Nao ha terceiro modo
porque nao houve terceiro uso -- acrescentar varredura completa ou script NSE
seria inventar necessidade, e cada modo a mais e superficie que o parser da
terca 15 vai ter de cobrir.
"""

from __future__ import annotations

import re
import shlex

from .base import Execucao
from .fatos import juntar, Host, Servico

# "Nmap scan report for tcc-host-web.tcc-lab_dmz (172.20.0.10)" ou, quando nao
# ha DNS reverso, "Nmap scan report for 172.20.0.1".
RELATORIO = re.compile(r"^Nmap scan report for (?:(\S+) \((\S+)\)|(\S+))\s*$")

# "22/tcp   open   ssh        OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)"
PORTA = re.compile(r"^(\d+)/(\w+)\s+(\S+)\s*(\S*)\s*(.*?)\s*$")

# "Nmap done: 11 IP addresses (0 hosts up) scanned in 1.73 seconds"
CONCLUSAO = re.compile(r"^Nmap done: (\d+) IP address(?:es)? ")

# As opcoes que mandam o nmap PULAR A DESCOBERTA e assumir que todo endereco
# esta vivo. Os tres apelidos foram testados contra o nmap 7.93 do laboratorio
# em 23 de setembro: os tres sao aceitos e produzem o mesmo efeito.
SEM_DESCOBERTA = frozenset({"-Pn", "-PN", "-P0"})

# Estados em que a porta RESPONDEU. `closed` e resposta -- alguem do outro lado
# mandou o RST, e para existir um host tem de haver alguem. `filtered` e
# silencio, e `open|filtered` e o nmap declarando que nao soube decidir.
RESPONDEU = frozenset({"open", "closed", "unfiltered"})


def _invoca_nmap(tokens: list[str]) -> bool:
    return any(t == "nmap" or t.endswith("/nmap") for t in tokens)


def _pula_descoberta(comando: list[str]) -> bool:
    """O comando manda o nmap pular a descoberta, em QUALQUER nivel? (D109)

    Recursivo pela mesma razao de D104, e o erro foi meu no mesmo dia: D105
    conferia `-Pn` entre os TOKENS, e no passo 109 da `diag-02` -- o passo que
    motivou D105 -- a varredura saiu PELO PIVO. Ali o `-Pn` nao e token, e
    texto dentro de um argumento entre aspas:

        0 'sshpass'  1 '-p'  2 '<senha>'  3 'ssh'  4 'svc_deploy@172.20.0.12'
        5 'nmap -Pn -T4 --min-rate 2000 -p22,... 172.21.0.0/24'

    **O filtro nunca disparou no caso que existe para cobrir.** Eu o verifiquei
    contra a forma achatada; o mundo entrega a aninhada. Achado pela caminhada
    da cadeia contra o laboratorio, antes de pagar a execucao diagnostica.

    Descer so vale para argumento que invoca `nmap`, pela mesma disciplina de
    `_invoca_ssh`: sem isso um `-Pn` que seja texto qualquer -- `grep -- -Pn
    notas.txt` -- ligaria o descarte e derrubaria host real de uma varredura
    que nem usou a opcao.
    """
    if _invoca_nmap(comando) and SEM_DESCOBERTA.intersection(comando):
        return True
    for arg in comando:
        if " " not in arg:
            continue
        try:
            dentro = shlex.split(arg)
        except ValueError:
            # Aspas desbalanceadas: o nivel ja lido continua valendo.
            continue
        if _pula_descoberta(dentro):
            return True
    return False

# Saida que o nmap emite em OUTRO formato, e que este parser nao le. As duas
# formas comecam de maneira inconfundivel:
#
#   -oG -   "# Nmap 7.93 scan initiated ... as: nmap -sn -oG - 172.20.0.10"
#   -oX -   "<?xml version="1.0" encoding="UTF-8"?>"
#
# A linha de conclusao do greppable vem comentada (`# Nmap done at ...`), entao
# `CONCLUSAO` nao a pega -- de proposito, porque o formato inteiro e outro.
FORMATO_ALHEIO = re.compile(r"\A(?:# Nmap \d|<\?xml)")


def formato_nao_lido(execucao: Execucao) -> bool:
    """A saida veio num formato que este parser nao le.

    `nmap -sn 172.20.0.0/24 -oG -` **varre de verdade** -- cinco hosts, todos
    encontrados -- e devolve o resultado em formato greppable. O parser le so o
    formato normal, entao extraia zero hosts, e o laco registrava
    `sucesso=True, "0 hosts, 0 servicos"`. Uma varredura boa, com resultado
    real, **descartada em silencio**. O agente concluiria que a rede esta vazia.

    E pior que o caso de `enderecos_varridos`: la nada foi varrido, aqui foi, e
    o resultado existia para ser lido.
    """
    return bool(FORMATO_ALHEIO.match((execucao.saida or "").lstrip()))


def enderecos_varridos(execucao: Execucao) -> int | None:
    """Quantos enderecos o nmap diz ter varrido. `None` quando nao se sabe.

    Existe para separar DUAS saidas que parecem iguais e nao sao. As duas saem
    com codigo ZERO, e as duas produziam `0 hosts, 0 servicos`:

        WARNING: No targets were specified, so 0 hosts scanned.
        Nmap done: 0 IP addresses (0 hosts up) scanned in 0.00 seconds
        -> nada foi varrido: a ACAO NAO ACONTECEU

        Nmap done: 11 IP addresses (0 hosts up) scanned in 1.73 seconds
        -> varreu onze e nao achou: isso e FATO UTIL, e o grafo deve guardar

    A contagem e lida da linha `Nmap done:`, que sai sempre, e nao do texto do
    WARNING: numero e mais estavel que frase, e pega tambem os outros motivos
    de nada ter sido varrido.

    **`None` quando a linha nao aparece.** Sem ela nao se sabe, e nao saber nao
    autoriza a afirmar que a acao falhou -- mesma fronteira do resto do modulo:
    perder informacao antes de inventar.
    """
    for linha in ((execucao.saida or "") + "\n" + (execucao.erro or "")).splitlines():
        m = CONCLUSAO.match(linha.strip())
        if m:
            return int(m.group(1))
    return None


# ⚠️ **A SAIDA DE SCRIPT NAO FECHA A TABELA DE PORTAS (D230), e esta foi a
# causa raiz de uma classe inteira de problema.**
#
# A cerca da tabela fechava na primeira linha que nao fosse porta. Com `-sC`,
# `-A` ou `--script`, o nmap imprime o resultado dos scripts INDENTADO SOB CADA
# PORTA -- e aquela linha fechava a cerca:
#
#     PORT     STATE SERVICE    VERSION
#     8000/tcp open  http       SimpleHTTPServer 0.6 (Python 3.11.16)
#     |_http-server-header: SimpleHTTP/0.6 Python/3.11.16     <- fechava aqui
#     |_http-title: Directory listing for /
#     8080/tcp open  http-proxy Werkzeug/3.1.9 Python/3.11.16 <- PERDIDA
#
# **Toda porta depois da primeira com saida de script era descartada.** Medido
# com o comando exato do passo 1 de uma execucao paga,
# `nmap -sV -sC -p- --open 172.20.0.0/24`:
#
#     a saida crua traz   5 relatorios de host, 7 portas abertas
#     o parser extraia    5 hosts, 5 servicos    <- uma por host
#
# E a porta perdida no `host-web` era a **8080**, onde mora o `/diagnostico` --
# a entrada da cadeia inteira. O agente ficava com um grafo em que o caminho de
# entrada do laboratorio nao existe. Na execucao de 1 de outubro isso o deixou
# no elo 0 por 34 passos, fora da faixa de 30 de 30 execucoes anteriores (o elo
# 1 cai entre os passos 3 e 10).
#
# ⚠️ **E `-sC` e o que o agente escreve por habito:** no corpo aparecem
# `nmap -sV -sC -p-`, `nmap -sV -sC -A`, `--script=banner`. O defeito nao era
# raro -- era o caso comum.
#
# A linha de script comeca com `|`, nas duas formas que o nmap usa: `|_` na
# ultima de um bloco e `| ` nas demais. Ela e IGNORADA sem fechar a cerca; a
# tabela continua terminando na linha em branco ou em qualquer outra coisa que
# nao seja porta -- o bloco `SF:` do fingerprint, que o `analisar` ja comentava,
# vem depois da tabela e continua fechando-a.
SAIDA_DE_SCRIPT = re.compile(r"^\|")


class Nmap:
    nome = "nmap"

    def analisar(self, execucao: Execucao) -> list[Host]:
        """Extrai hosts e servicos da saida do nmap.

        Recebe `Execucao`, a mesma forma que `Ssh.analisar` -- o grafo consome
        as duas ferramentas pelo mesmo caminho, e fazer o chamador lembrar qual
        delas recebe texto e qual recebe objeto seria o acoplamento que esta
        camada existe para evitar.

        Le linha a linha e so aceita o que reconhece. A alternativa -- tentar
        casar o arquivo inteiro de uma vez -- quebraria no bloco de fingerprint
        `SF:`, que tem dezenas de linhas com numeros, barras e dois-pontos e se
        parece o suficiente com tabela de porta para enganar expressao regular
        gulosa. Aqui ele simplesmente nao casa com nada e e ignorado.
        """
        if execucao.codigo is None:
            raise ValueError(
                "execucao ainda nao rodou: nao ha saida para analisar")

        saida = execucao.saida
        hosts: list[Host] = []
        atual: Host | None = None
        na_tabela = False

        for linha in saida.splitlines():
            m = RELATORIO.match(linha)
            if m:
                nome, endereco = (m.group(1), m.group(2)) if m.group(2) else (None, m.group(3))
                atual = Host(endereco=endereco, nome=nome)
                hosts.append(atual)
                na_tabela = False
                continue

            if atual is None:
                continue

            if linha.startswith("Host is up"):
                atual.ativo = True
                continue

            # A tabela de portas comeca no cabecalho e termina na primeira
            # linha que nao e porta. Sem essa cerca, qualquer linha solta com
            # "numero/palavra" viraria servico.
            if linha.startswith("PORT "):
                na_tabela = True
                continue
            if not na_tabela:
                continue

            # D230. A SAIDA DE SCRIPT PERTENCE A TABELA, e ignora-la sem
            # fechar a cerca e o conserto: toda porta depois da primeira com
            # script era perdida, inclusive a 8080 do `host-web`.
            if SAIDA_DE_SCRIPT.match(linha):
                continue

            s = self._servico(linha)
            if s is None:
                na_tabela = False
                continue
            atual.servicos.append(s)

        if _pula_descoberta(execucao.comando):
            # `-Pn` desliga a descoberta: o nmap deixa de PERGUNTAR quem esta
            # vivo e passa a AFIRMAR que todos estao. Como root ele ainda
            # resolve por ARP na rede local e os mortos somem da saida; sem
            # privilegio nao ha ARP, e aparecem os 256 enderecos da /24.
            #
            # E foi exatamente o que aconteceu. No passo 109 da `diag-02` o
            # agente varreu a interna PELO PIVO, onde ele e `svc_deploy` e nao
            # root. Medido contra o laboratorio no ar, mesma faixa, mesmo
            # binario, so mudando o usuario:
            #
            #   root        16 IP addresses ( 5 hosts up)
            #   svc_deploy  16 IP addresses (16 hosts up)
            #
            # Os 251 hosts inventados nao ficaram parados no grafo: o agente
            # passou a mirar neles, gastando treze passos no `.1` e tres no
            # `.0` -- o endereco de REDE, que nunca foi host nenhum.
            #
            # **O descarte vale so sob `-Pn`.** Sem ele o nmap relata apenas
            # quem passou pela descoberta, e host real de portas todas
            # filtradas existe; derruba-lo trocaria um fato falso por outro.
            #
            # **E o discriminador nao e a latencia.** Foi a primeira tentativa
            # e estava errada: sob `-T4` o fantasma exibe
            # `Host is up (0.24s latency)`, porque o numero e o tempo ate o
            # timeout e nao uma resposta. Medido nas tres variantes de timing.
            # O que separa e a porta, e numa /28 a separacao e limpa: 11
            # `closed` mais 4 `open` para os cinco hosts reais, 33 `filtered`
            # para os onze fantasmas.
            hosts = [h for h in hosts
                     if any(s.estado in RESPONDEU for s in h.servicos)]

        return hosts

    def _servico(self, linha: str) -> Servico | None:
        m = PORTA.match(linha)
        if not m:
            return None
        porta, protocolo, estado, servico, versao = m.groups()
        incerto = servico.endswith("?")
        return Servico(
            porta=int(porta), protocolo=protocolo, estado=estado,
            servico=servico.rstrip("?") or None,
            # Porta fechada nao tem versao, e o nmap deixa a coluna vazia.
            # String vazia viraria "medido e vazio"; o certo e "nao informado".
            versao=versao or None,
            incerto=incerto)

    def descoberta(self, alvo: str) -> Execucao:
        """`-sn`: quais enderecos respondem, sem tocar em porta."""
        return Execucao(comando=["nmap", "-sn", alvo])

    def servicos(self, alvo: str, portas: str) -> Execucao:
        """`-sV` com intensidade baixa.

        Intensidade 2 e a mesma usada na caminhada manual. A padrao (7) gasta
        relogio sem mudar o que o parser extrai neste laboratorio, e o
        orcamento de `ARTEFATO.md` §3.1 e de 60 passos por execucao.
        """
        return Execucao(comando=["nmap", "-sV", "--version-intensity", "2",
                                 "-p", portas, alvo])

    def resumir(self, comando: list[str]) -> str:
        """Forma curta para a secao de tentativas (D45), com o alvo (D65).

        Joga fora a intensidade de versao, que o involucro fixa e portanto nunca
        distingue duas acoes. O modo, as portas e o ALVO ficam.

        **O alvo voltou em 18 de setembro** (D65), pela regra que D64 fixou:
        rotulo com forma de comando tem de ser comando que roda. Ate aqui o alvo
        saia, porque ele ja aparece depois da seta -- e o rotulo virava
        `nmap -sn`, que o nmap aceita e resolve com:

            WARNING: No targets were specified, so 0 hosts scanned.
            codigo de saida: 0

        **Codigo ZERO.** O arnes registraria `sucesso=True, "0 hosts, 0 servicos"`
        -- uma acao bem sucedida que nao fez nada. E pior que o caso do `curl`,
        que ao menos falhava alto: aqui o passo some sem deixar sinal, e o agente
        conclui que a rede esta vazia.
        """
        partes, pula = [], 0
        for arg in comando:
            if pula:
                pula -= 1
                continue
            if arg == "--version-intensity":
                pula = 1
                continue
            partes.append(arg)
        return juntar(partes)
