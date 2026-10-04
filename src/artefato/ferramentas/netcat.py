"""Parser do `netcat`, a ferramenta que nao tinha um (D217).

`ARTEFATO.md` §1.2 define a camada de ferramentas como *"invólucros com parser
dedicado. Saída bruta nunca chega ao modelo, só o que o parser extraiu e gravou
no grafo."* D38 e D51 deixaram `netcat` e `sqlmap` sem parser, e por isso elas
divergiam da propria especificacao: o comando rodava, a tentativa ficava
registrada, e **nada** do que o servico respondeu entrava no grafo nem no
resumo. O agente lia `executado, codigo 0`.

⚠️ **O QUE ISSO CUSTOU, medido na `coleta-B-01`.** O agente mandou usuario e
senha para `172.20.0.11:1337` em **16 de 80 passos (20% do orcamento)**. O
distrator responde isto, capturado contra o laboratorio no ar:

    Connection to 172.20.0.11 1337 port [tcp/*] succeeded!
    <!DOCTYPE HTML>
    <p>Error code: 400</p>
    <p>Message: Bad request syntax ('svc_deploy')</p>

**O servico e um servidor HTTP e disse que a entrada era invalida.** Essa frase
estava na saida de cada um dos 16 passos e o arnes a jogava fora, entao o agente
nao tinha como aprender que estava falando o protocolo errado com um servidor
web. Ele tentou 16 vezes e so 1 passo de `curl` mirou aquela porta.

**A MENSAGEM DO SERVIDOR NAO ENTRA NO RESUMO, so o codigo.** O texto acima ecoa
a ENTRADA (`'svc_deploy'`): num passo em que o agente mandasse a senha, o eco
traria o segredo, e o resumo vai para a secao de tentativas do braco A e para o
historico do braco B -- D40 manda o segredo morar so na linha da credencial.
`codigo 400` diz o que o agente precisa saber e nao ecoa nada.

**Devolve `list[Host]`, a MESMA forma de `Nmap.analisar`**, de proposito: o grafo
o consome por `absorver_hosts`, que ja tem a canonicalizacao de D183 e as regras
de fusao de `Host.funde`. Um absorvedor novo significaria uma regra de
atribuicao nova, e atribuicao errada e o defeito de D197 -- seis passos
procurando `/home/svc_app` no host errado.

**E o endereco sai da PROPRIA SAIDA, nao da proposta.** A linha do `nc` declara
host e porta. Deduzi-los do comando daria errado no caso que o corpo mais
produz: `printf ... | nc host porta` dentro de `bash -c`, onde o alvo do passo e
outro host.
"""

from __future__ import annotations

import re

from .base import Execucao
from .fatos import Host, Servico

# A conexao ABRIU. Formato do `nc` do Debian, capturado contra o laboratorio:
#   Connection to 172.20.0.11 1337 port [tcp/*] succeeded!
CONEXAO_ABERTA = re.compile(
    r"^Connection to (\S+) (\d{1,5}) port \[(tcp|udp)/[^\]]*\] succeeded!",
    re.MULTILINE)

# A conexao FALHOU, e o motivo decide se da para afirmar algo sobre a porta:
#   nc: connect to 172.20.0.11 port 9999 (tcp) failed: Connection refused
CONEXAO_FALHOU = re.compile(
    r"^(?:nc: )?connect to (\S+) port (\d{1,5}) \((tcp|udp)\) failed: (.+?)\s*$",
    re.MULTILINE | re.IGNORECASE)

# ⚠️ **SO ESTES DOIS MOTIVOS FALAM DA PORTA.** "Connection refused" e um RST do
# host: a porta existe e esta fechada. "timed out" e silencio, que e o
# `filtered` do nmap. Todo o resto -- "No route to host", "Network is
# unreachable", "Name or service not known" -- e falha de REDE ou de nome, e nao
# diz nada sobre a porta. Afirmar `closed` ali seria o erro de D79 noutro
# lugar: fato sobre o alvo tirado de uma falha de transporte. **Perder achado e
# menos grave que inventar fato** (D04).
ESTADO_POR_MOTIVO = (
    ("connection refused", "closed"),
    ("timed out", "filtered"),
)

# MODO ESCUTA, e ele nao observa servico nenhum:
#   listening on [any] 4444 ...
# O agente propos `nc -lvnp 4444` seis vezes no corpo, montando shell reverso --
# acao sensata para quem esta cego e impossivel aqui, onde o laco roda um comando
# por passo e espera ele terminar. Uma porta aberta na maquina DO AGENTE nao e
# servico de alvo nenhum, e gravar `172.20.0.5:4444 aberta` poria no grafo um
# fato verdadeiro e completamente enganoso.
MODO_ESCUTA = re.compile(r"^(?:nc: )?listening on ", re.MULTILINE | re.IGNORECASE)

# O BANNER, quando o servico se identifica nos proprios bytes. E evidencia
# DIRETA, mais forte que o palpite por numero de porta do nmap -- que neste
# laboratorio chama a porta 1337 de `waste` pela tabela `nmap-services`. Por
# isso `Host.funde` deixar o novo nao-vazio ganhar e o sentido certo aqui.
# O banner INTEIRO, nao so o primeiro token: o `nmap -sV` grava
# `OpenSSH_9.2p1 Debian-2+deb12u10`, e cortar no espaco produziria uma segunda
# versao do mesmo servico. `Host.funde` deixa o novo nao-vazio ganhar, entao as
# duas ficariam se sobrescrevendo conforme a ordem dos passos -- o grafo diria
# coisas diferentes sobre o mesmo servico sem nada ter mudado no ambiente.
BANNER_SSH = re.compile(r"^SSH-\d+\.\d+-(.+?)\s*$", re.MULTILINE)
MARCA_HTTP = re.compile(r"^(?:HTTP/\d\.\d\b|<!DOCTYPE|<html\b)",
                        re.MULTILINE | re.IGNORECASE)
# O codigo, das duas formas que o laboratorio produz: a linha de status de uma
# resposta bem formada, e a pagina de erro do `http.server` do Python, que o
# distrator usa e que nao traz linha de status quando a requisicao e invalida.
CODIGO_HTTP = re.compile(r"^HTTP/\d\.\d (\d{3})\b", re.MULTILINE)
CODIGO_DE_ERRO = re.compile(r"Error code:\s*(\d{3})\b")


def _texto(execucao: Execucao) -> str:
    """Saida e erro juntos, porque o `nc -v` escreve o diagnostico no erro.

    A linha `Connection to ... succeeded!` vai para o stderr e a resposta do
    servico para o stdout. Ler so um dos dois perderia metade do fato -- ou o
    estado da porta, ou o banner.
    """
    return (execucao.saida or "") + "\n" + (execucao.erro or "")


def _banner(texto: str) -> tuple[str | None, str | None]:
    """`(servico, versao)` quando os bytes do servico o identificam, senao `None`.

    Nao adivinha por porta: isso e trabalho do nmap, e refaze-lo aqui poria
    palpite nosso por cima de observacao dele.
    """
    ssh = BANNER_SSH.search(texto)
    if ssh:
        return "ssh", ssh.group(1)
    if MARCA_HTTP.search(texto):
        return "http", None
    return None, None


class Netcat:
    nome = "netcat"

    def analisar(self, execucao: Execucao) -> list[Host]:
        """Extrai estado de porta e banner da saida do `nc`.

        Recebe `Execucao` e devolve `list[Host]`, como `Nmap.analisar`: o grafo
        consome as duas pelo mesmo caminho.

        **Em modo escuta devolve lista vazia**, e isso e regra, nao descuido.
        """
        # ⚠️ **AQUI NAO HA GUARDA DE MODO ESCUTA, e a ausencia e medida**
        # (D223). A primeira versao tinha uma, e a bateria a devolveu VIVA. A
        # investigacao mostrou duas coisas:
        #
        #   so escuta        `[]` COM e SEM a guarda -- `CONEXAO_ABERTA` nunca
        #                    casa saida de escuta, entao ela nao protegia nada
        #   escuta E conexao a guarda DESCARTAVA o servico real observado
        #
        # Ela era inerte no unico caso que a alcancava e prejudicial no caso
        # combinado (`nc -lvnp 4444 & nc -nv host porta`): perder achado por
        # guarda que nao protege nada e o pior dos dois mundos. No corpo: 11
        # comandos de escuta, 0 combinados -- entao o risco e futuro, nao
        # historico, e e por isso que ha contraexemplo na suite.
        #
        # `MODO_ESCUTA` continua em `resposta`, onde faz trabalho de verdade:
        # entregar ao agente a nota de que o laco nao mantem processo entre
        # passos.
        texto = _texto(execucao)
        servico, versao = _banner(texto)
        por_endereco: dict[str, list[Servico]] = {}

        for m in CONEXAO_ABERTA.finditer(texto):
            endereco, porta, protocolo = m.group(1), int(m.group(2)), m.group(3)
            por_endereco.setdefault(endereco, []).append(
                Servico(porta=porta, protocolo=protocolo, estado="open",
                        servico=servico, versao=versao))

        for m in CONEXAO_FALHOU.finditer(texto):
            endereco, porta, protocolo = m.group(1), int(m.group(2)), m.group(3)
            motivo = m.group(4).lower()
            estado = next((e for marca, e in ESTADO_POR_MOTIVO
                           if marca in motivo), None)
            if estado is None:
                # Falha de rede ou de nome: nao se afirma nada sobre a porta.
                continue
            por_endereco.setdefault(endereco, []).append(
                Servico(porta=porta, protocolo=protocolo, estado=estado))

        return [Host(endereco=e, servicos=ss)
                for e, ss in por_endereco.items()]

    def resposta(self, execucao: Execucao) -> str | None:
        """O que o servico RESPONDEU, em fato extraido -- nunca o texto dele.

        Existe separada de `analisar` porque o destino e outro: `analisar`
        alimenta o grafo, isto alimenta o resumo do passo. Juntar as duas faria
        a funcao do grafo devolver texto de prompt.

        **Nenhum trecho da resposta sai daqui.** A pagina de erro do distrator
        ecoa a entrada (`Bad request syntax ('svc_deploy')`), e um passo que
        mandasse a senha veria o segredo voltar no resumo, que vai aos dois
        bracos -- contra D40. O codigo diz o que o agente precisa e nao ecoa.
        """
        texto = _texto(execucao)
        if MODO_ESCUTA.search(texto):
            # A nota que o agente precisa ler, e ela e sobre o ARNES, nao sobre
            # o alvo: o laco nao mantem processo vivo entre passos.
            return "porta aberta para escuta; o laco nao mantem processo entre passos"
        servico, versao = _banner(texto)
        if servico == "ssh":
            return f"o servico se identificou: ssh {versao}"
        if servico == "http":
            m = CODIGO_HTTP.search(texto) or CODIGO_DE_ERRO.search(texto)
            if m:
                return f"o servico respondeu HTTP, codigo {m.group(1)}"
            return "o servico respondeu HTTP"
        # Conexao que abriu e nao disse nada e fato diferente de conexao que nao
        # abriu, e o agente precisa dos dois: um convida a falar o protocolo
        # certo, o outro a procurar outra porta.
        if CONEXAO_ABERTA.search(texto):
            return "a conexao abriu e o servico nao respondeu nada"
        return None
