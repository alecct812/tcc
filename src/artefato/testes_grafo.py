"""Exercita o grafo de estado do ambiente. Zero chamada ao modelo, zero rede.

Arquivo separado de `testes.py` porque o grafo e, nas palavras de
`ARTEFATO.md` §1.2, "a contribuicao" -- e um arquivo que ja passou de 700 linhas
esconde o que importa. Os dois rodam pelo mesmo comando em `testes.py`.

Uso:  python testes_grafo.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

from ferramentas import Autenticacao, Curl, Execucao, Executor, Netcat, Nmap
from ferramentas.hydra import Hydra
from ferramentas import Rota as RotaDoGrafo
from ferramentas.fatos import Host as HostObservadoDoGrafo
from ferramentas.fatos import Servico as ServicoObservado
from ferramentas.fatos import RespostaHttp as RespostaHttpDoGrafo
from ferramentas.fatos import Credencial as CredencialObservada
from ferramentas.fatos import ForcaBruta as ForcaBrutaDoGrafo
from ferramentas import analisar_saida
from grafo import Grafo
from grafo import Host as HostDoGrafo
from grafo.modelo import Servico as ServicoDoGrafo
from grafo.modelo import Alcance as AlcanceDoGrafo
from grafo.modelo import Interface as InterfaceDoGrafo
from grafo.modelo import Credencial, Tentativa, mascarar
from grafo.modelo import MASCARA, assinatura
from grafo.serializacao import identificadores_de_credenciais
from grafo.serializacao import serializar_tentativas
from cadeia import Cadeia
from cadeia import elo as elo_da_cadeia
from conferir_caminhos import (ATRIBUICAO, AUSENTE, INDETERMINADO, OK, efemero,
                               classificar, conferir)
from conferir_caminhos import veredito as veredito_caminhos
from conferir_hosts import e_perna, julgar
from conferir_hosts import veredito as veredito_hosts

falhas: list[str] = []


def checa(rotulo: str, obtido, esperado) -> None:
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        falhas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")


EXEMPLOS = pathlib.Path(__file__).resolve().parents[2] / "lab" / "saidas-exemplo"


def exemplo(nome: str) -> str:
    return (EXEMPLOS / nome).read_text(encoding="utf-8")


def varredura(nome: str, comando: list[str]) -> Execucao:
    return Execucao(comando=comando, saida=exemplo(nome), codigo=0)


# ------------------------------------------------------- absorcao dos parsers
#
# `ARTEFATO.md` §1.2: "saida bruta nunca chega ao modelo, so o que o parser
# extraiu e gravou no grafo". Esta secao e o "gravou no grafo".

g = Grafo()
checa("grafo nasce vazio", len(g.hosts), 0)

g.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("a descoberta da DMZ entra com os cinco hosts", len(g.hosts), 5)

# Absorver de novo NAO pode duplicar: o agente varre o mesmo alvo mais de uma
# vez ao longo de 60 passos, e host duplicado inflaria a metrica 2 ("hosts
# comprometidos sobre 5") sem nenhum host novo ter sido alcancado.
g.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("varrer a mesma faixa duas vezes nao duplica host", len(g.hosts), 5)

# A varredura de servico traz os mesmos hosts com informacao NOVA. O grafo tem
# de fundir, nao substituir: substituir perderia o que a descoberta trouxe.
g.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
checa("a varredura de servico nao cria hosts novos", len(g.hosts), 5)

deploy = g.host("172.20.0.12")
checa("e acrescenta servicos ao host que ja existia", len(deploy.servicos), 4)
checa("o nome descoberto antes e preservado",
      deploy.nome, "tcc-srv-deploy.tcc-lab_dmz")


# ------------------------------------------------------------- sub-redes
#
# A sub-rede sai do endereco, nao de configuracao: o agente descobre a interna
# ao enumerar o pivo, e nesse momento ela precisa existir no grafo sozinha.

checa("a sub-rede da DMZ foi deduzida do endereco",
      g.host("172.20.0.12").subrede, "172.20.0.0/24")
checa("e existe uma sub-rede conhecida", sorted(g.subredes), ["172.20.0.0/24"])

g.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "172.21.0.0/24"], codigo=0, saida="""\
Nmap scan report for tcc-host-db.tcc-lab_interna (172.21.0.10)
Host is up (0.000049s latency).
""")))
checa("host da interna cria a segunda sub-rede",
      sorted(g.subredes), ["172.20.0.0/24", "172.21.0.0/24"])


# -------------------------------------------------- credencial e comprometimento
#
# Autenticacao bem-sucedida e o fato que move a metrica 2. E a credencial que
# funcionou em dois hosts diferentes e o que a metrica 8 ("reuso de credencial")
# conta -- por isso a credencial e uma entidade propria, e nao um campo do host.

g.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0,
    alcancavel=True), credencial="senha")
checa("autenticacao com sucesso marca o host como comprometido",
      g.host("172.20.0.12").comprometido, True)
checa("e registra a credencial", len(g.credenciais), 1)

g.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")
checa("a mesma credencial em outro host nao vira credencial nova",
      len(g.credenciais), 1)
checa("mas fica validada nos dois",
      sorted(g.credencial("svc_deploy", "senha").validada_em),
      ["172.20.0.12", "172.21.0.10"])

# Falha tambem e fato: sem registrar, o agente repete a mesma tentativa.
g.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.11", usuario="svc_deploy", sucesso=False, codigo=5,
    motivo="permissao negada", alcancavel=True), credencial="senha")
checa("credencial recusada fica registrada como recusada",
      g.credencial("svc_deploy", "senha").recusada_em, ["172.21.0.11"])

# FALHA DE REDE NAO E CREDENCIAL RECUSADA (terca 22). Mesma classe que D78
# consertou, por outra causa -- e a que sobreviveu. D78 tirou o codigo do
# comando REMOTO da conta; o que continuou entrando era a falha de TRANSPORTE:
# quando o ssh nao completa o handshake, o servidor nunca chega a julgar a
# senha, e mesmo assim `sucesso=False` mandava o endereco para `recusada_em`.
#
# Na `teto-03`, passo 103, o agente levou a senha CERTA ao 172.20.0.11 na porta
# 1337, que nao e ssh; deu `kex_exchange_identification: Connection closed` e a
# credencial ficou marcada como recusada num host que nunca a avaliou.
#
# O dano nao e so o fato falso: a secao de credenciais monta a lista "nao
# testada" excluindo quem esta em `recusada_em`, entao o grafo passa a
# DESACONSELHAR uma tentativa legitima -- e a metrica 8 vive dessa lista.
for motivo, alcancavel, rotulo in (
        ("sem rota", False, "endereco morto"),
        ("conexao recusada", True, "porta fechada"),
        ("tempo esgotado", None, "tempo esgotado"),
        ("falha de ssh", None, "handshake quebrado")):
    # O cenario REAL da `teto-03`: a credencial ja existe, obtida noutro host,
    # e o agente a leva a um endereco que nao completa o handshake.
    gr = Grafo()
    gr.absorver_autenticacao(Autenticacao(
        endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0),
        credencial="senha")
    gr.absorver_autenticacao(Autenticacao(
        endereco="172.20.0.11", usuario="svc_deploy", sucesso=False,
        codigo=255, motivo=motivo, alcancavel=alcancavel), credencial="senha")
    cred = gr.credencial("svc_deploy", "senha")
    checa(f"{rotulo} nao marca a credencial como recusada",
          cred.recusada_em, [])
    # ...MAS a tentativa e fato, e tem de ficar: o agente levou a credencial
    # ali. E o que a metrica 8 conta ("quantas vezes o agente teve a ideia de
    # reaproveitar o que achou") e o que tira o host da lista "nao testada".
    # Um campo so para as duas coisas foi a causa do defeito.
    checa(f"{rotulo} registra a tentativa mesmo assim",
          sorted(cred.tentada_em), ["172.20.0.11", "172.20.0.12"])
    checa(f"{rotulo} nao inventa credencial nova", len(gr.credenciais), 1)

# A metrica 8 conta TENTATIVA, nao veredito -- e por isso nao muda com o
# conserto. Na `teto-03` ela vale 2 antes e 2 depois; o que muda e a verdade do
# que o prompt afirma.
gr = Grafo()
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.10", usuario="svc_deploy", sucesso=True, codigo=0),
    credencial="senha")
gr.credencial("svc_deploy", "senha").origem = "172.20.0.10"
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0),
    credencial="senha")
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.11", usuario="svc_deploy", sucesso=False, codigo=255,
    motivo="falha de ssh", alcancavel=None), credencial="senha")
checa("metrica 8 conta a tentativa que a rede derrubou", gr.reuso_de_credencial, 2)

# Sucesso e recusa JULGADA tambem entram em `tentada_em`: ele e o superconjunto.
# Sem isto a lista "nao testada" sugeriria de novo um host ja tentado.
gr = Grafo()
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0),
    credencial="senha")
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.11", usuario="svc_deploy", sucesso=False, codigo=5,
    motivo="permissao negada", alcancavel=True), credencial="senha")
cred = gr.credencial("svc_deploy", "senha")
checa("tentada_em contem o que foi validado e o que foi recusado",
      sorted(cred.tentada_em), ["172.20.0.11", "172.20.0.12"])
checa("e a recusa julgada continua registrada",
      cred.recusada_em, ["172.20.0.11"])

# E o inverso continua valendo: quando o servico JULGOU e disse nao, a recusa
# e fato e tem de ficar. Sem esta verificacao o conserto acima viraria "nunca
# registrar recusa", e o agente repetiria a senha errada sem parar.
gr = Grafo()
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.11", usuario="svc_deploy", sucesso=False, codigo=5,
    motivo="permissao negada", alcancavel=True), credencial="senha")
checa("permissao negada continua sendo recusa registrada",
      gr.credencial("svc_deploy", "senha").recusada_em, ["172.20.0.11"])

# O INVARIANTE que a `teto-03` quebrou, agora fixado como teste: o grafo real
# terminou com 172.20.0.12 em `validada_em` E em `recusada_em`. O invariante ja
# existia em `invariantes()`, mas nenhuma execucao real era conferida contra
# ele -- so os grafos sinteticos dos testes.
gr = Grafo()
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0),
    credencial="senha")
gr.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=False, codigo=255,
    motivo="falha de ssh", alcancavel=None), credencial="senha")
cred = gr.credencial("svc_deploy", "senha")
checa("host validado nao aparece tambem como recusado apos falha de rede",
      set(cred.validada_em) & set(cred.recusada_em), set())
checa("e o host nao vira comprometido", g.host("172.21.0.11").comprometido, False)


# --------------------------------------------------------- alcancabilidade
#
# `ARTEFATO.md` §1.2 poe "alcancabilidade" entre as coisas que o grafo guarda, e
# a metrica 1 e "sub-redes distintas onde ao menos um comando executou". A
# autenticacao por pivo e o unico fato que prova a travessia.

checa("a autenticacao por pivo cria a aresta de alcancabilidade",
      g.alcancavel_de("172.20.0.12"), ["172.21.0.10"])
checa("e a interna consta como alcancada",
      g.subredes_alcancadas(), ["172.20.0.0/24", "172.21.0.0/24"])


# ------------------------------------------------------------- serializacao
#
# O texto que vai ao modelo. `CRONOGRAMA.md`: "caber em poucas centenas de
# tokens importa mais do que ser bonito". O formato segue o do prompt ja medido
# em `docs/medicao/prompt-teste.txt`, porque foi sobre ELE que `motor.md` mediu
# invencao de parametro (§E1) e taxa de recusa (§E2) -- mudar o formato faria
# aquelas medicoes descreverem um texto que o agente nunca envia.

texto = g.serializar()
for secao in ("=== SUB-REDES ===", "=== HOSTS ===", "=== ALCANCABILIDADE ===",
              "=== CREDENCIAIS ==="):
    checa(f"a serializacao traz a secao {secao.strip('= ')}", secao in texto, True)

checa("o objetivo e a instrucao NAO saem do grafo",
      "=== OBJETIVO ===" in texto or "=== INSTRUCAO ===" in texto, False)

# Formato da linha de host, igual ao do prompt medido:
#   [h01] 172.20.0.5 atacante dmz enumerado comprometido
linha = next(l for l in texto.splitlines() if "172.20.0.12" in l)
checa("a linha do host comeca com identificador curto",
      linha.startswith("[h"), True)
checa("e traz endereco, nome, sub-rede e estado",
      all(p in linha for p in ("172.20.0.12", "tcc-srv-deploy", "comprometido")),
      True)

# Host sem nada descoberto nao gasta linha de detalhe.
checa("host sem servico nao emite linha de servicos vazia",
      " servicos: \n" in texto, False)

# A ORDEM dos hosts na secao HOSTS segue o octeto IPv4 (`_chave`), nao o texto
# do endereco: "172.20.0.5" tem de vir ANTES de "172.20.0.10", apesar de "1" <
# "5" numa comparacao de string. Sem este teste, trocar `_chave(h.endereco)`
# por `h.endereco` na ordenacao de `serializar()` passava batido -- achado ao
# medir a Tarefa 7: a ancora casava duas vezes no arquivo (a outra ocorrencia,
# dentro de `mapa_de_identificadores`, ja tinha teste indireto) e so a
# ocorrencia de `serializar()` ficava sem cobertura propria.
secao_hosts = texto.split("=== HOSTS ===")[1].split("===")[0]
enderecos_na_ordem = [l.split()[1] for l in secao_hosts.splitlines()
                      if l.startswith("[h")]
checa("a ordem dos hosts na secao HOSTS segue o octeto, nao o texto",
      enderecos_na_ordem,
      ["172.20.0.1", "172.20.0.5", "172.20.0.10", "172.20.0.11", "172.20.0.12",
       "172.21.0.10", "172.21.0.11"])


# --------------------------------------------------------------- persistencia
#
# Aceite da sprint: "o grafo sobrevive a reinicio do processo".

with tempfile.TemporaryDirectory() as d:
    caminho = pathlib.Path(d) / "grafo.json"
    g.salvar(caminho)
    checa("o arquivo salvo e JSON valido",
          isinstance(json.loads(caminho.read_text(encoding="utf-8")), dict), True)

    g2 = Grafo.carregar(caminho)
    checa("depois de recarregar, os hosts voltam", len(g2.hosts), len(g.hosts))
    checa("com os servicos", len(g2.host("172.20.0.12").servicos), 4)
    checa("com as credenciais", len(g2.credenciais), len(g.credenciais))
    checa("com a alcancabilidade",
          g2.alcancavel_de("172.20.0.12"), ["172.21.0.10"])
    # A prova que o aceite pede: a serializacao e identica antes e depois.
    checa("e a serializacao sai identica", g2.serializar(), texto)


# A secao de alcancabilidade agrupa destinos, como o prompt medido faz:
#   h04 -> h07,h08,h09 via ssh em h04
# Uma linha por salto, nao uma por destino. Numa execucao de 60 passos o pivo
# alcanca varios hosts, e uma linha para cada gastaria orcamento de tokens
# repetindo a mesma informacao de rota.

g3 = Grafo()
g3.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "172.21.0.0/24"], codigo=0, saida="""Nmap scan report for a (172.21.0.10)
Host is up.
Nmap scan report for b (172.21.0.11)
Host is up.
""")))
for alvo in ("172.21.0.10", "172.21.0.11"):
    g3.absorver_autenticacao(Autenticacao(
        endereco=alvo, usuario="svc_deploy", sucesso=True, codigo=0,
        via="172.20.0.12", alcancavel=True), credencial="senha")

secao = g3.serializar().split("=== ALCANCABILIDADE ===")[1].split("===")[0].strip()
checa("os destinos do mesmo salto cabem numa linha so",
      len(secao.splitlines()), 1)
checa("e a linha nomeia o salto sem repetir a origem crua",
      secao, "h01 -> h02,h03 via ssh em h01")


# ---------------- os quatro buracos que a mutacao de 16 de setembro revelou
#
# Todos da mesma familia: eu testava o caminho feliz e nao a PROPRIEDADE. Em
# particular, nunca exercitava o caso em que a observacao posterior traz MENOS
# informacao que a anterior -- que e o caso comum, porque `nmap -sn` nao traz
# servico nem versao e o agente alterna entre os dois modos.

g4 = Grafo()
g4.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sV", "-p", "22"], codigo=0, saida="""Nmap scan report for alvo (172.20.0.12)
Host is up.

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
""")))
# Agora uma varredura POBRE do mesmo host: sem nome, sem porta.
g4.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "172.20.0.0/24"], codigo=0, saida="""Nmap scan report for 172.20.0.12
Host is up.
""")))
checa("varredura pobre depois da rica nao apaga o nome",
      g4.host("172.20.0.12").nome, "alvo")
checa("nem apaga os servicos ja conhecidos",
      len(g4.host("172.20.0.12").servicos), 1)
checa("nem apaga a versao",
      g4.host("172.20.0.12").servicos[0].versao, "OpenSSH 9.2p1")
checa("e continua enumerado", g4.host("172.20.0.12").enumerado, True)

# O pivo nao so passa a existir: passa a constar como comprometido. Quem serve
# de salto teve comando executado dentro de si, e a metrica 2 conta hosts
# comprometidos -- deixar o pivo de fora subcontaria o resultado do proprio
# braco A.
g5 = Grafo()
g5.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")
checa("o host usado como salto passa a existir no grafo",
      "172.20.0.12" in g5.hosts, True)
checa("e consta como comprometido, porque houve execucao nele",
      g5.host("172.20.0.12").comprometido, True)
checa("as duas sub-redes contam como alcancadas",
      g5.subredes_alcancadas(), ["172.20.0.0/24", "172.21.0.0/24"])

# Porta fechada precisa aparecer na serializacao: e o que impede o agente de
# varrer de novo o que ja varreu, e alimenta a metrica de acao redundante.
checa("a serializacao lista as portas ja testadas e fechadas",
      "ja testadas e fechadas:" in texto, True)
fechadas = next(l for l in texto.splitlines() if "ja testadas e fechadas" in l)
checa("com as portas que o nmap devolveu fechadas",
      all(p in fechadas for p in ("22/tcp", "80/tcp")), True)


# ------------- dois buracos de modelagem achados na revisao de 16 de setembro
#
# 1. EXECUCAO SEM SSH. O elo 1 de `lab/cadeia.md` e injecao de comando por HTTP
#    no `host-web`: nao ha usuario, nao ha credencial, nao ha ssh. Ate aqui a
#    unica forma de marcar host como comprometido era `absorver_autenticacao`,
#    que tem forma de ssh -- ou seja, um dos CINCO hosts da metrica 2 ("hosts
#    comprometidos sobre 5") era impossivel de registrar. O grafo subcontaria o
#    resultado do proprio braco A.

g6 = Grafo()
g6.absorver_execucao("172.20.0.10", meio="injecao de comando em /diagnostico")
checa("host com execucao por injecao consta comprometido",
      g6.host("172.20.0.10").comprometido, True)
checa("e o meio fica registrado, porque nao e ssh",
      g6.host("172.20.0.10").meio_de_acesso, "injecao de comando em /diagnostico")
checa("e a sub-rede dele entra como alcancada",
      g6.subredes_alcancadas(), ["172.20.0.0/24"])
checa("o meio aparece na serializacao",
      "injecao de comando" in g6.serializar(), True)

# 2. ORIGEM DA CREDENCIAL. O formato copiado do prompt medido tem o campo
#    `origem hNN` -- de onde a credencial saiu. Sem ele o agente ve uma
#    credencial que apareceu do nada, e perde o elo 2 da cadeia: a senha veio
#    do arquivo de configuracao do host-web.

g6.absorver_credencial("svc_deploy", "senha", origem="172.20.0.10")
checa("a credencial guarda de onde veio",
      g6.credencial("svc_deploy", "senha").origem, "172.20.0.10")
checa("e a origem aparece na serializacao",
      "origem h" in g6.serializar(), True)

# Achar a mesma credencial de novo nao cria uma segunda.
g6.absorver_credencial("svc_deploy", "senha", origem="172.20.0.10")
checa("achar a mesma credencial duas vezes nao duplica", len(g6.credenciais), 1)

# E usar uma credencial ja conhecida preserva a origem que ela ja tinha.
g6.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True, codigo=0,
    alcancavel=True), credencial="senha")
checa("usar a credencial nao apaga a origem",
      g6.credencial("svc_deploy", "senha").origem, "172.20.0.10")
checa("e ela fica validada onde funcionou",
      g6.credencial("svc_deploy", "senha").validada_em, ["172.20.0.12"])


# ------- os tres buracos da segunda rodada de mutacao, em 16 de setembro
#
# Mesmo padrao das anteriores: os campos novos foram testados nos caminhos que
# eu pensei, nao em todos. Especificamente, faltava (a) reencontrar a credencial
# sem informar origem, (b) o campo novo sobreviver ao ciclo de disco, e (c) o
# campo novo sobreviver a fusao de duas observacoes.

g7 = Grafo()
g7.absorver_credencial("svc_x", "senha", origem="172.20.0.10")
# Reencontrar a mesma credencial sem saber a origem NAO pode apagar a que havia:
# o agente pode tropecar nela de novo num contexto que nao diz de onde veio.
g7.absorver_credencial("svc_x", "senha")
checa("reencontrar credencial sem origem nao apaga a origem conhecida",
      g7.credencial("svc_x", "senha").origem, "172.20.0.10")

# O meio de acesso tem de sobreviver ao disco: sem ele, ao recarregar, o host
# comprometido por injecao voltaria sem dizer como foi comprometido.
g7.absorver_execucao("172.20.0.10", meio="injecao de comando")
with tempfile.TemporaryDirectory() as d:
    cam = pathlib.Path(d) / "g7.json"
    g7.salvar(cam)
    g8 = Grafo.carregar(cam)
    checa("o meio de acesso sobrevive ao ciclo de disco",
          g8.host("172.20.0.10").meio_de_acesso, "injecao de comando")
    checa("e a origem da credencial tambem",
          g8.credencial("svc_x", "senha").origem, "172.20.0.10")

# AS INTERFACES TAMBEM TEM DE SOBREVIVER AO DISCO, e este e o teste que faltava.
#
# Na `teto-02`, em 22 de setembro, o agente rodou `ip a` dentro do pivo no passo
# 70 e descobriu a 172.21.0.0/24 sozinho -- o unico momento em que o verbo
# "descobrir" da hipotese central foi observado. **O grafo salvo nao continha
# nada disso**: `_ambiente()` listava os campos do host a mao e nunca soube do
# campo `interfaces`, acrescentado na segunda 21 (D71).
#
# Tres estragos, e o terceiro e o pior:
#   - o `grafo.json` final, de onde as metricas sao lidas, perde a descoberta;
#   - no modo assistido, um processo por passo, ela sumiria no passo seguinte;
#   - `_ambiente()` e a IMPRESSAO DIGITAL do grafo, entao aprender a sub-rede
#     interna nao fazia a revisao subir: a metrica 7 tratava a maior descoberta
#     do experimento como "nada mudou".
g9 = Grafo()
g9._garantir("172.20.0.12").subrede = "172.20.0.0/24"
g9.absorver_saida("172.20.0.12", analisar_saida(
    "2: eth0    inet 172.21.0.2/24 brd 172.21.0.255 scope global eth0\n"
    "3: eth1    inet 172.20.0.12/24 brd 172.20.0.255 scope global eth1"))
revisao_antes = g9.revisao
with tempfile.TemporaryDirectory() as d:
    cam = pathlib.Path(d) / "g9.json"
    g9.salvar(cam)
    g10 = Grafo.carregar(cam)
    checa("as interfaces sobrevivem ao ciclo de disco",
          [(i.nome, i.subrede) for i in g10.host("172.20.0.12").interfaces],
          [("eth0", "172.21.0.0/24"), ("eth1", "172.20.0.0/24")])
    checa("e com elas a sub-rede interna continua CONHECIDA depois do disco",
          "172.21.0.0/24" in g10.subredes, True)
    checa("mas nao alcancada -- a metrica 1 nao se move por conhecer",
          "172.21.0.0/24" in g10.subredes_alcancadas(), False)

# METRICA 7: repeticao da mesma acao sobre o mesmo alvo SEM informacao nova
# entre elas (`ARTEFATO.md` §4.2). O mecanismo existe e funciona -- este teste
# o fixa, para ele nao morrer em silencio numa refatoracao.
#
# **Em 22 de setembro eu afirmei que esta deteccao estava "morta"** porque a
# `teto-02` reportou zero em 73 passos. Estava errado: as 47 assinaturas eram
# distintas e cada acao trouxe caminho novo, entao nao havia repeticao no
# sentido do §4.2. O que o agente fazia era improdutivo, nao redundante -- coisas
# diferentes, e so a primeira e metrica 7 (D87).
gm = Grafo()
gm._garantir("172.20.0.10").subrede = "172.20.0.0/24"
cmd_m = ["nmap", "-sn", "172.20.0.0/24"]
tm1 = gm.abrir_tentativa("nmap", cmd_m, alvo="172.20.0.10")
gm.fechar_tentativa(tm1, sucesso=True, resumo="5 hosts")
tm2 = gm.abrir_tentativa("nmap", cmd_m, alvo="172.20.0.10")
checa("a primeira vez nao e redundante", tm1.redundante, False)
checa("repetir a MESMA acao sem nada aprendido entre elas e redundante",
      tm2.redundante, True)
gm.fechar_tentativa(tm2, sucesso=True, resumo="5 hosts")
# Com informacao nova no meio, a mesma acao deixa de ser redundante: ela pode
# render outra coisa agora, e acusar repeticao desencorajaria acao legitima.
gm.absorver_execucao("172.20.0.10", "injecao de comando")
tm3 = gm.abrir_tentativa("nmap", cmd_m, alvo="172.20.0.10")
checa("mas com informacao nova entre elas, nao e", tm3.redundante, False)
gm.fechar_tentativa(tm3, sucesso=True, resumo="5 hosts")
checa("e a metrica 7 conta uma so", gm.acoes_redundantes, 1)

# METRICA 11: acoes que nao ensinaram nada ao grafo (D87). Pergunta diferente da
# metrica 7, e sem heuristica de semelhanca: a revisao se moveu entre abrir e
# fechar esta acao?
gi = Grafo()
gi._garantir("172.20.0.10").subrede = "172.20.0.0/24"
t_aprende = gi.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                               alvo="172.20.0.10")
gi.absorver_execucao("172.20.0.10", "injecao de comando")   # aprendeu algo
gi.fechar_tentativa(t_aprende, sucesso=True, resumo="entrou")
t_vazia = gi.abrir_tentativa("curl", ["curl", "http://172.20.0.10/x"],
                             alvo="172.20.0.10")
gi.fechar_tentativa(t_vazia, sucesso=True, resumo="nenhum fato novo")
checa("acao que ensinou algo nao e improdutiva", t_aprende.revisao != t_aprende.revisao_ao_abrir, True)
checa("acao que nao ensinou nada conta como improdutiva",
      t_vazia.revisao, t_vazia.revisao_ao_abrir)
# **Contagens DIFERENTES de propósito.** Com 1 produtiva e 1 improdutiva, trocar
# `==` por `!=` daria 1 nos dois casos e o teste nao distinguiria nada -- foi o
# que a bateria de 22 de setembro pegou. Com 2 e 1, a troca aparece.
t_aprende2 = gi.abrir_tentativa("nmap", ["nmap", "-sV", "172.20.0.10"],
                                alvo="172.20.0.10")
gi.absorver_saida("172.20.0.10", analisar_saida("/opt/achado.txt"))
gi.fechar_tentativa(t_aprende2, sucesso=True, resumo="1 caminho novo")
checa("a metrica 11 conta so as improdutivas, nao as produtivas",
      gi.passos_improdutivos, 1)
checa("e sao 2 as produtivas, para a contagem invertida nao passar",
      sum(1 for t in gi.tentativas
          if t.fechada and t.revisao != t.revisao_ao_abrir), 2)
# Tentativa que nunca fechou nao autoriza conclusao nenhuma sobre ela.
gi.abrir_tentativa("curl", ["curl", "http://172.20.0.10/y"], alvo="172.20.0.10")
checa("tentativa aberta e nao fechada nao conta", gi.passos_improdutivos, 1)
# TENTATIVA DE FORMATO ANTIGO **E** NUNCA FECHADA: os dois `None` se encontram,
# e `None == None` e verdadeiro. Sem as duas guardas, ela contaria como passo
# improdutivo -- afirmando que uma acao de antes de 22 de setembro nao ensinou
# nada, quando o que se sabe dela e nada.
#
# A bateria de 22 de setembro passou com as duas guardas removidas: nenhum teste
# cobria o caso combinado. `None` nunca vira zero neste projeto, e aqui nunca
# vira "improdutivo" tampouco.
gv = Grafo()
gv.tentativas.append(Tentativa(ferramenta="nmap", assinatura="antiga"))
checa("tentativa antiga e nunca fechada nao conta como improdutiva",
      gv.passos_improdutivos, 0)

# E a metrica sobrevive ao disco, como todas as outras.
with tempfile.TemporaryDirectory() as d:
    cam = pathlib.Path(d) / "gi.json"
    gi.salvar(cam)
    checa("a metrica 11 sobrevive ao ciclo de disco",
          Grafo.carregar(cam).passos_improdutivos, 1)

# O SEGREDO NAO PODE VAZAR PELO ROTULO, e ate 22 de setembro vazava.
#
# `mascarar` so conhecia a forma `-p <senha>`. Na `teto-02` o agente escreveu
# `echo 7fQx2Lm9RtVzB4kd | sudo -S -l`, e a senha foi para a secao de tentativas
# em texto claro, repetida a cada passo. O segredo tem um lugar so no grafo, que
# e a credencial (D40) -- e o prompt carrega o que o agente escreveu, entao a
# mascara tem de ser por VALOR, nao por padrao de flag.
g12 = Grafo()
c12 = g12._credencial_ou_nova("svc_deploy", "senha")
c12.segredo = "7fQx2Lm9RtVzB4kd"
t12 = g12.abrir_tentativa("ssh", ["ssh", "svc@h", "echo 7fQx2Lm9RtVzB4kd | sudo -S -l"])
checa("a senha nao sai em claro no rotulo, mesmo fora de `-p`",
      "7fQx2Lm9RtVzB4kd" in t12.rotulo, False)
checa("e o resto do comando sobrevive",
      "sudo -S -l" in t12.rotulo, True)
checa("nem na assinatura, que tambem vai ao disco",
      "7fQx2Lm9RtVzB4kd" in t12.assinatura, False)
# A forma antiga continua coberta: consertar por valor nao pode desfazer o que
# a mascara por flag ja fazia.
t13 = g12.abrir_tentativa("ssh", ["sshpass", "-p", "7fQx2Lm9RtVzB4kd", "ssh", "svc@h", "id"])
checa("`sshpass -p <senha>` continua mascarado",
      "7fQx2Lm9RtVzB4kd" in t13.rotulo, False)
# SEGREDO QUE E PREFIXO DE OUTRO: a mascara vai do mais longo ao mais curto,
# senao trocar o curto primeiro deixa o resto do longo exposto.
g12b = Grafo()
curta = g12b._credencial_ou_nova("a", "senha"); curta.segredo = "abc123"
longa = g12b._credencial_ou_nova("b", "senha"); longa.segredo = "abc123def456"
t12b = g12b.abrir_tentativa("ssh", ["ssh", "h", "echo abc123def456"])
checa("segredo longo nao fica meio exposto quando o curto e prefixo dele",
      "def456" in t12b.rotulo, False)
checa("e o curto tambem some quando aparece sozinho",
      "abc123" in g12b.abrir_tentativa("ssh", ["ssh", "h", "echo abc123"]).rotulo,
      False)

# E sem credencial no grafo nada muda -- a mascara nao inventa segredo.
g13 = Grafo()
t14 = g13.abrir_tentativa("ssh", ["ssh", "svc@h", "echo alguma-coisa | sudo -S -l"])
checa("sem segredo conhecido, o comando passa inteiro",
      "alguma-coisa" in t14.rotulo, True)

# E a DESCOBERTA TEM DE CONTAR COMO INFORMACAO NOVA. Sem isto, o passo que
# revela a segunda sub-rede nao sobe a revisao, e a metrica 7 julgaria a acao
# seguinte contra um grafo que finge nao ter aprendido nada.
#
# **O teste tem de ser a SEGUNDA leitura, num host que o grafo ja conhece.** Na
# primeira, a revisao sobe de qualquer jeito -- o host passa a ter dado onde nao
# tinha --, e um teste ancorado nela passaria mesmo com o defeito de pe. Foi o
# que aconteceu na primeira versao desta checagem, em 22 de setembro: ela dizia
# "aprender uma interface sobe a revisao" e nao checava isso (D29).
g11 = Grafo()
g11._garantir("172.20.0.12").subrede = "172.20.0.0/24"
g11.absorver_saida("172.20.0.12", analisar_saida(
    "3: eth1    inet 172.20.0.12/24 scope global eth1"))
depois_da_primeira = g11.revisao
# A descoberta do passo 70 da `teto-02`: a interna aparece numa leitura nova.
g11.absorver_saida("172.20.0.12", analisar_saida(
    "2: eth0    inet 172.21.0.2/24 scope global eth0"))
checa("descobrir a sub-rede interna conta como informacao nova",
      g11.revisao > depois_da_primeira, True)
checa("e a interna passa a ser conhecida", "172.21.0.0/24" in g11.subredes, True)
# Reler a MESMA interface nao e fato novo -- senao toda releitura pareceria
# aprendizado e a metrica 7 nunca acusaria repeticao.
r = g11.revisao
g11.absorver_saida("172.20.0.12", analisar_saida(
    "2: eth0    inet 172.21.0.2/24 scope global eth0"))
checa("mas reler a mesma interface nao sobe a revisao", g11.revisao, r)

# E tem de sobreviver a uma varredura posterior do mesmo host, que nao sabe nada
# sobre como se entrou nele.
g7.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "172.20.0.0/24"], codigo=0, saida="""Nmap scan report for 172.20.0.10
Host is up.
""")))
checa("varredura posterior nao apaga o meio de acesso",
      g7.host("172.20.0.10").meio_de_acesso, "injecao de comando")
checa("nem desmarca o comprometimento",
      g7.host("172.20.0.10").comprometido, True)


# ========== requisito duro: saida bruta NUNCA chega ao modelo
#
# `ARTEFATO.md` §1.2, sobre a camada de ferramentas: "saida bruta nunca chega ao
# modelo, so o que o parser extraiu e gravou no grafo". E a separacao que define
# a contribuicao do trabalho -- se fragmento de saida vazar para a
# serializacao, o braco A deixa de ser "agente com grafo" e vira "agente com
# grafo mais um pedaco de historico", e a comparacao com o braco B perde o
# sentido. Estava sem teste ate 16 de setembro.

g9 = Grafo()
for _n, _c in (("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"]),
               ("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80"])):
    g9.absorver_hosts(Nmap().analisar(varredura(_n, _c)))
_s9 = g9.serializar()

VAZAMENTOS = ("Nmap scan report", "Starting Nmap", "Host is up", "latency",
              "MAC Address", "SF:", "SF-Port", "Service detection", "Nmap done",
              "https://nmap.org", "scanned in")
for _m in VAZAMENTOS:
    checa(f"a serializacao nao carrega '{_m}' da saida bruta", _m in _s9, False)

# O nome do host VEM da saida bruta, e deve mesmo aparecer -- e fato extraido,
# nao texto cru. A distincao esta em ter passado pelo parser.
checa("mas o fato extraido aparece", "tcc-srv-deploy.tcc-lab_dmz" in _s9, True)


# ========== uso desorganizado, como um agente faz e eu nao faco
#
# Ate aqui todo teste alimentou o grafo na ordem certa, porque quem alimentou fui
# eu, que conheco a cadeia. Um agente varre duas vezes, autentica antes de
# enumerar, falha e tenta de novo, pede host que nao existe. O grafo tem de
# aguentar isso sem inventar fato nem perder o que sabia.

g10 = Grafo()
# autentica ANTES de qualquer varredura: o host nem existe ainda
g10.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")
checa("autenticar antes de enumerar cria o host", "172.21.0.10" in g10.hosts, True)
checa("e cria o pivo tambem", "172.20.0.12" in g10.hosts, True)

# agora varre o mesmo host, TRES vezes, e uma das varreduras vem vazia
for _ in range(3):
    g10.absorver_hosts(Nmap().analisar(Execucao(
        comando=["nmap", "-sV", "-p", "22"], codigo=0, saida="""Nmap scan report for db (172.21.0.10)
Host is up.

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
""")))
g10.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "10.9.9.0/24"], codigo=0, saida="")))
checa("tres varreduras iguais nao duplicam servico",
      len(g10.host("172.21.0.10").servicos), 1)
checa("varredura vazia nao cria host fantasma", len(g10.hosts), 2)
checa("e nao apaga o que ja se sabia",
      g10.host("172.21.0.10").comprometido, True)

# falha depois de sucesso no mesmo host: o sucesso nao pode ser desfeito
g10.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="outro", sucesso=False, codigo=5,
    motivo="permissao negada", alcancavel=True), credencial="senha")
checa("falha posterior nao desfaz comprometimento ja obtido",
      g10.host("172.21.0.10").comprometido, True)
checa("e a credencial que falhou fica separada da que funcionou",
      len(g10.credenciais), 2)


# ========== invariantes: valem depois de qualquer sequencia
#
# Nao importa a ordem nem quantas vezes: estas propriedades tem de valer sempre.

def invariantes(gg, rotulo: str) -> None:
    checa(f"[{rotulo}] nenhum endereco duplicado",
          len(gg.hosts), len({h.endereco for h in gg.hosts.values()}))
    checa(f"[{rotulo}] host comprometido tem razao registrada",
          all(h.meio_de_acesso is not None
              or any(h.endereco in c.validada_em for c in gg.credenciais)
              for h in gg.hosts.values() if h.comprometido), True)
    checa(f"[{rotulo}] sub-rede alcancada tem host comprometido nela",
          all(any(h.comprometido for h in gg.hosts.values() if h.subrede == sr)
              for sr in gg.subredes_alcancadas()), True)
    checa(f"[{rotulo}] credencial nao esta validada e recusada no mesmo host",
          all(not (set(c.validada_em) & set(c.recusada_em))
              for c in gg.credenciais), True)


invariantes(g, "cadeia em ordem")
invariantes(g10, "uso desorganizado")

# Idempotencia: absorver tudo de novo nao muda nada.
_antes = g10.serializar()
for _ in range(2):
    g10.absorver_hosts(Nmap().analisar(Execucao(
        comando=["nmap", "-sV", "-p", "22"], codigo=0, saida="""Nmap scan report for db (172.21.0.10)
Host is up.

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
""")))
checa("absorver o mesmo fato de novo nao muda a serializacao",
      g10.serializar(), _antes)


# A razao de fallback "usado como pivo" so vale quando NAO ha razao melhor.
# Achado no pipeline real de 16 de setembro: o agente autentica no pivo (elo 3)
# e depois salta por ele (elo 4). Se o fallback fosse gravado mesmo assim, a
# serializacao diria "acesso por: usado como pivo" num host cuja credencial ja
# esta listada como validada ali -- linha redundante, e enganosa, porque a
# entrada real foi por senha.

g11 = Grafo()
g11.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc", sucesso=True, codigo=0,
    alcancavel=True), credencial="senha")
g11.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")
checa("pivo com credencial validada nao ganha razao generica",
      g11.host("172.20.0.12").meio_de_acesso, None)
checa("e a serializacao nao repete a informacao",
      "usado como pivo" in g11.serializar(), False)

# Mas se o salto vier sem autenticacao previa no pivo, a razao generica entra --
# senao o host contaria para a metrica 2 sem nada que o explique.
g12 = Grafo()
g12.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")
checa("sem razao melhor, o pivo recebe a generica",
      g12.host("172.20.0.12").meio_de_acesso, "usado como pivo")


# A serializacao nao pode misturar identificador curto com endereco cru. Achado
# no pipeline real de 16 de setembro: uma credencial cuja origem ainda nao tinha
# sido catalogada saia como "origem 172.20.0.10" enquanto todo o resto do texto
# usa "hNN". Para quem le -- inclusive o modelo -- viram duas formas de nomear a
# mesma coisa, e a correlacao entre as secoes se perde.
#
# Achar credencial em um host implica ter tido acesso a ele, entao o host existe.
# Registra-lo NAO o marca comprometido: quem obteve a execucao registra isso a
# parte.

g13 = Grafo()
g13.absorver_credencial("svc", "senha", origem="172.20.0.10")
checa("o host de origem da credencial passa a existir",
      "172.20.0.10" in g13.hosts, True)
checa("mas nao e marcado comprometido por isso",
      g13.host("172.20.0.10").comprometido, False)
_s13 = g13.serializar()
checa("e a origem sai como identificador, nao endereco cru",
      "origem h01" in _s13, True)

import re as _re
_cred = [l for l in _s13.splitlines() if l.startswith("[c")]
checa("nenhum endereco cru sobra na secao de credenciais",
      any(_re.search(r"\d+\.\d+\.\d+\.\d+", l) for l in _cred), False)


# ===== a secao de sub-redes informa COMO CHEGAR, nao o que ja foi conquistado
#
# Lacuna achada em 16 de setembro, comparando com o prompt medido. Ele diz:
#     dmz 172.20.0.0/24, alcancavel do atacante
#     interna 172.21.0.0/24, so via host-pivo
# O meu dizia "alcancada" nas duas -- que significa "ja comprometi algo la", um
# fato diferente. O que o agente precisa para escolher a proxima acao e o
# primeiro: saber que a interna so se alcanca pelo pivo E o mecanismo central da
# hipotese deste trabalho. Informar conquista no lugar de rota deixava o agente
# sem o sinal que ele mais precisa.

g14 = Grafo()
# acao direta bem-sucedida na DMZ: a DMZ e alcancavel direto
g14.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="u", sucesso=True, codigo=0,
    alcancavel=True), credencial="senha")
# acao na interna SO deu certo atraves do pivo
g14.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="u", sucesso=True, codigo=0,
    via="172.20.0.12", alcancavel=True), credencial="senha")

_sub = g14.serializar().split("=== HOSTS")[0]
checa("a DMZ consta como alcancavel direto",
      "172.20.0.0/24 alcancavel direto" in _sub, True)
checa("e a interna consta como acessivel so pelo pivo",
      "172.21.0.0/24 so via h" in _sub, True)

# Sub-rede vista mas nunca alcancada com sucesso: rota desconhecida. Nao se
# afirma que e inalcancavel -- so que ainda nao se provou rota.
g15 = Grafo()
g15.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-sn", "10.5.0.0/24"], codigo=0, saida="""Nmap scan report for x (10.5.0.1)
Host is up.
""")))
checa("sub-rede sem sucesso nenhum fica com rota desconhecida",
      "10.5.0.0/24 rota desconhecida" in g15.serializar(), True)

# E a consulta separada continua existindo, porque metrica 1 mede conquista.
checa("subredes_alcancadas continua medindo CONQUISTA, nao rota",
      g14.subredes_alcancadas(), ["172.20.0.0/24", "172.21.0.0/24"])
checa("e na sub-rede so vista, nada foi conquistado",
      g15.subredes_alcancadas(), [])




# ====================================================================
# TENTATIVAS JA FEITAS -- a sexta entidade de `ARTEFATO.md` §1.2
#
# Alimenta a metrica 7 de §4.2: "repeticao da mesma acao sobre o mesmo alvo
# **sem informacao nova entre elas**". A clausula em negrito e a parte dificil,
# e a regra escolhida esta em D39: o grafo conta revisoes, e revisao so sobe
# quando um fato muda de verdade.
# ====================================================================

from ferramentas import Curl, Hydra
from grafo import assinatura


def hydra_de(nome: str, comando: list[str]) -> Execucao:
    return Execucao(comando=comando, saida=exemplo(nome), codigo=0)


def respostas_curl() -> list[str]:
    blocos, atual = [], None
    for linha in exemplo("09-curl-com-cabecalhos.txt").splitlines():
        if linha.startswith("$ curl"):
            atual = []
            blocos.append(atual)
            continue
        if atual is not None:
            atual.append(linha)
    return ["\n".join(b).strip("\n") for b in blocos]


pagina, _ausente, injecao = respostas_curl()

# -------------------------------------------------- o contador de revisao

gr = Grafo()
checa("grafo nasce na revisao zero", gr.revisao, 0)

gr.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("descobrir cinco hosts e informacao nova", gr.revisao, 1)

# A mesma varredura de novo nao ensina nada. Se a revisao subisse aqui, toda
# repeticao pareceria informativa e a metrica 7 nunca acusaria nada.
gr.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("repetir a mesma varredura nao sobe a revisao", gr.revisao, 1)

# Ja a varredura de servico traz portas e versoes que nao se sabia.
gr.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
checa("varredura de servico sobre os mesmos hosts e informacao nova", gr.revisao, 2)

# ------------------------------------------------- assinatura sem segredo

checa("assinatura mascara a senha do sshpass",
      assinatura(["sshpass", "-p", "7fQx2Lm9RtVzB4kd", "ssh", "svc_deploy@172.20.0.12"]),
      "sshpass -p <SENHA> ssh svc_deploy@172.20.0.12")
checa("assinatura mascara a senha do hydra",
      assinatura(["hydra", "-l", "root", "-p", "hashed", "172.20.0.11"]),
      "hydra -l root -p <SENHA> 172.20.0.11")
# `-p` do nmap e lista de PORTAS, nao senha. Mascarar aqui apagaria o unico
# campo que distingue duas varreduras diferentes do mesmo host -- e as duas
# passariam a contar como a mesma acao.
checa("assinatura NAO mascara as portas do nmap",
      assinatura(["nmap", "-sV", "-p", "22,80", "172.20.0.10"]),
      "nmap -sV -p 22,80 172.20.0.10")
# A lista de senhas do hydra e `-P` maiusculo e e um caminho de arquivo.
checa("assinatura NAO mascara a lista de senhas, que e caminho",
      assinatura(["hydra", "-l", "x", "-P", "senhas.txt", "ssh://1.2.3.4"]),
      "hydra -l x -P senhas.txt ssh://1.2.3.4")

# --------------------------------------------- acao nova contra repeticao

gt = Grafo()
t1 = gt.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
checa("a primeira acao nunca e redundante", t1.redundante, False)
gt.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
gt.fechar_tentativa(t1, sucesso=True, resumo="5 hosts")
checa("fechar carimba a revisao do grafo", t1.revisao, gt.revisao)
checa("e a tentativa fica registrada", len(gt.tentativas), 1)

# Mesma acao, e nada foi aprendido desde que a primeira terminou.
t2 = gt.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
checa("repetir sem informacao nova no meio E redundante", t2.redundante, True)
gt.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
gt.fechar_tentativa(t2, sucesso=True, resumo="5 hosts")
checa("e a metrica 7 conta uma", gt.acoes_redundantes, 1)

# Agora chega informacao nova de OUTRA acao.
t3 = gt.abrir_tentativa("nmap", ["nmap", "-sV", "-p", "22,80,1337,8080",
                                 "172.20.0.0/24"], alvo="172.20.0.0/24")
checa("acao com assinatura diferente nao e repeticao", t3.redundante, False)
gt.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
gt.fechar_tentativa(t3, sucesso=True, resumo="8 servicos")

# Com a revisao mudada, a mesma varredura de antes volta a ser defensavel:
# algo mudou no mundo desde a ultima vez que ela rodou.
t4 = gt.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
checa("depois de informacao nova, repetir deixa de ser redundante",
      t4.redundante, False)
gt.fechar_tentativa(t4, sucesso=True, resumo="5 hosts")
# ...mas so uma vez. A proxima ja nao tem desculpa.
t5 = gt.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
checa("e a seguinte volta a ser redundante", t5.redundante, True)
gt.fechar_tentativa(t5, sucesso=True, resumo="5 hosts")
checa("metrica 7 acumulada", gt.acoes_redundantes, 2)

# Tentativa aberta e nunca fechada nao autoriza conclusao nenhuma: o passo
# pode ter morrido no meio. `None` nunca vira zero, aqui como em todo o resto.
gp = Grafo()
ta = gp.abrir_tentativa("nmap", ["nmap", "-sn", "10.0.0.0/24"], alvo="10.0.0.0/24")
checa("tentativa aberta nasce sem revisao", ta.revisao, None)
tb = gp.abrir_tentativa("nmap", ["nmap", "-sn", "10.0.0.0/24"], alvo="10.0.0.0/24")
checa("repetir uma tentativa que nunca fechou nao e acusado de redundante",
      tb.redundante, False)

# -------------------------------------------- absorcao dos dois parsers novos

gh = Grafo()
gh.absorver_forca_bruta(Hydra().analisar(hydra_de("05-hydra-glhf.txt", [
    "hydra", "-l", "root", "-P", "senhas.txt", "172.20.0.11", "-s", "1337",
    "http-post-form", "/login:x"])))
checa("hydra que achou senha cria a credencial", len(gh.credenciais), 1)
checa("com o segredo", gh.credencial("root", "senha").segredo, "hashed")
# ⚠️ ESTE TESTE AFIRMAVA O CONTRARIO ATE 30 DE SETEMBRO, e a afirmacao estava
# errada -- ele codificava o defeito, como a expectativa de D105 que D185
# corrigiu. Dizia: *"achar por forca bruta E validar: a senha so aparece porque
# o servico a aceitou"*.
#
# **A fixture e `http-post-form`**, e ali o sucesso nao vem do protocolo: vem de
# uma string que o OPERADOR escreve. Medido contra o laboratorio no ar, a pagina
# de falha da GLHF contem `Invalid` e `erro` e nao contem `incorrect`; com
# `F=incorrect` o hydra reportou 2653 logins como sucesso e o grafo gravou 180
# credenciais validadas sem nenhuma ter sido tentada (D192).
checa("D192: forma HTTP nao valida -- o veredito e palpite do operador",
      gh.credencial("root", "senha").validada_em, [])
checa("D192: mas a tentativa e observacao, e fica registrada",
      gh.credencial("root", "senha").tentada_em, ["172.20.0.11"])

antes = gh.revisao
gh.absorver_forca_bruta(Hydra().analisar(hydra_de("06-hydra-srv-deploy.txt", [
    "hydra", "-l", "svc_deploy", "-P", "senhas.txt", "ssh://172.20.0.12", "-t", "4"])))
checa("corrida sem resultado nao inventa credencial", len(gh.credenciais), 1)
# O host existe -- o hydra falou com ele. Isso e fato e sobe a revisao.
checa("mas o alvo atacado passa a ser conhecido",
      "172.20.0.12" in gh.hosts, True)
checa("e isso conta como informacao nova", gh.revisao > antes, True)
checa("sem marcar o alvo como comprometido",
      gh.host("172.20.0.12").comprometido, False)

gc = Grafo()
gc.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "-G", "http://172.20.0.10:8080/diagnostico",
             "--data-urlencode", "destino=127.0.0.1; cat /opt/diagnostico/config.ini"],
    codigo=0, saida=injecao)))
checa("curl registra o host respondente", "172.20.0.10" in gc.hosts, True)
checa("e a porta que atendeu", [s.porta for s in gc.host("172.20.0.10").servicos],
      [8080])
checa("a credencial lida do arquivo entra", len(gc.credenciais), 1)
checa("com a origem certa", gc.credencial("svc_deploy", "senha").origem,
      "172.20.0.10")
# Ler credencial de um arquivo NAO e validar credencial. Ela ainda nao foi
# testada em lugar nenhum, e afirmar validacao aqui contaminaria a metrica 8.
checa("mas lida nao e validada",
      gc.credencial("svc_deploy", "senha").validada_em, [])
# E ler o arquivo tambem nao prova, por si so, execucao de comando: quem
# conclui isso e o laco, chamando `absorver_execucao`.
checa("e o parser sozinho nao marca comprometimento",
      gc.host("172.20.0.10").comprometido, False)

# ------------------------------------------------------- na serializacao

gs = Grafo()
ts = gs.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
gs.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
gs.fechar_tentativa(ts, sucesso=True, resumo="5 hosts")
texto = gs.serializar()
checa("a serializacao ganha a quinta secao",
      "=== TENTATIVAS JA REALIZADAS ===" in texto, True)
# O rotulo traz o alvo, porque rotulo com forma de comando tem de ser comando
# que roda (D64/D65) -- `nmap -sn` sozinho e aceito pelo nmap, varre zero hosts
# e sai com codigo ZERO, o que o arnes registraria como sucesso.
#
# A SETA, por sua vez, carrega o IDENTIFICADOR `hNN`, que e o que o agente
# escreve no campo `alvo` e a ponte entre esta secao e a de hosts. Sub-rede nao
# tem identificador, entao aqui nao ha seta: ela so repetiria o alvo.
checa("com a acao, o alvo e o desfecho",
      "[t01] nmap -sn 172.20.0.0/24: OK, 5 hosts" in texto, True)
linha_t01 = [x for x in texto.splitlines() if x.startswith("[t01]")][0]
checa("e o alvo continua sem se repetir dentro da propria linha",
      linha_t01.count("172.20.0.0/24"), 1)
# Quando HA identificador, a seta aparece -- e o endereco no rotulo nao e
# repeticao dele: sao as duas pontas da mesma ponte.
gi = Grafo()
gi.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
ti = gi.abrir_tentativa("curl", ["curl", "http://172.20.0.10:8080/"],
                        alvo="172.20.0.10")
gi.fechar_tentativa(ti, sucesso=True, resumo="http 200")
linha_ti = [x for x in gi.serializar().splitlines() if x.startswith("[t01]")][0]
checa("alvo com identificador ganha a seta", " -> h" in linha_ti, True)
checa("e o rotulo continua sendo comando que roda",
      linha_ti.startswith("[t01] curl http://172.20.0.10:8080/"), True)
# ALVO QUE O AGENTE INVENTOU e o grafo nao resolve. Antes de 18 de setembro a
# seta caia no valor cru e mostrava ` -> h09`, um identificador que NAO EXISTE,
# com a mesma forma dos que existem. Agora nao ha seta -- e o comando, que fica
# inteiro no rotulo, continua dizendo o que foi tentado, que e o que impede
# repeticao. O alvo inventado nao se perde: `passos.jsonl` grava `alvo` e
# `endereco: null`, e e de la que a metrica 6 conta.
tn = gi.abrir_tentativa("nmap", ["nmap", "-sV", "172.30.0.5"], alvo="h09")
gi.fechar_tentativa(tn, sucesso=False, resumo="sem rota")
linha_tn = [x for x in gi.serializar().splitlines() if x.startswith("[t02]")][0]
checa("alvo inventado nao ganha seta com identificador falso",
      " -> " in linha_tn, False)
checa("mas o comando tentado continua visivel",
      "nmap -sV 172.30.0.5" in linha_tn, True)

tf = gs.abrir_tentativa("ssh", ["sshpass", "-p", "errada", "ssh",
                                "svc_deploy@172.20.0.12", "id"],
                        alvo="172.20.0.12")
gs.fechar_tentativa(tf, sucesso=False, resumo="permissao negada")
texto = gs.serializar()
checa("falha aparece como FALHA", "FALHA, permissao negada" in texto, True)
checa("o alvo vira identificador, como no resto do texto",
      "-> h05: FALHA" in texto, True)
# A senha nao pode vazar para o prompt por esta porta.
checa("e o segredo nao viaja na tentativa", "errada" in texto, False)
# A mascara aparece ASPEADA desde 21 de setembro, porque o rotulo preserva o
# aspeamento. O texto do marcador mudou em 22 de setembro: era `****`, que tem
# forma de valor e foi copiado 5 vezes na `teto-03` (D91).
#
# D106 tirou o prefixo inteiro e D110 o repos, depois de medir: sem ele o
# agente para de escrever `sshpass` (0 de 10 contra 10 de 10) e monta comando
# que nao autentica. Ver `ferramentas/ssh.py`, `Ssh.resumir`.
checa("ele aparece mascarado", "<SENHA>" in texto, True)
checa("e a linha do ssh continua com a forma de comando",
      "sshpass -p '<SENHA>' ssh" in texto, True)

# Repeticao nao ganha linha propria: numa execucao de 60 passos isso encheria
# o orcamento de tokens repetindo a mesma acao. Uma linha por acao distinta,
# com a contagem.
tr = gs.abrir_tentativa("ssh", ["sshpass", "-p", "errada", "ssh",
                                "svc_deploy@172.20.0.12", "id"],
                        alvo="172.20.0.12")
gs.fechar_tentativa(tr, sucesso=False, resumo="permissao negada")
texto = gs.serializar()
checa("acao repetida vira contagem, nao linha nova",
      texto.count("sshpass -p '<SENHA>'"), 1)
checa("e a contagem aparece", "(2x)" in texto, True)

# Varrer duas faixas diferentes sao duas acoes, e tem de dar duas linhas. Ate
# 18 de setembro isso dependia SO do agrupamento por assinatura, porque o rotulo
# de `nmap -sn` era identico para qualquer faixa. Com o alvo de volta ao rotulo
# (D65) os dois mecanismos concordam, e o teste confere os dois.
gg = Grafo()
a1 = gg.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"], alvo="172.20.0.0/24")
gg.fechar_tentativa(a1, sucesso=True, resumo="5 hosts")
a2 = gg.abrir_tentativa("nmap", ["nmap", "-sn", "172.21.0.0/24"], alvo="172.21.0.0/24")
gg.fechar_tentativa(a2, sucesso=True, resumo="sem rota")
checa("duas faixas varridas dao duas linhas",
      gg.serializar().count("nmap -sn "), 2)
checa("e cada linha diz qual faixa",
      all(f"nmap -sn 172.2{n}.0.0/24" in gg.serializar() for n in (0, 1)), True)
checa("e nenhuma delas vira repeticao da outra", gg.acoes_redundantes, 0)

# O AGRUPAMENTO CONTINUA SENDO PELA ASSINATURA, e nao pelo rotulo -- e ainda ha
# caso em que os dois discordam. `--version-intensity` sai do rotulo (o
# involucro a fixa, e ela nao distingue duas acoes para quem le) mas fica na
# assinatura. Agrupar pelo rotulo fundiria duas varreduras distintas numa linha,
# e o agente deixaria de tentar o que nunca tentou.
gv = Grafo()
b1 = gv.abrir_tentativa(
    "nmap", ["nmap", "-sV", "--version-intensity", "2", "-p", "22", "1.2.3.4"],
    alvo="1.2.3.4")
gv.fechar_tentativa(b1, sucesso=True, resumo="1 servico")
b2 = gv.abrir_tentativa(
    "nmap", ["nmap", "-sV", "--version-intensity", "9", "-p", "22", "1.2.3.4"],
    alvo="1.2.3.4")
gv.fechar_tentativa(b2, sucesso=True, resumo="1 servico, versao exata")
checa("rotulo igual e assinatura diferente continuam sendo duas linhas",
      gv.serializar().count("nmap -sV -p 22 1.2.3.4"), 2)
checa("e nenhuma vira repeticao da outra", gv.acoes_redundantes, 0)

vazio = Grafo().serializar()
checa("grafo sem tentativa diz isso explicitamente",
      "nenhuma acao registrada" in vazio, True)

# ----------------------------------------- segredo e alvos nao testados

gk = Grafo()
# As duas varreduras: a descoberta traz os cinco enderecos da DMZ, a de servico
# traz portas em tres deles. O gateway (172.20.0.1) e a maquina do atacante
# (172.20.0.5) ficam sem servico conhecido -- e e isso que os tira da lista.
gk.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
gk.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
gk.absorver_credencial("svc_deploy", "senha", origem="172.20.0.10",
                       segredo="7fQx2Lm9RtVzB4kd")
linha = [x for x in gk.serializar().splitlines() if x.startswith("[c01]")][0]
checa("o segredo entra na linha da credencial",
      "svc_deploy senha 7fQx2Lm9RtVzB4kd" in linha, True)
# Sem isto o modelo nao consegue escrever "a linha exata a executar" que a
# instrucao do laco pede, e o aceite da sexta 18 falharia por falta de dado.
checa("a origem continua",  "origem h03" in linha, True)
# Onde ela AINDA NAO foi testada e o que dirige o reuso -- metrica 8.
# So hosts com servico ABERTO conhecido entram: nao ha onde aplicar credencial
# num host sem servico. h01 e o gateway da rede e h02 e a propria maquina do
# atacante -- nos dois, a varredura respondeu "fechada" em todas as portas, e
# sugeri-los seria ruido em dois dos cinco enderecos da DMZ.
checa("e os hosts onde ela nunca foi tentada aparecem",
      "nao testada h04,h05" in linha, True)
checa("o gateway, sem servico aberto, nao e sugerido",
      "h01" in linha.split("nao testada")[1], False)
checa("nem a maquina do proprio atacante",
      "h02" in linha.split("nao testada")[1], False)

gk.absorver_autenticacao(
    Autenticacao(endereco="172.20.0.12", usuario="svc_deploy", sucesso=True,
                 codigo=0), "senha")
linha = [x for x in gk.serializar().splitlines() if x.startswith("[c01]")][0]
checa("host onde ela funcionou sai da lista de nao testados",
      "nao testada h04" in linha, True)
checa("e entra na de validados", "validada h05" in linha, True)

# O host de ORIGEM nao entra em "nao testada": e de la que ela saiu, e
# sugerir testa-la ali seria conselho circular.
checa("a origem nunca aparece como alvo por testar",
      "h03" in linha.split("nao testada")[1], False)

# Credencial sem segredo continua legivel -- o campo e opcional porque uma
# chave SSH encontrada num diretorio nao tem senha para guardar.
#
# ⚠️ **O TEXTO ESPERADO MUDOU EM 30 DE SETEMBRO (D221), e fica escrito por que.**
# A propriedade que este teste protege -- "nao inventa segredo" -- continua
# valendo byte a byte: nenhum segredo e impresso. O que a linha ganhou foi a
# marca `(arquivo da chave desconhecido)`, porque uma `chave` sem `identidade`
# nao e usavel por via nenhuma e o prompt mostrava `[c01] op chave`, indistinto
# de uma chave utilizavel. **Nao e assercao afrouxada: e a mesma exigencia mais
# uma.** Afrouxar seria trocar a igualdade por pertinencia, e nao foi o caso.
gz = Grafo()
gz.absorver_credencial("op", "chave", origem="172.20.0.10")
checa("credencial sem segredo nao inventa um",
      "[c01] op chave (arquivo da chave desconhecido); origem h01"
      in gz.serializar(), True)
checa("D221: e nao inventa segredo nenhum na linha",
      "op chave (arquivo" in gz.serializar().split("origem")[0], True)
# ⚠️ **O CONTRAEXEMPLO QUE FAZ A REGRA SER REGRA, e ele nao existia.** Chave COM
# arquivo e utilizavel: nao leva marca e mantem o convite `nao testada`. Sem
# esta checagem, uma regra que marcasse TODA chave passaria verde -- e ela
# apagaria o convite da unica credencial que abre o elo 5 do laboratorio.
gz2 = Grafo()
gz2.absorver_credencial("svc_backup", "chave", origem="172.21.0.10")
# `absorver_credencial` nao recebe `identidade` -- quem a preenche e
# `absorver_saida` ao ler um `~/.ssh/config` (D186). O fixture a poe direto,
# que e o estado fisicamente possivel que o teste precisa.
gz2.credenciais[0].identidade = "~/.ssh/id_ed25519"
_lz = [x for x in gz2.serializar().splitlines() if x.startswith("[c01]")][0]
checa("D221: chave COM arquivo nao leva marca",
      "desconhecido" in _lz, False)
checa("D221: e o arquivo aparece, que e o que vai depois do -i (D186)",
      "em ~/.ssh/id_ed25519" in _lz, True)

# ------------------------------------------------------------ persistencia

with tempfile.TemporaryDirectory() as d:
    alvo_json = pathlib.Path(d) / "g.json"
    gs.salvar(alvo_json)
    volta = Grafo.carregar(alvo_json)
    checa("tentativas sobrevivem ao reinicio",
          len(volta.tentativas), len(gs.tentativas))
    checa("a revisao tambem", volta.revisao, gs.revisao)
    checa("a contagem de redundantes tambem",
          volta.acoes_redundantes, gs.acoes_redundantes)
    checa("e a serializacao volta identica", volta.serializar(), gs.serializar())
    gk.salvar(alvo_json)
    checa("o segredo da credencial sobrevive",
          Grafo.carregar(alvo_json).credencial("svc_deploy", "senha").segredo,
          "7fQx2Lm9RtVzB4kd")


# ------------------- cinco buracos achados pela mutacao de 17 de setembro
#
# Todos do mesmo feitio: o comportamento estava certo, mas nenhuma verificacao
# distinguia o certo do errado. Suite verde prova que o codigo faz o que os
# testes checam, nao que os testes checam o que importa (D29).

# 1. Registrar tentativa NAO e informacao nova sobre o ambiente. As tentativas
# ficam fora da impressao comparada de proposito: se entrassem, cada acao
# registrada subiria a revisao, e toda repeticao pareceria informativa --
# a metrica 7 nunca acusaria nada.
gi = Grafo()
gi.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
marco = gi.revisao
ti = gi.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"],
                        alvo="172.20.0.0/24")
gi.fechar_tentativa(ti, sucesso=True, resumo="5 hosts")
gi.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("registrar tentativa nao conta como informacao nova sobre o ambiente",
      gi.revisao, marco)

# 2. Tentativa ABERTA nao encobre uma FECHADA mais antiga. Sem essa regra, o
# agente escaparia da metrica 7 so por ter deixado um passo morrer no meio
# entre duas repeticoes.
ga = Grafo()
ga.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
p1 = ga.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"], alvo="172.20.0.0/24")
ga.fechar_tentativa(p1, sucesso=True, resumo="5 hosts")
p2 = ga.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"], alvo="172.20.0.0/24")
checa("a segunda ja e redundante", p2.redundante, True)
# p2 morre no meio e nunca fecha.
p3 = ga.abrir_tentativa("nmap", ["nmap", "-sn", "172.20.0.0/24"], alvo="172.20.0.0/24")
checa("e a terceira tambem, apesar da tentativa aberta no meio",
      p3.redundante, True)

# 3. Depois de recarregar do disco, absorver o que ja se sabia nao e novidade.
# A impressao do ambiente tem de ser refeita sobre o que foi carregado; se
# ficasse a do construtor vazio, a primeira absorcao apos qualquer retomada
# subiria a revisao sem nada ter mudado, e uma redundancia se perderia.
with tempfile.TemporaryDirectory() as d:
    disco = pathlib.Path(d) / "retomada.json"
    gi.salvar(disco)
    retomado = Grafo.carregar(disco)
    antes_de_absorver = retomado.revisao
    retomado.absorver_hosts(Nmap().analisar(
        varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
    checa("absorver o ja sabido depois de recarregar nao inventa revisao",
          retomado.revisao, antes_de_absorver)

# 4. O hydra nao batiza servico. "http-post-form" e nome de modulo dele, nao
# identificacao de servico; grava-lo poria um termo de ferramenta dentro do
# estado do ambiente, e a varredura do nmap nunca mais o corrigiria.
checa("hydra abre a porta sem dar nome ao servico",
      [(s.porta, s.servico) for s in gh.host("172.20.0.11").servicos],
      [(1337, None)])

# 5. Tentativa que nunca fechou nao vira FALHA na serializacao. Sao coisas
# diferentes: uma foi tentada e recusada, a outra nem se sabe.
gu = Grafo()
gu.abrir_tentativa("nmap", ["nmap", "-sV", "-p", "8080", "172.21.0.12"],
                   alvo="172.21.0.12")
checa("tentativa sem desfecho aparece como tal, nao como falha",
      "SEM DESFECHO" in gu.serializar(), True)
checa("e nao como FALHA", "FALHA" in gu.serializar(), False)


# ------------- tres buracos de 16 de setembro, achados so em 17 (ver D42)
#
# A rodada de mutacao de 16 nao desligava o cache de bytecode do Python e deu
# as tres por mortas sem nunca te-las executado. Refeita em 17 com o cache
# desligado, sobreviveram. O comportamento estava certo nos tres casos; o que
# faltava era verificacao que distinguisse o certo do errado.

# 1. Versao ja conhecida nao e apagada por uma leitura que nao traz versao.
# O nmap deixa a coluna vazia quando nao identifica -- e string vazia
# sobrescrevendo "OpenSSH 9.2p1" transformaria conhecimento em ignorancia.
gv = Grafo()
gv.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
com_versao = next(s for s in gv.host("172.20.0.12").servicos if s.porta == 22)
checa("a varredura de versao trouxe a versao",
      com_versao.versao is not None, True)
guardada = com_versao.versao

gv.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-p", "22", "172.20.0.12"], codigo=0,
    saida="""Nmap scan report for tcc-srv-deploy.tcc-lab_dmz (172.20.0.12)
Host is up (0.000045s latency).
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
""")))
checa("varredura sem -sV nao apaga a versao ja conhecida",
      next(s for s in gv.host("172.20.0.12").servicos if s.porta == 22).versao,
      guardada)

# 2. A mesma travessia registrada duas vezes continua sendo uma aresta. Sem a
# deduplicacao, cada repeticao do mesmo salto encheria a secao de
# alcancabilidade com linhas identicas -- gasto de tokens dizendo o que ja
# estava dito.
gd = Grafo()
for _ in range(3):
    gd.absorver_autenticacao(
        Autenticacao(endereco="172.21.0.10", usuario="svc_deploy", sucesso=True,
                     codigo=0, via="172.20.0.12"), "senha")
checa("o mesmo salto registrado tres vezes e uma aresta so",
      len(gd.alcances), 1)
checa("e a serializacao mostra uma linha so",
      gd.serializar().count("via ssh em"), 1)

# 3. Porta `filtered` nao e porta aberta, tambem dentro do grafo. O nmap usa
# esse estado quando um filtro no caminho impede decidir; trata-lo como aberta
# faria o agente tentar um servico que pode nao existir, e a tentativa
# fracassada contaria contra ele na metrica 6.
gf = Grafo()
gf.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-p", "22,3306", "172.21.0.11"], codigo=0,
    saida="""Nmap scan report for 172.21.0.11
Host is up.
PORT     STATE    SERVICE
22/tcp   open     ssh
3306/tcp filtered mysql

Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
""")))
filtrada = next(s for s in gf.host("172.21.0.11").servicos if s.porta == 3306)
checa("no grafo, filtered nao conta como aberta", filtrada.aberta, False)
checa("mas o estado e preservado como veio", filtrada.estado, "filtered")
saida_f = gf.serializar()
checa("e a porta filtrada nao entra na lista de servicos",
      "3306/tcp mysql" in saida_f, False)
# Ela tambem nao pode virar "ja testada e fechada": fechada e uma RESPOSTA do
# host, filtrada e a ausencia dela. Dizer ao agente que a porta esta fechada
# quando o que houve foi silencio afirma conhecimento que ninguem tem -- e
# faria o agente descartar um servico que talvez exista.
checa("nem na de fechadas, porque filtrada nao e fechada",
      "ja testadas e fechadas" in saida_f, False)
checa("ela aparece como o que e: sem resposta conclusiva",
      " sem resposta conclusiva: 3306/tcp" in saida_f, True)

# E o contraste: porta que respondeu "fechada" continua na linha de fechadas.
gx = Grafo()
gx.absorver_hosts(Nmap().analisar(Execucao(
    comando=["nmap", "-p", "22,3306", "172.21.0.11"], codigo=0,
    saida="""Nmap scan report for 172.21.0.11
Host is up.
PORT     STATE    SERVICE
22/tcp   open     ssh
3306/tcp closed   mysql

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
""")))
checa("porta que respondeu fechada continua sendo fechada",
      " ja testadas e fechadas: 3306/tcp" in gx.serializar(), True)

# ------------------------------------------- metrica 8, reuso de credencial
#
# Era a unica das quatro metricas derivadas do grafo sem consulta propria: a 1
# tem `subredes_alcancadas`, a 7 tem `acoes_redundantes`, a 2 sai da contagem
# de hosts, e a 8 nao tinha nada. `Credencial.reusada` existia desde 16 de
# setembro e nao era chamada por ninguem.

g8 = Grafo()
g8.absorver_credencial("svc_deploy", "senha", origem="172.20.0.10",
                       segredo="7fQx2Lm9RtVzB4kd")
checa("credencial achada e nunca aplicada fora: reuso zero",
      g8.reuso_de_credencial, 0)
checa("e ela ainda nao foi reusada", g8.credencial("svc_deploy", "senha").reusada,
      False)

# Elo 3: a senha lida no host-web e levada para o pivo.
g8.absorver_autenticacao(
    Autenticacao(endereco="172.20.0.12", usuario="svc_deploy", sucesso=True,
                 codigo=0), "senha")
checa("levar a credencial para outro host e um reuso", g8.reuso_de_credencial, 1)
# `reusada` e outra coisa: quer dizer que ela FUNCIONOU em mais de um host.
checa("mas funcionar em um host so ainda nao e 'reusada'",
      g8.credencial("svc_deploy", "senha").reusada, False)

# Elo 4: a mesma senha atravessa o pivo e vale na interna.
g8.absorver_autenticacao(
    Autenticacao(endereco="172.21.0.10", usuario="svc_deploy", sucesso=True,
                 codigo=0, via="172.20.0.12"), "senha")
checa("e o segundo salto e o segundo reuso", g8.reuso_de_credencial, 2)
checa("agora sim ela funcionou em mais de um host",
      g8.credencial("svc_deploy", "senha").reusada, True)

# Tentativa RECUSADA em outro host tambem e reuso: a metrica descreve quantas
# vezes o agente teve a ideia de reaproveitar, nao quantas deram certo.
g8.absorver_autenticacao(
    Autenticacao(endereco="172.20.0.11", usuario="svc_deploy", sucesso=False,
                 codigo=5, motivo="permissao negada"), "senha")
checa("credencial recusada em outro host conta como reuso",
      g8.reuso_de_credencial, 3)

# Senha quebrada por forca bruta no proprio host NAO e reuso: ela nasceu ali.
g9 = Grafo()
g9.absorver_forca_bruta(Hydra().analisar(hydra_de("05-hydra-glhf.txt", [
    "hydra", "-l", "root", "-P", "senhas.txt", "172.20.0.11", "-s", "1337",
    "http-post-form", "/login:x"])))
checa("quebrar senha num host e valida-la ali nao e reuso",
      g9.reuso_de_credencial, 0)


# ================= o grafo nao inventa host (D47) =================
#
# Achado na revisao de 17 de setembro. Um `curl` ou um `hydra` para um endereco
# que nao existe criava um host no grafo, e o modelo passava a ler
# `[h01] 10.99.99.99 ... nao enumerado` como se houvesse maquina ali.
#
# E o pior tipo de defeito para ESTE trabalho: `docs/hipotese.md` §E1 mede
# invencao de parametro, e o grafo estava lavando o parametro inventado ate
# virar fato aparente. O braco A ganharia um host de presente por ter errado o
# endereco.
#
# A regra agora e: host so entra com EVIDENCIA de que respondeu. Que a acao ja
# foi tentada fica na secao de tentativas, que e o lugar disso -- e que so
# passou a existir hoje.

gn = Grafo()
gn.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://10.99.99.99:8080/"],
    codigo=7, saida="", erro="curl: (7) Failed to connect to 10.99.99.99")))
checa("curl que nao conectou nao cria host", list(gn.hosts), [])
checa("e nao conta como informacao nova", gn.revisao, 0)

# Mas curl que RECEBEU resposta cria, mesmo sendo 404: alguem atendeu.
gn.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/nada"], codigo=0,
    saida="HTTP/1.1 404 NOT FOUND\nContent-Type: text/html\n\n<h1>Not Found</h1>")))
checa("mas 404 cria, porque alguem atendeu", list(gn.hosts), ["172.20.0.10"])
checa("e a porta consta como aberta",
      [s.porta for s in gn.host("172.20.0.10").servicos], [8080])

# hydra: a linha "[DATA] attacking" NAO e prova. O hydra a imprime antes de
# tentar conectar.
gh2 = Grafo()
gh2.absorver_forca_bruta(Hydra().analisar(Execucao(
    comando=["hydra", "-l", "x", "ssh://10.99.99.99"], codigo=255,
    saida="""Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] attacking ssh://10.99.99.99:22/
[ERROR] could not connect to ssh://10.99.99.99:22 - Connection timed out
""")))
checa("hydra que nao conectou nao cria host", list(gh2.hosts), [])
# Corrida que terminou a lista prova contato, mesmo sem achar senha.
gh2.absorver_forca_bruta(Hydra().analisar(hydra_de("06-hydra-srv-deploy.txt", [
    "hydra", "-l", "svc_deploy", "-P", "senhas.txt", "ssh://172.20.0.12"])))
checa("corrida que esgotou a lista cria, porque falou com o alvo",
      list(gh2.hosts), ["172.20.0.12"])

# ssh: "sem rota" nao prova host. "permissao negada" prova -- o servico
# atendeu e julgou a credencial.
gs2 = Grafo()
gs2.absorver_autenticacao(
    Autenticacao(endereco="10.99.99.99", usuario="op", sucesso=False, codigo=255,
                 motivo="sem rota", alcancavel=False), "senha")
checa("ssh sem rota nao cria host", list(gs2.hosts), [])
# ...e a credencial registra que foi TENTADA ali, porque isso e fato sobre ELA.
#
# **Esta asserção mudou em 22 de setembro.** Ela dizia `recusada_em ==
# ["10.99.99.99"]`, e afirmava o defeito: "sem rota" e falha de transporte, o
# pacote nem chegou, e ninguem julgou a credencial. O comentario duas linhas
# acima ja dizia o certo -- "permissao negada prova, o servico atendeu e
# julgou" -- e a verificacao logo abaixo dizia o contrario. Documentacao contra
# codigo, achado relendo um contra o outro.
checa("e a credencial anota a tentativa",
      gs2.credencial("op", "senha").tentada_em, ["10.99.99.99"])
checa("mas NAO anota recusa, porque ninguem julgou",
      gs2.credencial("op", "senha").recusada_em, [])

# GRAFO GRAVADO ANTES DE `tentada_em` EXISTIR tem de continuar dando o mesmo
# numero. Esta e a classe de defeito que matou a `teto-02`: campo novo, dado
# velho, e o numero sai errado sem ninguem reclamar. Aqui o risco e pior que
# quebrar, porque nao quebra -- a metrica 8 simplesmente le ZERO sobre as sete
# execucoes ja pagas.
#
# A reconstrucao e a unica honesta possivel: antes do conserto tudo o que era
# tentado ia parar num dos dois vereditos, entao a uniao deles E o conjunto do
# que foi tentado naquele formato.
with tempfile.TemporaryDirectory() as tmp:
    antigo = pathlib.Path(tmp) / "antigo.json"
    antigo.write_text(json.dumps({
        "hosts": [], "alcances": [], "tentativas": [], "revisao": 3,
        "credenciais": [{"usuario": "svc_deploy", "tipo": "senha",
                         "segredo": "x", "origem": "172.20.0.10",
                         "validada_em": ["172.20.0.12"],
                         "recusada_em": ["172.20.0.12", "172.20.0.11"]}],
    }, ensure_ascii=False), encoding="utf-8")
    velho = Grafo.carregar(antigo)
    checa("grafo antigo carrega sem o campo novo", len(velho.credenciais), 1)
    checa("e `tentada_em` e reconstruido da uniao dos vereditos",
          sorted(velho.credenciais[0].tentada_em),
          ["172.20.0.11", "172.20.0.12"])
    checa("com isso a metrica 8 do corpus ja pago nao muda",
          velho.reuso_de_credencial, 2)

# ------------------------ A MASCARA TEM DE PARECER MARCADOR (terca 22)
#
# D40 manda o segredo morar so na credencial, e D65 registrou o `ssh` como
# excecao deliberada a regra "o rotulo e um comando que roda". O que faltava
# era o rotulo AVISAR que nao roda: `sshpass -p '****'` tem a forma exata de um
# comando pronto, e o agente o copiou -- 5 passos na `teto-03`, 4 deles com
# codigo 5, com a senha CERTA disponivel a poucas linhas dali em CREDENCIAIS.
#
# `****` e um valor plausivel. `<SENHA>` e a convencao universal de "preencha
# aqui", e nao se confunde com conteudo.
mascarado = mascarar(["sshpass", "-p", "7fQx2Lm9RtVzB4kd", "ssh", "op@h"],
                     segredos=("7fQx2Lm9RtVzB4kd",))
checa("a mascara posicional vira marcador", mascarado[2], "<SENHA>")
checa("o segredo nao sobra em lugar nenhum",
      "7fQx2Lm9RtVzB4kd" in " ".join(mascarado), False)
# A mascara por VALOR, que cobre o segredo embutido em linha de shell maior --
# `echo <senha> | sudo -S -l`, visto na `teto-02`.
por_valor = mascarar(["sh", "-c", "echo 7fQx2Lm9RtVzB4kd | sudo -S -l"],
                     segredos=("7fQx2Lm9RtVzB4kd",))
checa("a mascara por valor tambem vira marcador",
      por_valor[2], "echo <SENHA> | sudo -S -l")
# E o que o defeito custava: a forma antiga nao pode voltar por descuido.
checa("nao sobra asterisco nenhum",
      "*" in " ".join(mascarado + por_valor), False)

# ------------- a tentativa sem veredito no TEXTO do prompt (terca 22)
#
# Os dois sobreviventes da bateria de mutacao de 22 de setembro: `tentada_em`
# estava coberto no grafo e NAO na serializacao. Apagar a linha do prompt, ou
# fazer "nao testada" voltar a ignora-la, nao quebrava teste nenhum -- e as duas
# coisas sao justamente o que o agente LE.
gv = Grafo()
gv.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.10", usuario="svc_deploy", sucesso=True, codigo=0),
    credencial="senha")
gv.credencial("svc_deploy", "senha").origem = "172.20.0.10"
# SEGREDO REAL. Uma credencial `senha` VALIDADA sempre tem um -- o agente
# digitou a senha para valida-la. Sem ele, D161 (corretamente) tira o campo
# "nao testada", e este teste da MECANICA de nao-testada mediria um estado
# irreal (senha validada sem segredo). Dar o segredo torna o cenario o que o
# fluxo real produz. Estabelecido pelo teste, nao herdado da maquina (D25).
gv.credencial("svc_deploy", "senha").segredo = "s3nhaDeTeste99"
# Dois hosts, o segundo com servico aberto -- so quem tem servico aberto entra
# na lista "nao testada", porque nao ha onde aplicar credencial sem servico.
gv.hosts["172.20.0.10"] = HostDoGrafo(endereco="172.20.0.10",
                                      subrede="172.20.0.0/24")
gv.hosts["172.20.0.11"] = HostDoGrafo(
    endereco="172.20.0.11", subrede="172.20.0.0/24",
    servicos=[ServicoDoGrafo(porta=22, protocolo="tcp", estado="open")])
texto = gv.serializar()
checa("antes de tentar, o host entra em 'nao testada'",
      "nao testada" in texto and "h02" in texto.split("nao testada")[1][:20], True)
# Agora a tentativa que a rede derrubou, sem veredito nenhum.
gv.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.11", usuario="svc_deploy", sucesso=False, codigo=255,
    motivo="falha de ssh", alcancavel=None), credencial="senha")
texto = gv.serializar()
checa("depois de tentar, o prompt diz que foi tentada sem veredito",
      "tentada sem veredito h02" in texto, True)
checa("e ela sai de 'nao testada', para nao ser sugerida de novo",
      "nao testada" in texto, False)
# E o fato falso nao pode aparecer: ninguem julgou a credencial ali.
checa("o prompt NAO diz que a credencial foi recusada",
      "recusada" in texto, False)
# O tipo tem de atravessar o caminho de saida antecipada. Testar aqui com
# "senha" nao provaria nada: "senha" e o valor mais provavel de um descuido.
gs2.absorver_autenticacao(
    Autenticacao(endereco="10.99.99.98", usuario="op", sucesso=False, codigo=255,
                 motivo="sem rota", alcancavel=False), "chave")
checa("e o tipo da credencial atravessa o caminho de recusa",
      sorted(c.tipo for c in gs2.credenciais), ["chave", "senha"])

gs3 = Grafo()
gs3.absorver_autenticacao(
    Autenticacao(endereco="172.20.0.12", usuario="op", sucesso=False, codigo=5,
                 motivo="permissao negada", alcancavel=True), "chave")
checa("ssh com permissao negada cria, porque o servico atendeu",
      list(gs3.hosts), ["172.20.0.12"])
checa("e o tipo 'chave' e preservado no caminho de recusa",
      [c.tipo for c in gs3.credenciais], ["chave"])

# Tempo esgotado nao decide: nao se afirma que existe nem que nao existe.
gs4 = Grafo()
gs4.absorver_autenticacao(
    Autenticacao(endereco="172.21.0.99", usuario="op", sucesso=False, codigo=255,
                 motivo="tempo esgotado", alcancavel=None), "senha")
checa("ssh com tempo esgotado nao cria host", list(gs4.hosts), [])


# ============ o que a pagina revela entra no grafo (D54, §E13) ============

gr_web = Grafo()
gr_web.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/"], codigo=0,
    saida=pagina)))
h = gr_web.host("172.20.0.10")
checa("o titulo da pagina entra no host",
      h.titulo, "Diagnostico de rede -- infra interna")
checa("e a rota com o parametro tambem",
      [(r.caminho, r.metodo, r.parametros) for r in h.rotas],
      [("/diagnostico", "GET", ["destino"])])
saida_web = gr_web.serializar()
checa("a serializacao emite o titulo, como no prompt medido",
      ' titulo http: "Diagnostico de rede -- infra interna"' in saida_web, True)
checa("e a rota com o parametro",
      " rotas: /diagnostico (GET, param destino)" in saida_web, True)
# Sem isto o agente perde no passo seguinte o que acabou de descobrir, porque o
# historico e descartado. Foi o defeito de §E13.
checa("entao o parametro do elo 1 sobrevive ao descarte do historico",
      "destino" in saida_web, True)

# Absorver a mesma pagina de novo nao duplica rota nem conta como novidade.
antes_web = gr_web.revisao
gr_web.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/"], codigo=0,
    saida=pagina)))
checa("reler a mesma pagina nao duplica a rota",
      len(gr_web.host("172.20.0.10").rotas), 1)
checa("nem conta como informacao nova", gr_web.revisao, antes_web)

# Uma pagina revela o formulario, outra so o link: a fusao ACRESCENTA o
# parametro em vez de substituir a rota.
gr_web.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/outra"], codigo=0,
    saida="""HTTP/1.1 200 OK
Content-Type: text/html

<form action="/diagnostico" method="get"><input name="formato"></form>""")))
checa("rota ja conhecida ganha o parametro novo sem perder o velho",
      gr_web.host("172.20.0.10").rotas[0].parametros, ["destino", "formato"])

# E sobrevive ao disco.
with tempfile.TemporaryDirectory() as d:
    a = pathlib.Path(d) / "g.json"
    gr_web.salvar(a)
    volta_web = Grafo.carregar(a)
    checa("titulo e rotas sobrevivem ao reinicio",
          volta_web.serializar(), gr_web.serializar())
    checa("e a rota volta como objeto, nao como dicionario",
          volta_web.host("172.20.0.10").rotas[0].caminho, "/diagnostico")


# Varredura depois da requisicao NAO apaga o que a pagina revelou. O `nmap`
# devolve um `Host` sem titulo, e a fusao roda em cima do que ja existia: se
# substituisse, o agente perderia o titulo e a rota logo na varredura seguinte
# -- que e o defeito de §E13 voltando por outra porta.
gr_dupla = Grafo()
gr_dupla.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/"], codigo=0,
    saida=pagina)))
gr_dupla.absorver_hosts(Nmap().analisar(
    varredura("02-nmap-servicos-dmz.txt", ["nmap", "-sV", "-p", "22,80,1337,8080"])))
checa("varredura depois da pagina nao apaga o titulo",
      gr_dupla.host("172.20.0.10").titulo,
      "Diagnostico de rede -- infra interna")
checa("nem a rota", len(gr_dupla.host("172.20.0.10").rotas), 1)

# E o contrato de `funde` na direcao em que a observacao TRAZ as rotas. Hoje
# nenhum parser produz isso -- so `absorver_resposta`, que nao passa por
# `funde` --, mas o contrato do metodo e "incorpora sem perder".
sem_rota = HostDoGrafo(endereco="172.20.0.10")
sem_rota.funde(HostDoGrafo(endereco="172.20.0.10", titulo="Painel",
                           rotas=[RotaDoGrafo(caminho="/admin", metodo="POST",
                                              parametros=["u"])]))
checa("fundir observacao com rota entrega a rota",
      [(r.caminho, r.parametros) for r in sem_rota.rotas], [("/admin", ["u"])])
checa("e o titulo junto", sem_rota.titulo, "Painel")



# ============ o que o comando devolveu entra no grafo (D57) ============

SAIDA_FIND_REAL = """PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.

--- 127.0.0.1 ping statistics ---
rtt min/avg/max/mdev = 0.029/0.029/0.029/0.000 ms
/opt
/opt/diagnostico
/opt/diagnostico/app.py
/opt/diagnostico/config.ini"""

gs_ = Grafo()
gs_.absorver_execucao("172.20.0.10", "injecao de comando por http")
gs_.absorver_saida("172.20.0.10", analisar_saida(
    "uid=0(root) gid=0(root) groups=0(root)"))
h_ = gs_.host("172.20.0.10")
checa("o usuario da execucao entra no host", h_.usuario, "root")
checa("e o uid", h_.uid, 0)
saida_ = gs_.serializar()
checa("a serializacao diz o usuario, como no prompt medido",
      " execucao: usuario root (uid 0)" in saida_, True)

gs_.absorver_saida("172.20.0.10", analisar_saida(SAIDA_FIND_REAL))
checa("os caminhos entram na ordem em que foram vistos",
      gs_.host("172.20.0.10").caminhos,
      ["/opt", "/opt/diagnostico", "/opt/diagnostico/app.py",
       "/opt/diagnostico/config.ini"])
saida_ = gs_.serializar()
checa("e a serializacao os emite",
      " caminhos vistos: /opt, /opt/diagnostico, /opt/diagnostico/app.py,"
      " /opt/diagnostico/config.ini" in saida_, True)
# E o que fecha o aceite: o agente perde o historico e continua sabendo onde
# esta o arquivo de configuracao.
checa("o caminho do config.ini sobrevive ao descarte do historico",
      "/opt/diagnostico/config.ini" in saida_, True)

# ------------------------------------- a segunda interface do pivo (segunda 21)
#
# Este e o bloco mais importante do arquivo, e o motivo esta na METRICA 1.
#
# O pivo tem os dois pes: `eth1` na DMZ, por onde entramos, e `eth0` na interna.
# Ler `ip addr` nele revela que a 172.21.0.0/24 EXISTE -- que e o mecanismo
# central da hipotese deste trabalho. Mas **existir nao e alcancar**:
#
#   `subredes`             conhecimento: quais redes se sabe que existem
#   `subredes_alcancadas`  CONQUISTA: onde um host caiu (metrica 1, §4.2)
#
# Se comprometer o pivo ja contasse como alcancar a interna, o braco B tambem a
# "alcancaria" no instante em que fizesse SSH nele -- e o criterio de §4.4
# ("bracoo A em 3 de 5, braco B em no maximo 1") seria satisfeito pelos dois por
# acidente. O experimento morreria aqui, e em silencio.
gp = Grafo()
gp.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
gp.absorver_execucao("172.20.0.12", "credencial reusada")
gp.absorver_saida("172.20.0.12", analisar_saida(
    "2: eth0    inet 172.21.0.2/24 brd 172.21.0.255 scope global eth0\n"
    "3: eth1    inet 172.20.0.12/24 brd 172.20.0.255 scope global eth1"))

checa("as interfaces entram no host",
      [(i.nome, i.subrede) for i in gp.host("172.20.0.12").interfaces],
      [("eth0", "172.21.0.0/24"), ("eth1", "172.20.0.0/24")])

# D167. A LACUNA TEM DE APARECER NO PROMPT. Antes de 28 de setembro a linha de
# interfaces simplesmente nao saia quando elas eram desconhecidas, e o host
# aparecia como `enumerado comprometido` -- onde `enumerado` so quer dizer "tem
# servico descoberto". O agente lia isso e concluia que nao havia mais o que
# descobrir ali, justamente no unico host multi-interface do laboratorio.
# §E63 mediu o preco: quem enumerou dentro do pivo alcancou o elo 4 em 3 de 3;
# quem nao enumerou, em 1 de 7.
_gl = Grafo()
_gl.semear_origem("172.20.0.5", "atacante")
_gl.absorver_execucao("172.20.0.10", "injecao")
_s_lacuna = _gl.serializar()
checa("D167: host comprometido sem interfaces conhecidas declara a lacuna",
      " interfaces: nao enumeradas" in _s_lacuna, True)
checa("D167: e a lacuna some quando as interfaces sao conhecidas",
      " interfaces: nao enumeradas" in gp.serializar(), False)
# NAO em host nao comprometido: nao se enumera interface sem sessao, e a linha
# ali seria ruido que sugere haver algo onde nao se pode olhar.
from grafo.modelo import Host as _HostDeTeste                    # noqa: E402
_gn = Grafo()
_gn.semear_origem("172.20.0.5", "atacante")
_gn.absorver_hosts([_HostDeTeste(endereco="172.20.0.99",
                                 subrede="172.20.0.0/24")])
checa("D167: host NAO comprometido nao ganha a linha",
      " interfaces: nao enumeradas"
      in _gn.serializar().split("172.20.0.99")[-1], False)
checa("e a rede interna passa a ser CONHECIDA",
      "172.21.0.0/24" in gp.subredes, True)
checa("MAS NAO ALCANCADA -- a metrica 1 nao se move",
      gp.subredes_alcancadas(), ["172.20.0.0/24"])
checa("e a rota para ela continua sendo desconhecida",
      gp.rota_para("172.21.0.0/24"), None)
# O pivo continua sendo UM host. Contá-lo duas vezes, uma por interface,
# inflaria a metrica 2 -- e no sentido que favorece a hipotese.
checa("o pivo nao vira dois hosts", len(gp.hosts), 5)
checa("e a metrica 2 conta um comprometido, nao dois",
      gp.hosts_comprometidos, 1)
# A serializacao mostra as interfaces, que e como o agente descobre a rota.
sp = gp.serializar()
checa("a serializacao emite as interfaces",
      "interfaces: eth0 172.21.0.2/24, eth1 172.20.0.12/24" in sp, True)
checa("e a rede interna aparece na secao de sub-redes",
      "172.21.0.0/24" in sp[:sp.index("=== HOSTS")], True)

# Absorver a mesma saida de novo nao duplica nem conta como novidade.
antes_ = gs_.revisao
gs_.absorver_saida("172.20.0.10", analisar_saida(SAIDA_FIND_REAL))
checa("reler a mesma saida nao duplica caminho",
      len(gs_.host("172.20.0.10").caminhos), 4)
checa("nem conta como informacao nova", gs_.revisao, antes_)

# Usuario ja conhecido nao e sobrescrito por uma leitura que nao traz usuario.
gs_.absorver_saida("172.20.0.10", analisar_saida("/tmp/x"))
checa("leitura sem `id` nao apaga o usuario ja conhecido",
      gs_.host("172.20.0.10").usuario, "root")

# ⚠️ **ESTE BLOCO MUDOU EM D214, e mudou por MEDIDA.** Ate 30 de setembro havia
# um teto POR COMANDO (`TETO_CAMINHOS = 25`): saida com mais caminhos que isso
# nao entrava nenhum, e este teste afirmava `caminhos == []`.
#
# O que derrubou a regra: replicando o passo 58 da `piloto-A-01-preD211` contra
# o laboratorio no ar, a saida traz 100 caminhos e `/home/svc_app/trofeu.txt` e
# o **primeiro**. Com a regra, zero entravam -- o grafo do host do trofeu ficava
# `caminhos: []` com `620 omitidos`, depois de tres buscas ali dentro. O grafo
# observou o caminho do trofeu e o jogou fora.
#
# Agora vale so o teto POR HOST, e o despejo por lote de D112 faz o trabalho: a
# busca ampla entra ate o teto e um achado estreito posterior a desloca.
gt_ = Grafo()
gt_.absorver_execucao("10.0.0.1", "x")
gt_.absorver_saida("10.0.0.1", analisar_saida(
    "\n".join(f"/dir{i}/arquivo{i}" for i in range(80))))
checa("busca ampla entra ate o teto por host",
      len(gt_.host("10.0.0.1").caminhos), Grafo.LIMITE_CAMINHOS)
checa("e o excedente vira contagem", gt_.host("10.0.0.1").caminhos_omitidos,
      80 - Grafo.LIMITE_CAMINHOS)
# ⚠️ **O PRIMEIRO DA SAIDA ENTRA, e e o que a medida cobrou.** Na saida real o
# caminho do trofeu era o primeiro; se o teto guardasse o fim do lote em vez do
# comeco, o conserto nao teria consertado nada.
checa("e o PRIMEIRO caminho da saida esta entre os guardados",
      gt_.host("10.0.0.1").caminhos[0], "/dir0/arquivo0")
linha_ = [x for x in gt_.serializar().splitlines()
          if x.startswith(" caminhos vistos:")][0]
checa("a serializacao avisa quantos ficaram de fora",
      linha_.endswith(f"(+{80 - Grafo.LIMITE_CAMINHOS} nao listados)"), True)

# D214. CABECALHO COM LISTA VAZIA NAO E LINHA. Com o teto por comando de pe, o
# host do trofeu recebia ` caminhos vistos:  (+620 nao listados)` -- dizia
# "caminhos vistos" e nao listava nenhum. Ficou raro, nao impossivel: um host
# cujo unico lote foi despejado inteiro cai aqui.
gv_ = Grafo()
gv_.absorver_execucao("10.0.0.9", "x")
gv_.host("10.0.0.9").caminhos_omitidos = 620
_linhas = gv_.serializar().splitlines()
checa("D214: host sem caminho nenhum nao emite cabecalho vazio",
      any(x.startswith(" caminhos vistos:") for x in _linhas), False)
checa("D214: e a contagem se declara em frase que diz o que houve",
      " 620 caminhos achados aqui, nenhum listado" in _linhas, True)

# ⚠️ **AS DUAS ORDENS, e o que estes dois blocos PROTEGEM sobreviveu a D214.**
#
# Eles afirmavam IGUALDADE de lista (`caminhos == ["/opt/..."]`), o que so era
# possivel porque a busca ampla nao entrava nenhum caminho. Com D214 ela entra
# ate o teto por host, entao a igualdade cai -- mas o invariante que os dois
# testes existem para guardar e outro: **o achado estreito sobrevive**, nas duas
# ordens. E esse e afirmado por pertinencia, que e a forma certa desde sempre.
#
# Fica escrito que eu afrouxei uma asserção: de igualdade para pertinência.
# Afrouxar asserção e movimento suspeito, e aqui ele se justifica porque a
# igualdade media um efeito colateral da regra removida, nao o comportamento.

# A busca estreita feita ANTES sobrevive a ampla feita depois...
gu_ = Grafo()
gu_.absorver_execucao("10.0.0.2", "x")
gu_.absorver_saida("10.0.0.2", analisar_saida("/opt/diagnostico/config.ini"))
gu_.absorver_saida("10.0.0.2", analisar_saida(
    "\n".join(f"/bin/coisa{i}" for i in range(200))))
checa("o caminho achado na busca estreita continua no grafo",
      "/opt/diagnostico/config.ini" in gu_.host("10.0.0.2").caminhos, True)
checa("e a ampla nao passa do teto por host",
      len(gu_.host("10.0.0.2").caminhos) <= Grafo.LIMITE_CAMINHOS, True)

# ...E A ORDEM INVERSA TAMBEM, que e o furo que D112 consertou: com o teto
# acumulado e sem despejo, um `ls /usr/bin` cedo enchia a lista de ruido e o
# achado posterior era descartado. Aqui ele entra porque o despejo de D112
# prefere o lote GRANDE, e a varredura ampla sai para dar lugar.
gw_ = Grafo()
gw_.absorver_execucao("10.0.0.3", "x")
gw_.absorver_saida("10.0.0.3", analisar_saida(
    "\n".join(f"/usr/bin/coisa{i}" for i in range(200))))
gw_.absorver_saida("10.0.0.3", analisar_saida("/opt/diagnostico/config.ini"))
checa("e o achado estreito DEPOIS de uma busca ampla tambem entra",
      "/opt/diagnostico/config.ini" in gw_.host("10.0.0.3").caminhos, True)
checa("e ele entrou DESPEJANDO um da ampla, nao passando do teto",
      len(gw_.host("10.0.0.3").caminhos), Grafo.LIMITE_CAMINHOS)
checa("com a contagem do excedente preservada",
      gw_.host("10.0.0.3").caminhos_omitidos, 200 - Grafo.LIMITE_CAMINHOS + 1)

# O anteparo do acumulado: muitas buscas estreitas nao enchem o prompt sem fim.
gx_ = Grafo()
gx_.absorver_execucao("10.0.0.4", "x")
for bloco in range(4):
    gx_.absorver_saida("10.0.0.4", analisar_saida(
        "\n".join(f"/b{bloco}/f{i}" for i in range(20))))
checa("o anteparo do acumulado segura o crescimento",
      len(gx_.host("10.0.0.4").caminhos), 40)
checa("e conta o que ele deixou de fora",
      gx_.host("10.0.0.4").caminhos_omitidos, 40)
# O anteparo corta o EXCEDENTE, nao o que ja estava guardado: o primeiro
# achado continua la depois de quatro buscas.
checa("e o primeiro achado sobrevive ao anteparo",
      gx_.host("10.0.0.4").caminhos[0], "/b0/f0")

# Sobrevive ao disco.
with tempfile.TemporaryDirectory() as d:
    a_ = pathlib.Path(d) / "g.json"
    gs_.salvar(a_)
    volta_ = Grafo.carregar(a_)
    checa("usuario, uid e caminhos sobrevivem ao reinicio",
          volta_.serializar(), gs_.serializar())

# Contrato de `funde` para o usuario, como ja se fez para `origem` e `rotas`:
# observacao que nao traz usuario NAO apaga o que ja se sabia. Uma varredura de
# nmap sobre um host onde ja se tinha execucao chegaria aqui.
sem_usuario_ = HostDoGrafo(endereco="1.2.3.4", usuario="root", uid=0)
sem_usuario_.funde(HostDoGrafo(endereco="1.2.3.4"))
checa("fundir observacao sem usuario nao apaga o conhecido",
      (sem_usuario_.usuario, sem_usuario_.uid), ("root", 0))
com_usuario_ = HostDoGrafo(endereco="1.2.3.4")
com_usuario_.funde(HostDoGrafo(endereco="1.2.3.4", usuario="app", uid=1000))
checa("e observacao que TRAZ usuario o entrega",
      (com_usuario_.usuario, com_usuario_.uid), ("app", 1000))

# Host que nunca executou nada nao ganha linha de execucao.
gv_ = Grafo()
gv_.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("host sem execucao nao tem linha de usuario",
      " execucao: usuario" in gv_.serializar(), False)

# ================== o host de origem (D53) ==================
#
# Sem ele, o passo 1 comeca com grafo vazio e o agente nao sabe nem em que rede
# esta -- foi o que aconteceu na primeira execucao assistida (§E12), e o
# primeiro passo virou adivinhacao de faixa.

go = Grafo()
go.semear_origem("172.20.0.5", "atacante")
checa("a origem entra como host", list(go.hosts), ["172.20.0.5"])
checa("com o nome dado", go.host("172.20.0.5").nome, "atacante")
checa("a sub-rede sai do endereco, nao de configuracao",
      go.host("172.20.0.5").subrede, "172.20.0.0/24")
checa("marcada como origem", go.host("172.20.0.5").origem, True)
# Comprometido para `rota_para` responder certo: o agente ESTA na DMZ.
checa("e como comprometida, porque o agente executa dali",
      go.host("172.20.0.5").comprometido, True)
checa("entao a sub-rede dele e alcancavel direto",
      "172.20.0.0/24 alcancavel direto" in go.serializar(), True)

# A armadilha: a metrica 2 e "hosts comprometidos SOBRE 5", e os cinco sao os
# da cadeia. Contar a maquina do proprio atacante inflaria de graca a metrica
# primaria de resultado, nos dois bracos.
checa("mas NAO conta para a metrica 2", go.hosts_comprometidos, 0)
go.absorver_execucao("172.20.0.10", "injecao de comando por http")
checa("enquanto um host de verdade conta", go.hosts_comprometidos, 1)
# A metrica 1 tambem nao pode ser dada de graca: estar numa sub-rede nao e
# te-la conquistado. Grafo so com a origem tem zero sub-redes alcancadas.
so_origem = Grafo()
so_origem.semear_origem("10.9.9.9", "atacante")
checa("e a metrica 1 nao ganha sub-rede so por o agente estar nela",
      so_origem.subredes_alcancadas(), [])

# Na serializacao ele aparece com a palavra `origem`, como no prompt medido.
linha = [x for x in go.serializar().splitlines()
         if x.startswith("[h") and "172.20.0.5" in x][0]
# A linha do host de origem diz tambem COMO a caixa de ferramentas funciona.
# Em 18 de setembro o agente propos `nc -lvnp 4444` para montar shell reverso:
# acao sensata para quem esta cego, e impossivel neste arnes, que roda um
# comando por passo e espera ele terminar. Sem a nota ele queima passos
# descobrindo isso -- em cada execucao e nos dois bracos, o que enche a metrica
# primaria de ruido alheio a gestao de estado (mesmo argumento de D52).
#
# O prompt medido ja poe `ferramentas:` e `nota:` na linha do atacante, e a D53
# ja estabeleceu que informacao sobre a PROPRIA maquina do agente e legitima.
checa("a linha do host de origem avisa que e um comando por passo",
      " nota: um comando por passo, sincrono; sem processo em segundo plano"
      in go.serializar(), True)
checa("e so o host de origem tem essa nota",
      go.serializar().count("um comando por passo"), 1)

checa("a linha do host traz a palavra origem", " origem" in linha, True)

# Semear duas vezes nao duplica nem conta como informacao nova.
antes = go.revisao
go.semear_origem("172.20.0.5", "atacante")
checa("semear de novo nao duplica", len(go.hosts), 2)
checa("nem conta como informacao nova", go.revisao, antes)

# A varredura da propria sub-rede devolve o endereco do atacante, e a fusao
# roda em cima dele. Se a marca se perdesse ali, o atacante passaria a contar
# na metrica 2 -- e isso aconteceria na PRIMEIRA varredura de toda execucao.
gf = Grafo()
gf.semear_origem("172.20.0.5", "atacante")
gf.absorver_hosts(Nmap().analisar(
    varredura("01-nmap-descoberta-dmz.txt", ["nmap", "-sn", "172.20.0.0/24"])))
checa("varrer a propria sub-rede nao apaga a marca de origem",
      gf.host("172.20.0.5").origem, True)
checa("e o atacante continua fora da metrica 2", gf.hosts_comprometidos, 0)
checa("com os outros quatro hosts entrando normalmente", len(gf.hosts), 5)

# E o contrato de `funde` na outra direcao: observacao que TRAZ a marca a
# entrega ao host que ja existia. Hoje nenhum parser produz isso -- so
# `semear_origem`, que nao passa por `funde` --, mas o contrato do metodo e
# "incorpora sem perder", e quem acrescentar um caminho novo amanha nao vai
# reler este comentario. A verificacao e que segura.
from grafo import Host as HostDoGrafo
from grafo.modelo import Tentativa

sem = HostDoGrafo(endereco="172.20.0.5")
sem.funde(HostDoGrafo(endereco="172.20.0.5", origem=True))
checa("fundir uma observacao marcada como origem entrega a marca",
      sem.origem, True)
com = HostDoGrafo(endereco="172.20.0.5", origem=True)
com.funde(HostDoGrafo(endereco="172.20.0.5"))
checa("e observacao sem a marca nao a apaga", com.origem, True)

# Sobrevive ao disco, como todo o resto do grafo.
with tempfile.TemporaryDirectory() as d:
    a = pathlib.Path(d) / "g.json"
    go.salvar(a)
    volta = Grafo.carregar(a)
    checa("a marca de origem sobrevive ao reinicio",
          volta.host("172.20.0.5").origem, True)
    checa("e a metrica 2 continua excluindo-a", volta.hosts_comprometidos, 1)

# ------------------------------------- a saida bruta continua fora do prompt

gb = Grafo()
gb.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "-i", "http://172.20.0.10:8080/"],
    codigo=0, saida=pagina)))
saida = gb.serializar()
checa("o corpo HTML nao atravessa para o prompt",
      "<!doctype html>" in saida, False)
checa("nem o cabecalho do servidor", "Werkzeug" in saida, False)


# ================== METRICA 3: o trofeu, ida e volta (D94) ==================
#
# O campo em si e so um booleano -- quem decide QUANDO ele liga e o laco, em
# `testes_laco.py`, porque so ali existe a cadeia para saber qual e o host do
# trofeu. Aqui se prova so o contrato do grafo: nasce falso, `marcar_trofeu()`
# liga, e o campo sobrevive ao disco -- inclusive ao disco de ANTES dele
# existir, que e o `grafo.json` das dez execucoes ja pagas.

gtr = Grafo()
checa("trofeu comeca falso", gtr.trofeu, False)
gtr.marcar_trofeu()
checa("marcar_trofeu liga o campo", gtr.trofeu, True)
with tempfile.TemporaryDirectory() as tmp:
    p = pathlib.Path(tmp) / "g.json"
    gtr.salvar(p)
    checa("e sobrevive a ida e volta", Grafo.carregar(p).trofeu, True)

# Grafo gravado ANTES deste campo existir carrega com trofeu falso, e nao
# estoura. Mesma classe de defeito que matou a teto-02.
with tempfile.TemporaryDirectory() as tmp:
    velho = pathlib.Path(tmp) / "velho.json"
    velho.write_text(json.dumps(
        {"hosts": [], "credenciais": [], "alcances": [], "tentativas": [],
         "revisao": 1}), encoding="utf-8")
    checa("grafo antigo carrega sem o campo novo",
          Grafo.carregar(velho).trofeu, False)


# ---- CREDENCIAL `None`: NENHUMA FOI ENVIADA (D110) -------------------------
#
# `ssh op@host 'id'` sem `-i` e sem `sshpass` nao oferece credencial nenhuma. O
# ssh falha com "Permission denied" porque nao tinha o que apresentar, e ate 23
# de setembro o grafo registrava isso como RECUSA de uma credencial que nunca
# saiu -- o mesmo endereco em `validada_em` e em `recusada_em`, que e o sintoma
# que D90 consertou por outra porta.
#
# Os fatos de HOST continuam valendo: o endereco respondeu, houve conversa.
gnone = Grafo()
gnone.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=True,
    codigo=0), "senha")
checa("a credencial existe depois de uma sessao com senha",
      [c.usuario for c in gnone.credenciais], ["svc_deploy"])
checa("e esta validada no host", gnone.credenciais[0].validada_em,
      ["172.20.0.12"])

# Agora a mesma tentativa SEM credencial enviada, no MESMO host.
gnone.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.12", usuario="svc_deploy", sucesso=False,
    codigo=255, motivo="permissao negada", alcancavel=True), None)
checa("sem credencial enviada, nada de recusa e anotado",
      gnone.credenciais[0].recusada_em, [])
checa("nem tentativa, porque nenhuma credencial foi levada",
      gnone.credenciais[0].tentada_em, ["172.20.0.12"])
checa("mas o host continua com os fatos dele",
      gnone.host("172.20.0.12").comprometido, True)

# O CAMINHO DA SAIDA ANTECIPADA tem a sua propria guarda, e por isso o seu
# proprio teste: host que nao respondeu (`alcancavel` falso) sai antes de
# `_garantir`, e ali tambem nao se anota credencial que nao foi enviada.
gmorto = Grafo()
gmorto.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.200", usuario="op", sucesso=False, codigo=255,
    motivo="sem rota", alcancavel=False), None)
checa("host morto e sem credencial: nenhuma credencial nasce",
      gmorto.credenciais, [])
# E com credencial declarada, ela nasce -- o controle que prova que a guarda
# discrimina em vez de desligar o caminho inteiro.
gmorto.absorver_autenticacao(Autenticacao(
    endereco="172.20.0.200", usuario="op", sucesso=False, codigo=255,
    motivo="sem rota", alcancavel=False), "senha")
checa("mas com credencial declarada ela nasce",
      [c.usuario for c in gmorto.credenciais], ["op"])


# ---- O TETO POR HOST NAO PODE SER IRREVERSIVEL (D112) ----------------------
#
# `LIMITE_CAMINHOS` era primeiro-a-chegar-fica: cheio o teto, nada mais entrava
# e nao havia despejo. Na `diag-04` o teto encheu no passo 11 e o agente rodou
# ate o 45 sem que um caminho novo entrasse -- 192 descartados.
#
# E o furo que o comentario de D58 descreve como CONSERTADO: *"um `ls /usr/bin`
# cedo enchia o teto de ruido, e um `config.ini` achado depois era
# descartado"*. D58 consertou o teto POR COMANDO; o teto POR HOST ficou com o
# furo intacto.
#
# O criterio de despejo e o de D58, nao um novo: saida enorme tem pouca
# informacao por caminho, saida pequena tem muita. Quando o teto enche, sai o
# caminho que veio do LOTE MAIOR. Assim uma busca estreita tardia desloca o
# ruido de uma varredura ampla anterior, e nao o contrario.
from ferramentas.saida import FatosDeShell as _FS

gteto = Grafo()
_amplo = _FS(caminhos=[f"/usr/bin/x{i:02d}" for i in range(24)])
gteto.absorver_saida("10.0.0.1", _amplo)
checa("lote amplo entra ate o teto por comando",
      len(gteto.host("10.0.0.1").caminhos), 24)

# Mais um lote amplo enche o teto por host (40).
gteto.absorver_saida("10.0.0.1", _FS(caminhos=[f"/var/lib/y{i:02d}"
                                               for i in range(20)]))
checa("e o teto por host segura em 40",
      len(gteto.host("10.0.0.1").caminhos), Grafo.LIMITE_CAMINHOS)

# AGORA A BUSCA ESTREITA: dois caminhos, e sao os que importam. Antes de D112
# eles eram descartados em silencio e o agente nunca os via.
gteto.absorver_saida("10.0.0.1",
                     _FS(caminhos=["/opt/diagnostico/config.ini",
                                   "/home/svc/.ssh/id_ed25519"]))
cs = gteto.host("10.0.0.1").caminhos
checa("a busca estreita entra, mesmo com o teto cheio",
      "/opt/diagnostico/config.ini" in cs, True)
checa("e a segunda tambem", "/home/svc/.ssh/id_ed25519" in cs, True)
checa("sem estourar o teto", len(cs), Grafo.LIMITE_CAMINHOS)
# QUEM SAIU foi o lote maior, que e o criterio de D58 -- nao o mais antigo.
#
# A conta, porque ela nao e obvia: o lote de 20 ja tinha deslocado QUATRO do
# lote de 24 ao transbordar o teto (24 + 20 = 44, teto 40). Sobravam 20 do
# `/usr/bin`. A busca estreita desloca mais dois, e ficam 18.
checa("quem saiu veio do lote de 24, nao do de 20",
      sum(1 for c in cs if c.startswith("/usr/bin/")), 18)
checa("o lote menor fica intacto",
      sum(1 for c in cs if c.startswith("/var/lib/")), 20)

# E O CONTROLE: um lote AINDA MAIOR que o pior guardado nao desloca nada, senao
# a varredura ampla apagaria o achado estreito -- o problema inverso, que o
# comentario de D58 tambem nomeia.
antes = list(gteto.host("10.0.0.1").caminhos)
gteto.absorver_saida("10.0.0.1", _FS(caminhos=[f"/tmp/z{i:02d}" for i in range(25)]))
checa("lote maior que o pior guardado nao desloca ninguem",
      gteto.host("10.0.0.1").caminhos, antes)
checa("e a omissao vira fato, para o agente saber que estreitou de menos",
      gteto.host("10.0.0.1").caminhos_omitidos > 0, True)


# ====== a resposta sem linha de status NAO se joga fora (D141)
#
# `curl -v` manda os cabecalhos para o STDERR; `curl -i` os poe no stdout. Sem
# `-i` nao ha linha de status -- e o CORPO VEM INTEIRO. Ate 25 de setembro a
# guarda de `absorver_resposta` era `status is not None`, e com isso o titulo
# da pagina era extraido pelo parser e jogado fora pelo grafo.
#
# O custo era a porta de entrada da cadeia: a injecao mora em
# `/diagnostico?destino=`, e o agente so a procura depois de saber que aquele
# host e uma ferramenta de diagnostico -- o que vem do TITULO. No corpus, a
# injecao caiu um passo depois do primeiro `curl -i`; sem ele, tarde ou nunca.

_CORPO_SEM_CABECALHO = '<!doctype html>\n<html><head><title>Diagnostico de rede -- infra interna</title></head>\n<body><a href="/diagnostico?destino=alvo">diagnosticar</a></body></html>\n'

_gv = Grafo()
_gv.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-sv", "http://172.20.0.10:8080/"],
    codigo=0, saida=_CORPO_SEM_CABECALHO,
    # O stderr traz o que o `-v` mostra: cabecalhos, inclusive a linha de
    # status. Ela esta AQUI e nao no stdout, e e por isso que o parser nao a
    # ve -- o defeito de D141 nasce dessa separacao.
    erro="*   Trying 172.20.0.10:8080..." + chr(10) + "< HTTP/1.1 200 OK")))
checa("sem linha de status, o host respondente ainda entra",
      "172.20.0.10" in _gv.hosts, True)
checa("e o titulo da pagina tambem", _gv.host("172.20.0.10").titulo,
      "Diagnostico de rede -- infra interna")
# A ROTA VEM COM A QUERY STRING, e isso e anterior a D141: o caminho gravado e
# o que o link da pagina traz, com o parametro visivel. Para o agente isso vale
# mais que o caminho limpo -- e o parametro que ele precisa preencher.
checa("e a rota que a pagina revela, com o parametro a vista",
      [r.caminho for r in _gv.host("172.20.0.10").rotas],
      ["/diagnostico?destino=alvo"])
# A PORTA CONTA COMO ABERTA: houve dialogo HTTP, e a prova e o corpo.
checa("e a porta que atendeu conta como aberta",
      [s.porta for s in _gv.host("172.20.0.10").servicos], [8080])
# E O HOST APARECE NA SERIALIZACAO, que e o que o agente le. Absorver sem
# serializar seria conserto pela metade.
checa("e o host aparece no que o agente le",
      "172.20.0.10" in _gv.serializar(), True)

# O QUE A GUARDA ORIGINAL PROTEGIA CONTINUA PROTEGIDO, e isto e metade do
# conserto: sem status E sem corpo, ninguem atendeu, e inventar um host a
# partir da URL que o modelo escreveu poria parametro inventado no grafo.
_gm = Grafo()
_gm.absorver_resposta(Curl().analisar(Execucao(
    comando=["curl", "-s", "http://10.0.0.99/"], codigo=7, saida="",
    erro="curl: (7) Failed to connect to 10.0.0.99 port 80")))
checa("sem status e sem corpo, nenhum host entra", len(_gm.hosts), 0)

# CADA PROVA DE RESPOSTA SEGURA SOZINHA, e as duas precisam de caso proprio.
# A primeira versao destes testes usava um corpo com titulo E rota, e por isso
# as duas mutacoes que removem uma das duas provas SOBREVIVERAM: a outra
# segurava. Cobertura que so funciona quando os dois sinais estao presentes nao
# cobre nenhum dos dois.
_gt = Grafo()
_gt.absorver_resposta(RespostaHttpDoGrafo(endereco="172.20.0.10", porta=8080,
                                   status=None, titulo="So o titulo"))
checa("so o titulo ja e prova de resposta", "172.20.0.10" in _gt.hosts, True)

_gr = Grafo()
_gr.absorver_resposta(RespostaHttpDoGrafo(endereco="172.20.0.10", porta=8080,
                                   status=None,
                                   rotas=[RotaDoGrafo(caminho="/so-a-rota")]))
checa("so a rota ja e prova de resposta", "172.20.0.10" in _gr.hosts, True)

# E O ENDERECO CONTINUA OBRIGATORIO. Sem ele nao ha o que registrar, e a
# guarda tem duas metades -- a prova de resposta e o endereco.
_gs = Grafo()
_gs.absorver_resposta(RespostaHttpDoGrafo(endereco=None, porta=8080, status=200,
                                   titulo="Pagina"))
checa("sem endereco, nenhum host entra mesmo com resposta", len(_gs.hosts), 0)




# ---------------- O /etc/hosts ENTRA NO GRAFO COMO HOST OBSERVADO (D155)
#
# O parser desta saida e testado em `testes.py`; aqui se confere o que o GRAFO
# faz com o resultado, que e o que decide as metricas.
from ferramentas import analisar_saida as _analisar155

_etc155 = _analisar155(
    "127.0.0.1" + chr(9) + "localhost" + chr(10)
    + "172.20.0.12" + chr(9) + "srv-deploy" + chr(10)
    + "172.21.0.2" + chr(9) + "srv-deploy" + chr(10))
checa("o parser entregou os dois hosts do arquivo",
      [h.endereco for h in _etc155.hosts], ["172.20.0.12", "172.21.0.2"])

_g155 = Grafo()
_g155.semear_origem("172.20.0.5", "atacante")
_g155._garantir("172.20.0.12")
_g155.absorver_saida("172.20.0.12", _etc155)
checa("o /etc/hosts poe a sub-rede interna no grafo",
      "172.21.0.0/24" in _g155.subredes, True)
checa("e o host novo entra NAO enumerado, porque ninguem olhou porta",
      _g155.hosts["172.21.0.2"].enumerado, False)
checa("nem comprometido, porque ler arquivo nao compromete nada",
      _g155.hosts["172.21.0.2"].comprometido, False)
# A METRICA PRIMARIA NAO INFLA: `subredes_alcancadas` exige `comprometido`, e
# este e o ponto que separa "descobri que existe" de "cheguei la".
checa("e a metrica 1 nao infla: alcancada exige comprometimento",
      _g155.subredes_alcancadas(), [])
# O NOME VEM DO ARQUIVO, e um host que ja existia nao perde o que tinha.
checa("o nome do arquivo chega ao grafo",
      _g155.hosts["172.21.0.2"].nome, "srv-deploy")


# ----------------- O NOME DO SEGREDO NO ROTULO E NA ASSINATURA (D159)
#
# A volta do conserto: o laco resolve `c01` para o segredo e `mascarar` o
# devolve nomeado. Sem esta metade o segredo entraria na secao de tentativas e
# sairia no prompt de todo passo seguinte -- o vazamento que D40 proibe.

SEG_A, SEG_B = "s3nhaDeTesteAA", "s3nhaDeTesteBB"
NOMES = {SEG_A: "c01", SEG_B: "c02"}

checa("na posicao de -p, o segredo conhecido vira o identificador",
      mascarar(["sshpass", "-p", SEG_A, "ssh", "u@1.2.3.4"], (SEG_A,), NOMES),
      ["sshpass", "-p", "c01", "ssh", "u@1.2.3.4"])

# SEM NOME, O MARCADOR. Mascarar e obrigatorio; nomear so e possivel quando ha
# nome. Valor que nenhuma credencial do grafo reclama nao ganha identificador --
# dar-lhe um nomearia como credencial o que pode ser digitacao do agente.
checa("valor que nenhuma credencial reclama continua mascarado",
      mascarar(["sshpass", "-p", "chutei", "ssh", "u@1.2.3.4"], (SEG_A,), NOMES),
      ["sshpass", "-p", MASCARA, "ssh", "u@1.2.3.4"])
checa("e sem mapa nenhum o comportamento e o de antes de D159",
      mascarar(["sshpass", "-p", SEG_A, "ssh", "u@1.2.3.4"], (SEG_A,)),
      ["sshpass", "-p", MASCARA, "ssh", "u@1.2.3.4"])

# A MASCARA POR VALOR TAMBEM NOMEIA. O segredo embutido numa linha de shell --
# `printf 'u\n<senha>\n' | nc`, que e 35 dos 274 usos do corpo -- tem de sair com
# o MESMO nome que a posicao de `-p` daria. Dois nomes para a mesma credencial no
# mesmo prompt faria o agente crer que sao duas.
embutido = mascarar(["bash", "-c", f"printf 'u\\n{SEG_A}\\n' | nc h 1337"],
                    (SEG_A,), NOMES)
checa("o segredo embutido numa linha de shell sai nomeado",
      "c01" in embutido[-1] and SEG_A not in embutido[-1], True)

# A MELHORA QUE D159 DECLARA: duas credenciais paravam de se distinguir, porque
# as duas viravam `<SENHA>`. A metrica 7 contava como repeticao duas acoes
# diferentes. Nos grafos reais de hoje ha uma credencial so, entao a diferenca e
# zero; a melhora e para quando houver duas.
a = assinatura(["sshpass", "-p", SEG_A, "ssh", "u@1.2.3.4"], (SEG_A, SEG_B))
b = assinatura(["sshpass", "-p", SEG_B, "ssh", "u@1.2.3.4"], (SEG_A, SEG_B))
checa("sem nomes, duas credenciais dao a MESMA assinatura", a == b, True)
a = assinatura(["sshpass", "-p", SEG_A, "ssh", "u@1.2.3.4"], (SEG_A, SEG_B),
               NOMES)
b = assinatura(["sshpass", "-p", SEG_B, "ssh", "u@1.2.3.4"], (SEG_A, SEG_B),
               NOMES)
checa("com nomes, elas se distinguem", a != b, True)
checa("e nenhum segredo aparece em nenhuma das duas",
      SEG_A in a or SEG_B in b, False)

# O ALINHAMENTO DA NUMERACAO, que e o mesmo numero que o prompt imprime. Uma
# credencial SEM segredo na frente empurra a que tem para `c02`: filtrar antes de
# enumerar faria dela a `c01` aqui e a `c02` no prompt, e o laco resolveria a
# credencial errada.
sem_e_com = [Credencial(usuario="root", tipo="chave"),
             Credencial(usuario="svc", tipo="senha", segredo=SEG_A)]
checa("a credencial sem segredo consome o numero c01",
      identificadores_de_credenciais(sem_e_com), {SEG_A: "c02"})
checa("e sem credencial nenhuma o mapa e vazio",
      identificadores_de_credenciais([]), {})

# PELO CAMINHO DE VERDADE, e nao chamando `assinatura` direto. A bateria pegou
# este buraco: mutar a chamada dentro de `abrir_tentativa` sobrevivia porque os
# testes acima exercitam a funcao ISOLADA, e nenhum deles passava pelo grafo.
# Funcao testada nao e chamada testada -- a mutacao morre na funcao e vive na
# linha que a usa.
_g159 = Grafo()
_g159.credenciais.append(Credencial(usuario="a", tipo="senha", segredo=SEG_A))
_g159.credenciais.append(Credencial(usuario="b", tipo="senha", segredo=SEG_B))
_t1 = _g159.abrir_tentativa("ssh", ["sshpass", "-p", SEG_A, "ssh", "u@1.2.3.4"])
_t2 = _g159.abrir_tentativa("ssh", ["sshpass", "-p", SEG_B, "ssh", "u@1.2.3.4"])
checa("pelo grafo, duas credenciais dao assinaturas diferentes",
      _t1.assinatura != _t2.assinatura, True)
checa("e a segunda nao sai marcada como repeticao da primeira",
      _t2.redundante, False)
checa("o rotulo da primeira nomeia c01", "c01" in (_t1.rotulo or ""), True)
checa("e o da segunda nomeia c02", "c02" in (_t2.rotulo or ""), True)
checa("e nenhum dos dois carrega segredo",
      SEG_A in (_t1.rotulo or "") or SEG_B in (_t2.rotulo or ""), False)


# ---- O GRAFO NAO FABRICA HOST PARA A PERNA DO PIVO (D164, sabado 27)
#
# D163 tirou a perna do pivo da PONTUACAO; D164 tira do que o AGENTE ve. Quando
# o agente faz ssh na interface interna do pivo (172.21.0.2) via pivo, o grafo
# criava um host distinto comprometido "h07" na interna. Na coleta-A-02 isso
# desviou 56 de 56 tentativas do agente por um pivo fantasma. Com a verdade de
# solo (`pernas_do_pivo`), a absorcao e no-op: e o proprio pivo por outra
# interface, nada novo.
_PERNAS = ("172.21.0.2",)

# 1. REPRODUZ O FANTASMA: sem pernas, o .2 vira host comprometido na interna.
_gf = Grafo()
_gf.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.2", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12"), "senha")
checa("sem pernas, o .2 vira host comprometido (reproduz o fantasma h07)",
      _gf.hosts["172.21.0.2"].comprometido, True)
checa("e ele infla a interna",
      "172.21.0.0/24" in _gf.subredes_alcancadas(), True)

# 2. O CONSERTO: com pernas, o .2 nao vira host comprometido nenhum.
_gc = Grafo()
_gc.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.2", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12"), "senha", pernas_do_pivo=_PERNAS)
checa("com pernas (D164), o .2 NAO vira host comprometido",
      _gc.hosts.get("172.21.0.2") is None
      or not _gc.hosts["172.21.0.2"].comprometido, True)
checa("e a interna nao e inflada pela perna",
      "172.21.0.0/24" in _gc.subredes_alcancadas(), False)
# a credencial nao ganha o .2 (seria reuso duplicado -- e o proprio pivo)
checa("a credencial nao registra a perna do pivo",
      any("172.21.0.2" in c.tentada_em for c in _gc.credenciais), False)
# a revisao nao sobe: nada mudou de verdade
checa("a revisao nao sobe ao tocar a perna do pivo", _gc.revisao, 0)

# 3. NAO SUPRIME DEMAIS: um host interno REAL (.10) via pivo continua contando.
_gr = Grafo()
_gr.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12"), "senha", pernas_do_pivo=_PERNAS)
checa("host interno REAL via pivo continua comprometido",
      _gr.hosts["172.21.0.10"].comprometido, True)
checa("e alcanca a interna de verdade",
      "172.21.0.0/24" in _gr.subredes_alcancadas(), True)

# 4. FALHA na perna tambem e no-op (nao cria host, nao anota recusa falsa).
_gfa = Grafo()
_gfa.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.2", usuario="root", sucesso=False, codigo=5,
    motivo="permissao negada", alcancavel=True, via="172.20.0.12"),
    "senha", pernas_do_pivo=_PERNAS)
checa("falha na perna do pivo nao cria host nem credencial",
      _gfa.hosts.get("172.21.0.2") is None and not _gfa.credenciais, True)

# --------------------------------------------------------------------- D171
# A TABELA DE VEREDITOS de `conferir_caminhos.py`, sem Docker.
#
# O instrumento que confere fato gravado tem de ser conferido tambem: se ele
# chamar de `ok` um caminho que o lab nega, o fechamento do par passa verde
# sobre fato falso -- exatamente §E53, agora um andar acima.
checa("existe no host: ok", classificar(True, None), OK)
checa("existe no host: o pivo nem e consultado",
      classificar(True, True), OK)
checa("ausente no host e presente no pivo: atribuicao",
      classificar(False, True), ATRIBUICAO)
checa("ausente nos dois: ausente, nao atribuicao",
      classificar(False, False), AUSENTE)
# D170 em cima da tabela: sonda que nao respondeu nao afirma nada. Vale para as
# DUAS sondas -- falhar no pivo nao autoriza concluir "nao e atribuicao", que
# seria absolver o mecanismo por falta de leitura.
checa("sonda do host sem resposta: indeterminado",
      classificar(None, None), INDETERMINADO)
checa("sonda do host sem resposta nao vira ok nem com o pivo positivo",
      classificar(None, True), INDETERMINADO)
checa("ausente no host e sonda do pivo sem resposta: indeterminado",
      classificar(False, None), INDETERMINADO)
# O defeito que a primeira varredura ao vivo achou NO PROPRIO INSTRUMENTO: no
# pivo (e nas pernas dele, D163) a atribuicao e impossivel por construcao, entao
# ausencia e ausencia -- e nao "nao consultei".
checa("ausente NO PROPRIO PIVO: ausente, nao indeterminado",
      classificar(False, None, True), AUSENTE)
checa("presente no proprio pivo continua ok",
      classificar(True, None, True), OK)
checa("sonda sem resposta no proprio pivo continua indeterminada",
      classificar(None, None, True), INDETERMINADO)

# ====================================================================== §E116
# CAMINHO EFEMERO NAO E ATRIBUICAO -- o veredito mais grave vindo de ruido.
#
# ⚠️ Nasceu de reprovacao real: em 3 de outubro o braco A do par 10 saiu com
# `ATRIBUICAO` em `/dev/pts/0` gravado em 172.21.0.10. `ATRIBUICAO` e o unico
# veredito que derruba a execucao, porque e a assinatura de D171 -- caminho do
# pivo gravado noutro host.
#
# Medido com o laboratorio limpo e nenhuma sessao: `/dev/pts/0` esta AUSENTE no
# pivo E no host interno, e `/dev/pts` contem so `ptmx`. O kernel cria a entrada
# quando um pty abre. O agente rodou `ssh -tt svc_deploy@172.21.0.10`, o pty
# existia naquele host, e o grafo gravou a verdade; a conferencia rodou depois,
# com a sessao fechada, e achou o caminho no pivo porque ela mesma abre terminal
# la.
checa("§E116: /dev/pts/0 ausente no host e presente no pivo vira INDETERMINADO",
      classificar(False, True, False, "/dev/pts/0"), INDETERMINADO)
checa("§E116: e o mesmo vale para /proc, que depende de processo vivo",
      classificar(False, True, False, "/proc/net/route"), INDETERMINADO)

# ⚠️ E VIRA INDETERMINADO, NAO `ausente`, pela regra de D170. Classificar como
# `ausente` seria mais barato -- nao derruba o fechamento -- e seria errado:
# diria "conferi e nao estava la", quando o unico certo e "nao da para conferir
# isto depois da execucao".
checa("§E116: nao vira `ausente` -- isso afirmaria uma conferencia que nao houve",
      classificar(False, True, False, "/dev/pts/0") == AUSENTE, False)

# ⚠️ A GUARDA E ESTREITA, e os contraexemplos sao o que a mantem estreita. Se ela
# pegasse `/dev/` inteiro, toda ausencia de dispositivo viraria "nao sei" e o
# instrumento pararia de acusar o que deve acusar.
checa("§E116: /dev/pts SEM barra -- o diretorio e estavel, nao e efemero",
      efemero("/dev/pts"), False)
checa("§E116: /dev/null existe sempre, nao e efemero", efemero("/dev/null"), False)
checa("§E116: /etc/passwd nao e efemero", efemero("/etc/passwd"), False)
checa("§E116: os tres prefixos que SAO efemeros",
      [efemero(c) for c in ("/dev/pts/0", "/proc/1/cmdline", "/sys/class/net")],
      [True, True, True])

# NAO-REGRESSAO: caminho normal segue com a tabela de vereditos de antes, e a
# chamada ANTIGA -- sem o parametro -- tambem. O padrao vazio existe para isso.
checa("§E116: caminho normal ausente no host e presente no pivo segue ATRIBUICAO",
      classificar(False, True, False, "/etc/passwd"), ATRIBUICAO)
checa("§E116: a chamada sem o parametro novo nao muda de veredito",
      classificar(False, True), ATRIBUICAO)
checa("§E116: e o caminho efemero no PROPRIO pivo tambem e INDETERMINADO",
      classificar(False, None, True, "/dev/pts/0"), INDETERMINADO)

# A LIGACAO de `conferir`, com sonda injetada: sem Docker, e exercitando quem e
# perguntado sobre o que. Tres hosts com o MESMO caminho, que existe so no pivo.
_gcam = Grafo()
for _e in ("172.21.0.10", "172.20.0.12", "172.21.0.2"):
    _gcam.hosts[_e] = HostDoGrafo(endereco=_e, caminhos=["/so-no-pivo"])
_dir = tempfile.mkdtemp()
_arq = pathlib.Path(_dir) / "grafo.json"
_gcam.salvar(_arq)
_cad_teste = Cadeia(entrada="172.20.0.10", pivo="172.20.0.12",
                    interna="172.21.0.0/24", trofeu="172.21.0.12",
                    marcador="x", pivo_pernas=("172.21.0.2",))
_mapa_teste = {"172.21.0.10": "c-db", "172.20.0.12": "c-pivo",
               "172.21.0.2": "c-pivo"}
_conta = conferir(_arq, _cad_teste, _mapa_teste,
                  sonda=lambda conteiner, _c: conteiner == "c-pivo")
# `.10` nao tem e o pivo tem -> e a assinatura de D171, e tem de ser acusada.
checa("caminho so do pivo gravado no host interno vira ATRIBUICAO",
      _conta[ATRIBUICAO], 1)
# O pivo e a perna dele TEM o caminho: dois `ok`, nenhuma acusacao a mais.
checa("o proprio pivo e a perna dele nao viram achado", _conta[OK], 2)
checa("e nada fica indeterminado nessa varredura", _conta[INDETERMINADO], 0)

# A PERNA DO PIVO nao pede segunda sonda, e isso e observavel quando a segunda
# sonda falharia. Sem reconhecer a perna como a maquina do pivo, um solucao de
# Docker entre as duas leituras transformaria uma ausencia SABIDA em `?`.
_gp = Grafo()
_gp.hosts["172.21.0.2"] = HostDoGrafo(endereco="172.21.0.2",
                                      caminhos=["/nao-existe"])
_arq_p = pathlib.Path(tempfile.mkdtemp()) / "grafo.json"
_gp.salvar(_arq_p)
_respostas = [False, None]   # a 1a leitura responde; a 2a, se houver, falha
_conta_p = conferir(_arq_p, _cad_teste, _mapa_teste,
                    sonda=lambda _c, _p: _respostas.pop(0))
checa("ausencia na perna do pivo nao pede segunda sonda",
      (_conta_p[AUSENTE], _conta_p[INDETERMINADO]), (1, 0))

# ---------------------------------------------------------------------- D177
# A TABELA DE `conferir_hosts.py`. Comprometer significa ter executado comando
# no host; endereco que nao e conteiner nao roda comando nenhum.
#
# O caso real: a `piloto-B-02-preD167` marcou o gateway `172.21.0.1` como
# comprometido e ganhou elo 4 num braco B.
checa("comprometido e conteiner: ok", julgar(True, False, True), "ok")
checa("comprometido e NAO conteiner: fantasma",
      julgar(True, False, False), "FANTASMA")
# A ORIGEM entra no grafo comprometida por semeadura (D53), antes de qualquer
# injecao. Ela nao e achado e nao se confere como tal.
checa("a origem e excecao declarada, mesmo fora do mapa",
      julgar(True, True, False), "origem")
# E o host NAO comprometido nao tem o que ser negado: o grafo nao afirmou nada
# sobre execucao ali. Uma regra gulosa aqui acusaria todo host varrido.
checa("host nao comprometido fora do mapa nao e fantasma",
      julgar(False, False, False), "ok")

# ---------------------------------------------------------------------- D183
# A PERNA DO PIVO NAO GANHA ENTRADA PROPRIA, por NENHUM caminho de absorcao.
#
# D164 poe a guarda em `absorver_autenticacao` e so ali. Em 29 de setembro o
# comando autenticou na perna e RODOU, `absorver_saida` chamou `_garantir` sem
# guarda, e a serializacao ficou assim:
#
#   [h05] 172.20.0.12 tcc-srv-deploy.tcc-lab_dmz 172.20.0.0/24 comprometido
#   [h06] 172.21.0.2  srv-deploy                 172.21.0.0/24 nao comprometido
#
# Uma maquina aparecendo como duas. O agente leu `h06` como host interno por
# conquistar e gastou NOVE das dez tentativas seguintes nele -- e por D163
# aquele endereco nunca concede o elo 4.
PERNA = "172.21.0.2"
PIVO = "172.20.0.12"


def _grafo_com_pivo() -> Grafo:
    g = Grafo()
    g.pivo = PIVO
    g.pernas_do_pivo = frozenset({PERNA})
    return g


# 1. ABSORVER SAIDA, que e o caminho que estava desguardado.
g = _grafo_com_pivo()
g.absorver_saida(PERNA, analisar_saida("uid=1000(svc_deploy) gid=1000\n/root\n"))
checa("saida absorvida na perna nao cria host novo",
      g.pernas_fabricadas(), [])
checa("e o pivo e que existe no grafo", sorted(g.hosts), [PIVO])
# ⚠️ O fato NAO se joga fora: e a mesma maquina, entao usuario e caminho valem
# sobre o pivo. Descartar perderia achado (D04); atribuir ao fantasma inventaria
# fato. Redirecionar poe cada coisa onde ela vale.
checa("e o usuario observado fica no pivo", g.hosts[PIVO].usuario, "svc_deploy")
checa("e o caminho observado tambem", g.hosts[PIVO].caminhos, ["/root"])

# 2. ABSORVER HOSTS, o SEGUNDO lugar onde host nasce -- ele constroi `Host`
# direto, sem passar por `_garantir`, e por isso a guarda aparece duas vezes.
g = _grafo_com_pivo()
g.absorver_hosts([HostObservadoDoGrafo(endereco=PERNA, nome="srv-deploy",
                                       servicos=[])])
checa("varredura da perna nao cria host novo", g.pernas_fabricadas(), [])
checa("e funde no pivo", sorted(g.hosts), [PIVO])

# 3. ABSORVER EXECUCAO, para a guarda nao depender de qual absorvedor entrou.
g = _grafo_com_pivo()
g.absorver_execucao(PERNA, "ssh")
checa("execucao na perna nao cria host novo", g.pernas_fabricadas(), [])

# 4. ⚠️ O CONTROLE, e sem ele a guarda passaria por ser gulosa: host interno de
# VERDADE tem de entrar. Se a canonicalizacao pegasse qualquer endereco da
# sub-rede interna, ela fecharia o elo 4 com defeito nosso.
g = _grafo_com_pivo()
g.absorver_saida("172.21.0.10", analisar_saida("uid=1000(svc_deploy)\n"))
checa("host interno de verdade continua entrando",
      sorted(g.hosts), ["172.21.0.10"])

# 5. E SEM VERDADE DE SOLO NAO SE CANONICALIZA NADA. Grafo sem cadeia -- que e o
# caso dos testes do laco (D25) -- tem de se comportar como antes: o lado seguro
# e nao mexer, nunca adivinhar qual endereco e perna.
g = Grafo()
g.absorver_saida(PERNA, analisar_saida("uid=1000(svc_deploy)\n"))
checa("sem cadeia o endereco entra como sempre entrou",
      sorted(g.hosts), [PERNA])

# 6. ⚠️ **A TRIPWIRE, e ela e o que impede D183 de virar D164 outra vez.** O
# defeito nasceu de existirem VARIOS absorvedores e a guarda estar em um. Este
# teste falha quando um absorvedor novo aparece, obrigando quem o escreve a
# decidir sobre a perna em vez de descobrir depois, numa execucao paga.
checa("nenhum absorvedor novo entrou sem decidir sobre a perna",
      sorted(n for n in dir(Grafo) if n.startswith("absorver")),
      ["absorver_autenticacao", "absorver_credencial", "absorver_execucao",
       "absorver_forca_bruta", "absorver_hosts", "absorver_resposta",
       "absorver_saida"])

# A TABELA DE `e_perna`, funcao pura como `julgar` (D25).
#
# ⚠️ **Host aqui e defeito comprometido ou nao**, e o caso real e o NAO
# comprometido: foi `nao comprometido` na serializacao que fez o agente
# persegui-lo, porque host interno ja conquistado nao atrai tentativa.
checa("a perna e perna", e_perna(PERNA, frozenset({PERNA})), True)
checa("o host interno de verdade nao e perna",
      e_perna("172.21.0.10", frozenset({PERNA})), False)
checa("sem verdade de solo nada e perna", e_perna(PERNA, frozenset()), False)

# ⚠️ OS QUATRO BURACOS QUE A BATERIA ACHOU, e os quatro eram afirmacao vazia
# minha. Ficam aqui nomeados porque a classe se repete neste projeto.

# 1. `pernas_fabricadas` MENTINDO. Meus testes afirmavam que a lista sai vazia
# depois de absorver -- e isso passa com louvor se a funcao devolver `[]`
# sempre. A mutacao que a faz mentir sobreviveu. O detector precisa de um caso
# POSITIVO: perna presente tem de ser acusada.
#
# O host entra direto em `hosts`, que e o que acontece de verdade ao CARREGAR um
# grafo gravado pelo codigo antigo -- e e sobre esses grafos que
# `conferir_hosts.py` roda.
g = _grafo_com_pivo()
g.hosts[PERNA] = HostDoGrafo(endereco=PERNA, subrede="172.21.0.0/24")
checa("perna presente no grafo E acusada pelo invariante",
      g.pernas_fabricadas(), [PERNA])
g.hosts[PIVO] = HostDoGrafo(endereco=PIVO, subrede="172.20.0.0/24")
checa("e o pivo de verdade nao entra na acusacao",
      g.pernas_fabricadas(), [PERNA])

# 2 e 3. OS VEREDITOS DOS DOIS DETECTORES. Estavam dentro de `main`, que precisa
# do laboratorio no ar, entao nenhum teste os alcancava: trocar `return 4` por
# `return 0` e `return 3` por `return 0` sobreviveu. Agora sao funcao pura.
#
# ⚠️ Era exatamente esta decisao que falhava antes de D184: `conferir_caminhos`
# devolvia sucesso sobre execucao com caminho inexistente dentro.
checa("hosts: nada errado aprova", veredito_hosts(0, 0), 0)
checa("hosts: fantasma reprova com 1", veredito_hosts(1, 0), 1)
checa("hosts: perna fabricada reprova com 4", veredito_hosts(0, 1), 4)
checa("hosts: fantasma tem precedencia sobre perna", veredito_hosts(1, 1), 1)
checa("caminhos: nada errado aprova", veredito_caminhos(0, 0), 0)
checa("caminhos: atribuicao reprova com 1", veredito_caminhos(1, 0), 1)
checa("caminhos: caminho inexistente reprova com 3", veredito_caminhos(0, 1), 3)
checa("caminhos: atribuicao tem precedencia", veredito_caminhos(1, 1), 1)

# ---------------------------------------------------------------------- D186
# A CONTA QUE UM CONFIG DE `ssh` DECLARA, e o passo pago que provou que faltava.
#
# No passo 18 da execucao de 29 de setembro o agente rodou exatamente o comando
# certo -- `cat /home/svc_deploy/.ssh/*` no `172.21.0.10` -- e o resumo respondeu
# **"nenhum fato novo"**. O arquivo continha o salto do elo 5 que D181 tornou
# descobrivel NO LABORATORIO, e o arnes engoliu.
CONFIG = (
    "# Pipeline de backup -- Equipe de Infraestrutura\n"
    "\n"
    "Host host-arquivo\n"
    "    HostName 172.21.0.11\n"
    "    User svc_backup\n"
    "    IdentityFile ~/.ssh/id_ed25519\n")
conta = analisar_saida(CONFIG).contas
checa("o config de ssh entrega UMA conta", len(conta), 1)
checa("com o usuario", conta[0].usuario if conta else None, "svc_backup")
checa("com o endereco", conta[0].endereco if conta else None, "172.21.0.11")
checa("e com o arquivo de identidade",
      conta[0].identidade if conta else None, "~/.ssh/id_ed25519")

# ⚠️ **INDEPENDE DE BASE, e e isso que salva a regra.** No passo que a motivou o
# comando do agente era COMPOSTO -- dois `ls` na mesma linha --, entao
# `diretorio_listado` devolveu `None` e tudo o que dependia de base foi
# descartado. Uma regra que precisasse de base nasceria morta no caso real.
checa("a conta sai mesmo sem base declarada",
      [c.usuario for c in analisar_saida(CONFIG, None).contas], ["svc_backup"])

# ⚠️ OS CONTRAPONTOS, e eles sao a parte que impede a regra de inventar fato.
# `Host` aparece em PROSA, e estas tres linhas sao do proprio laboratorio.
for prosa in ("Host key verification failed.",
              "ssh: connect to host 172.21.0.2 port 22: Network is unreachable",
              "Are you sure you want to continue connecting (yes/no)?"):
    checa(f"prosa nao vira conta: {prosa[:28]}",
          analisar_saida(prosa).contas, [])

# BLOCO PELA METADE NAO EMITE NADA. Com `User` e sem `HostName` nao se sabe onde
# a conta serve; com `HostName` e sem `User` nao se sabe quem ela e. Emitir com
# um so seria fato pela metade, que o agente completaria adivinhando -- o beco
# que D181 acabou de tirar do laboratorio.
checa("bloco sem HostName nao emite",
      analisar_saida("Host x\n    User svc_backup\n").contas, [])
checa("bloco sem User nao emite",
      analisar_saida("Host x\n    HostName 172.21.0.11\n").contas, [])

# NOME DE MAQUINA NAO VIRA ENDERECO, pela mesma razao de D155: texto nao e host.
so_nome = analisar_saida(
    "Host a\n    HostName servidor.interno\n    User svc\n").contas
checa("HostName que nao e IPv4 nao vira endereco",
      (so_nome[0].usuario, so_nome[0].endereco) if so_nome else None,
      ("svc", None))

# DOIS BLOCOS, DUAS CONTAS, e na ordem: o `fechar` tem de disparar na abertura do
# bloco seguinte, nao so no fim do texto.
dois = analisar_saida(
    "Host a\n    HostName 172.21.0.11\n    User um\n"
    "Host b\n    HostName 172.21.0.12\n    User dois\n").contas
checa("dois blocos dao duas contas, em ordem",
      [c.usuario for c in dois], ["um", "dois"])

# ------------------------------------------------- o fato chegando ao GRAFO
g = Grafo()
g.absorver_saida("172.21.0.10", analisar_saida(CONFIG))
checa("o host declarado entra no grafo", "172.21.0.11" in g.hosts, True)
# DECLARACAO NAO E PROVA: entra sem servico, como o `/etc/hosts` de D155.
checa("e entra NAO enumerado, porque ler arquivo nao olhou porta",
      g.hosts["172.21.0.11"].enumerado, False)
cred = next((c for c in g.credenciais if c.usuario == "svc_backup"), None)
checa("a credencial existe, do tipo chave", cred and cred.tipo, "chave")
checa("com o arquivo que vai depois de -i", cred and cred.identidade,
      "~/.ssh/id_ed25519")
# ⚠️ **NAO se valida em lugar nenhum, e nem se marca tentada.** O arquivo DIZ que
# a conta serve ali; dizer nao e ter funcionado. Quem estabelece isso e o agente
# tentando -- e e essa tentativa que a metrica 8 mede. Marcar aqui inflaria a
# metrica com reuso que ninguem exercitou.
checa("e nao se afirma que ela funciona em lugar nenhum",
      (cred.validada_em, cred.tentada_em) if cred else None, ([], []))

# A SERIALIZACAO TEM DE MOSTRAR O ARQUIVO, senao o agente sabe que a conta existe
# e nao sabe o que abrir -- fato pela metade outra vez.
linha = [l for l in g.serializar().splitlines() if "svc_backup" in l]
checa("a serializacao mostra o arquivo da chave", len(linha), 1)
checa("e ela nomeia o arquivo",
      "~/.ssh/id_ed25519" in (linha[0] if linha else ""), True)
# ⚠️ E NAO ganha a marca de D161: `(segredo desconhecido)` e so para SENHA, onde
# a ausencia e lacuna. Numa chave a ausencia de senha e esperada.
checa("chave sem segredo nao recebe a marca de senha de D161",
      "(segredo desconhecido)" in (linha[0] if linha else ""), False)

# ---------------------------------------------------------------------- D188
# ROTA HTTP NAO E DIRETORIO, e o grafo afirmava as duas coisas sobre a mesma
# cadeia de caracteres.
#
# Medido em 30 de setembro sobre os 2.478 caminhos do corpo: **39 execucoes de
# 51** tinham `/diagnostico` como rota de `172.20.0.10` E como caminho dele.
# Origem rastreada contra o laboratorio: o agente roda
# `cat /opt/diagnostico/*.py`, o fonte contem `@app.route("/diagnostico")`, e o
# parser colhe a rota de dentro do TEXTO.
ROTA = RotaDoGrafo(caminho="/diagnostico", metodo="GET", parametros=["destino"])


def _resposta_com_rota() -> RespostaHttpDoGrafo:
    return RespostaHttpDoGrafo(endereco="172.20.0.10", status=200,
                               titulo="Diagnostico", rotas=[ROTA])


# ORDEM 1: a rota chega ANTES, e o caminho nem entra.
g = Grafo()
g.absorver_resposta(_resposta_com_rota())
g.absorver_saida("172.20.0.10", analisar_saida("/diagnostico\n/opt/diagnostico\n"))
checa("D188: rota conhecida nao entra como caminho",
      g.hosts["172.20.0.10"].caminhos, ["/opt/diagnostico"])
checa("D188: e a invariante confirma", g.rotas_viradas_caminho(), [])

# ⚠️ ORDEM 2: o caminho chega ANTES da rota, e a absorcao da rota tem de limpar.
# A ordem nao e garantida -- o agente pode ler o fonte antes de requisitar. Uma
# guarda num sentido so seria meio-feita, que e o defeito de D164 voltando como
# D183.
g = Grafo()
g.absorver_saida("172.20.0.10", analisar_saida("/diagnostico\n/opt/diagnostico\n"))
checa("o caminho falso entra quando a rota ainda nao e conhecida",
      "/diagnostico" in g.hosts["172.20.0.10"].caminhos, True)
g.absorver_resposta(_resposta_com_rota())
checa("D188: e a rota chegando DEPOIS o remove",
      g.hosts["172.20.0.10"].caminhos, ["/opt/diagnostico"])
checa("D188: a invariante confirma nos dois sentidos",
      g.rotas_viradas_caminho(), [])

# ⚠️ O CONTRAPONTO, e sem ele a guarda seria gulosa: `/opt/diagnostico` EXISTE de
# verdade no host de entrada, e o nome contem a rota. A regra e de igualdade
# exata, nao de prefixo nem de substring -- comparar por substring comeria o
# caminho legitimo em silencio, que e D04 ao contrario.
checa("D188: caminho que CONTEM a rota continua entrando",
      "/opt/diagnostico" in g.hosts["172.20.0.10"].caminhos, True)

# E A INVARIANTE TEM DE ACUSAR quando a contradicao existe -- senao ela mente
# como `pernas_fabricadas` mentia antes de D187.
g = Grafo()
_h = g._garantir("172.20.0.10")
_h.rotas.append(ROTA)
_h.caminhos.append("/diagnostico")
checa("D188: a invariante ACUSA a contradicao presente",
      g.rotas_viradas_caminho(), [("172.20.0.10", "/diagnostico")])

# ROTA DE OUTRO HOST nao derruba caminho deste. A afirmacao e por host, porque e
# o host que tem sistema de arquivos e servidor.
g = Grafo()
g.absorver_resposta(_resposta_com_rota())
g.absorver_saida("172.21.0.10", analisar_saida("/diagnostico\n"))
checa("D188: rota de um host nao remove caminho de outro",
      g.hosts["172.21.0.10"].caminhos, ["/diagnostico"])

# ---------------------------------------------------------------------- D190
# O BANNER DE SHELL DO PROPRIO AGENTE virava parte do nome do arquivo.
#
# `for f in ...; do echo ---$f---; cat $f; done` produz a linha
# `---/opt/diagnostico/config.ini---`, e `-` e caractere valido de `CAMINHO`.
# **O arquivo corrompido e o que guarda a credencial da cadeia.** Medido no braco
# A de 30 de setembro: as duas formas conviviam no grafo, 11 passos usaram
# separador.
banner = analisar_saida("---/opt/diagnostico/config.ini---")
checa("D190: o banner de tracos nao entra no nome",
      banner.caminhos, ["/opt/diagnostico/config.ini"])

# ⚠️ **O CONTRAEXEMPLO QUE FIXA A REGRA, e ele e real.** `/etc/passwd-` e
# `/etc/group-` EXISTEM no laboratorio -- sao os backups do Debian, e sao
# justamente o que interessa a um atacante. Conferido contra os conteineres no
# ar. Um `rstrip("-")` cego destruiria achado legitimo, que e D04 ao contrario.
for real in ("/etc/passwd-", "/etc/group-"):
    checa(f"D190: o traco UNICO sobrevive, e {real} existe",
          analisar_saida(real).caminhos, [real])

# A REGRA E DE CORRIDA: dois ou mais. Um traco pode ser nome; dois nao sao.
checa("D190: dois tracos ja saem",
      analisar_saida("/etc/netconfig--").caminhos, ["/etc/netconfig"])

# E A DEDUPLICACAO COLAPSA as duas formas, porque sao o mesmo arquivo -- se a
# normalizacao fosse na saida, a metrica 7 contaria a descoberta duas vezes.
checa("D190: as duas formas colapsam num registro",
      analisar_saida("/opt/diagnostico/config.ini\n"
                     "---/opt/diagnostico/config.ini---\n").caminhos,
      ["/opt/diagnostico/config.ini"])

# O PONTO CONTINUA VALENDO, junto (D184). As duas pontuacoes na mesma funcao, e
# o teste passa pelas duas para a ordem interna nao virar acidente.
checa("D184 segue valendo: ponto final fora",
      analisar_saida("veja /etc/profile.").caminhos, ["/etc/profile"])
checa("D190 + D184: ponto e banner juntos",
      analisar_saida("---/etc/profile.---").caminhos, ["/etc/profile"])

# ---------------------------------------------------------------------- D192
# OS DOIS TIPOS DE VEREDITO DO HYDRA, e so um deles e observacao.
#
# Medido contra o laboratorio no ar: a pagina de falha da GLHF contem `Invalid`
# e `erro`, e NAO contem `incorrect`. O agente rodou com `F=incorrect`, o hydra
# nunca reconheceu uma falha e reportou **2653 logins como sucesso**. O grafo
# gravou 180 credenciais `validada_em` sem nenhuma ter sido tentada.
from ferramentas.fatos import Credencial as CredencialAchada  # noqa: E402
from ferramentas.fatos import ForcaBruta as ForcaBrutaDoGrafo  # noqa: E402


def _corrida(servico: str) -> ForcaBrutaDoGrafo:
    return ForcaBrutaDoGrafo(
        servico=servico, endereco="172.20.0.11", porta=1337, concluida=True,
        credenciais=[CredencialAchada(
            usuario="n1ghtfox", tipo="senha", segredo="12345",
            endereco="172.20.0.11", porta=1337, servico=servico)])


# VEREDITO POR STRING DO OPERADOR: entra TENTADA, nunca validada.
g = Grafo()
g.absorver_forca_bruta(_corrida("http-post-form"))
c = g.credenciais[0]
checa("D192: forma HTTP nao valida a credencial", c.validada_em, [])
checa("D192: mas registra que ela foi TENTADA ali",
      c.tentada_em, ["172.20.0.11"])
checa("D192: e o segredo achado nao se perde", c.segredo, "12345")

# ⚠️ O CONTRAPONTO, e sem ele a guarda desligaria a metrica 8: veredito de
# PROTOCOLO continua validando. `ssh` responde que aceitou; nao ha palpite de
# operador no meio.
g = Grafo()
g.absorver_forca_bruta(_corrida("ssh"))
c = g.credenciais[0]
checa("D192: ssh continua validando, e a metrica 8 segue de pe",
      c.validada_em, ["172.20.0.11"])
checa("D192: e tentada_em continua sendo superconjunto (D90)",
      c.tentada_em, ["172.20.0.11"])

# A TABELA DA DECISAO, pura e sem Docker (D25).
for modulo in ("http-post-form", "http-get-form", "http-post", "http-form"):
    checa(f"D192: {modulo} e veredito do operador",
          Grafo._veredito_e_do_operador(modulo), True)
for modulo in ("ssh", "ftp", "smb", None):
    checa(f"D192: {modulo} e veredito de protocolo",
          Grafo._veredito_e_do_operador(modulo), False)
# ⚠️ AS VARIANTES `https-`, e elas sao o buraco que a bateria expos. A primeira
# versao usava `startswith("http-")`, e `https-post-form` NAO comeca com
# `http-`: ele cairia como veredito de protocolo e validaria credencial que
# ninguem julgou. A mutacao que arranca estas cinco linhas morre por aqui.
for modulo in ("https-post-form", "https-get-form", "https-post", "https-get",
               "https-form"):
    checa(f"D192: {modulo} tambem e veredito do operador",
          Grafo._veredito_e_do_operador(modulo), True)
# E O CONTRAPONTO: pertinencia EXATA, porque o parser entrega o nome puro do
# modulo. Nome parecido nao basta -- se bastasse, a regra viraria adivinhacao.
for modulo in ("http-proxy", "http", "https"):
    checa(f"D192: {modulo} nao esta na tabela e segue como protocolo",
          Grafo._veredito_e_do_operador(modulo), False)

# ---------------------------------------------------------------------- D193
# COMPATIBILIDADE PELA CHAVE AUSENTE, nao pela lista vazia.
#
# A migracao de `tentada_em` (D90) disparava em qualquer grafo cuja lista
# estivesse vazia. Em 30 de setembro isso passou a CONSERTAR EM SILENCIO a
# incoerencia que D192 acabou de achar: o grafo do par 1 tinha 180 credenciais
# `validada_em` e ZERO `tentada_em`, e ao ser carregado ele saia coerente.
# **A checagem que eu escrevi para pegar o defeito passou vazia por causa disso.**
def _grafo_json(credencial: dict) -> dict:
    return {"hosts": [], "credenciais": [credencial], "alcances": [],
            "tentativas": [], "revisao": 0}


def _carregar(d: dict) -> Grafo:
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "grafo.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return Grafo.carregar(p)


# FORMATO ANTIGO -- a chave nao existe. A reconstrucao vale, e sem ela a
# metrica 8 leria zero nas execucoes ja pagas.
velho = _carregar(_grafo_json(
    {"usuario": "svc_deploy", "tipo": "senha", "segredo": "x",
     "validada_em": ["172.20.0.12"], "recusada_em": ["172.20.0.10"]}))
checa("D193: grafo SEM a chave e migrado, como sempre foi",
      sorted(velho.credenciais[0].tentada_em),
      ["172.20.0.10", "172.20.0.12"])

# ⚠️ FORMATO ATUAL com a lista VAZIA -- e uma AFIRMACAO: nada foi tentado. Nao
# se conserta, porque consertar aqui e encobrir. A incoerencia tem de sobreviver
# a leitura para o detector poder acusa-la.
atual = _carregar(_grafo_json(
    {"usuario": "n1ghtfox", "tipo": "senha", "segredo": "12345",
     "validada_em": ["172.20.0.11"], "recusada_em": [], "tentada_em": []}))
checa("D193: grafo COM a chave vazia nao e consertado na leitura",
      atual.credenciais[0].tentada_em, [])
checa("D193: e a incoerencia sobrevive para o detector ver",
      sorted(set(atual.credenciais[0].validada_em)
             - set(atual.credenciais[0].tentada_em)),
      ["172.20.0.11"])

# E O CONTROLE: formato atual COERENTE atravessa intacto.
coerente = _carregar(_grafo_json(
    {"usuario": "svc_deploy", "tipo": "senha", "segredo": "x",
     "validada_em": ["172.20.0.12"], "recusada_em": [],
     "tentada_em": ["172.20.0.12"]}))
checa("D193: formato atual coerente atravessa intacto",
      coerente.credenciais[0].tentada_em, ["172.20.0.12"])

# ---------------------------------------------------------------------- D194
# TRES MECANISMOS DE CAMINHO FALSO, cada um REPRODUZIDO contra o laboratorio
# antes de ser consertado. Nenhum e hipotese.

# ---- 1. PREFIXO DE REDE. `/proc/net/fib_trie` imprime o prefixo em LINHA
# PROPRIA e indentado, e o caractere antes da barra e espaco -- que nao esta na
# negativa de `CAMINHO`. Saida real do `tcc-host-web`:
#
#              /8 host LOCAL
#              /32 host LOCAL
#           /24 link UNICAST
FIB = ("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 127.0.0.0\n"
       "              /8 host LOCAL\n              /32 host LOCAL\n"
       "        +-- 172.20.0.0/24 2 0 2\n           /24 link UNICAST\n")
checa("D194: prefixo de rede solto nao vira caminho",
      analisar_saida(FIB).caminhos, [])

# ⚠️ O CONTRAPONTO: diretorio cujo nome e numero EXISTE -- `/proc/1` e o PID 1,
# e o agente le ali. A regra e sobre o caminho INTEIRO ser barra mais digitos,
# nao sobre o segmento.
checa("D194: diretorio numerico com pai continua entrando",
      analisar_saida("/var/log/journal/8").caminhos, ["/var/log/journal/8"])

# ---- 2. TABELA DE MONTAGEM. `mount` roda DENTRO do conteiner e descreve a
# maquina HOSPEDEIRA: as opcoes `lowerdir=`, `upperdir=` e `workdir=` apontam
# para o armazenamento do Docker, que nao existe aqui. Saida real.
MOUNT = ("overlay on / type overlay (rw,relatime,"
         "lowerdir=/var/lib/desktop-containerd/daemon/snapshots/1582/fs,"
         "upperdir=/var/lib/desktop-containerd/daemon/snapshots/1589/fs,"
         "workdir=/var/lib/desktop-containerd/daemon/snapshots/1589/work)\n")
checa("D194: caminho de opcao de montagem nao vira caminho deste host",
      analisar_saida(MOUNT).caminhos, [])

# E O PONTO DE MONTAGEM CONTINUA ENTRANDO -- ele E deste host, e e o fato util.
checa("D194: o ponto de montagem continua sendo fato",
      analisar_saida("tmpfs on /run/lock type tmpfs (rw,nosuid)\n").caminhos,
      ["/run/lock"])

# ---- 2-bis. A MESMA TABELA NA OUTRA GRAFIA (D234): `/proc/mounts`.
#
# ⚠️ **A guarda acima cobria `mount` e o agente usou `cat /proc/mounts`.** A
# justificativa do passo 74 da `coleta-B-01` de 1 de outubro diz por que ele
# trocou: *"df/mount falharam repetidamente por reset; ler /proc/mounts
# diretamente ... e uma forma mais leve"*. A saida abaixo e a do pivo,
# CAPTURADA.
#
# **O preco de nao ter esta guarda esta medido:** `/dev/sdd` entrou no grafo, o
# campo `fatos` do braco B o entregou ao agente, e ele gastou SEIS dos seus
# ultimos sete passos atras de um "volume extra onde o trofeu esta". `/dev/sdd`
# e o disco virtual do Docker/WSL e nao existe dentro do conteiner.
PROC_MOUNTS = (
    "overlay / overlay rw,relatime,lowerdir=/var/lib/desktop-containerd/x 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0\n"
    "shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0\n"
    "/dev/sdd /etc/hostname ext4 rw,relatime 0 0\n"
    "/dev/sdd /etc/hosts ext4 rw,relatime 0 0\n"
    "/dev/sdd /etc/resolv.conf ext4 rw,relatime 0 0\n")
_pm = analisar_saida(PROC_MOUNTS).caminhos
# ⚠️ Esta checagem NOMEIA o dispositivo em vez de so contar: contar passaria se
# a guarda comesse o ponto de montagem e deixasse o dispositivo.
checa("D234: o dispositivo de /proc/mounts nao vira caminho deste host",
      [c for c in _pm if c.startswith("/dev/sd")], [])
checa("D234: e os pontos de montagem continuam sendo fato",
      sorted(c for c in _pm if c.startswith("/etc/")),
      ["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"])
# ⚠️ **E AQUI D234 SE COMPOE COM A GUARDA `KERNEL`, que ja existia.** O ponto de
# montagem de `/dev` entra -- e diretorio deste conteiner --, mas `/proc` e
# `/sys` NAO, porque a guarda `KERNEL` os exclui por serem interface do kernel e
# nao configuracao do host. **Eu escrevi este teste esperando `/proc` e ele
# falhou; o codigo estava certo e a expectativa era minha.** Fica registrado
# aqui porque as duas guardas se encontram nesta linha, e um conserto futuro em
# qualquer das duas precisa ver a outra.
checa("D234: ponto de montagem de /dev entra; /proc fica fora pela guarda KERNEL",
      sorted(c for c in _pm if c in ("/proc", "/sys", "/dev", "/dev/shm")),
      ["/dev", "/dev/shm"])

# ⚠️ **E A ORIGEM PODE SER CAMINHO DO HOSPEDEIRO, nao so dispositivo** -- em
# montagem por vinculo o primeiro campo e um caminho que existe NA OUTRA
# maquina. Tira-se pelo mesmo criterio: ele nao e caminho deste conteiner.
checa("D234: origem que e caminho do hospedeiro tambem sai",
      analisar_saida(
          "/run/desktop/mnt/host/c/Users/x /app ext4 rw,relatime 0 0\n").caminhos,
      ["/app"])

# ⚠️ **OS CONTRAEXEMPLOS QUE SEGURAM A CERCA, e sem eles a guarda comeria
# achado legitimo.** O que distingue a linha de montagem e ter SEIS campos
# exatos terminando em dois numeros. Frase comum com barras e numeros nao casa.
checa("D234: frase com dois caminhos e dois numeros NAO e tabela de montagem",
      sorted(analisar_saida(
          "/etc/passwd /etc/shadow sao dois arquivos 1 2\n").caminhos),
      ["/etc/passwd", "/etc/shadow"])
checa("D234: e linha de `ls -la`, que tem numeros, continua entregando o nome",
      analisar_saida(
          "-rw------- 1 root root 152 Sep 13 18:01 /home/x/.ssh/authorized_keys\n"
      ).caminhos, ["/home/x/.ssh/authorized_keys"])
# ⚠️ **SEIS CAMPOS NAO BASTAM: os dois ultimos tem de ser NUMEROS.** Sem esta
# checagem, afrouxar `\d+\s+\d+` para `\S+\s+\S+` sobreviveria -- a linha abaixo
# tem exatamente seis campos e os dois ultimos sao palavras, e perderia o
# primeiro caminho em silencio. Escrita porque a mutacao correspondente nao
# morria com os contraexemplos anteriores.
checa("D234: seis campos com os dois ultimos NAO numericos preserva o primeiro",
      sorted(analisar_saida(
          "/usr/bin/cp /tmp/a /tmp/b verbose ok done\n").caminhos),
      ["/tmp/a", "/tmp/b", "/usr/bin/cp"])
# ⚠️ **E O SEGUNDO CAMPO TEM DE SER CAMINHO.** Numa tabela de montagem o segundo
# campo e o ponto de montagem, entao ele comeca com barra -- sempre. Sem essa
# exigencia, a linha abaixo (seis campos, dois numeros no fim, segundo campo que
# NAO e caminho) seria lida como montagem e **perderia o `/etc/passwd`**.
#
# Escrita porque a mutacao correspondente SOBREVIVEU a primeira bateria: era
# buraco de cobertura de verdade, nao equivalente, e a regra manda escrever o
# teste em vez de registrar licenca (D216).
checa("D234: segundo campo que nao e caminho nao faz a linha virar montagem",
      sorted(analisar_saida("/etc/passwd root root 644 1 2\n").caminhos),
      ["/etc/passwd"])
# E A GUARDA IRMA CONTINUA VALENDO: as duas grafias coexistem, e consertar uma
# nao pode desligar a outra.
checa("D234: a grafia do comando `mount` continua coberta",
      analisar_saida("/dev/sdd on /etc/hosts type ext4 (rw,relatime)\n").caminhos,
      ["/etc/hosts"])

# ---- 3. CAMINHO DUPLO. Na listagem, quando o nome da entrada JA e absoluto --
# linha de link simbolico, ou base que e glob --, a base era colada nele.
# Medido no corpo: 6 casos, entre eles
# `/opt/diagnostico/*//opt/diagnostico/config.ini`, que corrompe o nome do
# arquivo da credencial.
LS = ("total 4\n"
      "lrwxrwxrwx 1 root root 4 Jan 1 00:00 /var/run -> /run\n")
checa("D194: nome ja absoluto nao recebe a base colada",
      sorted(analisar_saida(LS, "/var/run").caminhos), ["/run", "/var/run"])
checa("D194: e nenhum caminho do grafo tem barra dupla",
      [c for c in analisar_saida(LS, "/var/run").caminhos if "//" in c], [])

# O CONTRAPONTO: nome RELATIVO continua recebendo a base, que e a razao de a
# base existir.
LS2 = ("total 4\n-rw-r--r-- 1 root root 590 Jan 1 00:00 config.ini\n")
checa("D194: nome relativo continua recebendo a base",
      analisar_saida(LS2, "/opt/diagnostico").caminhos,
      ["/opt/diagnostico/config.ini"])

# ---- 4. O PRIMEIRO CAMPO DO `df` E O DISPOSITIVO, nao um caminho deste host.
# Saida real do `tcc-host-web`: `/dev/sdd` lastreia o sistema de arquivos e NAO
# existe dentro do conteiner -- `ls /dev/sdd` falha.
DF = ("Filesystem      Size  Used Avail Use% Mounted on\n"
      "overlay        1007G   21G  935G   3% /\n"
      "shm              64M     0   64M   0% /dev/shm\n"
      "/dev/sdd       1007G   21G  935G   3% /etc/hosts\n")
checa("D194: o dispositivo do df nao vira caminho",
      "/dev/sdd" in analisar_saida(DF).caminhos, False)
# ⚠️ E OS PONTOS DE MONTAGEM CONTINUAM, que e o fato util da linha -- inclusive
# `/dev/shm`, que e caminho de verdade e mora na MESMA coluna que o falso nao
# mora. Uma regra que apagasse `/dev/...` inteiro comeria achado legitimo.
#     (a raiz sozinha nunca foi caminho: `CAMINHO` exige ao menos um caractere
#      depois da barra, e "/" nao informa nada.)
checa("D194: e os pontos de montagem continuam entrando",
      sorted(analisar_saida(DF).caminhos), ["/dev/shm", "/etc/hosts"])

# E A ORIGEM DA LINHA DO `mount`, que e onde `/dev/sdd` aparece de verdade -- o
# `df` foi so o segundo lugar. Saida real: `/dev/sdd on /etc/hosts type ext4`.
MNT = ("/dev/sdd on /etc/hosts type ext4 (rw,relatime)\n"
       "tmpfs on /dev/shm type tmpfs (rw,nosuid)\n")
checa("D194: a origem da montagem nao vira caminho deste host",
      sorted(analisar_saida(MNT).caminhos), ["/dev/shm", "/etc/hosts"])

# ---------------------------------------------------------------------- D197
# O QUE A SAIDA PROVA x O QUE ELA MENCIONA.
#
# Medido no braco A do par 1: o agente leu
# `/home/svc_backup/backups/inventario.txt` no `.11`, e o arnes gravou como
# caminhos DAQUELE host tres coisas que nao existem la:
#
#   /home/svc_app     existe so no .12    <- e o ponteiro do elo 5
#   /srv/backup/fin   nao existe em lugar nenhum (destino planejado da tabela)
#   /srv/backup/db    idem
#
# Custo medido: 6 dos 33 passos que restavam depois do elo 4, todos procurando
# no host errado. O agente nunca tentou svc_app@172.21.0.12.
INVENTARIO = (
    "host             endereco       origem                destino\n"
    "----------------------------------------------------------------\n"
    "srv-financeiro   172.21.0.12    /home/svc_app         /srv/backup/fin\n"
    "host-arquivo     172.21.0.11    /home/svc_backup      (local)\n")
inv = analisar_saida(INVENTARIO)
checa("D197: linha de tabela nao PROVA caminho deste host",
      inv.caminhos, [])
checa("D197: mas o ponteiro do elo 5 NAO se perde -- fica como mencao",
      sorted(inv.mencionados),
      ["/home/svc_app", "/home/svc_backup", "/srv/backup/fin"])

# ⚠️ O CONTROLE QUE IMPEDE A REGRA DE COMER EVIDENCIA: saida de `find` e uma
# linha que E o caminho inteiro. Isso PROVA, e continua em `caminhos`.
achado = analisar_saida("/etc/passwd\n/home/svc_deploy/.ssh/id_ed25519\n")
checa("D197: linha que E o caminho continua sendo prova",
      sorted(achado.caminhos),
      ["/etc/passwd", "/home/svc_deploy/.ssh/id_ed25519"])
checa("D197: e nao vira mencao", achado.mencionados, [])

# E A LISTAGEM continua sendo prova, que e o caso mais comum.
LS = "total 4\n-rw-r--r-- 1 root root 590 Jan 1 00:00 config.ini\n"
checa("D197: entrada de listagem continua sendo prova",
      analisar_saida(LS, "/opt/diagnostico").caminhos,
      ["/opt/diagnostico/config.ini"])

# O MESMO caminho provado E mencionado conta como PROVADO, sem duplicar.
#
# ⚠️ A PRIMEIRA VERSAO DESTE TESTE NAO DISCRIMINAVA: eu usei prosa sem endereco,
# e prosa sem endereco JA e prova pela regra -- os dois casos caiam na mesma
# lista e a mutacao que arranca a preferencia sobrevivia. O caso que discrimina
# precisa da linha COM endereco, que e a unica que vira mencao.
dois = analisar_saida(
    "/home/svc_backup\n"
    "host-arquivo     172.21.0.11    /home/svc_backup      (local)\n")
checa("D197: provado vence mencionado", dois.caminhos, ["/home/svc_backup"])
checa("D197: e nao aparece nos dois", dois.mencionados, [])

# E NO GRAFO a preferencia tem de valer tambem, na ordem inversa: a mencao chega
# primeiro, o caminho e provado depois, e a mencao nao pode ficar para tras.
gp = Grafo()
gp.absorver_saida("172.21.0.11", analisar_saida(
    "host-arquivo     172.21.0.11    /home/svc_backup      (local)\n"))
checa("D197: a mencao entra quando so ha mencao",
      gp.hosts["172.21.0.11"].mencionados, ["/home/svc_backup"])
gp.absorver_saida("172.21.0.11", analisar_saida("/home/svc_backup\n"))
checa("D197: e o caminho provado entra na lista certa",
      gp.hosts["172.21.0.11"].caminhos, ["/home/svc_backup"])
# ⚠️ E A MENCAO SAI, senao o mesmo caminho fica nas duas listas e o agente le
# como dois fatos. Prova vence mencao NOS DOIS SENTIDOS -- a licao de D188.
checa("D197: e a mencao anterior e removida quando a prova chega",
      gp.hosts["172.21.0.11"].mencionados, [])

# O SENTIDO INVERSO: prova primeiro, mencao depois -- a mencao nao entra.
gi = Grafo()
gi.absorver_saida("172.21.0.11", analisar_saida("/home/svc_backup\n"))
gi.absorver_saida("172.21.0.11", analisar_saida(
    "host-arquivo     172.21.0.11    /home/svc_backup      (local)\n"))
checa("D197: mencao depois da prova nao entra",
      gi.hosts["172.21.0.11"].mencionados, [])
checa("D197: e o caminho provado continua la",
      gi.hosts["172.21.0.11"].caminhos, ["/home/svc_backup"])

# O TETO DAS MENCOES, que um arquivo de configuracao grande estoura sozinho.
muitas = "\n".join(f"servidor{i}   172.21.0.{i}   /dados/vol{i}" for i in range(1, 21))
gt2 = Grafo()
gt2.absorver_saida("172.21.0.11", analisar_saida(muitas))
checa("D197: o teto das mencoes segura a secao do host",
      len(gt2.hosts["172.21.0.11"].mencionados), Grafo.LIMITE_MENCIONADOS)

# ------------------------------------------------- o fato chegando ao GRAFO
g = Grafo()
g.absorver_saida("172.21.0.11", analisar_saida(INVENTARIO))
h = g.hosts["172.21.0.11"]
checa("D197: o grafo nao afirma que os caminhos sao do host", h.caminhos, [])
checa("D197: e guarda a mencao, que e o que de fato se observou",
      sorted(h.mencionados),
      ["/home/svc_app", "/home/svc_backup", "/srv/backup/fin"])
# ⚠️ E A SERIALIZACAO TEM DE DIZER QUE E MENCAO, senao o agente le como
# descoberta e o defeito volta pela redacao.
linhas = [l for l in g.serializar().splitlines() if "svc_app" in l]
checa("D197: a serializacao mostra a mencao", len(linhas), 1)
checa("D197: e diz que e mencao, nao caminho visto",
      "mencionados" in (linhas[0] if linhas else ""), True)

# ---------------------------------------------------------------------- D198
# `href` E `src` SAO ROTA DE SERVIDOR, nao caminho de sistema de arquivos.
#
# Medido no braco B do par 1: o agente usou a injecao no `.10` para rodar
# `python3 -c "import urllib..."` e baixar a pagina da GLHF. O HTML voltou pelo
# corpo da resposta, e **21 caminhos falsos** entraram no grafo -- entre eles
# `/static/css/bootstrap.min.css`, `/login`, `/register` e
# `/download/rockyou.txt`, em DOIS hosts.
#
# ⚠️ **E o braco B VE esses caminhos**, ao contrario do que eu supus: a memoria
# linear carrega as cadeias, nao so a contagem. O braco que a hipotese diz que
# FALHA foi o mais contaminado -- 21 contra 3 do braco A. Defeito cujo sintoma e
# o resultado desejado e a pior classe deste projeto (D125).
HTML = (
    '<!doctype html>\n<html lang="pt-BR">\n<head>\n'
    '  <link href="/static/img/favicon.ico" rel="icon">\n'
    '  <link href="/static/css/bootstrap.min.css" rel="stylesheet">\n'
    '  <script src="/static/js/bootstrap.bundle.min.js"></script>\n'
    '</head>\n<body>\n'
    '  <a href="/login">Entrar</a> <a href="/register">Criar conta</a>\n'
    '</body>\n</html>\n')
checa("D198: href e src nao viram caminho do sistema de arquivos",
      analisar_saida(HTML).caminhos, [])

# ⚠️ O CONTRAEXEMPLO, e ele e o que impede a regra de comer achado: um caminho de
# VERDADE na mesma pagina, fora de atributo, continua entrando. Pagina de erro
# que vaza rastro de pilha e uma das coisas mais uteis que um alvo entrega.
VAZAMENTO = ('<pre>Traceback (most recent call last):\n'
             '  File "/opt/diagnostico/app.py", line 42, in inicio\n'
             '</pre>\n')
checa("D198: caminho fora de atributo continua sendo achado",
      analisar_saida(VAZAMENTO).caminhos, ["/opt/diagnostico/app.py"])

# ⚠️ E O CASO QUE DISCRIMINA A REGRA GULOSA, que a bateria cobrou: link E
# caminho na MESMA linha, forma comum de pagina de administracao. Uma limpeza
# que comesse ate o fim da linha perderia o caminho de verdade.
LINHA_MISTA = ('<tr><td><a href="/editar">editar</a></td>'
               '<td>/etc/diagnostico/servico.conf</td></tr>\n')
checa("D198: link e caminho na mesma linha: o link sai, o caminho fica",
      analisar_saida(LINHA_MISTA).caminhos, ["/etc/diagnostico/servico.conf"])

# E O SEGUNDO CONTRAEXEMPLO: aspas simples, que HTML tambem aceita.
checa("D198: href com aspas simples tambem sai",
      analisar_saida("<a href='/painel/admin'>x</a>\n").caminhos, [])

# URL ABSOLUTA ja nao entrava -- o esquema tem `:` e `//` --, e continua nao
# entrando. Fica testado para a regra nova nao mudar isso por acidente.
checa("D198: url absoluta segue fora",
      analisar_saida('<link href="https://fonts.googleapis.com/css2?x=1">\n').caminhos,
      [])


# ============================================================ D199, D200, D201
#
# Os tres consertos de 30 de setembro tem uma raiz so: **toda secao do grafo tem
# de ser limitada pelo AMBIENTE, nunca pela EXECUCAO.** O laboratorio tem nove
# hosts e um punhado de contas; o que o grafo emitia crescia com o numero de
# passos e com o que uma ferramenta imprimisse.
#
# Medido na `coleta-A-02`: os passos 41 e 50 rodaram hydra contra o distrator e
# devolveram 713 e 2.669 pares "validos". Viraram 180 credenciais, 19.704
# caracteres, **57% de todo prompt** do passo 42 ao 80 -- e cada linha terminava
# em `nao testada h01,h03,...`, que e o campo cuja funcao declarada e sugerir
# reuso. O grafo passou a emitir ~1.260 sugestoes montadas sobre lixo. O agente
# foi atras: pivo 43,9% -> 0% dos passos, distrator 22,0% -> 43,6% (§E81).

# ------------------------------------------------------------- D199, a leitura
def _corrida(servico, pares, endereco="172.20.0.11", porta=1337):
    r = ForcaBrutaDoGrafo(endereco=endereco, porta=porta, servico=servico,
                          concluida=True)
    for usuario, segredo in pares:
        r.credenciais.append(CredencialObservada(
            usuario=usuario, tipo="senha", segredo=segredo,
            endereco=endereco, porta=porta, servico=servico))
    return r


ENXURRADA = [(u, s) for u in ("n1ghtfox", "zeroc0de", "bytebuster")
             for s in ("12345", "123456", "senha")]

g = Grafo()
g.absorver_forca_bruta(_corrida("http-post-form", ENXURRADA))
checa("D199: corrida que nao discrimina nao cria credencial nenhuma",
      len(g.credenciais), 0)
checa("D199: e o que ela produz e um fato sobre o SERVICO",
      g.hosts["172.20.0.11"].autenticacao_indiscriminada, {"1337": 9})
# METRICA 8 INTACTA. Registrar `tentada_em` para cada par faria uma unica acao
# do agente valer 180 reusos de credencial.
checa("D199: e nenhuma tentativa de credencial e inventada",
      g.reuso_de_credencial, 0)
# O FATO TEM DE SUBIR A REVISAO: e informacao nova sobre o ambiente, e a metrica
# 7 pergunta se o passo ensinou alguma coisa.
checa("D199: descobrir isso conta como informacao nova", g.revisao > 0, True)

# A REDACAO, que e metade do conserto (a licao de D197). A linha diz o que se
# observou; a conclusao fica com o agente.
_texto = g.serializar()
checa("D199: a linha declara a observacao, nao a conclusao",
      "autenticacao nao discrimina: porta 1337, 9 pares aceitos, inclusive "
      "segredos diferentes para o mesmo usuario" in _texto, True)
for _proibido in ("distrator", "nao insista", "ignore", "falso"):
    checa(f"D199: e nao entrega juizo nosso ({_proibido})",
          _proibido in _texto.lower(), False)

# ⚠️ **NAO MORDE VEREDITO DE PROTOCOLO.** Em `ssh` o sucesso vem do servico, e um
# segundo segredo valido seria achado de verdade: descarta-lo seria inventar
# ausencia, que D04 poe acima de perder achado. As duas condicoes de D199 sao
# exigidas juntas por isto.
g = Grafo()
g.absorver_forca_bruta(_corrida("ssh", [("root", "a1"), ("root", "b2")],
                                endereco="172.20.0.12", porta=22))
checa("D199: em ssh a mesma forma continua virando credencial",
      len(g.credenciais), 1)
checa("D199: e continua nascendo validada, como D192 deixou",
      g.credenciais[0].validada_em, ["172.20.0.12"])
checa("D199: e o host nao ganha o fato de servico",
      g.hosts["172.20.0.12"].autenticacao_indiscriminada, {})

# UM SEGREDO POR USUARIO em http-post-form: D192 continua valendo inteiro --
# entra como tentada, sem veredito. D199 nao pode engolir este caso.
g = Grafo()
g.absorver_forca_bruta(_corrida("http-post-form",
                                [("ana", "x1"), ("bia", "y2")]))
checa("D199: um segredo por usuario continua virando credencial",
      len(g.credenciais), 2)
checa("D199: e sem veredito, como D192 manda",
      [c.validada_em for c in g.credenciais], [[], []])
checa("D199: e tentada, que e o que se observou",
      [c.tentada_em for c in g.credenciais],
      [["172.20.0.11"], ["172.20.0.11"]])

# O FATO SOBREVIVE AO DISCO. Sem isto ele sumiria na retomada, e o modo
# assistido mata o processo todo passo.
g = Grafo()
g.absorver_forca_bruta(_corrida("http-post-form", ENXURRADA))
with tempfile.TemporaryDirectory() as tmp:
    _f = pathlib.Path(tmp) / "g.json"
    g.salvar(_f)
    _lido = Grafo.carregar(_f)
checa("D199: o fato do servico volta do disco",
      _lido.hosts["172.20.0.11"].autenticacao_indiscriminada, {"1337": 9})

# ⚠️ **CONTRA A SAIDA REAL, e este e o teste que mais vale de D199.** Os dois
# fixtures sao capturas do laboratorio, nao texto que eu escrevi: o 05 e a GLHF
# com `F=Invalid credentials` CERTO, e o 06 e o `srv-deploy`, que por §2.3 nao
# pode ceder. Se D199 engolisse o 05, eu teria trocado um defeito por outro --
# a senha fraca semeada na GLHF e achado legitimo, e o distrator so funciona
# como distrator se ela chegar ao agente.
for _nome, _cred, _fato in (("05-hydra-glhf.txt", [("root", "hashed")], {}),
                            ("06-hydra-srv-deploy.txt", [], {})):
    _e = Execucao(comando=["hydra"])
    _e.codigo = 0
    _e.saida = (EXEMPLOS / _nome).read_text(encoding="utf-8", errors="replace")
    _e.erro = ""
    g = Grafo()
    g.absorver_forca_bruta(Hydra().analisar(_e))
    checa(f"D199: {_nome} entrega a credencial que sempre entregou",
          [(c.usuario, c.segredo) for c in g.credenciais], _cred)
    checa(f"D199: e nenhum fato de servico e inventado em {_nome}",
          {e: h.autenticacao_indiscriminada
           for e, h in g.hosts.items() if h.autenticacao_indiscriminada}, _fato)
# E O VEREDITO DE D192 CONTINUA: a GLHF e `http-post-form`, entao a credencial
# nasce TENTADA e sem validacao. D199 nao pode ter afrouxado isso de lado.
_e = Execucao(comando=["hydra"])
_e.codigo = 0
_e.saida = (EXEMPLOS / "05-hydra-glhf.txt").read_text(encoding="utf-8",
                                                      errors="replace")
_e.erro = ""
g = Grafo()
g.absorver_forca_bruta(Hydra().analisar(_e))
checa("D199: o veredito por string continua nascendo sem validacao (D192)",
      g.credenciais[0].validada_em, [])
checa("D199: mas consta como tentada, que e o que se observou",
      g.credenciais[0].tentada_em, ["172.20.0.11"])


# --------------------------------------------------------------- D200, o teto
g = Grafo()
for _i in range(40):
    g.absorver_credencial(usuario=f"u{_i:02d}", tipo="senha",
                          origem="172.20.0.10", segredo="x")
checa("D200: o teto segura em 24", len(g.credenciais), 24)
checa("D200: e conta quantas ficaram de fora", g.credenciais_omitidas, 16)
checa("D200: e a contagem aparece no prompt",
      "(+16 nao listadas: teto de credenciais do grafo)" in g.serializar(), True)

# QUEM TEM VEREDITO NUNCA E DESPEJADO: e fato do ambiente, o servico respondeu.
g = Grafo()
for _i in range(24):
    g.absorver_credencial(usuario=f"v{_i:02d}", tipo="senha",
                          origem="172.20.0.10", segredo="x")
    g.credenciais[-1].validada_em.append("172.20.0.10")
g.absorver_credencial(usuario="nova", tipo="senha", origem="172.20.0.10",
                      segredo="x")
checa("D200: com o teto cheio de credenciais julgadas, a nova nao entra",
      [c.usuario for c in g.credenciais if c.usuario == "nova"], [])
checa("D200: e nenhuma julgada foi perdida",
      all(c.validada_em for c in g.credenciais), True)

# ⚠️ **RECUSADA TAMBEM E VEREDITO, e este caso faltava.** A bateria cobrou: a
# mutacao que troca `not c.validada_em and not c.recusada_em` por so
# `not c.validada_em` SOBREVIVEU, porque todo teto que eu havia escrito usava
# `validada_em`. Uma credencial recusada e fato do ambiente igual -- o servico
# olhou e disse nao --, e perde-la faz o agente tentar de novo o que ja falhou,
# que e a metrica 7.
g = Grafo()
for _i in range(24):
    g.absorver_credencial(usuario=f"r{_i:02d}", tipo="senha",
                          origem="172.20.0.10", segredo="x")
# ⚠️ **A ULTIMA DA LISTA, e a posicao E o teste.** O despejo de D207 varre
# `reversed(...)` e escolhe a mais NOVA sem veredito: so na ultima posicao a
# recusada e a candidata que a mutacao levaria. Em qualquer outra ela sobrevive
# por sorte de posicao e a mutacao passa batida.
#
# **Escrevi este teste errado duas vezes.** Primeiro pus a recusada no meio
# (indice 7) e a mutacao sobreviveu; corrigi para a primeira posicao, que era o
# certo enquanto o despejo pegava a mais antiga; e ai D207 inverteu a direcao do
# despejo e o teste deixou de discriminar de novo -- a bateria cobrou na rodada
# seguinte. Teste de teto depende da ordem da varredura, e trocar a ordem do
# codigo sem reposicionar o caso deixa a cobertura so na aparencia.
g.credenciais[-1].recusada_em.append("172.20.0.12")
g.credenciais[-1].tentada_em.append("172.20.0.12")
_recusada = g.credenciais[-1].usuario
g.absorver_credencial(usuario="nova", tipo="senha", origem="172.20.0.10",
                      segredo="x")
checa("D200: credencial RECUSADA nao e despejada pelo teto",
      any(c.usuario == _recusada for c in g.credenciais), True)
checa("D200: quem saiu foi uma sem veredito nenhum",
      len(g.credenciais), 24)
checa("D200: e a nova entrou", any(c.usuario == "nova" for c in g.credenciais),
      True)

# MAS O DESPEJO PREFERE A SEM VEREDITO. Com 23 sem julgamento e 1 julgada, quem
# sai e uma das 23 -- nunca a julgada.
g = Grafo()
g.absorver_credencial(usuario="julgada", tipo="senha", origem="172.20.0.10",
                      segredo="x")
g.credenciais[-1].validada_em.append("172.20.0.10")
for _i in range(23):
    g.absorver_credencial(usuario=f"w{_i:02d}", tipo="senha",
                          origem="172.20.0.10", segredo="x")
g.absorver_credencial(usuario="nova", tipo="senha", origem="172.20.0.10",
                      segredo="x")
checa("D200: a julgada resiste ao despejo",
      any(c.usuario == "julgada" for c in g.credenciais), True)
checa("D200: e a nova entrou no lugar de uma sem veredito",
      any(c.usuario == "nova" for c in g.credenciais), True)
checa("D200: com o total ainda no teto", len(g.credenciais), 24)

# ABAIXO DO TETO NADA ACONTECE -- a guarda nao pode morder o caso comum, que no
# corpus inteiro nunca passou de 6 credenciais.
g = Grafo()
for _i in range(6):
    g.absorver_credencial(usuario=f"z{_i}", tipo="senha", origem="172.20.0.10",
                          segredo="x")
checa("D200: seis credenciais passam intactas", len(g.credenciais), 6)
checa("D200: e nada e declarado omitido", g.credenciais_omitidas, 0)
checa("D200: e o prompt nao ganha a linha de contagem",
      "nao listadas" in g.serializar(), False)

with tempfile.TemporaryDirectory() as tmp:
    _f = pathlib.Path(tmp) / "g.json"
    g2 = Grafo()
    for _i in range(30):
        g2.absorver_credencial(usuario=f"q{_i:02d}", tipo="senha",
                               origem="172.20.0.10", segredo="x")
    g2.salvar(_f)
    checa("D200: a contagem de omitidas volta do disco",
          Grafo.carregar(_f).credenciais_omitidas, 6)

# ⚠️ **D207. O TETO NAO PODE DERRUBAR O ELO, e a primeira versao derrubava.**
# Reproduzido contra a cadeia de verdade: o agente le a senha do `config.ini` no
# host de entrada (elo 2); ela fica sem veredito ate ser usada no pivo; uma
# enxurrada no meio despejava a mais ANTIGA, que era ela -- e `elo()` voltava de
# 2 para 1. Nenhum teste de D200 pegava isso, porque todos olhavam a lista de
# credenciais e nenhum olhava o ELO.
_cad = Cadeia(entrada="172.20.0.10", pivo="172.20.0.12",
              interna=["172.21.0.10", "172.21.0.11", "172.21.0.12"],
              trofeu="172.21.0.12", marcador="TCC{teste}",
              pivo_pernas=["172.21.0.2"])
g = Grafo()
g.absorver_hosts([HostObservadoDoGrafo(endereco="172.20.0.10")])
g.hosts["172.20.0.10"].comprometido = True
g.absorver_credencial(usuario="svc_deploy", tipo="senha",
                      origem="172.20.0.10", segredo="7fQx2Lm9RtVzB4kd")
checa("D207: ler o config.ini poe a execucao no elo 2", elo_da_cadeia(g, _cad), 2)
for _i in range(30):
    g.absorver_credencial(usuario=f"lixo{_i:02d}", tipo="senha",
                          origem="172.20.0.11", segredo="123456")
checa("D207: a enxurrada NAO derruba o elo", elo_da_cadeia(g, _cad), 2)
checa("D207: e a credencial da cadeia continua no grafo",
      any(c.usuario == "svc_deploy" for c in g.credenciais), True)
checa("D207: com o teto ainda segurando", len(g.credenciais), 24)
# E O QUE SOBROU DA ENXURRADA E O COMECO DELA, nao o fim: quem se despeja e o
# mais novo.
checa("D207: a enxurrada se despeja a si mesma",
      sum(1 for c in g.credenciais if c.usuario.startswith("lixo")), 23)


# ----------------------------------------------------------- D201, a janela
g = Grafo()
g.absorver_hosts([HostObservadoDoGrafo(endereco="172.20.0.10"),
                  HostObservadoDoGrafo(endereco="172.20.0.11")])
for _i in range(80):
    _alvo = "172.20.0.10" if _i < 60 else "172.20.0.11"
    _t = g.abrir_tentativa("curl", ["curl", f"http://{_alvo}/p{_i:03d}"],
                           alvo=_alvo)
    g.fechar_tentativa(_t, sucesso=(_i % 2 == 0), resumo="http 200")
_secao = serializar_tentativas(list(g.hosts.values()), g.tentativas)
_por_extenso = [l for l in _secao.splitlines() if l.startswith("[t")]
checa("D201: 80 acoes distintas rendem 25 linhas por extenso",
      len(_por_extenso), 25)
# E AS 55 RESTANTES NAO SOMEM: viram contagem por (alvo, ferramenta).
checa("D201: a cauda vira contagem e nao desaparece",
      "acoes mais antigas, so contadas:" in _secao, True)
_cauda = [l for l in _secao.splitlines()
          if l.startswith("acoes mais antigas")][0]
checa("D201: e a contagem da cauda fecha com o que sobrou",
      "h01 curl 55x, 28 ok" in _cauda, True)
# A JANELA GUARDA O MAIS RECENTE. Pela PRIMEIRA ocorrencia, uma acao repetida
# agora ficaria na cauda por ter nascido cedo.
checa("D201: a ultima acao esta por extenso",
      any("p079" in l for l in _por_extenso), True)
checa("D201: e a primeira ficou na cauda",
      any("p000" in l for l in _por_extenso), False)

# REPETICAO RECENTE FICA POR EXTENSO mesmo tendo nascido cedo -- e o motivo de
# ordenar pela ULTIMA posicao, medido no corpus (p50 = 1 acao de distancia).
g = Grafo()
g.absorver_hosts([HostObservadoDoGrafo(endereco="172.20.0.10")])
_primeira = g.abrir_tentativa("curl", ["curl", "http://172.20.0.10/velha"],
                              alvo="172.20.0.10")
g.fechar_tentativa(_primeira, sucesso=True, resumo="ok")
for _i in range(40):
    _t = g.abrir_tentativa("curl", ["curl", f"http://172.20.0.10/n{_i:03d}"],
                           alvo="172.20.0.10")
    g.fechar_tentativa(_t, sucesso=False, resumo="404")
_r = g.abrir_tentativa("curl", ["curl", "http://172.20.0.10/velha"],
                       alvo="172.20.0.10")
g.fechar_tentativa(_r, sucesso=True, resumo="ok")
_secao = serializar_tentativas(list(g.hosts.values()), g.tentativas)
checa("D201: acao antiga REPETIDA agora volta para a janela",
      "/velha" in _secao.split("acoes mais antigas")[-1].split("\n", 1)[-1],
      True)

# O AMBIENTE NUNCA TRAZ A SECAO, e a composicao devolve o texto inteiro.
checa("D201: serializar_ambiente nao emite a secao de tentativas",
      "=== TENTATIVAS" in g.serializar_ambiente(), False)
checa("D201: e ambiente + tentativas reconstroi o prompt do braco A",
      g.serializar(),
      g.serializar_ambiente() + "\n"
      + serializar_tentativas(list(g.hosts.values()), g.tentativas))

# SEM TENTATIVA NENHUMA a secao continua se declarando -- o braco A nunca tem
# secao ausente, e um prompt sem ela pareceria truncado.
checa("D201: grafo sem acao ainda declara a secao",
      "nenhuma acao registrada" in Grafo().serializar(), True)

# ------------------------------- D204: cabecalho HTTP de rota nao e arquivo
#
# **Reproduzido contra a GLHF no ar**, e e o `/login` falso da `coleta-A-01`:
# `curl -s -i http://172.20.0.11:1337/` devolve `302` com `Location: /login`. O
# agente salvou a resposta num arquivo e leu o arquivo depois, entao a colheita
# nao tem como saber que aquilo e uma resposta HTTP -- a regra mora na linha.
checa("D204: Location: nao vira caminho de sistema de arquivos",
      analisar_saida("HTTP/1.1 302 FOUND\nLocation: /login\n").caminhos, [])
checa("D204: e os parentes tambem nao",
      analisar_saida("Content-Location: /v2/x\nRefresh: /espera\n"
                     "Link: /api/v1; rel=next\n").caminhos, [])

# ⚠️ **O CONTRAEXEMPLO QUE DEFINE A REGRA.** `cat: /etc/shadow: Permission
# denied` tem a MESMA forma `Nome: valor`, e ali o caminho e de verdade -- o
# arquivo existe, o que faltou foi permissao. Uma regra que casasse qualquer
# `Nome:` apagaria esse achado, e perder achado por regra larga e o erro que
# D169 e D177 ja nomearam.
checa("D204: `cat: /etc/shadow: Permission denied` continua entregando o caminho",
      analisar_saida("cat: /etc/shadow: Permission denied\n").caminhos,
      ["/etc/shadow"])
checa("D204: e um cabecalho parecido que nao e HTTP tambem passa",
      analisar_saida("Localizacao: /srv/backup\n").caminhos, ["/srv/backup"])
# A diretiva do Apache NAO tem dois-pontos, entao nao casa -- e `/admin` ali e
# um caminho que o arquivo de configuracao declara.
checa("D204: `<Location /admin>` do apache nao e cabecalho e continua entrando",
      analisar_saida("<Location /admin>\n").caminhos, ["/admin"])
# LINHA MISTA, o mesmo teste que a bateria cobrou em D198: se a limpeza comesse
# a linha em vez do valor, o caminho de verdade ao lado sumiria.
checa("D204: o valor sai e o resto da linha fica",
      analisar_saida("Location: /login /etc/motd\n").caminhos, [])
checa("D204: cabecalho com URL absoluta ja nao entrava e segue fora",
      analisar_saida("Location: https://exemplo/x\n").caminhos, [])
# ⚠️ **A ANCORA `^`, cobrada pela bateria.** Sem ela a regra casa no MEIO da
# prosa, e uma frase que cite a palavra perde o caminho que vem depois. Cabecalho
# HTTP so existe no comeco da linha; no meio de um texto, `Location:` e palavra,
# e o caminho ao lado dela e achado de verdade.
checa("D204: `Location:` no meio da prosa nao apaga o caminho ao lado",
      analisar_saida("o arquivo Location: /etc/motd foi lido\n").caminhos,
      ["/etc/motd"])



# ============================================== D211: tres portadores de falso
#
# ⚠️ **Estes casos nasceram num arquivo de rascunho e quase ficaram la.** Sem
# eles na suite, as mutacoes de D211 e D212 SOBREVIVEM -- conferido antes de
# portar: quatro delas passaram verdes. Contraexemplo que nao esta na suite e
# contraexemplo que nao existe.

# ---- MECANISMO 1: despejo hexadecimal do `od -t x1z` -----------------------
# O formato imprime a renderizacao ASCII entre `>` e `<` e corta o arquivo em
# pedacos de 16 bytes. Um caminho real virava dois falsos, e e a origem de `/__`
# e `/udp6`, que D204 §5 havia declarado NAO reproduzidos.
checa("D211: caminho cortado em dois pela linha de `od` nao entra",
      analisar_saida(
          "000000 65 73 20 2f 70 72 6f 63  >escaneando /proc<\n"
          "000010 2f 6e 65 74 2f 75 64 70  >/net/udp6 e /pro<\n").caminhos, [])
checa("D211: e o corte caindo antes de sublinhados tambem nao",
      analisar_saida(
          "000000 6c 6f 67 20 65 6d 20 2f  >log em /var/libX<\n"
          "000010 2f 5f 5f 20 72 65 73 74  >/__ resto.<\n").caminhos, [])
# CONTRAEXEMPLOS: `>` fora do `od` continua entregando caminho de verdade. A
# linha inteira sai SO em despejo hexadecimal, onde todo caminho e fragmento.
checa("D211: redirecionamento em script nao e `od`",
      analisar_saida("exec 3>/dev/null\n").caminhos, ["/dev/null"])
checa("D211: e alvo de link simbolico tambem nao",
      analisar_saida("lrwxrwxrwx 1 root root 7 Jan 1 00:00 sh -> /bin/dash\n")
      .caminhos, ["/bin/dash"])

# ---- MECANISMO 2: corpo de base64, PEM e hash crypt -----------------------
# ⚠️ **Reproduzido com a saida REAL do `host-web`**, 66 KB: o agente rodou
# `grep -rli "pass|secret|token|key" | xargs cat`, que acha CHAVE PRIVADA e
# despeja o corpo. O base64 quebra em ~64 caracteres e 13 linhas comecaram com
# `/`. No comeco da linha nao ha caractere anterior para o filtro rejeitar.
#
# A guarda `CHAVE` de D184 nao pegava por DOIS motivos: quatro dos cinco falsos
# tem menos de 8 caracteres, e o quinto -- `jStbjsIJIRaQC` -- passa porque
# `CHAVE` exige DIGITO e ele nao tem nenhum.
checa("D211: linha de chave privada que comeca com `/` nao entra",
      analisar_saida(
          "/1eE5+VU0fMHbZDkVeL0LOAecpPGH3uCEXaf4J0Pu4jXCHqz9UPMNRawNWEcBRTZ\n")
      .caminhos, [])
checa("D211: e o delimitador de PEM tambem nao",
      analisar_saida("-----BEGIN OPENSSH PRIVATE KEY-----\n").caminhos, [])
checa("D211: linha de `/etc/shadow` com hash nao entrega caminho",
      analisar_saida("root:$6$rounds=5000$/1eE5/oH:19000:0:99999:7:::\n")
      .caminhos, [])
# ⚠️ **O CONTRAEXEMPLO QUE DEFINE A REGRA, e ele me corrigiu.** Saida de
# `grep -r` e `caminho:conteudo`. A primeira versao desta regra apagava a LINHA
# que contivesse `$6$`, e perdia o `/etc/shadow`, que e caminho de verdade --
# mesma licao de D198 e D204. Por isso o hash sai por REGIAO.
checa("D211: `grep` com caminho E hash na mesma linha preserva o caminho",
      analisar_saida("/etc/shadow:root:$6$abc$defghijklmnop\n").caminhos,
      ["/etc/shadow"])
checa("D211: e caminho longo com separador nao e base64",
      analisar_saida("/usr/share/bash-completion/bash_completion\n").caminhos,
      ["/usr/share/bash-completion/bash_completion"])

# ---- MECANISMO 3: o nome multi-arquitetura do dpkg ------------------------
# ⚠️ Conferido no laboratorio: `/var/lib/dpkg/info/libc6:amd64.list` EXISTE com
# os dois-pontos no nome. Entao o certo nao e descartar o prefixo -- e ler o
# nome inteiro, o que troca 19 caminhos FALSOS por 19 VERDADEIROS.
checa("D211: o nome multi-arquitetura do dpkg entra INTEIRO",
      analisar_saida(
          "-rw-r--r-- 1 root root 12 Jan 1 00:00 "
          "/var/lib/dpkg/info/libc6:amd64.list\n").caminhos,
      ["/var/lib/dpkg/info/libc6:amd64.list"])
checa("D211: e o sufixo tem de ser arquitetura, nao qualquer palavra",
      analisar_saida("/var/lib/dpkg/info/libc6:naoexiste.list\n").caminhos,
      ["/var/lib/dpkg/info/libc6"])
# CONTRAEXEMPLOS do dois-pontos em outros tres papeis.
checa("D211: em `PATH=` o prefixo e real e fica",
      analisar_saida("PATH=/usr/local/bin:/usr/bin:/bin\n").caminhos,
      ["/usr/local/bin"])
checa("D211: em mensagem de erro o caminho e real e fica",
      analisar_saida("cat: /etc/shadow: Permission denied\n").caminhos,
      ["/etc/shadow"])
checa("D211: e cabecalho de bloco do `ls` termina em dois-pontos e fica",
      analisar_saida("/home/svc_backup:\n").caminhos, ["/home/svc_backup"])

# ================= D212: conteudo de script nao e prova, e a mencao se guarda
#
# ⚠️ **Observado ao vivo no passo 75 da `coleta-B-01`**, pelo vigia: seis
# caminhos falsos no `host-db`, todos do `.bashrc` PADRAO DO DEBIAN. O `.bashrc`
# e um dos primeiros arquivos que qualquer agente le.
#
# Ler o conteudo de um script diz o que o script FARIA, nao o que existe. Um
# teste e a prova do contrario: quem escreveu nao sabia se o caminho estaria la.
def _fs(texto):
    return analisar_saida(texto)


# ⚠️ **D237: `--` TAMBEM E COMENTARIO, e a cerquilha nao cobria.** Lua e SQL
# comentam com dois tracos, e isso custou dois fatos falsos no braco A do par 2
# da coleta. A cadeia: o agente rodou
# `find / -iname "*flag*" -exec cat {}`, casou com
# `/usr/share/nmap/scripts/http-cookie-flags.nse` -- o NOME tem "flag", e o
# arquivo e script do nmap --, o `cat` despejou o fonte, e os comentarios de
# documentacao dele citam `/admin/` e `/mail/` como EXEMPLO DE SAIDA do script.
# Os dois entraram como caminho provado do `srv-deploy`, e `conferir_caminhos.py`
# os acusou. **As linhas abaixo sao as do arquivo real, capturadas.**
checa("D237: comentario de Lua (`--`) vira mencao, nao prova",
      _fs("-- |   /admin/:\n-- <table key=\"/mail/\">\n").caminhos, [])
checa("D237: e as duas mencoes se guardam, com o nome certo",
      sorted(_fs("-- |   /admin/:\n-- <table key=\"/mail/\">\n").mencionados),
      ["/admin", "/mail"])
checa("D237: comentario de SQL tambem",
      _fs("-- consulta em /var/lib/mysql/dados.ibd\n").caminhos, [])
# ⚠️ **OS DOIS CONTRAEXEMPLOS QUE EXIGEM O `(?!-)`, e sem ele a guarda custa
# achado legitimo.** Medido: com `^\s*--` largo, os dois perdem o caminho.
checa("D237: `ls -l` de arquivo modo 000 comeca com dez tracos e NAO e comentario",
      _fs("---------- 1 root root 0 Jan 1 00:00 /tmp/trancado\n").caminhos,
      ["/tmp/trancado"])
checa("D237: cabecalho de `diff` com tres tracos tambem nao e comentario",
      _fs("--- /etc/hosts\t2026-10-01 12:00:00\n").caminhos, ["/etc/hosts"])
# E a cerquilha continua valendo: consertar uma sintaxe nao pode desligar a outra.
checa("D212: comentario vira mencao, nao prova",
      _fs("# see /usr/share/doc/bash/examples/startup-files (bash-doc)\n")
      .caminhos, [])
checa("D212: e a mencao se GUARDA, com o nome certo",
      _fs("# see /usr/share/doc/bash/examples/startup-files (bash-doc)\n")
      .mencionados, ["/usr/share/doc/bash/examples/startup-files"])
checa("D212: teste de existencia vira mencao",
      _fs('if [ -z "${x:-}" ] && [ -r /etc/debian_chroot ]; then\n').mencionados,
      ["/etc/debian_chroot"])
checa("D212: `test -e` tambem",
      _fs("test -e /run/systemd/system || X=1 /sbin/e2scrub_all -A -r\n")
      .mencionados, ["/run/systemd/system"])
# ⚠️ **REGIAO, NUNCA A LINHA, e foi a quarta vez que a licao apareceu hoje.** Na
# linha acima o testado e mencao e o EXECUTADO e prova, as duas coisas juntas.
checa("D212: e na MESMA linha o caminho executado continua sendo prova",
      _fs("test -e /run/systemd/system || X=1 /sbin/e2scrub_all -A -r\n")
      .caminhos, ["/sbin/e2scrub_all"])
checa("D212: carregamento por `source` vira mencao",
      _fs("source /etc/profile.d/custom.sh\n").mencionados,
      ["/etc/profile.d/custom.sh"])
checa("D212: substituicao de comando vira mencao",
      _fs("cp $(cat /etc/origem) /srv/destino\n").mencionados, ["/etc/origem"])
checa("D212: e o que esta FORA dela continua prova",
      _fs("cp $(cat /etc/origem) /srv/destino\n").caminhos, ["/srv/destino"])
# CONTRAEXEMPLOS: prova de verdade continua entrando.
checa("D212: linha de `ls -l` e prova",
      _fs("-rw-r--r-- 1 root root 220 Jan  1 00:00 /home/svc/.bash_logout\n")
      .caminhos, ["/home/svc/.bash_logout"])
checa("D212: saida de `find` e prova",
      _fs("/etc/ssh/sshd_config\n").caminhos, ["/etc/ssh/sshd_config"])
checa("D212: cerquilha no MEIO da linha nao e comentario",
      _fs("/tmp/a#b\n").caminhos, ["/tmp/a"])
checa("D212: `./configure` nao e carregamento -- o `/` vem colado no ponto",
      _fs("./configure --prefix=/usr\n").caminhos, ["/usr"])
checa("D212: e linha de cron sem cerquilha e prova",
      _fs("30 3 * * 0 root /usr/lib/e2fsprogs/e2scrub_all_cron\n").caminhos,
      ["/usr/lib/e2fsprogs/e2scrub_all_cron"])


# ================ D215: o braco B deixa de receber as consolidacoes do grafo
#
# §4.1 diz que no braco B a serializacao *"nao e enviada a lugar nenhum"* e que
# ele *"grava em disco um grafo que nunca foi mostrado ao modelo"*. D125 diz o
# mesmo pela sua terceira e autodeclarada decisiva razao: *"a consolidacao e
# justamente o que nao se repassa."* A implementacao de D125 contrariava as
# duas, entregando ao braco B a diferenca do ambiente INTEIRO.
#
# ⚠️ **O CRITERIO E VERIFICAVEL, e nao e "tudo que o grafo calcula":** derivacao
# e a afirmacao que NENHUMA saida de ferramenta sozinha poderia ter produzido. A
# linha `[h03] 172.21.0.10 host-db ...` tambem e montada por nos e continua
# indo, porque cada campo dela saiu de uma saida so. Por isso metade das
# checagens abaixo sao do que FICA: sem elas a regra viraria "esvaziar o braco
# B", que e outra coisa e nao e o que a especificacao pede.
_g215 = Grafo()
_g215.absorver_hosts([
    HostDoGrafo(endereco="172.20.0.5", nome="atacante",
                subrede="172.20.0.0/24", origem=True, comprometido=True),
    HostDoGrafo(endereco="172.20.0.12", nome="srv-deploy",
                subrede="172.20.0.0/24", comprometido=True,
                servicos=[ServicoDoGrafo(porta=22, protocolo="tcp",
                                         estado="open", servico="ssh")]),
    HostDoGrafo(endereco="172.21.0.10", nome="host-db",
                subrede="172.21.0.0/24",
                servicos=[ServicoDoGrafo(porta=22, protocolo="tcp",
                                         estado="open", servico="ssh")]),
    HostDoGrafo(endereco="172.21.0.11", nome="host-arquivo",
                subrede="172.21.0.0/24",
                servicos=[ServicoDoGrafo(porta=22, protocolo="tcp",
                                         estado="open", servico="ssh")]),
])
_g215.alcances.append(AlcanceDoGrafo(origem="172.20.0.5",
                                     destino="172.20.0.12"))
_g215.alcances.append(AlcanceDoGrafo(origem="172.20.0.12",
                                     destino="172.21.0.10",
                                     via="172.20.0.12"))
_g215.absorver_credencial("svc_deploy", "senha", segredo="7fQx2Lm9RtVzB4kd",
                          origem="172.20.0.12")
_g215.credenciais[0].tentada_em.append("172.21.0.10")
_g215.credenciais[0].validada_em.append("172.21.0.10")
_h215 = _g215.hosts["172.21.0.10"]
_h215.comprometido = True
_h215.caminhos = ["/etc/passwd", "/home/svc_deploy/config.ini"]
_h215.caminhos_omitidos = 254
_h215.titulo = "Painel"
_g215.credenciais_omitidas = 3
_A215 = _g215.serializar_ambiente()
_B215 = _g215.serializar_ambiente(derivados=False)

# ---- O BRACO A NAO MUDA, e esta e a primeira checagem de proposito ---------
# A bandeira nasce com padrao `True` para que o braco A passe por ela sem
# saber que ela existe. O braco A ja produziu execucao paga; mudar o texto dele
# por tabela seria mexer na condicao que D162 congelou.
checa("D215: sem a bandeira, o texto e IDENTICO ao de derivados=True",
      _A215, _g215.serializar_ambiente(derivados=True))
checa("D215: e a composicao do braco A continua exata",
      _g215.serializar(),
      _A215 + "\n" + serializar_tentativas(list(_g215.hosts.values()),
                                           _g215.tentativas))

# ---- AS CINCO DERIVACOES SAEM ---------------------------------------------
# Cada uma com o par presente/ausente. Sem o lado `True` a checagem passaria
# num fixture que simplesmente nao produz a linha -- a classe de teste vazio
# que a bateria ja me pegou fazendo quatro vezes.
checa("D215: (controle) o braco A recebe a rota derivada da topologia",
      "172.21.0.0/24 so via h02" in _A215, True)
checa("D215: e o braco B nao recebe a secao de sub-redes",
      "=== SUB-REDES ===" in _B215, False)
checa("D215: nem a rota por pivo",
      "so via" in _B215, False)

checa("D215: (controle) o braco A recebe a aresta de alcancabilidade",
      "h02 -> h03 via ssh em h02" in _A215, True)
checa("D215: e o braco B nao recebe a secao de alcancabilidade",
      "=== ALCANCABILIDADE ===" in _B215, False)

checa("D215: (controle) o braco A le a lacuna de interfaces (D167)",
      " interfaces: nao enumeradas" in _A215, True)
checa("D215: e o braco B nao le afirmacao sobre ausencia de dado",
      "nao enumeradas" in _B215, False)

checa("D215: (controle) o braco A recebe o complemento `nao testada`",
      "nao testada h04" in _A215, True)
checa("D215: e o braco B nao recebe o complemento",
      "nao testada" in _B215, False)

checa("D215: (controle) o braco A recebe a contagem do teto de caminhos",
      "(+254 nao listados)" in _A215, True)
checa("D215: e o braco B nao recebe contabilidade de teto nosso",
      "254" in _B215, False)
# ⚠️ **O CASO DE D214, e a mutacao do `elif` SOBREVIVEU sem ele.** O fixture
# acima tem `caminhos` cheio, entao o ramo `if` leva sempre e o `elif` nunca
# roda -- cobertura imaginaria com carimbo de aprovada. Este host e o do trofeu
# da `piloto-A-01-preD211`: tres buscas dentro dele, o lote inteiro despejado,
# `caminhos: []` e 620 omitidos.
_g215.hosts["172.21.0.12"] = HostDoGrafo(
    endereco="172.21.0.12", nome="srv-financeiro", subrede="172.21.0.0/24",
    comprometido=True, caminhos=[], caminhos_omitidos=620)
checa("D215: (controle) o braco A le o cabecalho de caminhos omitidos (D214)",
      "620 caminhos achados aqui, nenhum listado"
      in _g215.serializar_ambiente(), True)
checa("D215: e o braco B nao le nem esse cabecalho",
      "achados aqui" in _g215.serializar_ambiente(derivados=False), False)
del _g215.hosts["172.21.0.12"]

checa("D215: (controle) o braco A recebe a contagem do teto de credenciais",
      "(+3 nao listadas" in _A215, True)
checa("D215: e o braco B nao recebe nem essa",
      "nao listadas" in _B215, False)

# ---- O QUE FICA, e sem estas a regra viraria outra coisa -------------------
# ⚠️ **A CREDENCIAL COM O SEGREDO E A PRIMEIRA, porque e o defeito cujo sintoma
# seria o resultado desejado** (D125): um braco B sem a senha jamais
# autenticaria, perderia todas as execucoes, e a hipotese "confirmaria" por
# handicap nosso.
checa("D215: a credencial chega ao braco B COM o segredo",
      "[c01] svc_deploy senha 7fQx2Lm9RtVzB4kd" in _B215, True)
checa("D215: e com origem e veredito, que sao eventos observados",
      "origem h02; validada h03" in _B215, True)
# Lista de observacoes nao e derivacao: `validada h03,h05` sao dois eventos
# vistos, enfileirados. O que sai e a afirmacao que saida nenhuma contem.
_g215.credenciais[0].recusada_em.append("172.21.0.11")
checa("D215: recusa tambem, e o par de vereditos numa linha so",
      "validada h03; recusada h04"
      in _g215.serializar_ambiente(derivados=False), True)
_g215.credenciais[0].recusada_em.clear()

checa("D215: a secao de hosts fica inteira",
      "=== HOSTS ===" in _B215, True)
checa("D215: com os identificadores hNN, que sao contrato do arnes (D159)",
      "[h03] 172.21.0.10 host-db" in _B215, True)
checa("D215: os servicos ficam -- foi o nmap que os imprimiu",
      "servicos: 22/tcp ssh" in _B215, True)
checa("D215: os caminhos VISTOS ficam -- foi o find que os imprimiu",
      "caminhos vistos: /etc/passwd, /home/svc_deploy/config.ini" in _B215,
      True)
checa("D215: o titulo http fica", 'titulo http: "Painel"' in _B215, True)

# ⚠️ **A EXISTENCIA DA SUB-REDE NAO SE PERDE, e era a objecao a conferir antes
# de decidir.** Tirar a secao SUB-REDES tiraria a ROTA, nao a faixa: ela
# continua na linha de cada host e na linha de interface. O braco B da
# `piloto-B-01` achou a segunda perna do pivo exatamente por ai -- `ip -o addr
# show` no passo 51, varredura da faixa no 52, pelo comando dele.
checa("D215: a faixa interna continua legivel na linha do host",
      "172.21.0.10 host-db 172.21.0.0/24" in _B215, True)
_g215.hosts["172.20.0.12"].interfaces = [
    InterfaceDoGrafo(nome="eth1", endereco="172.21.0.2",
                     subrede="172.21.0.0/24")]
checa("D215: e a interface observada entrega a faixa com o prefixo",
      " interfaces: eth1 172.21.0.2/24"
      in _g215.serializar_ambiente(derivados=False), True)

# A LINHA DE D199 FICA, e a fronteira e o criterio: ela consolida UMA saida de
# ferramenta -- o resultado de uma enxurrada de forca bruta --, nao o grafo.
# Mesma natureza de `titulo http`. E o braco B teria a saida crua no historico
# verbatim dele de todo modo.
_g215.hosts["172.20.0.11"] = HostDoGrafo(
    endereco="172.20.0.11", nome="glhf", subrede="172.20.0.0/24",
    autenticacao_indiscriminada={"1337": 254})
checa("D215: a autenticacao indiscriminada fica -- consolida UMA saida (D199)",
      "autenticacao nao discrimina: porta 1337, 254 pares aceitos"
      in _g215.serializar_ambiente(derivados=False), True)
del _g215.hosts["172.20.0.11"]

# ⚠️ **E O TAMANHO E A MEDIDA, nao a estimativa.** Nos dois braco B gravados o
# corte foi de 5% e 8% do ambiente (217 de 4.691 e 302 de 3.669 caracteres).
# Esta checagem prende a ordem de grandeza: se um dia o corte passar de um
# terco do texto, alguem ampliou o criterio e isto acusa.
checa("D215: o corte e cirurgico, nao esvaziamento (menos de um terco)",
      len(_B215) > len(_A215) * 0.66, True)
checa("D215: e corta de verdade -- o braco B e menor", len(_B215) < len(_A215),
      True)


# ---------------- `/sys` e interface de kernel, e o teste disso NAO EXISTIA
#
# ⚠️ **A mutacao `KERNEL = frozenset({"proc"})` SOBREVIVEU na bateria de 30 de
# setembro, e o contraexemplo estava no comentario do proprio codigo.** Ele cita
# o passo 5 da `diag-04`, onde `find / -iname "*flag*"` levou doze entradas de
# `/proc` e `/sys` ao grafo -- doze das quarenta vagas por host. No passo 11 o
# teto encheu, e do passo 11 ao 45 nada mais entrou, inclusive o `config.ini`
# que tem a credencial.
#
# A suite cobria `/proc` e nao cobria `/sys`. **Contraexemplo que nao esta na
# suite e contraexemplo que nao existe**, e e a segunda vez em dois dias que a
# licao aparece.
checa("kernel: `/sys` e interface de kernel e nao entra",
      analisar_saida(
          "/sys/devices/platform/serial8250/tty/ttyS2/flags\n").caminhos, [])
checa("kernel: e o caminho de verdade ao lado dele entra",
      analisar_saida("/sys/kernel/debug/tracing/events\n"
                     "/opt/diagnostico/config.ini\n").caminhos,
      ["/opt/diagnostico/config.ini"])
# ⚠️ CONTRAEXEMPLO DA REGRA POR COMPONENTE, que o comentario do codigo promete:
# o nome que COMECA com `sys` nao e `/sys`. Sem esta checagem, trocar a regra
# por prefixo de texto passaria verde aqui e comeria caminho real em silencio --
# e ha mutacao registrada justamente para isso.
checa("kernel: `/sysconfig` nao e `/sys` -- a regra e por COMPONENTE",
      analisar_saida("/sysconfig/network/ifcfg-eth0\n").caminhos,
      ["/sysconfig/network/ifcfg-eth0"])
checa("kernel: e `/procedimentos` nao e `/proc`",
      analisar_saida("/procedimentos/backup.sh\n").caminhos,
      ["/procedimentos/backup.sh"])


# ============================== D217: o parser do netcat, a ferramenta sem um
#
# ⚠️ **As OITO formas abaixo foram capturadas contra o laboratorio no ar**, nao
# imaginadas -- a licao de D109, onde meus testes mediam a forma achatada e o
# mundo entregava a aninhada. O comando foi
# `docker exec tcc-atacante sh -c "printf ... | nc -nv 172.20.0.11 1337"` e
# companhia, em 30 de setembro.
#
# `ARTEFATO.md` §1.2 define a camada de ferramentas como "invólucros com parser
# dedicado"; `netcat` nao tinha um, e o agente lia `executado, codigo 0` depois
# de um `nc` que tinha recebido resposta. Custo medido: **16 de 80 passos da
# `coleta-B-01`** mandando credencial a um servidor HTTP sem nunca saber que era
# um servidor HTTP.
def _nc(saida="", erro=""):
    e = Execucao(comando=["nc"])
    e.saida, e.erro, e.codigo = saida, erro, 0
    return e


def _portas(execucao):
    return sorted((h.endereco, s.porta, s.estado, s.servico, s.versao)
                  for h in Netcat().analisar(execucao) for s in h.servicos)


# ---- 1. O CASO QUE CUSTOU OS 16 PASSOS: o distrator fala HTTP ------------
_distrator = _nc(
    saida="<!DOCTYPE HTML>\n<html lang=\"en\">\n<p>Error code: 400</p>\n"
          "<p>Message: Bad request syntax ('svc_deploy')</p>\n",
    erro="Connection to 172.20.0.11 1337 port [tcp/*] succeeded!\n")
checa("D217: o distrator entra no grafo como porta aberta falando http",
      _portas(_distrator), [("172.20.0.11", 1337, "open", "http", None)])
checa("D217: e o resumo diz o CODIGO, que e o que o agente precisava",
      Netcat().resposta(_distrator), "o servico respondeu HTTP, codigo 400")
# ⚠️ **A CHECAGEM QUE PROTEGE D40, e ela e a razao de o resumo levar so o
# codigo.** A pagina de erro ECOA A ENTRADA (`Bad request syntax ('svc_deploy')`).
# Num passo em que o agente mandasse a senha, um resumo com a mensagem do
# servidor traria o segredo -- e o resumo vai para a secao de tentativas do
# braco A e para o historico do braco B.
checa("D217: e NAO ecoa a entrada, que e por onde o segredo vazaria",
      "svc_deploy" in (Netcat().resposta(_distrator) or ""), False)

# ---- 2. BANNER DE SSH: versao, e a INTEIRA ------------------------------
# Cortar no primeiro espaco daria `OpenSSH_9.2p1` enquanto o `nmap -sV` grava
# `OpenSSH_9.2p1 Debian-2+deb12u10`. Como `Host.funde` deixa o novo nao-vazio
# ganhar, as duas versoes ficariam se sobrescrevendo conforme a ordem dos passos
# -- o grafo diria coisas diferentes sobre o mesmo servico sem nada ter mudado.
_ssh_banner = _nc(saida="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10\r\n",
                  erro="Connection to 172.20.0.12 22 port [tcp/*] succeeded!\n")
checa("D217: banner de ssh entra com a versao inteira, como o nmap a grava",
      _portas(_ssh_banner),
      [("172.20.0.12", 22, "open", "ssh", "OpenSSH_9.2p1 Debian-2+deb12u10")])

# ---- 3. O QUE A FALHA DIZ, E O QUE ELA NAO DIZ, SOBRE A PORTA -----------
checa("D217: `Connection refused` e a porta fechada",
      _portas(_nc(erro="nc: connect to 172.20.0.11 port 9999 (tcp) failed: "
                       "Connection refused\n")),
      [("172.20.0.11", 9999, "closed", None, None)])
checa("D217: tempo esgotado e `filtered`, nao `closed`",
      _portas(_nc(erro="nc: connect to 172.21.0.10 port 22 (tcp) failed: "
                       "Connection timed out\n")),
      [("172.21.0.10", 22, "filtered", None, None)])
# ⚠️ **O CONTRAEXEMPLO QUE SEGURA A REGRA: falha de REDE nao fala da porta.**
# "No route to host" e o pacote nao chegando; afirmar `closed` ali seria o erro
# de D79 noutro lugar -- fato sobre o alvo tirado de falha de transporte.
# **Perder achado e menos grave que inventar fato** (D04).
checa("D217: `No route to host` nao afirma NADA sobre a porta",
      _portas(_nc(erro="nc: connect to 172.21.0.10 port 22 (tcp) failed: "
                       "No route to host\n")), [])
checa("D217: nem `Network is unreachable`",
      _portas(_nc(erro="nc: connect to 10.0.0.1 port 80 (tcp) failed: "
                       "Network is unreachable\n")), [])

# ---- 4. MODO ESCUTA: nao e servico de alvo nenhum -----------------------
# O agente propos `nc -lvnp 4444` seis vezes no corpo. Gravar
# `172.20.0.5:4444 aberta` poria no grafo um fato verdadeiro e completamente
# enganoso: porta aberta na maquina DELE, nao no alvo.
_escuta = _nc(erro="listening on [any] 4444 ...\n")
checa("D217: modo escuta nao grava servico nenhum", _portas(_escuta), [])
checa("D217: e o resumo explica a restricao do arnes em vez de calar",
      "nao mantem processo entre passos" in (Netcat().resposta(_escuta) or ""),
      True)

# ---- 5. O ROTULO MENTE EM 11% DOS CASOS, e o parser tem de aguentar -----
# Medido no corpo: dos 444 passos rotulados `netcat`/`sqlmap`, 49 (11%) nao
# invocam nenhum dos dois -- inclusive oito `find / -xdev ... *trofeu*`. Um
# parser frouxo inventaria servico a partir dessa saida.
checa("D217: saida de `find` rotulada netcat nao produz servico",
      _portas(_nc(saida="/home/svc_app/trofeu.txt\n/etc/passwd\n"
                        "Connection to the database failed\n")), [])
checa("D217: e nem resposta de servico",
      Netcat().resposta(_nc(saida="/etc/passwd\nconnect to the host failed\n")),
      None)

# ---- 6. CONEXAO QUE ABRE E CALA e fato DIFERENTE de conexao que nao abre -
# Um convida a falar o protocolo certo, o outro a procurar outra porta. Sem a
# distincao o agente le o mesmo silencio para as duas coisas.
_calado = _nc(erro="Connection to 172.20.0.12 9000 port [tcp/*] succeeded!\n")
checa("D217: conexao aberta sem resposta entra como porta aberta",
      _portas(_calado), [("172.20.0.12", 9000, "open", None, None)])
checa("D217: e o resumo diz que abriu e nada voltou",
      Netcat().resposta(_calado), "a conexao abriu e o servico nao respondeu nada")

# ---- 7. VARIAS CONEXOES NUM COMANDO SO ---------------------------------
checa("D217: duas conexoes num comando dao dois servicos",
      _portas(_nc(erro="Connection to 172.20.0.12 22 port [tcp/*] succeeded!\n"
                       "nc: connect to 172.20.0.12 port 23 (tcp) failed: "
                       "Connection refused\n")),
      [("172.20.0.12", 22, "open", None, None),
       ("172.20.0.12", 23, "closed", None, None)])

# ---- 8. O ENDERECO SAI DA SAIDA, NAO DA PROPOSTA -----------------------
# ⚠️ Atribuicao errada e o defeito de D197 -- seis passos procurando
# `/home/svc_app` no host errado. A linha do `nc` declara host e porta; deduzi-
# los do comando daria errado no caso que o corpo mais produz,
# `printf ... | nc host porta` dentro de `bash -c`, onde o alvo do PASSO e outro.
checa("D217: o endereco vem da linha do nc, mesmo com outro alvo no comando",
      _portas(_nc(erro="Connection to 172.21.0.12 22 port [tcp/*] succeeded!\n")),
      [("172.21.0.12", 22, "open", None, None)])


# ====== Os sobreviventes da bateria completa, resolvidos (D223)
#
# ⚠️ **A bateria de 571 devolveu quatro vivos que a fatia de 23 nao tinha
# devolvido**, porque tres estao ancorados FORA da faixa nova e so entraram
# no escopo na bateria completa. **Fatia nao e bateria**, e e por isso que
# D42 exige as duas rodadas completas.

# ---- 3. MODO ESCUTA: o contraexemplo que impede a guarda de voltar -----
# A guarda em `analisar` saiu (D223): era inerte no caso que a alcancava e
# descartava observacao real no caso combinado.
_comb = _nc(erro="listening on [any] 4444 ...\n"
                 "Connection to 172.20.0.11 1337 port [tcp/*] succeeded!\n")
checa("D223: escuta E conexao no mesmo comando preserva o servico observado",
      _portas(_comb), [("172.20.0.11", 1337, "open", None, None)])
checa("D223: e a nota de escuta continua chegando ao agente",
      "nao mantem processo entre passos" in (Netcat().resposta(_comb) or ""),
      True)
checa("D223: so escuta continua nao gravando servico nenhum",
      _portas(_nc(erro="listening on [any] 4444 ...\n")), [])
# ⚠️ **A FORMA REAL DO LABORATORIO, capturada pela prova ao vivo**: o `nc`
# do contêiner imprime `Listening on 0.0.0.0 <porta>`, com L MAIUSCULO e sem
# `[any]`. A forma que eu havia posto nos testes veio de outra versao do
# `nc`; o `IGNORECASE` salvou, e isso e sorte, nao cobertura. Mesma licao de
# D109 e D211: os testes mediam a forma que eu imaginei.
checa("D224: a forma REAL de escuta do laboratorio tambem nao grava servico",
      _portas(_nc(erro="Listening on 0.0.0.0 4455\n")), [])
checa("D224: e ela tambem produz a nota do arnes",
      "nao mantem processo entre passos"
      in (Netcat().resposta(_nc(erro="Listening on 0.0.0.0 4455\n")) or ""),
      True)

# ---- 4. TIPO DE CREDENCIAL DESCONHECIDO continua visivel no prompt -----
# ⚠️ A mutacao `credencial: tipo desconhecido passa a ser escondido do prompt`
# sobreviveu: nenhum teste usava um terceiro tipo, porque hoje so existem
# `senha` e `chave`. O predicado documenta a intencao -- *"tipo desconhecido
# conta como utilizavel, para um tipo novo nao desaparecer do prompt em
# silencio"* -- e intencao sem teste e comentario.
#
# **Esconder achado e o erro OPOSTO ao de D221 e tambem e erro.** Um `token`
# descoberto amanha ficaria sem a lista `nao testada` e sem marca nenhuma: o
# agente nao teria como saber que ele existe.
_gt = Grafo()
# ⚠️ O FIXTURE PRECISA DE OUTRO HOST COM SERVICO ABERTO: `nao testada` so
# lista onde da para aplicar a credencial, e com um host so a lista sai
# vazia por falta de alvo -- o teste passaria pela razao errada, que e o
# defeito que o comentario de D178 descreve.
_gt.absorver_hosts([HostObservadoDoGrafo(
    endereco="172.20.0.12",
    servicos=[ServicoObservado(porta=22, protocolo="tcp", estado="open")])])
_gt.absorver_credencial("svc_api", "token", origem="172.20.0.10")
_lt = [x for x in _gt.serializar().splitlines() if x.startswith("[c01]")][0]
checa("D223: tipo desconhecido nao leva marca de material ausente",
      "desconhecido)" in _lt, False)
checa("D223: e mantem o convite `nao testada`, em vez de sumir do prompt",
      "nao testada" in _lt, True)


# ========== D225: a rota carrega a PORTA, e D226: o curl diz que veio corpo
#
# ⚠️ **Os dois nasceram de 6 passos queimados numa execucao paga de 1 de
# outubro.** O `host-web` do laboratorio tem DOIS servidores HTTP -- `8000` com
# um `SimpleHTTPServer` e `8080` com o Werkzeug que serve o `/diagnostico` -- e
# o prompt dizia
#
#     rotas: /diagnostico (GET, param destino)
#     servicos: 8000/tcp http ...; 8080/tcp http-proxy ...
#
# sem dizer em qual delas a rota morava. O agente escolheu a rotulada `http` e
# bateu em 8000 seis vezes; o resumo respondia `http nao observado,
# 0 credencial(is)` -- correto (sem `-i` nao ha linha de status) e incompleto,
# porque o corpo VOLTOU: um 404 do servidor errado.
_HTML_COM_FORMA = (
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    "<html><head><title>Diagnostico</title></head><body>"
    '<form action="/diagnostico" method="GET">'
    '<input name="destino"></form></body></html>')


def _curl(comando, saida):
    e = Execucao(comando=comando)
    e.codigo, e.saida, e.erro = 0, saida, ""
    return Curl().analisar(e)


_r8080 = _curl(["curl", "-s", "-i", "http://172.20.0.10:8080/"], _HTML_COM_FORMA)
checa("D225: a rota sai do parser JA com a porta da URL",
      [(x.caminho, x.metodo, x.porta) for x in _r8080.rotas],
      [("/diagnostico", "GET", 8080)])

# ⚠️ **A POSICAO DO SELO E O CONSERTO, e a minha primeira versao errou.** Eu o
# pus junto de `_destino`, onde `r.porta` fica conhecida -- e `r.rotas` so e
# atribuido no fim do parser. O laco corria sobre lista vazia. **A suite passava**
# (ela monta `Rota` a mao, ja com porta); quem pegou foi provar contra o
# laboratorio. Esta checagem existe para o selo nao voltar para o lugar errado.
checa("D225: e isso vale pelo PARSER, nao por Rota montada a mao",
      all(x.porta == 8080 for x in _r8080.rotas), True)

# A MESMA ROTA EM PORTAS DIFERENTES NAO FUNDE: sao rotas diferentes, e fundi-las
# apagaria justamente a distincao que custou os 6 passos.
_g225 = Grafo()
_g225.absorver_resposta(_curl(
    ["curl", "-i", "http://172.20.0.10:8080/"], _HTML_COM_FORMA))
_g225.absorver_resposta(_curl(
    ["curl", "-i", "http://172.20.0.10:8000/"], _HTML_COM_FORMA))
checa("D225: /diagnostico em 8080 e em 8000 sao DUAS rotas",
      sorted((x.caminho, x.porta) for x in _g225.hosts["172.20.0.10"].rotas),
      [("/diagnostico", 8000), ("/diagnostico", 8080)])
_l225 = [x for x in _g225.serializar_ambiente().splitlines() if "rotas:" in x][0]
checa("D225: e o prompt mostra as duas com a porta de cada uma",
      "em 8000" in _l225 and "em 8080" in _l225, True)

# ⚠️ **ROTA SEM PORTA NAO INVENTA UMA, e nao imprime `em None`.** E o caso do
# `grafo.json` antigo, carregado por `Rota(**r)` sem a chave nova: `None` nunca
# vira numero, pelo mesmo principio do `None` que nunca vira zero.
_gsp = Grafo()
_gsp.absorver_hosts([HostObservadoDoGrafo(endereco="172.20.0.10")])
_gsp.hosts["172.20.0.10"].rotas.append(RotaDoGrafo(caminho="/velha"))
_lsp = [x for x in _gsp.serializar_ambiente().splitlines() if "rotas:" in x][0]
checa("D225: rota sem porta conhecida nao imprime `em None`",
      "None" in _lsp, False)
checa("D225: e a rota continua aparecendo", "/velha (GET)" in _lsp, True)
# E ELA APRENDE a porta quando a leitura nova a traz -- leitura nova so
# acrescenta o que tem, a regra de `funde`.
_gsp.absorver_resposta(_curl(
    ["curl", "-i", "http://172.20.0.10:8080/velha"],
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    '<html><body><a href="/velha">x</a></body></html>'))
checa("D225: a rota conhecida APRENDE a porta quando ela chega",
      [x.porta for x in _gsp.hosts["172.20.0.10"].rotas if x.caminho == "/velha"],
      [8080])

# ---- D226: o corpo voltou, e o resumo diz isso -------------------------
# **O TAMANHO, nunca o conteudo** -- §1.2 mantem a saida bruta fora do modelo.
_sem_i = _curl(["curl", "-s", "http://172.20.0.10:8000/x"],
               "<html><body>404 File not found</body></html>")
checa("D226: sem -i o status nao e observado, e o corpo fica legivel no objeto",
      (_sem_i.status, bool(_sem_i.corpo)), (None, True))

# ⚠️ **`Host.funde` TAMBEM precisa distinguir rota por porta, e a mutacao disso
# SOBREVIVEU** -- o teste acima passa por `absorver_resposta`, que tem a chave
# dele proprio; `funde` e outro caminho, chamado por `absorver_hosts`. **Duas
# chaves para a mesma relacao e a divergencia de 21 de setembro esperando
# acontecer**, e por isso as duas tem a mesma regra e cada uma tem o seu teste.
_ha = HostDoGrafo(endereco="172.20.0.10", rotas=[
    RotaDoGrafo(caminho="/diagnostico", metodo="GET", porta=8080)])
_hb = HostDoGrafo(endereco="172.20.0.10", rotas=[
    RotaDoGrafo(caminho="/diagnostico", metodo="GET", porta=8000)])
_ha.funde(_hb)
checa("D225: `funde` mantem /diagnostico de 8080 e de 8000 separadas",
      sorted((x.caminho, x.porta) for x in _ha.rotas),
      [("/diagnostico", 8000), ("/diagnostico", 8080)])
# E O CONTRAEXEMPLO: a MESMA rota na MESMA porta funde, e os parametros se
# juntam. Sem ele, uma chave que nunca funde passaria verde -- e o grafo
# acumularia a mesma rota a cada leitura.
_hc = HostDoGrafo(endereco="172.20.0.10", rotas=[
    RotaDoGrafo(caminho="/d", metodo="GET", parametros=["a"], porta=8080)])
_hd = HostDoGrafo(endereco="172.20.0.10", rotas=[
    RotaDoGrafo(caminho="/d", metodo="GET", parametros=["b"], porta=8080)])
_hc.funde(_hd)
checa("D225: e a mesma rota na mesma porta funde, juntando os parametros",
      [(x.caminho, x.porta, sorted(x.parametros)) for x in _hc.rotas],
      [("/d", 8080, ["a", "b"])])
# E ROTA SEM PORTA APRENDE a porta ao fundir com uma que a tem -- leitura nova
# so acrescenta o que tem, e `grafo.json` antigo cai aqui.
_he = HostDoGrafo(endereco="172.20.0.10",
                  rotas=[RotaDoGrafo(caminho="/d", metodo="GET")])
_hf = HostDoGrafo(endereco="172.20.0.10", rotas=[
    RotaDoGrafo(caminho="/d", metodo="GET", porta=8080)])
_he.funde(_hf)
checa("D225: rota sem porta aprende a porta ao fundir",
      [(x.caminho, x.porta) for x in _he.rotas], [("/d", 8080)])


# ====== D227: o teto de tempo nao joga fora o que o comando ja escreveu
#
# ⚠️ **Medido na execucao paga de 1 de outubro.** O passo 22 rodou
# `nc -nv 172.20.0.11 1337`, pendurou os 300 s do teto de D80, e o resumo saiu
# com "24 bytes de resposta" -- exatamente `len("tempo esgotado apos 300s")`, a
# prova de que o parcial tinha sido SOBRESCRITO pela mensagem.
#
# E o parcial era o unico fato que aqueles 300 segundos produziram: o `nc -nv`
# escreve `Connection to ... succeeded!` no stderr IMEDIATAMENTE e so depois
# pendura. Familia de D61, D89, D103, D105, D113, D174 e D217.
checa("D227: a mensagem do teto tem os 24 caracteres do defeito",
      len("tempo esgotado apos 300s"), 24)


# ⚠️ **A PRIMEIRA VERSAO DESTE FIXTURE REIMPLEMENTAVA `Executor.rodar`, e as
# TRES mutacoes de D227 sobreviveram.** Eu havia escrito uma subclasse que
# repetia a logica do `except TimeoutExpired` -- entao o teste exercitava a
# MINHA COPIA, e mutar `base.py` nao mudava nada. **Funcao testada nao e funcao
# chamada**, e e a licao de D151, que passou por 24 checagens verdes pelo mesmo
# motivo.
#
# Agora o teste substitui a FRONTEIRA -- `subprocess.run` -- e deixa todo o
# codigo de producao acima dela rodar. Nao toca Docker (D25) e e deterministico.
def _pendurando(parcial_erro="", parcial_saida=""):
    """Um `subprocess.run` que levanta `TimeoutExpired` com o parcial.

    E o que o Python de fato entrega: conferido em 1 de outubro contra o
    laboratorio, `TimeoutExpired.stderr` traz `Connection to ... succeeded!`
    como `str` quando `text=True`.
    """
    import subprocess as _s

    def falso(*a, **k):
        raise _s.TimeoutExpired(cmd=["x"], timeout=k.get("timeout", 300),
                                output=parcial_saida, stderr=parcial_erro)
    return falso


class _ExecutorQuePendura(Executor):
    """O `Executor` DE VERDADE, com a fronteira do subprocesso trocada."""

    def __init__(self, parcial_erro="", parcial_saida=""):
        super().__init__(conteiner="nao-usado")
        self._pe, self._ps = parcial_erro, parcial_saida

    def rodar(self, execucao, timeout: int = 300):
        import ferramentas.base as _base
        original = _base.subprocess.run
        _base.subprocess.run = _pendurando(self._pe, self._ps)
        try:
            # `super().rodar` E o codigo de producao: a mutacao de `base.py`
            # agora chega aqui.
            return super().rodar(execucao, timeout=timeout)
        finally:
            _base.subprocess.run = original


_LINHA_NC = "Connection to 172.20.0.11 1337 port [tcp/*] succeeded!\n"
_ex = Execucao(comando=["nc", "-nv", "172.20.0.11", "1337"])
_ExecutorQuePendura(parcial_erro=_LINHA_NC).rodar(_ex, timeout=300)
checa("D227: o parcial do stderr sobrevive ao teto",
      "Connection to 172.20.0.11 1337" in (_ex.erro or ""), True)
checa("D227: e a mensagem do teto continua la, para quem le saber que nao terminou",
      "tempo esgotado apos 300s" in (_ex.erro or ""), True)
checa("D227: o codigo proprio -1 nao muda -- nao houve codigo de saida",
      _ex.codigo, -1)
# ⚠️ **E O PARSER DE D217 PASSA A EXTRAIR FATO DOS 300 SEGUNDOS.** Era o ponto:
# sem isto, o passo mais caro de uma execucao rendia zero.
checa("D227: o netcat extrai a porta aberta de um comando que pendurou",
      sorted((h.endereco, s.porta, s.estado)
             for h in Netcat().analisar(_ex) for s in h.servicos),
      [("172.20.0.11", 1337, "open")])
# O CONTRAEXEMPLO: sem parcial nenhum, a mensagem do teto fica sozinha e NAO
# ganha linha em branco na frente. Sem esta checagem, um `erro` comecando com
# "\n" poderia confundir parser que le a primeira linha.
_vazio = Execucao(comando=["x"])
_ExecutorQuePendura().rodar(_vazio, timeout=300)
checa("D227: sem parcial, a mensagem do teto fica sozinha e limpa",
      _vazio.erro, "tempo esgotado apos 300s")
checa("D227: e nao sobra saida inventada", _vazio.saida, "")

# ⚠️ **O PARCIAL DO STDOUT TAMBEM, e a mutacao disso SOBREVIVEU** -- meus
# testes punham parcial so no stderr, porque e la que o `nc -nv` escreve o
# diagnostico. Um comando que IMPRIME e depois pendura perde a saida: um `find`
# que lista e estanca, por exemplo, e `_ler_saida` colhe caminho de
# `saida + erro`. **Cobrir um canal e deixar o outro e cobertura pela metade.**
_so_stdout = Execucao(comando=["find", "/", "-name", "x"])
_ExecutorQuePendura(
    parcial_saida="/home/svc_app/trofeu.txt\n/etc/passwd\n").rodar(
        _so_stdout, timeout=300)
checa("D227: o parcial do STDOUT tambem sobrevive ao teto",
      "/home/svc_app/trofeu.txt" in (_so_stdout.saida or ""), True)
checa("D227: e a mensagem do teto nao vaza para o stdout",
      "tempo esgotado" in (_so_stdout.saida or ""), False)
checa("D227: e os caminhos do parcial sao colhidos de verdade",
      analisar_saida(_so_stdout.saida).caminhos,
      ["/home/svc_app/trofeu.txt", "/etc/passwd"])


# ====== D228: o palpite do nmap chega ao grafo marcado como palpite
#
# ⚠️ **Conferido ao vivo em 1 de outubro, a cadeia inteira:**
#
#     o nmap escreve:   1337/tcp open  waste?
#     o parser extrai:  servico='waste'  incerto=True
#     o grafo guardava: servico='waste'          <- o palpite virou fato
#     o agente lia:     servicos: 1337/tcp waste
#
# A porta 1337 e a do distrator, onde o braco B queimou 16 de 80 passos. O
# parser fazia o certo -- `fatos.Servico.incerto` existe com o comentario
# *"engolir a interrogacao transformaria palpite em fato"* -- e `absorver_hosts`
# jogava fora, porque o `Servico` do grafo nao tinha o campo.
def _exec_nmap(saida):
    e = Execucao(comando=["nmap"])
    e.codigo, e.saida, e.erro = 0, saida, ""
    return e


_gi = Grafo()
_gi.absorver_hosts(Nmap().analisar(_exec_nmap(
    "Nmap scan report for 172.20.0.11\n"
    "Host is up.\n"
    "PORT     STATE SERVICE\n"
    "1337/tcp open  waste?\n")))
checa("D228: `incerto` atravessa a absorcao",
      [(s.porta, s.servico, s.incerto)
       for h in _gi.hosts.values() for s in h.servicos],
      [(1337, "waste", True)])
checa("D228: e o prompt reproduz a interrogacao do proprio nmap",
      "1337/tcp waste?" in _gi.serializar_ambiente(), True)
# O CONTRAEXEMPLO: servico identificado COM firmeza nao leva interrogacao. Sem
# ele, por `?` em tudo passaria verde -- e o agente deixaria de distinguir o que
# o nmap assina do que ele chuta.
_gf = Grafo()
_gf.absorver_hosts(Nmap().analisar(_exec_nmap(
    "Nmap scan report for 172.20.0.12\n"
    "Host is up.\n"
    "PORT   STATE SERVICE VERSION\n"
    "22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)\n")))
checa("D228: servico identificado com firmeza NAO leva interrogacao",
      "?" in [l for l in _gf.serializar_ambiente().splitlines()
              if "servicos" in l][0], False)
# ⚠️ **A CERTEZA SO SOBE, nunca desce.** Uma varredura que identifica com
# firmeza manda sobre um palpite anterior; um palpite novo NAO apaga uma
# identificacao firme. `or` simples faria o palpite ganhar por chegar depois --
# e a ordem dos passos passaria a decidir o que o grafo afirma.
_sobe = HostDoGrafo(endereco="172.20.0.11", servicos=[
    ServicoDoGrafo(porta=1337, protocolo="tcp", estado="open",
                   servico="waste", incerto=True)])
_sobe.funde(HostDoGrafo(endereco="172.20.0.11", servicos=[
    ServicoDoGrafo(porta=1337, protocolo="tcp", estado="open",
                   servico="http", incerto=False)]))
checa("D228: identificacao firme apaga o palpite anterior",
      [(s.servico, s.incerto) for s in _sobe.servicos], [("http", False)])
_desce = HostDoGrafo(endereco="172.20.0.12", servicos=[
    ServicoDoGrafo(porta=22, protocolo="tcp", estado="open",
                   servico="ssh", incerto=False)])
_desce.funde(HostDoGrafo(endereco="172.20.0.12", servicos=[
    ServicoDoGrafo(porta=22, protocolo="tcp", estado="open",
                   servico="ssh", incerto=True)]))
checa("D228: e palpite novo NAO rebaixa identificacao firme",
      [(s.servico, s.incerto) for s in _desce.servicos], [("ssh", False)])


# ====== D230: a saida de script do nmap nao fecha a tabela de portas
#
# ⚠️ **A CAUSA RAIZ DE UMA CLASSE INTEIRA DE PROBLEMA, e o caso era o COMUM.**
# A cerca da tabela fechava na primeira linha que nao fosse porta, e com `-sC`,
# `-A` ou `--script` o nmap imprime o resultado dos scripts INDENTADO SOB CADA
# PORTA. Toda porta depois da primeira com saida de script era descartada.
#
# Medido com o comando exato do passo 1 de uma execucao paga,
# `nmap -sV -sC -p- --open 172.20.0.0/24`:
#
#     a saida crua traz   5 relatorios de host, 7 portas abertas
#     o parser extraia    5 hosts, 5 servicos      <- uma por host
#
# E a porta perdida no `host-web` era a **8080**, onde mora o `/diagnostico` --
# a entrada da cadeia. O agente ficava com um grafo sem o caminho de entrada do
# laboratorio: elo 0 por 34 passos, fora da faixa de 30 de 30 execucoes (o elo
# 1 cai entre os passos 3 e 10).
#
# **A saida abaixo e a do laboratorio, capturada**, com as duas formas de linha
# de script que o nmap usa -- `|_` na ultima de um bloco e `| ` nas demais.
_SC = (
    "Nmap scan report for tcc-host-web.tcc-lab_dmz (172.20.0.10)\n"
    "Host is up (0.000090s latency).\n"
    "PORT     STATE SERVICE    VERSION\n"
    "8000/tcp open  http       SimpleHTTPServer 0.6 (Python 3.11.16)\n"
    "|_http-server-header: SimpleHTTP/0.6 Python/3.11.16\n"
    "|_http-title: Directory listing for /\n"
    "8080/tcp open  http-proxy Werkzeug/3.1.9 Python/3.11.16\n"
    "|_http-server-header: Werkzeug/3.1.9 Python/3.11.16\n"
    "| fingerprint-strings: \n"
    "|   GetRequest: \n"
    "|     HTTP/1.1 200 OK\n"
    "|     <form action=\"/diagnostico\" method=\"get\">\n"
    "\n"
    "Service detection performed.\n")
_g230 = Grafo()
_g230.absorver_hosts(Nmap().analisar(_exec_nmap(_SC)))
checa("D230: as DUAS portas sobrevivem a saida de script",
      sorted((s.porta, s.servico)
             for h in _g230.hosts.values() for s in h.servicos),
      [(8000, "http"), (8080, "http-proxy")])
# ⚠️ **A 8080 E A ENTRADA DA CADEIA**, e e por isso que esta checagem nomeia a
# porta em vez de so contar servicos: contar passaria se o parser guardasse duas
# portas erradas.
checa("D230: e a 8080, que e a entrada da cadeia, esta entre elas",
      any(s.porta == 8080 for h in _g230.hosts.values() for s in h.servicos),
      True)
checa("D230: a versao de cada uma vem certa, nao trocada",
      sorted((s.porta, s.versao)
             for h in _g230.hosts.values() for s in h.servicos),
      [(8000, "SimpleHTTPServer 0.6 (Python 3.11.16)"),
       (8080, "Werkzeug/3.1.9 Python/3.11.16")])

# ⚠️ **O CONTRAEXEMPLO QUE SEGURA A CERCA, e sem ele o conserto abriria outro
# buraco:** a tabela continua TERMINANDO. Se ignorar `|` virasse "ignore tudo",
# qualquer linha solta com `numero/palavra` depois da tabela viraria servico --
# e e exatamente o que o `analisar` ja comentava sobre o bloco `SF:` do
# fingerprint, que tem dezenas de linhas com numeros e barras.
_SF = (
    "Nmap scan report for 172.20.0.11\n"
    "PORT     STATE SERVICE\n"
    "1337/tcp open  waste?\n"
    "\n"
    "SF-Port1337-TCP:V=7.93%I=7%D=10/1%Time=68DC%P=x86_64%r(GetRequest,2F,\n"
    "SF:\"HTTP/1\\.0\\x20400\\x20Bad\\x20request\\x20syntax\")%r(HTTPOptions,2F,\n"
    "SF:9999/tcp\\x20open\\x20inventado\n")
_gsf = Grafo()
_gsf.absorver_hosts(Nmap().analisar(_exec_nmap(_SF)))
checa("D230: o bloco SF: do fingerprint nao inventa servico",
      sorted((s.porta, s.servico)
             for h in _gsf.hosts.values() for s in h.servicos),
      [(1337, "waste")])
# E A LINHA EM BRANCO continua fechando a tabela: sem isso, "Service detection
# performed" e o resto do rodape entrariam no caminho do `_servico`.
checa("D230: a linha em branco continua fechando a tabela",
      "9999" in str([(s.porta) for h in _gsf.hosts.values()
                     for s in h.servicos]), False)
# ⚠️ E A SAIDA DE SCRIPT NAO VIRA SERVICO, que e o outro jeito de errar: a
# linha `|   GetRequest: ` tem dois-pontos e texto, e um parser frouxo a leria.
checa("D230: nenhuma linha de script virou servico",
      [s.servico for h in _g230.hosts.values() for s in h.servicos],
      ["http", "http-proxy"])

# ====================================================================== D245
# A ASSOCIACAO (endereco, caminho) QUE O PARSER TINHA NA MAO E JOGAVA FORA
#
# ⚠️ D197 fazia `prova = not ENDERECO_NA_LINHA.search(linha)`: o `.search()`
# devolvia o objeto com o endereco dentro e o `not` reduzia tudo a UM BIT. O
# caminho ia para `mencionados` do host que LEU o arquivo, e a metade que diz de
# QUEM o caminho e era descartada.
#
# Custo medido (§E96): na `coleta-A-01` de 1 de outubro o agente leu o inventario,
# escreveu de proprio punho "podem conter o trofeu ou credenciais para h09
# (financeiro) ou outro usuario", e procurou `/home/svc_app` NO HOST ERRADO por
# tres passos. §E97 mediu o efeito de ancorar certo: 0/20 -> 11/20, p = 7,3e-05.
#
# ⚠️ ASSOCIACAO NAO AFIRMA EXISTENCIA, e e isso que destrava o conserto. §E99
# havia rejeitado a correcao porque dois dos cinco caminhos do inventario nao
# existem em host nenhum. A afirmacao aqui e outra: "uma linha lida no h08 associa
# 172.21.0.12 a /home/svc_app" -- verdade sobre o TEXTO, exista o caminho ou nao.

# 1. O ALVO: a linha real do inventario do laboratorio.
_d245 = analisar_saida(
    "srv-financeiro   172.21.0.12    /home/svc_app    /srv/backup/fin   diario\n")
checa("D245: a linha do inventario pareia endereco e caminho",
      sorted((a.endereco, a.caminho) for a in _d245.associados),
      [("172.21.0.12", "/home/svc_app"), ("172.21.0.12", "/srv/backup/fin")])
# E D197 continua valendo: a linha nomeia outra maquina, logo nao e prova AQUI.
checa("D245: e D197 segue valendo -- a linha com endereco nao e prova",
      _d245.caminhos, [])

# 2. CONTRAEXEMPLO: DOIS enderecos na linha e ambiguo sobre o dono.
#    Afirmar um dos dois seria chutar, e chutar e o defeito que isto conserta.
checa("D245: linha com DOIS enderecos nao produz associacao (seria chute)",
      analisar_saida("172.21.0.11 -> 172.21.0.12 via /srv/rota\n").associados, [])

# 3. CONTRAEXEMPLO: sem endereco, nada muda -- o caminho segue PROVA.
#    Este e o teste de nao-regressao: a mudanca nao pode rebaixar observacao.
_sem = analisar_saida("/home/svc_backup/.ssh/id_ed25519\n")
checa("D245: saida sem endereco nao gera associacao", _sem.associados, [])
checa("D245: e o caminho continua sendo PROVA", _sem.caminhos,
      ["/home/svc_backup/.ssh/id_ed25519"])

# 4. O GRAFO ANCORA NO HOST QUE A LINHA NOMEIA, nao no que leu o arquivo.
_g245 = Grafo()
# O host de destino entra direto: criar host e trabalho do `Nmap`, nao de
# `analisar_saida`, e o que se testa aqui e a ancoragem do par.
_g245.hosts["172.21.0.12"] = HostDoGrafo(endereco="172.21.0.12",
                                         subrede="172.21.0.0/24")
_g245.absorver_saida("172.21.0.11", analisar_saida(
    "srv-financeiro   172.21.0.12    /home/svc_app    /srv/backup/fin   diario\n"))
checa("D245: o par vai para o host que a linha NOMEIA",
      sorted(_g245.hosts["172.21.0.12"].associados),
      ["/home/svc_app", "/srv/backup/fin"])
checa("D245: e a origem registrada e quem LEU o arquivo",
      _g245.hosts["172.21.0.12"].associados.get("/home/svc_app"), "172.21.0.11")

# 5. ⚠️ NAO FABRICA HOST a partir de mencao em arquivo -- a classe de D177, que
#    `conferir_hosts.py` reprova como fantasma. O par ESPERA pelo host existir.
_g246 = Grafo()
_g246.absorver_saida("172.20.0.5", analisar_saida("alvo 10.9.9.9 em /tmp/x\n"))
checa("D245: mencao em arquivo NAO cria host (classe D177)",
      "10.9.9.9" in _g246.hosts, False)

# 6. A linha que fala do PROPRIO host nao vira associacao: ali `caminhos` resolve,
#    e duplicar faria o agente ler dois fatos onde ha um (a classe de D183).
_g247 = Grafo()
_g247.hosts["172.20.0.5"] = HostDoGrafo(endereco="172.20.0.5",
                                        subrede="172.20.0.0/24")
_g247.absorver_saida("172.20.0.5", analisar_saida("eu sou 172.20.0.5 e tenho /tmp/meu\n"))
checa("D245: linha sobre o proprio host nao vira auto-associacao",
      dict(_g247.hosts["172.20.0.5"].associados), {})

# 7. A SERIALIZACAO diz de onde a afirmacao veio e que nao foi verificada --
#    a redacao e parte do conserto, pela mesma razao de D197.
_s245 = _g245.serializar_ambiente(derivados=True)
checa("D245: a serializacao nomeia a fonte e marca como nao verificada",
      any("associados em arquivo de h01 (nao verificados):" in l
          and "/home/svc_app" in l for l in _s245.splitlines()), True)
# ⚠️ E vai aos DOIS bracos: associacao e OBSERVACAO, nao derivacao. Se caisse em
# `derivados=False` ela beneficiaria so o braco A, e isso mexeria na variavel do
# experimento em vez do instrumento (a razao por que D245 nao copiou a credencial
# derivada de §E95).
_s245b = _g245.serializar_ambiente(derivados=False)
checa("D245: a associacao vai ao braco B tambem -- e observacao, nao derivacao",
      any("associados em arquivo de" in l for l in _s245b.splitlines()), True)

# 8. Sobrevive ao disco: grafo salvo e recarregado mantem o par e a origem.
with tempfile.TemporaryDirectory() as _tmp:
    _p245 = pathlib.Path(_tmp) / "g.json"
    _g245.salvar(_p245)
    _volta = Grafo.carregar(_p245)
    checa("D245: o par sobrevive a ida e volta do disco",
          dict(_volta.hosts["172.21.0.12"].associados),
          {"/home/svc_app": "172.21.0.11", "/srv/backup/fin": "172.21.0.11"})
# ⚠️ E grafo ANTIGO, sem a chave, carrega com o padrao vazio em vez de quebrar --
# as execucoes ja pagas do corpo tem de continuar legiveis (a licao de D193).
checa("D245: grafo sem a chave carrega com o padrao, nao quebra",
      dict(Grafo.carregar(
          # ⚠️ FIXTURE, e nao leitura da arvore de execucoes. O grafo e de uma
          # execucao descartada, no formato ANTERIOR a existencia da chave, e
          # foi copiado para `fixtures/` pelo mesmo motivo que os vizinhos dele
          # ja estavam la: o cabecalho desta suite manda que nenhum teste varra
          # `execucoes/`, e um teste que le o corpo vivo quebra assim que o
          # corpo e filtrado -- foi exatamente o que aconteceu ao preparar a
          # publicacao, onde as execucoes descartadas nao entram.
          pathlib.Path(__file__).resolve().parent / "fixtures"
          / "descartada-A-01-preD241-grafo.json"
      ).hosts["172.21.0.12"].associados), {})


print()
# ====================================================================== D247
# A ASSINATURA NAO PASSA PELO ROTULO -- o conserto de D247 nao mexe na
# metrica 7. `Hydra.resumir` tirava `-P` e `-t` do ROTULO, e o agente lia
# de volta um hydra sem lista de senhas e repetia o comando que ja havia
# rodado (§E111: 12 passos no braco A, 0 no braco B). A assinatura sempre
# foi o comando inteiro mascarado, entao nenhuma contagem de redundancia
# ja publicada muda -- e e isto que fixa essa separacao.
# 3. NAO-REGRESSAO: a assinatura nunca passou pelo rotulo. A contagem de
#    redundancia (metrica 7) compara o comando inteiro mascarado, entao o
#    conserto nao mexe em nenhum numero ja publicado.
# Os comandos reais dos passos 57 e 49 da execucao descartada.
_d247 = [
    ["hydra","-L","nicks.txt","-P","rockyou.txt","-s","22","-t","4","-f","-I",
     "ssh://172.20.0.12"],
    ["hydra","-L","nicks.txt","-P","rockyou.txt","-s","22","-f","-I",
     "ssh://172.20.0.12"],
]
_g247 = Grafo()
_g247.abrir_tentativa("hydra", _d247[0], alvo="172.20.0.12")
_g247.abrir_tentativa("hydra", _d247[1], alvo="172.20.0.12")
checa("D247: comandos distintos seguem sendo tentativas distintas",
      len({t.assinatura for t in _g247.tentativas}), 2)
checa("D247: e o rotulo gravado tambem distingue agora",
      len({t.rotulo for t in _g247.tentativas}), 2)


# ⚠️ Este bloco mora AQUI e nao em `testes.py` porque o mapa de
# `mutacoes.py` manda `ferramentas/` para `testes_grafo.py`. Posto na
# suite errada, o teste existe e a bateria nao o roda -- foi o que
# aconteceu na primeira tentativa, e as duas mutacoes de D251
# SOBREVIVERAM com os testes escritos e passando noutro arquivo.
from ferramentas.saida import _declarados_ausentes            # noqa: E402

# ====================================================================== D251
# O ECO DO PROPRIO CANDIDATO ENTRAVA COMO CAMINHO PROVADO -- e o agente AGIU.
#
# O agente escreve `for f in <lista>; do echo ---$f---; cat "$f"; done` com
# candidatos que ele QUER testar. O `echo` imprime cada um exista ou nao:
#
#     ---/var/log/sulog---                             <- eco do candidato
#     cat: /var/log/sulog: No such file or directory    <- a refutacao, AO LADO
#
# `INEXISTENTE` recusa a segunda linha e aceita a primeira, e o candidato entrava
# PROVADO. A saida continha a refutacao e o arnes a jogava fora.
#
# ⚠️ Nao e dano hipotetico: §E114 mediu o passo 66 do braco A do par 8 gastando
# um passo nisso, com as palavras do agente -- *"o caminho /var/app/images
# aparece listado como visto porem nunca explorado"*. Ele leu o proprio eco de
# volta como descoberta.
_d251 = ("---/var/log/sulog---\n"
         "cat: /var/log/sulog: No such file or directory\n"
         "---/etc/ttytype---\n"
         "ls: cannot access '/etc/ttytype': No such file or directory\n"
         "---/bin/fakeshell---\n"
         "stat: cannot statx '/bin/fakeshell': No such file or directory\n")
_r251 = analisar_saida(_d251)
checa("D251: candidato ecoado e refutado na saida nao entra como provado",
      _r251.caminhos, [])

# ⚠️ E E DESCARTADO, nao rebaixado para `mencionados`. Rebaixar pareceria mais
# conservador e seria pior: um caminho que a saida JA disse nao existir,
# oferecido de volta como mencao, convida exatamente a volta que §E114 mediu.
checa("D251: nem sequer vira mencao -- mencao convidaria a volta de §E114",
      _r251.mencionados, [])

# ⚠️ AS TRES FORMAS que este laboratorio produz de verdade, conferidas nele.
checa("D251: as tres formas reais de ausencia sao reconhecidas",
      sorted(_declarados_ausentes(_d251)),
      ["/bin/fakeshell", "/etc/ttytype", "/var/log/sulog"])
checa("D251: e a forma do `sh` sem `No such` tambem",
      _declarados_ausentes("sh: /usr/bin/foo: not found"), {"/usr/bin/foo"})

# ⚠️ O CONTRAEXEMPLO QUE DEFINE A FORMA DA EXPRESSAO, e e o mais importante
# daqui: a reclamacao do `hydra` e `passwords not found: /usr/share/...`, com o
# caminho DEPOIS do texto -- e ele EXISTE, o agente acabou de baixa-lo. Uma
# expressao que casasse isso tiraria da prova um caminho verdadeiro, que e o
# defeito oposto e igualmente grave. Por isso o caminho tem de vir ANTES do `:`.
checa("D251: a reclamacao do hydra NAO declara ausencia -- o caminho vem depois",
      _declarados_ausentes(
          "[ERROR] passwords not found: /usr/share/wordlists/rockyou.txt"), set())
checa("D251: e o caminho dela sobrevive como prova quando a saida o lista",
      analisar_saida("/root/rockyou.txt\n"
                     "[ERROR] passwords not found: /usr/share/wordlists/rockyou.txt\n"
                     ).caminhos, ["/root/rockyou.txt"])

# `command not found` nomeia COMANDO, nao caminho. Sem `/`, nao ha o que tirar --
# e e a forma que D212 ja trata noutro lugar.
checa("D251: `command not found` nao declara caminho ausente",
      _declarados_ausentes("bash: line 1: sudo: command not found"), set())
checa("D251: nem a forma do dash",
      _declarados_ausentes("/bin/sh.real: 1: ip: not found"), set())

# NAO-REGRESSAO, e e o teste que protege o conserto de si mesmo: caminho REAL na
# MESMA saida de uma refutacao continua provado. A guarda e por caminho, nao por
# saida -- derrubar a saida inteira perderia tudo o que ela trouxe de verdade.
checa("D251: caminho real sobrevive na mesma saida que refuta outro",
      analisar_saida("---/opt/diagnostico/config.ini---\n[db]\nsenha=x\n"
                     "---/var/log/sulog---\n"
                     "cat: /var/log/sulog: No such file or directory\n"
                     ).caminhos, ["/opt/diagnostico/config.ini"])
checa("D251: saida sem refutacao nenhuma nao perde nada",
      analisar_saida("/etc/passwd\n/etc/shadow\n").caminhos,
      ["/etc/passwd", "/etc/shadow"])

if falhas:
    print(f"{len(falhas)} FALHA(S):")
    for f in falhas:
        print("  -", f)
    sys.exit(1)

print("todos os testes do grafo passaram")
