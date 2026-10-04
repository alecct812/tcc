"""Os parsers contra o laboratorio NO AR, com os comandos que o agente escreve.

⚠️ **Esta verificacao existe porque D230 atravessou TRINTA execucoes.** O parser
do nmap descartava toda porta depois da primeira que tivesse saida de script, e
a porta perdida no `host-web` era a **8080** -- onde mora o `/diagnostico`, a
entrada da cadeia. Nada acusava: a suite testava o parser com saida que EU
escrevi, `percorrer_cadeia.py` usa comandos fixos sem `-sC`, e `grafo.json`
guarda o que o parser deixou passar, nao a saida crua (§1.2).

**A lacuna tinha nome:** nenhuma verificacao comparava *o que a ferramenta
imprime* com *o que o parser guarda*, usando os comandos que o AGENTE de fato
escreve. As tres camadas antigas conferem o que o codigo faz; esta confere se o
codigo le o que o mundo diz.

**O criterio e contagem, nao conteudo.** Contar linha de porta aberta na saida
crua e comparar com o numero de servicos absorvidos nao depende de eu adivinhar
a forma -- e foi exatamente o adivinhar que falhou em D109, D211 e D230.

Grátis: nao chama modelo nenhum. Precisa do laboratorio no ar.

Uso:  python conferir_ferramentas.py
"""
from __future__ import annotations

import re
import shlex
import subprocess
import sys

from ferramentas import Curl, Execucao, Executor, Netcat, Nmap

ATACANTE = "tcc-atacante"

falhas: list[str] = []
notas: list[str] = []


def checa(rotulo: str, ok: bool, detalhe: str = "") -> None:
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}"
          + (f"   {detalhe}" if detalhe and not ok else ""))
    if not ok:
        falhas.append(f"{rotulo}: {detalhe}")


def nota(texto: str) -> None:
    print(f"  .. {texto}")
    notas.append(texto)


def rodar(comando: str, timeout: int = 420) -> Execucao | None:
    """Roda no atacante **pelo caminho de producao**, e devolve a `Execucao`.

    ⚠️ **A primeira versao desta funcao montava o `docker exec` a mao e punha
    `comando=["sh", "-c", <linha>]`.** Com isso a checagem de D225 falhou, e a
    culpa era dela: `Curl._destino` le a URL do **argv**, e eu havia escondido a
    URL dentro de um argumento do shell. O laco de verdade faz
    `comando = shlex.split(linha)` (`laco/__init__.py:994`) e entrega as duas
    coisas -- argv para o parser, linha para o shell do conteiner (D202).

    Dois defeitos meus no mesmo lugar, e os dois ja tinham nome no projeto:
    **D109/D211** (o teste media a forma que eu imaginei, o mundo entrega outra)
    e a licao da fixture de D227 (**reimplementar a fronteira em vez de passar
    por ela** -- la sobreviveram 3 mutacoes por isso). Agora quem executa e o
    `Executor`, e quem monta o argv e o `shlex.split` -- o mesmo par que roda na
    execucao paga. Verificacao que nao passa pelo codigo de producao nao verifica
    producao.
    """
    ex = Execucao(comando=shlex.split(comando), linha=comando)
    try:
        Executor(conteiner=ATACANTE).rodar(ex, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as erro:
        nota(f"nao rodou `{comando[:40]}`: {erro}")
        return None
    return ex


# ⚠️ **OS COMANDOS SAO OS QUE O AGENTE ESCREVEU**, copiados do corpo -- nao os
# que eu escolheria. `-sC` aparece por habito nas execucoes, e era justamente
# ele que disparava D230.
VARREDURAS = [
    ("a varredura inicial, com -sC, que foi o passo 1 de uma execucao paga",
     "nmap -sV -sC -p- --open 172.20.0.0/24"),
    ("varredura com -A, que tambem liga script",
     "nmap -sV -sC -p8000,8080 -A 172.20.0.10"),
    ("e sem script nenhum, o controle",
     "nmap -sV -p8000,8080 172.20.0.10"),
]

# ⚠️ **O CRITERIO COMPARA (PORTA, ESTADO), e nao a contagem de portas abertas.**
#
# A primeira versao contava so linha `open` na saida crua e comparava com TODOS
# os servicos que o parser guardou. Funcionou enquanto o laboratorio estava
# sujo -- e quebrou no laboratorio limpo, onde a 8000 do `host-web` esta
# `closed`: a saida declarava 1 aberta, o parser guardava 2 servicos, e a
# verificacao acusou o parser.
#
# **O parser estava certo.** `8000/tcp closed` e fato, e guarda-lo e o trabalho
# dele -- `RESPONDEU` em `nmap.py` ja distingue estado para decidir quem esta
# vivo. Quem estava errado era o criterio, que comparava coisa com outra.
#
# O criterio agora e mais forte do que o anterior e nao depende de estado
# nenhum: **cada linha da tabela de portas vira um servico, com o mesmo
# estado.** Mais e invencao, menos e descarte, e estado trocado e fato falso.
PORTA_NA_TABELA = re.compile(r"^(\d+)/(?:tcp|udp)\s+(\S+)", re.MULTILINE)

print("=" * 70)
print("OS PARSERS CONTRA O LABORATORIO, com os comandos que o agente escreve")
print("=" * 70)

_primeira: Execucao | None = None

for rotulo, comando in VARREDURAS:
    ex = rodar(comando)
    if ex is None:
        continue
    if _primeira is None:
        _primeira = ex
    cruas = {(int(porta), estado)
             for porta, estado in PORTA_NA_TABELA.findall(ex.saida or "")}
    hosts = Nmap().analisar(ex)
    guardados = {(s.porta, s.estado) for h in hosts for s in h.servicos}
    # ⚠️ A CONTAGEM E O CRITERIO. Igualdade exata: cada linha `open` da saida
    # tem de virar um servico. Mais que isso seria invencao, menos e descarte.
    checa(f"nmap: toda linha de porta chega ao grafo com o estado -- {rotulo}",
          bool(cruas) and cruas == guardados,
          f"a saida declarou {sorted(cruas)} e o parser guardou "
          f"{sorted(guardados)}"
          + ("  -- NENHUMA porta na saida crua: conjunto vazio igual a conjunto "
             "vazio aprovaria esta checagem sem verificar nada"
             if not cruas else ""))
    if cruas and cruas == guardados:
        print(f"      {len(hosts)} host(s), {len(guardados)} servico(s): "
              + "; ".join(f"{h.endereco}:"
                          + ",".join(f"{s.porta}/{s.estado}" for s in h.servicos)
                          for h in sorted(hosts, key=lambda x: x.endereco))[:110])

# ---------------------------------------------------------------- D228
# O palpite do nmap tem de chegar MARCADO como palpite.
ex = rodar("nmap -sV -p1337 172.20.0.11")
if ex is not None:
    incertos = [(s.porta, s.servico, s.incerto)
                for h in Nmap().analisar(ex) for s in h.servicos]
    tem_interrogacao = "?" in (ex.saida or "")
    if tem_interrogacao:
        checa("D228: o `?` do nmap chega ao grafo como `incerto`",
              any(i for _, _, i in incertos), f"extraido: {incertos}")
    else:
        nota("o nmap identificou a 1337 com firmeza nesta rodada; o caso de "
             "`incerto` nao se exercita (e isso muda com a versao do nmap)")

# ---------------------------------------------------------------- D227
# O teto de tempo preserva o que o comando ja escreveu. Usa um teto CURTO de
# proposito: o de producao e 300s (D80) e esta verificacao e grátis, nao lenta.
ex = rodar("nc -nv 172.20.0.11 1337", timeout=8)
if ex is not None and ex.codigo == -1:
    checa("D227: o parcial sobrevive ao teto de tempo",
          "succeeded" in (ex.erro or ""),
          f"erro={(ex.erro or '')[:70]!r}")
    checa("D227: e a mensagem do teto continua la",
          "tempo esgotado" in (ex.erro or ""), f"erro={(ex.erro or '')[:70]!r}")
    portas = [(h.endereco, s.porta, s.estado)
              for h in Netcat().analisar(ex) for s in h.servicos]
    checa("D227+D217: e o parser extrai fato do comando que pendurou",
          portas == [("172.20.0.11", 1337, "open")], f"extraido: {portas}")
elif ex is not None:
    nota(f"o `nc` nao pendurou nesta rodada (codigo {ex.codigo}); o caso do "
         "teto de tempo nao se exercita")

# ---------------------------------------------------------------- D225
# A rota sai do parser com a PORTA em que ela mora.
ex = rodar("curl -s -i http://172.20.0.10:8080/", timeout=30)
if ex is not None:
    r = Curl().analisar(ex)
    rotas = [(x.caminho, x.porta) for x in r.rotas]
    checa("D225: a rota sai do curl com a porta da URL",
          rotas and all(p == 8080 for _, p in rotas), f"rotas={rotas}")
    checa("D225: e a rota de entrada da cadeia esta entre elas",
          any(c == "/diagnostico" for c, _ in rotas), f"rotas={rotas}")

# ---------------------------------------------------------------- CONTROLE
# ⚠️ **O CONTROLE POSITIVO: esta verificacao TEM de acusar o defeito que ela
# existe para pegar.** Sem isto ela e so uma afirmacao minha.
#
# O defeito de D230 se reproduz em UMA linha -- a cerca volta a fechar na saida
# de script se `SAIDA_DE_SCRIPT` nunca casar. A troca e **em memoria, no objeto
# do modulo**: nada e escrito no disco, nao ha trava, nao ha arvore para
# corromper. E a saida reaproveitada e a que ja foi capturada acima, entao o
# controle nao custa varredura nenhuma.
#
# E ele confere as DUAS coisas que separam um controle de um enfeite: que a
# contagem passa a divergir, e que **a porta perdida e a 8080** -- a entrada da
# cadeia. Contagem sozinha passaria se o parser perdesse outra porta qualquer.
import ferramentas.nmap as _n   # noqa: E402

if _primeira is not None:
    _guardado = _n.SAIDA_DE_SCRIPT
    try:
        _n.SAIDA_DE_SCRIPT = re.compile("(?!)")   # nunca casa: a cerca volta
        _hosts = Nmap().analisar(_primeira)
        _n_servicos = sum(len(h.servicos) for h in _hosts)
        _portas = {s.porta for h in _hosts for s in h.servicos}
        _cruas_portas = {int(p) for p, _ in
                         PORTA_NA_TABELA.findall(_primeira.saida or "")}
    finally:
        _n.SAIDA_DE_SCRIPT = _guardado
    _cruas = len(PORTA_NA_TABELA.findall(_primeira.saida or ""))
    checa("controle: com a cerca de volta, a contagem DIVERGE",
          _n_servicos < _cruas,
          f"com o defeito reposto o parser guardou {_n_servicos} de "
          f"{_cruas} -- se forem iguais, esta verificacao nao pega nada")
    # ⚠️ **A AFIRMACAO SOBRE A 8080 SAIU DAQUI, e a razao esta em D233:** ela
    # dependia de o laboratorio estar SUJO. Com a 8000 aberta e vindo antes, a
    # cerca fechava nela e a 8080 se perdia; num laboratorio limpo a 8080 e a
    # primeira da tabela do `host-web` e sobrevive ao defeito.
    #
    # O caso especifico vive na suite, sobre saida CAPTURADA do laboratorio sujo
    # (`D230: as DUAS portas sobrevivem a saida de script`), que e onde ele pode
    # ser afirmado sem depender do estado de hoje. Aqui fica o que e verdade em
    # qualquer laboratorio: **alguma porta se perde**, e e isso que importa.
    checa("controle: e alguma porta da tabela se perde de fato",
          len(_portas) < len(_cruas_portas),
          f"com o defeito reposto sobraram {sorted(_portas)} de "
          f"{sorted(_cruas_portas)}")
    # E depois do controle o parser volta ao normal -- se o `finally` falhasse,
    # toda checagem posterior mediria o modulo quebrado.
    checa("controle: e o parser volta ao normal depois",
          8080 in {s.porta for h in Nmap().analisar(_primeira)
                   for s in h.servicos}, "o restauro do regex nao pegou")

print()
print("=" * 70)
if falhas:
    print(f"{len(falhas)} FALHA(S) -- o parser nao le o que a ferramenta diz:")
    for f in falhas:
        print("  -", f)
    sys.exit(1)
if notas:
    print(f"{len(notas)} nota(s), nenhuma e falha")
print("os parsers leem o que as ferramentas dizem, nos comandos do agente")
