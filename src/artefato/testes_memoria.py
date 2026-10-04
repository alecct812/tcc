"""Exercita o braco B: memoria conversacional linear com resumo entre fases.

Arquivo separado pela mesma razao dos outros: a peca e outra. Roda pelo mesmo
comando em `testes.py`, para ninguem executar so metade.

**Nenhum teste toca a rede, o Docker ou `execucoes/`** (D25). O motor e falso, o
executor e falso, e o grafo e montado aqui dentro.

O teste mais importante deste arquivo e `o segredo da credencial chega a
memoria`. Ele existe porque `Laco._absorver` devolve `"1 credencial(is)"` e
empurra o valor para o grafo: um braco B montado a partir dos resumos nunca
veria a senha, jamais autenticaria, e o resultado pareceria confirmar a
hipotese de forma esmagadora -- por handicap nosso (D125).

Uso:  python testes_memoria.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

from ferramentas import Executor
from grafo import Grafo
from grafo.modelo import Host
from laco import Laco
from laco.memoria import (CABECALHO, PEDIDO_DE_RESUMO, TETO_DE_TEXTO,
                          MemoriaLinear, fatos_novos)
from grafo.serializacao import NOTA_DO_ARNES, serializar_tentativas
from laco.prompt import RABO
from modelo.resultado import Resultado

falhas: list[str] = []


def checa(rotulo: str, obtido, esperado) -> None:
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        falhas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")


class MotorDeResumo:
    """Devolve resumos prontos e conta chamadas. Nao fala com ninguem."""

    nome = "falso"

    def __init__(self, *respostas: str, categoria: str = "aceita",
                 categoria_recusa: str | None = None):
        self.respostas = list(respostas)
        self.categoria = categoria
        self.categoria_recusa = categoria_recusa
        self.prompts: list[str] = []
        self.regime = "raciocinio"
        self.modelo = "falso-1"

    def identificacao(self) -> dict:
        return {"motor": self.nome, "modelo": self.modelo,
                "regime": self.regime}

    def chamar(self, prompt: str) -> Resultado:
        self.prompts.append(prompt)
        texto = self.respostas.pop(0) if self.respostas else "resumo"
        return Resultado(motor=self.nome, modelo=self.modelo,
                         regime=self.regime, texto=texto,
                         categoria=self.categoria,
                         categoria_recusa=self.categoria_recusa,
                         entrada_tokens=100, saida_tokens=20)


# ============================================================ fatos_novos

# D201. OS DOIS TEXTOS SAO AMBIENTE, sem a secao de tentativas -- e isso e o
# contrato novo, nao economia de fixture. Quem escolhe o que entra no diff e
# quem chama (`Grafo.serializar_ambiente`), nao mais um recorte por string
# dentro de `fatos_novos`.
ANTES = """=== HOSTS ===
[h01] 172.20.0.5 atacante origem
[h02] 172.20.0.10 nao enumerado

=== CREDENCIAIS ===
nenhuma obtida
"""
DEPOIS = """=== HOSTS ===
[h02] 172.20.0.10 3 servicos
[h01] 172.20.0.5 atacante origem

=== CREDENCIAIS ===
[c1] svc_deploy senha 7fQx2Lm9RtVzB4kd origem 172.20.0.10
"""

novos = fatos_novos(ANTES, DEPOIS)
checa("o fato novo aparece", "[h02] 172.20.0.10 3 servicos" in novos, True)
# O SEGREDO VEM JUNTO, e e a linha que impede o braco B de ser aleijado.
checa("e a credencial vem COM o segredo",
      any("7fQx2Lm9RtVzB4kd" in l for l in novos), True)
checa("linha que so mudou de lugar nao e fato novo",
      any("atacante origem" in l for l in novos), False)
# A SECAO DE TENTATIVAS DE A **E** O HISTORICO DE B: incluí-la poria cada acao
# duas vezes no prompt, uma como `acao:` e outra como `fato:`.
#
# ⚠️ **A CHECAGEM MUDOU DE LUGAR, e o lugar era o defeito (D201).** Ate 30 de
# setembro ela entregava a `fatos_novos` um texto COM a secao de tentativas e
# exigia que a funcao a recortasse. Isso provava que o cortador de string
# funcionava; nunca provava que o laco CHAMAVA o cortador com o texto certo. O
# contrato agora e de quem chama, entao e quem chama que tem de ser provado --
# as tres checagens abaixo, e a ultima e um passo de verdade do braco B.
_g = Grafo()
_g.absorver_hosts([Host(endereco="172.20.0.10")])
_g.abrir_tentativa("curl", ["curl", "http://172.20.0.10"])
checa("D201: o ambiente serializado nunca traz a secao de tentativas",
      "=== TENTATIVAS" in _g.serializar_ambiente(), False)
# E O BRACO A NAO PERDE NADA: a composicao tem de ser exata, byte a byte. Sem
# esta, partir a funcao poderia calar uma secao inteira do prompt do braco A e
# nenhuma checagem notaria.
checa("D201: a composicao devolve o texto inteiro do braco A",
      _g.serializar(),
      _g.serializar_ambiente() + "\n"
      + serializar_tentativas(list(_g.hosts.values()), _g.tentativas))
checa("linha em branco nao vira fato", all(l.strip() for l in novos), True)
# E A GUARDA PRECISA DE UM CASO PROPRIO. No fixture acima o ANTES ja tem linhas
# em branco, entao elas caem no `not in velhas` e a guarda `l.strip()` nunca
# roda -- a mutacao que a remove sobreviveu por isso. Aqui o ANTES nao tem
# nenhuma, e so a guarda separa o fato da linha vazia. O caminho e real:
# `_anotar_na_memoria` chama com `antes or ""`.
checa("e a guarda vale mesmo quando o ANTES nao tem linha em branco",
      fatos_novos("[h01] 172.20.0.5",
                  "[h01] 172.20.0.5\n\n[h02] 172.20.0.10"),
      ["[h02] 172.20.0.10"])
# Grafo que nao mudou nao produz fato: sem isto todo passo pareceria descobrir
# alguma coisa, e a metrica 11 e a 7 perderiam sentido no braco B.
checa("grafo parado nao produz fato", fatos_novos(DEPOIS, DEPOIS), [])


# ======================================================= montar o prompt

m = MemoriaLinear(MotorDeResumo())
p = m.montar(passo=1, limite=60)
checa("o prompt abre com o cabecalho do braco B",
      p.startswith(CABECALHO.format(passo=1, limite=60)), True)
# O RABO E BYTE A BYTE O DO BRACO A. Se divergir, os bracos deixam de
# compartilhar "mesmos prompts" (§4.1) e a comparacao nao isola mais nada.
checa("e termina com o RABO do braco A, byte a byte", p.endswith(RABO), True)
checa("o braco B nao anuncia grafo nenhum", "=== HOSTS ===" in p, False)
# HISTORICO VAZIO SE DECLARA: o braco A imprime "nenhuma acao registrada" e
# nunca omite secao. Cair direto na instrucao faria o passo 1 parecer truncado.
checa("historico vazio se declara", "nenhuma ação registrada" in p, True)
checa("e sem fase fechada nao ha secao de resumo",
      "RESUMO DAS FASES" in p, False)

m.anotar(numero=1, ferramenta="nmap", comando="nmap -sn 172.20.0.0/24",
         justificativa="mapear a DMZ", resumo="2 hosts, 0 servicos",
         fatos=["[h02] 172.20.0.10 nao enumerado"])
p = m.montar(passo=2, limite=60)
checa("a acao entra no historico", "acao: nmap nmap -sn 172.20.0.0/24" in p,
      True)
checa("o motivo tambem", "motivo: mapear a DMZ" in p, True)
checa("o resultado tambem", "resultado: 2 hosts, 0 servicos" in p, True)
checa("e o fato tambem", "fato: [h02] 172.20.0.10 nao enumerado" in p, True)
checa("o numero do passo vai no cabecalho", "PASSO 2 de 60" in p, True)


# ================================================== o fechamento da fase

def _encher(memoria, ate: int, fatos=None) -> None:
    for i in range(1, ate + 1):
        memoria.anotar(numero=i, ferramenta="nmap",
                       comando="nmap -sV -p- 172.20.0.10",
                       justificativa="enumerar servicos do host de entrada",
                       resumo="1 hosts, 3 servicos", fatos=fatos or [])


motor = MotorDeResumo("A fase 1 varreu a DMZ e achou o host de entrada.")
m = MemoriaLinear(motor, teto=1000)
_encher(m, 3)
checa("dentro do teto, a fase nao fecha", m.chamadas_de_resumo, 0)
_encher(m, 6)
checa("estourou o teto: a fase fecha", m.chamadas_de_resumo, 1)
checa("e quem escreveu o resumo foi o MODELO",
      m.resumos[0], "A fase 1 varreu a DMZ e achou o host de entrada.")
# O INVARIANTE E O TETO, nao a folga: depois de fechar, o historico volta a
# crescer ate bater no teto de novo. Afirmar "sempre abaixo da metade" seria
# afirmar mais do que o desenho promete -- e o teste falharia por estar errado,
# nao o codigo.
checa("o historico verbatim nunca passa do teto",
      len(m._texto_dos_passos()) <= 1000, True)
checa("a fase fechada saiu do verbatim", len(m.passos) < 9, True)
checa("mas nao ficou vazio", len(m.passos) > 0, True)
p = m.montar(passo=16, limite=60)
checa("o resumo entra no prompt, em secao propria",
      "=== RESUMO DAS FASES ANTERIORES ===" in p
      and "A fase 1 varreu a DMZ" in p, True)
# O PEDIDO DE RESUMO NAO DIZ O QUE PRESERVAR. Listar "credencial, host, rota"
# seria o arnes jogando o jogo pelo braco B -- a mesma objecao que
# `Laco._absorver` ja registra sobre nao instruir o agente a usar `-i`.
_instrucao = PEDIDO_DE_RESUMO.split("{historico}")[0].lower()
checa("o pedido de resumo nao lista o que preservar",
      any(x in _instrucao
          for x in ("credencial", "host", "rota", "sub-rede")), False)
checa("...e o historico a resumir vai junto no pedido",
      "host de entrada" in motor.prompts[0], True)

# A CHAMADA DE RESUMO CUSTA, e o custo entra na metrica 9. Ela NAO consome
# passo -- e gestao de contexto, nao acao --, mas cobra tokens que o braco A
# nunca gasta, e essa assimetria e ela propria um dado (D92).
checa("os tokens do resumo sao contados", (m.entrada_tokens, m.saida_tokens),
      (100, 20))
d = m.como_dicionario()
checa("e o registro conta as fases fechadas", d["fases_fechadas"], 1)
checa("e as chamadas de resumo", d["chamadas_de_resumo"], 1)

# UM PASSO SEMPRE FICA: um turno unico maior que o teto esvaziaria o historico
# inteiro e o agente decidiria o passo seguinte sem nada verbatim na frente.
m = MemoriaLinear(MotorDeResumo(), teto=10)
m.anotar(numero=1, ferramenta="nmap", comando="x" * 500, resumo="y" * 500)
checa("turno maior que o teto nao esvazia o historico", len(m.passos), 1)
checa("e nao dispara resumo de nada", m.chamadas_de_resumo, 0)

# RECUSA NAO VIRA RESUMO INVENTADO. O arnes escrever o resumo aqui seria o
# grafo com outro nome, justo onde o braco B mais precisa nao ter um.
m = MemoriaLinear(MotorDeResumo("", categoria="recusa",
                                categoria_recusa="cyber"), teto=1000)
_encher(m, 15)
checa("resumo recusado nao e inventado pelo arnes",
      "o resumo nao foi produzido" in m.resumos[0], True)
checa("e a fase perdida se declara como perdida",
      "se perdeu" in m.resumos[0], True)
# Resumo vazio conta igual: texto em branco no lugar de uma fase inteira seria
# perda silenciosa, e silencio e o que este projeto trata como pior que erro.
m = MemoriaLinear(MotorDeResumo("   "), teto=1000)
_encher(m, 15)
checa("resumo vazio tambem se declara perdido",
      "o resumo nao foi produzido" in m.resumos[0], True)

# O TETO PADRAO E O TAMANHO MEDIDO DO BRACO A, nao um numero redondo qualquer.
checa("o teto padrao e o do braco A medido no corpus", TETO_DE_TEXTO, 11200)


# ============================================== integracao com o laco

class ExecutorMudo(Executor):
    def __init__(self):
        super().__init__(conteiner="tcc-atacante")

    def rodar(self, execucao):
        execucao.codigo = 0
        execucao.saida = ""
        execucao.erro = ""
        execucao.wall_s = 0.1
        return execucao


class MotorQuePropoe:
    nome = "falso"

    def __init__(self, *respostas):
        self.respostas = list(respostas)
        self.prompts: list[str] = []
        self.regime = "raciocinio"
        self.modelo = "falso-1"

    def identificacao(self) -> dict:
        return {"motor": self.nome, "modelo": self.modelo,
                "regime": self.regime}

    def chamar(self, prompt: str) -> Resultado:
        self.prompts.append(prompt)
        return Resultado(motor=self.nome, modelo=self.modelo,
                         regime=self.regime,
                         texto=self.respostas.pop(0) if self.respostas else "",
                         categoria="aceita", entrada_tokens=10,
                         saida_tokens=2)


def _grafo_com_host() -> Grafo:
    g = Grafo()
    g.absorver_hosts([Host(endereco="172.20.0.10")])
    return g


PROPOSTA = ('{"alvo": "h02", "ferramenta": "nmap", '
            '"comando": "nmap -sn 172.20.0.10", "pivo": null, '
            '"justificativa": "mapear"}')

with tempfile.TemporaryDirectory() as tmp:
    motor = MotorQuePropoe(PROPOSTA)
    mem = MemoriaLinear(MotorDeResumo())
    laco = Laco(motor=motor, executor=ExecutorMudo(), grafo=_grafo_com_host(),
                pasta=pathlib.Path(tmp), limite=60, memoria=mem)
    p = laco.propor()
    enviado = motor.prompts[0]

checa("o braco B nao envia a serializacao do grafo",
      "=== HOSTS ===" in enviado, False)
checa("...e envia o historico", "=== HISTÓRICO ===" in enviado, True)

with tempfile.TemporaryDirectory() as tmp:
    motor = MotorQuePropoe(PROPOSTA)
    laco = Laco(motor=motor, executor=ExecutorMudo(), grafo=_grafo_com_host(),
                pasta=pathlib.Path(tmp), limite=60)
    laco.propor()
checa("e o braco A continua enviando o grafo, intacto",
      "=== HOSTS ===" in motor.prompts[0], True)


# O SEGREDO DA CREDENCIAL CHEGA A MEMORIA. E o teste que justifica o desenho
# de D125: sem ele o braco B veria "1 credencial(is)" e nunca o valor.
g = _grafo_com_host()
# `derivados=False` porque e o que o laco passa (D215): sem a bandeira
# este teste montaria o texto do braco A e o rotulo dele -- "chega ao
# prompt do braco B" -- viraria falso, que e a classe de defeito que §E53
# nomeia como a pior deste projeto.
antes = g.serializar_ambiente(derivados=False)
g.absorver_credencial(usuario="svc_deploy", tipo="senha",
                      segredo="7fQx2Lm9RtVzB4kd", origem="172.20.0.10")
mem = MemoriaLinear(MotorDeResumo())
mem.anotar(numero=1, ferramenta="curl", comando="curl http://172.20.0.10",
           justificativa="ler o config", resumo="http 200, 1 credencial(is)",
           fatos=fatos_novos(
               antes, g.serializar_ambiente(derivados=False)))
prompt = mem.montar(passo=2, limite=60)
checa("o resumo do passo NAO traz o segredo (e o que o laco produz)",
      "7fQx2Lm9RtVzB4kd" in "http 200, 1 credencial(is)", False)
checa("mas o segredo CHEGA ao prompt do braco B pelo fato",
      "7fQx2Lm9RtVzB4kd" in prompt, True)


# O BRACO VIAJA COM O PASSO (D125), como o limite em D116.
with tempfile.TemporaryDirectory() as tmp:
    pasta = pathlib.Path(tmp)
    laco = Laco(motor=MotorQuePropoe(PROPOSTA), executor=ExecutorMudo(),
                grafo=_grafo_com_host(), pasta=pasta, limite=60,
                memoria=MemoriaLinear(MotorDeResumo()))
    p = laco.propor()
    laco.executar(p)
    import json as _json
    linha = _json.loads(
        (pasta / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
checa("o passo do braco B se declara B", linha["braco"], "B")
checa("e traz o estado da memoria", linha["memoria"]["passos_verbatim"], 1)

# D201, O CHAMADOR -- que e o que o teste antigo nunca alcancava.
#
# Dois passos de verdade pelo laco, com propostas DIFERENTES para os dois
# fecharem. No segundo, o `antes` ja carrega a tentativa que o primeiro
# registrou, e o `depois` carrega as duas. Se o laco voltar a passar
# `serializar()` a `fatos_novos`, a acao do passo 2 entra no historico do braco
# B como `fato:` alem de como `acao:` -- duplicada, contra o teto de D125.
SEGUNDA_PROPOSTA = ('{"alvo": "h02", "ferramenta": "curl", '
                    '"comando": "curl http://172.20.0.10/", "pivo": null, '
                    '"justificativa": "ler a raiz"}')
with tempfile.TemporaryDirectory() as tmp:
    _laco = Laco(motor=MotorQuePropoe(PROPOSTA, SEGUNDA_PROPOSTA),
                 executor=ExecutorMudo(), grafo=_grafo_com_host(),
                 pasta=pathlib.Path(tmp), limite=60,
                 memoria=MemoriaLinear(MotorDeResumo()))
    _laco.executar(_laco.propor())
    _antes_inteiro = _laco.grafo.serializar()
    _laco.executar(_laco.propor())
    _depois_inteiro = _laco.grafo.serializar()
    _fatos = [f for p in _laco.memoria.passos for f in p.fatos]

# ⚠️ **CONTROLE POSITIVO, e sem ele a checagem seguinte nao vale nada.** Com
# `ExecutorMudo` o grafo nao ganha host nenhum, entao a lista de fatos e vazia
# por varios motivos -- e uma checagem que exige lista sem acao passaria mesmo
# se `fatos_novos` estivesse quebrada. Esta linha prova que HA o que vazar: com
# o texto inteiro, o diff traz a acao do passo 2. E a classe de teste vazio que
# a bateria ja me pegou fazendo quatro vezes.
_vazaria = fatos_novos(_antes_inteiro, _depois_inteiro)
checa("D201: (controle) com o texto inteiro a acao vazaria para o historico",
      any(l.lstrip().startswith("[t") for l in _vazaria), True)
checa("D201: o laco passa o ambiente, e nenhum fato carrega acao",
      any(f.lstrip().startswith("[t") for f in _fatos), False)
checa("D201: nem o texto do comando ja registrado",
      any("curl http://172.20.0.10/" in f for f in _fatos), False)

with tempfile.TemporaryDirectory() as tmp:
    pasta = pathlib.Path(tmp)
    laco = Laco(motor=MotorQuePropoe(PROPOSTA), executor=ExecutorMudo(),
                grafo=_grafo_com_host(), pasta=pasta, limite=60)
    p = laco.propor()
    laco.executar(p)
    import json as _json
    linha = _json.loads(
        (pasta / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
checa("o passo do braco A se declara A", linha["braco"], "A")
# `None`, nao zero: no braco A nao ha memoria linear, e zero afirmaria que ha
# uma e que ela esta vazia (D57).
checa("e a memoria e None, nao zero", linha["memoria"], None)


# O VETO ENTRA NO HISTORICO, porque entra no grafo do braco A. Omiti-lo daria
# ao braco B menos informacao -- ele repetiria a acao vetada sem saber.
FORA = ('{"alvo": "h02", "ferramenta": "nmap", '
        '"comando": "nmap -sn 8.8.8.8", "pivo": null, '
        '"justificativa": "varrer fora"}')
with tempfile.TemporaryDirectory() as tmp:
    mem = MemoriaLinear(MotorDeResumo())
    laco = Laco(motor=MotorQuePropoe(FORA), executor=ExecutorMudo(),
                grafo=_grafo_com_host(), pasta=pathlib.Path(tmp), limite=60,
                escopo=["172.20.0.0/24"], memoria=mem)
    p = laco.propor()
    laco.executar(p)
checa("a acao vetada entra no historico do braco B", len(mem.passos), 1)
checa("e o historico diz que foi vetada",
      "rejeitada" in (mem.passos[0].resumo or ""), True)

# RECUSA DE SALVAGUARDA NAO ENTRA: ela nao abre tentativa e nao aparece no
# prompt do braco A. Anota-la aqui daria ao braco B um sinal que A nao tem.
class MotorQueRecusa:
    nome = "falso"
    regime = "raciocinio"
    modelo = "falso-1"

    def identificacao(self) -> dict:
        return {"motor": self.nome, "modelo": self.modelo,
                "regime": self.regime}

    def chamar(self, prompt: str) -> Resultado:
        return Resultado(motor=self.nome, modelo=self.modelo,
                         regime=self.regime, texto="", categoria="recusa",
                         categoria_recusa="cyber", entrada_tokens=10,
                         saida_tokens=0)


with tempfile.TemporaryDirectory() as tmp:
    mem = MemoriaLinear(MotorDeResumo())
    laco = Laco(motor=MotorQueRecusa(), executor=ExecutorMudo(),
                grafo=_grafo_com_host(), pasta=pathlib.Path(tmp), limite=60,
                memoria=mem)
    laco.propor()
checa("recusa de salvaguarda nao entra no historico", len(mem.passos), 0)

with tempfile.TemporaryDirectory() as tmp:
    mem = MemoriaLinear(MotorDeResumo())
    laco = Laco(motor=MotorQuePropoe("isto nao e JSON"),
                executor=ExecutorMudo(), grafo=_grafo_com_host(),
                pasta=pathlib.Path(tmp), limite=60, memoria=mem)
    laco.propor()
checa("proposta malformada tambem nao entra", len(mem.passos), 0)


# --------------------------- O PONTO DE PARTIDA DO BRACO B (D151, sabado 26)
#
# `semear_origem` poe a maquina do agente no grafo antes do passo 1, e o braco A
# a le na serializacao. O braco B recebe fato por DIFF da serializacao (D125), e
# um fato que ja estava la antes do primeiro diff NUNCA e novo: ele comecava sem
# saber o proprio endereco.
#
# A `coleta-B-01` pagou: 80 passos, elo 0, nenhum comando contra 172.20 ou
# 172.21, 49 deles varrendo faixas inexistentes. E a "adivinhacao de faixa" que
# §E12 mediu em 18 de setembro, e que `semear_origem` existe para evitar.
with tempfile.TemporaryDirectory() as tmp:
    mem_b = MemoriaLinear(MotorDeResumo())
    laco_b = Laco(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                  grafo=Grafo(), pasta=pathlib.Path(tmp) / "b", limite=80,
                  memoria=mem_b)
    laco_b.semear_origem("172.20.0.5", "atacante")
    p1 = mem_b.montar(passo=1, limite=80)
    checa("o braco B sabe o proprio endereco no passo 1", "172.20.0.5" in p1, True)
    checa("e a sub-rede da propria maquina", "172.20.0.0/24" in p1, True)
    # NAO E O GRAFO COM OUTRO NOME: prosa, sem secao nem rotulo de host. Dar
    # estrutura ao braco B apagaria a variavel independente.
    checa("e nao recebe secao de grafo nenhuma",
          [s for s in ("=== SUB-REDES ===", "=== HOSTS ===",
                       "=== ALCANCABILIDADE ===", "=== CREDENCIAIS ===",
                       "=== TENTATIVAS JA REALIZADAS ===") if s in p1], [])
    checa("nem o rotulo [h01] que a serializacao usa", "[h01]" in p1, False)
    # A SUB-REDE INTERNA continua por descobrir: §2.3 restringe plantar o que
    # aponta para ela, e o proprio endereco nao aponta.
    checa("e a sub-rede interna nao vaza junto",
          [t for t in ("172.21", "interna") if t in p1], [])
    # EM TODO PASSO, nao so no primeiro: emitir uma vez daria ao braco B um
    # fato que ele PERDE, e perda e assimetria nova em vez de conserto.
    mem_b.anotar(numero=1, ferramenta="nmap", comando="nmap -sn 172.20.0.0/24",
                 justificativa="varrer", resumo="5 hosts", fatos=[])
    checa("o ponto de partida sobrevive ao primeiro turno",
          "172.20.0.5" in mem_b.montar(passo=2, limite=80), True)

# SEM ORIGEM SEMEADA nao se inventa ponto de partida: memoria construida sozinha
# nao ganha secao nenhuma.
mem_solta = MemoriaLinear(MotorDeResumo())
checa("memoria sem semeadura nao inventa ponto de partida",
      "=== PONTO DE PARTIDA ===" in mem_solta.montar(passo=1, limite=80), False)

# O BRACO A NAO GANHA A SECAO: ela e a forma do braco B para o mesmo fato, e
# duplicar no A seria dizer duas vezes o que a serializacao ja diz.
with tempfile.TemporaryDirectory() as tmp:
    laco_a = Laco(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                  grafo=Grafo(), pasta=pathlib.Path(tmp) / "a", limite=80)
    laco_a.semear_origem("172.20.0.5", "atacante")
    checa("semear no braco A nao quebra por nao haver memoria",
          laco_a.grafo.hosts["172.20.0.5"].origem, True)

print()
# ------------------ A MEMORIA SOBREVIVE A MORTE DO PROCESSO (D152, sabado 26)
#
# `retomar` restaurava o grafo e os contadores e NAO reconstruia a memoria: um
# braco B interrompido voltava com historico vazio no passo em que parou -- sem
# erro, sem aviso, com o contador de passos seguindo em frente. Mesma classe de
# D126, onde o `limite` gravado nao vinculava ninguem.
#
# O modo ASSISTIDO torna isto obrigatorio: la o processo morre entre propor e
# executar, TODO passo, e o braco B nunca teria memoria nenhuma.
with tempfile.TemporaryDirectory() as tmp:
    pasta_d152 = pathlib.Path(tmp) / "exec"
    mem_1 = MemoriaLinear(MotorDeResumo())
    laco_1 = Laco(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                  grafo=Grafo(), pasta=pasta_d152, limite=80, memoria=mem_1)
    laco_1.semear_origem("172.20.0.5", "atacante")
    mem_1.anotar(numero=1, ferramenta="nmap",
                 comando="nmap -sn 172.20.0.0/24", justificativa="varrer",
                 resumo="5 hosts", fatos=["h02 aprendido"])
    mem_1.anotar(numero=2, ferramenta="curl", comando="curl http://alvo/",
                 justificativa="ler", resumo="http 200", fatos=[])
    laco_1.passo = 3
    laco_1._salvar()
    checa("a memoria do braco B vai ao disco", (pasta_d152 / "memoria.json").exists(), True)

    # O PROCESSO MORREU. Objeto novo, memoria nova, mesma pasta.
    mem_2 = MemoriaLinear(MotorDeResumo())
    laco_2 = Laco.retomar(motor=MotorDeResumo(),
                          executor=Executor(conteiner="x"), pasta=pasta_d152,
                          limite=80, memoria=mem_2)
    checa("e volta inteira ao retomar", len(mem_2.passos), 2)
    p_d152 = mem_2.montar(passo=laco_2.passo, limite=80)
    checa("o turno 1 esta no prompt de novo", "nmap -sn 172.20.0.0/24" in p_d152, True)
    checa("o turno 2 tambem", "curl http://alvo/" in p_d152, True)
    checa("e o FATO aprendido nao se perde", "h02 aprendido" in p_d152, True)
    checa("nem o ponto de partida", "172.20.0.5" in p_d152, True)

    # O CUSTO DO RESUMIDOR volta junto: a metrica 9 soma a execucao inteira, e
    # zerar na retomada subnotificaria o custo do braco B -- a assimetria de
    # custo que D92 manda medir.
    mem_3 = MemoriaLinear(MotorDeResumo())
    mem_3.chamadas_de_resumo, mem_3.entrada_tokens, mem_3.saida_tokens = 2, 600, 90
    mem_3.resumos = ["resumo da fase 1"]
    laco_3 = Laco(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                  grafo=Grafo(), pasta=pasta_d152, limite=80, memoria=mem_3)
    laco_3._salvar()
    mem_4 = MemoriaLinear(MotorDeResumo())
    Laco.retomar(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                 pasta=pasta_d152, limite=80, memoria=mem_4)
    checa("as chamadas de resumo voltam, para a metrica 9 nao subnotificar",
          (mem_4.chamadas_de_resumo, mem_4.entrada_tokens, mem_4.saida_tokens),
          (2, 600, 90))
    checa("e os resumos de fase ja escritos voltam como texto",
          mem_4.resumos, ["resumo da fase 1"])

# BRACO A NAO GRAVA memoria.json: nao ha memoria, e criar arquivo vazio faria
# `braco` parecer B para quem ler a pasta.
with tempfile.TemporaryDirectory() as tmp:
    pasta_a = pathlib.Path(tmp) / "a"
    la = Laco(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
              grafo=Grafo(), pasta=pasta_a, limite=80)
    la.semear_origem("172.20.0.5", "atacante")
    la._salvar()
    checa("o braco A nao grava memoria.json", (pasta_a / "memoria.json").exists(), False)
    # E retomar um braco A com pasta sem memoria.json nao levanta.
    Laco.retomar(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                 pasta=pasta_a, limite=80)
    checa("e retomar o braco A continua funcionando", True, True)

# EXECUCAO NO PASSO 1 nao tem memoria.json, e a memoria vazia esta certa ali.
with tempfile.TemporaryDirectory() as tmp:
    mem_nova = MemoriaLinear(MotorDeResumo())
    Laco.retomar(motor=MotorDeResumo(), executor=Executor(conteiner="x"),
                 pasta=pathlib.Path(tmp) / "nunca-rodou", limite=80,
                 memoria=mem_nova)
    checa("pasta sem memoria.json nao levanta, e a memoria fica vazia",
          (len(mem_nova.passos), mem_nova.partida), (0, []))


# =============== D215: a CONSEQUENCIA, medida no que chega ao braco B mesmo
#
# ⚠️ **As 30 checagens de `testes_grafo.py` cobrem o RENDERIZADOR; estas cobrem
# o que o braco B recebe.** A distincao nao e academica: em 30 de setembro D207
# passou por cinco testes de D200 porque todos olhavam a lista de credenciais e
# nenhum olhava o elo. Cobertura de mecanismo sem cobertura de consequencia.
#
# E vai pelo LACO, nao por chamada a mao -- a licao de D151, que passou por 24
# checagens verdes justamente por montar a memoria por fora do caminho real.
SAIDA_DA_VARREDURA = (
    "Starting Nmap 7.93\n"
    "Nmap scan report for 172.21.0.10\n"
    "Host is up (0.00030s latency).\n"
    "PORT   STATE SERVICE\n"
    "22/tcp open  ssh\n"
    "Nmap scan report for 172.21.0.11\n"
    "Host is up (0.00028s latency).\n"
    "PORT   STATE SERVICE\n"
    "22/tcp open  ssh\n"
    "Nmap done: 2 IP addresses (2 hosts up) scanned in 0.30 seconds\n")


class ExecutorQueVarre(ExecutorMudo):
    """Devolve uma varredura de verdade, e guarda o texto do braco A no caminho.

    O instantaneo e tirado DENTRO do `rodar`, que e o intervalo entre o `antes`
    do laco e a absorcao -- e `abrir_tentativa`, que roda nesse intervalo, mexe
    em `tentativas` e nao no ambiente. Entao este texto e o `antes` do laco,
    renderizado como o braco A o receberia. E o que torna o controle honesto.
    """

    def __init__(self, grafo):
        super().__init__()
        self.grafo = grafo
        self.antes_do_braco_a = ""

    def rodar(self, execucao):
        self.antes_do_braco_a = self.grafo.serializar_ambiente()
        execucao.codigo = 0
        execucao.saida = SAIDA_DA_VARREDURA
        execucao.erro = ""
        execucao.wall_s = 0.2
        return execucao


VARREDURA_INTERNA = ('{"alvo": "172.21.0.0/24", "ferramenta": "nmap", '
                     '"comando": "nmap -sT -p22 172.21.0.0/24", '
                     '"pivo": "h02", "justificativa": "varrer a interna"}')

with tempfile.TemporaryDirectory() as tmp:
    _g215 = Grafo()
    _exe215 = ExecutorQueVarre(_g215)
    _laco215 = Laco(motor=MotorQuePropoe(VARREDURA_INTERNA), executor=_exe215,
                    grafo=_g215, pasta=pathlib.Path(tmp), limite=60,
                    memoria=MemoriaLinear(MotorDeResumo()))
    _laco215.semear_origem("172.20.0.5", "atacante")
    _g215.absorver_hosts([Host(endereco="172.20.0.12", nome="srv-deploy",
                               comprometido=True)])
    _laco215.executar(_laco215.propor())
    _fatos215 = [f for p in _laco215.memoria.passos for f in p.fatos]
    _controle215 = fatos_novos(_exe215.antes_do_braco_a,
                              _g215.serializar_ambiente())

# ⚠️ **O CONTROLE POSITIVO E A METADE QUE FAZ A CHECAGEM VALER.** Sem ele, "o
# braco B nao recebe rota" passaria verde num passo que nao produz rota
# nenhuma, e a bateria "descobriria" um buraco que eu mesmo cavei. Este passo
# PRODUZ a derivacao: a varredura acha dois hosts numa faixa nova, e o texto do
# braco A ganha a linha de rota junto com as linhas de host.
checa("D215: (controle) o texto do braco A entregaria a rota como fato",
      any("172.21.0.0/24 rota desconhecida" in f for f in _controle215), True)
checa("D215: e o laco do braco B nao entrega rota nenhuma",
      any("rota desconhecida" in f or "so via" in f for f in _fatos215), False)
# E AS QUATRO OUTRAS DERIVACOES, no mesmo passo real.
checa("D215: nem secao de sub-redes",
      any("SUB-REDES" in f for f in _fatos215), False)
checa("D215: nem aresta de alcancabilidade",
      any("ALCANCABILIDADE" in f or " via ssh em " in f for f in _fatos215),
      False)
checa("D215: nem afirmacao sobre ausencia de dado",
      any("nao enumeradas" in f for f in _fatos215), False)
checa("D215: nem complemento de conjunto",
      any("nao testada" in f for f in _fatos215), False)
checa("D215: nem contabilidade de teto",
      any("nao listados" in f or "nao listadas" in f for f in _fatos215),
      False)

# ---- E O QUE O BRACO B CONTINUA APRENDENDO, pelo mesmo passo --------------
# Sem estas o teste acima seria satisfeito por um braco B que nao recebe nada,
# e "nao recebe nada" nao e o que §4.1 pede -- §4.1 pede que ele receba os
# EVENTOS em vez do estado consolidado.
checa("D215: o braco B aprende os dois hosts que a varredura achou",
      sum(1 for f in _fatos215 if "172.21.0.1" in f), 2)
checa("D215: com a faixa interna legivel na linha do host",
      any("172.21.0.10 sem nome 172.21.0.0/24" in f for f in _fatos215), True)
checa("D215: e com o servico que o nmap imprimiu",
      any("servicos: 22/tcp ssh" in f for f in _fatos215), True)
# A CONTA FECHA: o controle tem os 4 fatos de observacao mais a 1 linha de
# derivacao. Se um dia um fato de observacao sumir junto com as derivacoes,
# esta linha acusa -- a igualdade exige que a diferenca seja de exatamente uma.
checa("D215: a diferenca entre os dois e de UMA linha, a derivada",
      len(_controle215) - len(_fatos215), 1)


# ---- O `antes` TAMBEM TEM DE SER SEM DERIVADOS, e as duas mutacoes disso
#      SOBREVIVERAM ao primeiro teste ------------------------------------
#
# ⚠️ **EU ARGUMENTEI QUE ERA EQUIVALENTE E A MEDIDA ME DESMENTIU.** O raciocinio
# era: mutar so o `antes` apenas ACRESCENTA linhas a ele, e o `depois` nunca tem
# linha derivada, entao `(A - B) ∩ B = ∅` e o diff nao muda. A algebra esta
# certa e a premissa estava errada -- **ela esquece as linhas MISTAS**, as que
# tem observacao E derivacao no mesmo texto:
#
#   antes COM derivados   ` caminhos vistos: /etc/passwd (+254 nao listados)`
#   depois SEM derivados  ` caminhos vistos: /etc/passwd`
#
# Sao strings diferentes, entao a segunda e "nova" e volta como fato. Medido
# sobre o grafo da `piloto-B-01-preD211`, reconstruido host a host: **14 de 20
# transicoes divergem**, e na `piloto-A-01` a linha de caminhos tem mais de dois
# mil caracteres -- repetidos a cada passo, contra o teto de texto que D125
# existe para manter. A linha de credencial com `; nao testada ...` faz o mesmo.
#
# Nao e so desperdicio: o braco B passaria a receber um "fato novo" que nao e
# fato nenhum, em todo passo, e a metrica 11 contaria descoberta onde nao houve.
UM_CAMINHO_E_UM_TETO = ('{"alvo": "h02", "ferramenta": "nmap", '
                        '"comando": "nmap -sn 172.20.0.11", "pivo": null, '
                        '"justificativa": "achar o vizinho"}')
SAIDA_DO_VIZINHO = ("Nmap scan report for 172.20.0.11\n"
                    "Host is up (0.00022s latency).\n"
                    "Nmap done: 1 IP address (1 host up) scanned in 0.2s\n")


class ExecutorQueAchaVizinho(ExecutorMudo):
    def rodar(self, execucao):
        execucao.codigo = 0
        execucao.saida = SAIDA_DO_VIZINHO
        execucao.erro = ""
        execucao.wall_s = 0.1
        return execucao


def _com_teto_de_caminhos() -> Grafo:
    """Um grafo em que a linha de caminhos e MISTA: observacao mais contagem.

    E a forma que todo host do laboratorio toma depois de um `find` largo, e a
    unica em que a mutacao do `antes` tem efeito. Sem este fixture os dois
    testes passam verdes e as mutacoes sobrevivem -- foi o que aconteceu.
    """
    g = _grafo_com_host()
    h = g.hosts["172.20.0.10"]
    h.caminhos = ["/etc/passwd", "/opt/diagnostico/config.ini"]
    h.caminhos_omitidos = 254
    return g


with tempfile.TemporaryDirectory() as tmp:
    _mem217 = MemoriaLinear(MotorDeResumo())
    _laco217 = Laco(motor=MotorQuePropoe(UM_CAMINHO_E_UM_TETO),
                    executor=ExecutorQueAchaVizinho(),
                    grafo=_com_teto_de_caminhos(), pasta=pathlib.Path(tmp),
                    limite=60, memoria=_mem217)
    _laco217.executar(_laco217.propor())
    _f217 = [f for p in _mem217.passos for f in p.fatos]
checa("D215: o passo EXECUTADO aprende o host novo",
      any("172.20.0.11" in f for f in _f217), True)
checa("D215: e nao repete a linha de caminhos que nao mudou",
      any("caminhos vistos" in f for f in _f217), False)

# E O MESMO PELO CAMINHO DA REJEICAO, que e a OUTRA chamada e pode esquecer a
# bandeira sozinha. O veto nao muda o ambiente, entao a lista de fatos tem de
# sair VAZIA -- com a mutacao ela traz a linha de caminhos inteira.
with tempfile.TemporaryDirectory() as tmp:
    _mem218 = MemoriaLinear(MotorDeResumo())
    _laco218 = Laco(motor=MotorQuePropoe(FORA), executor=ExecutorMudo(),
                    grafo=_com_teto_de_caminhos(), pasta=pathlib.Path(tmp),
                    limite=60, escopo=["172.20.0.0/24"], memoria=_mem218)
    _laco218.executar(_laco218.propor())
    _f218 = [f for p in _mem218.passos for f in p.fatos]
checa("D215: (controle) a acao vetada entrou no historico", len(_mem218.passos),
      1)
checa("D215: e o passo REJEITADO nao produz fato nenhum", _f218, [])
# O SEGREDO pelo caminho sem derivados esta checado acima, no teste
# `mas o segredo CHEGA ao prompt do braco B pelo fato`, que D215 poe no
# caminho do laco. Uma segunda copia dele morava aqui e saiu: duas
# checagens iguais nao somam cobertura, fazem uma mutacao sobreviver e
# convidam a registra-la como equivalente.


# ================ D218: a restricao do arnes chega aos DOIS bracos
#
# ⚠️ **Por nove dias e quinze execucoes ela chegava a UM.** A frase saia na linha
# do host de origem, dentro de `serializar_ambiente`: o braco A a lia em todo
# passo e o braco B **nunca**. Conferido nas 15 execucoes do braco B com memoria
# em disco -- ausente em `partida`, nos fatos, nos resumos de passo e nos de
# fase, em 15 de 15.
#
# E o comentario que justifica a linha afirmava o contrario: *"sem isto ele
# queima passos descobrindo a restricao, em toda execucao e NOS DOIS BRACOS"*.
# Rotulo falso na nossa propria documentacao, a classe que §E53 nomeia como a
# pior do projeto. Medido na `coleta-B-01`: 2 passos do braco B montando
# `nohup nc -lvnp 4444 &`, shell reverso, contra 0 do braco A.
#
# **Nao e estado do ambiente nem derivacao do grafo** -- e como ESTA FERRAMENTA
# funciona. Por isso entra pela semeadura (o canal de D151) e nao pelo diff de
# fatos: pelo diff ela nunca chegaria, porque a semeadura acontece antes do
# primeiro `antes` e a linha ja esta no lado velho. **Foi exatamente assim que
# ela se perdeu.**
with tempfile.TemporaryDirectory() as tmp:
    _mn = MemoriaLinear(MotorDeResumo())
    _ln = Laco(motor=MotorDeResumo(), executor=ExecutorMudo(), grafo=Grafo(),
               pasta=pathlib.Path(tmp), limite=80, memoria=_mn)
    _ln.semear_origem("172.20.0.5", "atacante")
    _pn = _mn.montar(passo=1, limite=80)
checa("D218: a restricao do arnes chega ao prompt do braco B",
      NOTA_DO_ARNES in _pn, True)
checa("D218: e vem no ponto de partida, nao em secao de grafo",
      NOTA_DO_ARNES in "\n".join(_mn.partida), True)
# ⚠️ **A MESMA CONSTANTE NOS DOIS, nao duas copias da frase.** Em 21 de setembro
# duas copias de `juntar` e `autenticou` divergiram em menos de uma hora; aqui
# elas divergiriam em silencio e a assimetria voltaria sem teste vermelho.
_gn = Grafo()
_gn.semear_origem("172.20.0.5", "atacante")
checa("D218: e o braco A continua recebendo a MESMA frase",
      NOTA_DO_ARNES in _gn.serializar_ambiente(), True)
checa("D218: byte a byte, na linha que ele ja lia",
      f" nota: {NOTA_DO_ARNES}" in _gn.serializar_ambiente(), True)
# E O CONTROLE: a constante nao e vazia. Com `NOTA_DO_ARNES = ""` as quatro
# checagens acima passariam com louvor sem verificar nada -- a classe de D158,
# a guarda que so falha quando e necessaria.
checa("D218: (controle) a constante tem texto de verdade",
      len(NOTA_DO_ARNES) > 20 and "segundo plano" in NOTA_DO_ARNES, True)
# ⚠️ E O QUE A FRASE NAO PODE SER: instrucao do que fazer. Ela descreve a
# restricao e para ali -- dizer "use X em vez de shell reverso" seria o arnes
# jogando pelo agente, e a instrucao iria para os dois bracos, podendo apagar a
# diferenca que §4.4 mede (D145, D148).
checa("D218: e ela nao ensina o que fazer no lugar",
      any(t in NOTA_DO_ARNES.lower() for t in ("use ", "escreva", "prefira")),
      False)
# A SEMEADURA DO BRACO A NAO LEVANTA sem memoria, e o braco A nao ganha
# `partida` -- a nota chega a ele pela serializacao, nao por aqui.
with tempfile.TemporaryDirectory() as tmp:
    _la = Laco(motor=MotorDeResumo(), executor=ExecutorMudo(), grafo=Grafo(),
               pasta=pathlib.Path(tmp), limite=80)
    _la.semear_origem("172.20.0.5", "atacante")
checa("D218: no braco A a semeadura nao cria memoria nenhuma",
      _la.memoria, None)


# ====== D229: o BRACO pertence a execucao, nao a invocacao
#
# ⚠️ **A variavel independente do experimento podia trocar no meio da execucao,
# em silencio, e o registro passava a concordar com a corrupcao.**
#
# D126 guarda `limite` e `ate_elo` com o argumento *"o protocolo pertence a
# execucao, nao a invocacao"*. O braco nao tinha guarda -- e `--braco` tem
# padrao **"A"** na CLI, entao retomar um braco B esquecendo `--braco B` fazia
# o laco seguir como braco A: a `memoria.json` ficava orfa e o `estado.json`
# era REESCRITO dizendo `"braco": "A"`.
#
# Reproduzido em 1 de outubro: gravado `braco='B'`, retomado sem `memoria`, um
# salvamento, e o registro dizia `'A'`.
with tempfile.TemporaryDirectory() as tmp:
    _pb = pathlib.Path(tmp) / "exec"
    _mb = MemoriaLinear(MotorDeResumo())
    _lb = Laco(motor=MotorQuePropoe(PROPOSTA), executor=ExecutorMudo(),
               grafo=Grafo(), pasta=_pb, limite=80, memoria=_mb)
    _lb.semear_origem("172.20.0.5", "atacante")
    _lb.executar(_lb.propor())
    _eb = json.loads((_pb / "estado.json").read_text(encoding="utf-8"))
    checa("D229: (cenario) o braco B se declara no registro", _eb["braco"], "B")
    checa("D229: (cenario) e a memoria.json existe no disco",
          (_pb / "memoria.json").exists(), True)

    # RETOMAR SEM MEMORIA LEVANTA, e a mensagem diz o que fazer.
    _erro = None
    try:
        Laco.retomar(motor=MotorDeResumo(), executor=ExecutorMudo(), pasta=_pb)
    except ValueError as e:
        _erro = str(e)
    checa("D229: retomar um braco B sem memoria LEVANTA", _erro is not None,
          True)
    checa("D229: e a mensagem diz os dois bracos e o que fazer",
          all(t in (_erro or "") for t in ("braco=B", "braco=A", "--braco B")),
          True)
    # ⚠️ E O REGISTRO NAO FOI TOCADO: levantar antes de salvar e o que impede a
    # evidencia de ser apagada. Sem esta checagem, uma guarda que levantasse
    # DEPOIS do `_salvar` passaria verde e o estrago estaria feito.
    checa("D229: e o registro continua dizendo B, intacto",
          json.loads((_pb / "estado.json").read_text(encoding="utf-8"))["braco"],
          "B")

    # E A SIMETRIA: retomar COM memoria uma execucao do braco A tambem levanta.
    _pa = pathlib.Path(tmp) / "execA"
    _la = Laco(motor=MotorQuePropoe(PROPOSTA), executor=ExecutorMudo(),
               grafo=Grafo(), pasta=_pa, limite=80)
    _la.semear_origem("172.20.0.5", "atacante")
    _la.executar(_la.propor())
    _erro2 = None
    try:
        Laco.retomar(motor=MotorDeResumo(), executor=ExecutorMudo(), pasta=_pa,
                     memoria=MemoriaLinear(MotorDeResumo()))
    except ValueError as e:
        _erro2 = str(e)
    checa("D229: e a guarda e SIMETRICA -- braco A com memoria tambem levanta",
          _erro2 is not None, True)

    # ⚠️ **O CONTRAEXEMPLO QUE SEGURA A GUARDA, e sem ele a coleta nao roda:**
    # retomar com o braco CERTO continua funcionando. Uma guarda gulosa aqui
    # impediria o modo assistido, que retoma a cada passo.
    _ok = Laco.retomar(motor=MotorDeResumo(), executor=ExecutorMudo(),
                       pasta=_pb, memoria=MemoriaLinear(MotorDeResumo()))
    checa("D229: retomar com o braco certo continua funcionando",
          (_ok.memoria is not None, _ok.passo), (True, 2))
    _oka = Laco.retomar(motor=MotorDeResumo(), executor=ExecutorMudo(),
                        pasta=_pa)
    checa("D229: e o braco A tambem", (_oka.memoria, _oka.passo), (None, 2))

    # E EXECUCAO NOVA, sem `estado.json`, nao tem o que conferir -- a guarda
    # nao pode inventar divergencia onde nao ha registro.
    _nova = Laco.retomar(motor=MotorDeResumo(), executor=ExecutorMudo(),
                         pasta=pathlib.Path(tmp) / "nunca-rodou")
    checa("D229: pasta sem registro nao levanta", _nova.passo, 1)

if falhas:
    print(f"{len(falhas)} FALHA(S):")
    for f in falhas:
        print("  -", f)
    sys.exit(1)
print("todos os testes da memoria passaram")
