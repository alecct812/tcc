"""Exercita o laco de decisao. Zero chamada ao modelo, zero rede, zero Docker.

Arquivo separado pelo mesmo motivo de `testes_grafo.py`: o laco e a peca que
`ARTEFATO.md` §1.2 poe entre o grafo e o mundo, e um arquivo unico ja passou de
mil linhas. Roda pelo mesmo comando em `testes.py`, para ninguem executar so
metade.

**O motor e falso de proposito.** O laco tem de ser testavel sem gastar chamada
e sem laboratorio de pe -- regra D25: nenhum teste depende de estado ambiente
da maquina.

Uso:  python testes_laco.py
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile
import types

import laco.__main__ as cli
from cadeia import carregar_cadeia
from ferramentas import Autenticacao, Execucao, Executor, Nmap, Ssh, julgou
from ferramentas import base
from ferramentas.ssh import CHAVE_INACESSIVEL, PERMISSAO_NEGADA
from ferramentas import analisar_saida
from grafo import Grafo
from grafo import Host as HostDoGrafo
from grafo.modelo import ACESSO_POR_PIVO, Credencial
from grafo.modelo import Servico as ServicoDoGrafo

# Valor de teste, deliberadamente DIFERENTE do segredo do laboratorio: um teste
# que casasse com `lab/cadeia.md` passaria a depender da configuracao do
# ambiente, e nenhum teste deste projeto depende de estado de maquina (D25).
SEGREDO_DE_TESTE = "s3nhaDeTeste99"
from laco import Laco, Proposta, ler_proposta
from laco.prompt import ESQUEMA, montar
from modelo import Resultado

falhas: list[str] = []


def checa(rotulo: str, obtido, esperado) -> None:
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        falhas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")


EXEMPLOS = pathlib.Path(__file__).resolve().parents[2] / "lab" / "saidas-exemplo"

# A raiz do repositorio, no mesmo formato que `testes_cadeia.py` ja usa (a
# Tarefa 1 a introduziu). Precisa existir aqui tambem: a metrica 3 so pode ser
# testada com a cadeia REAL do laboratorio, porque o teste do foco de revisao
# nº 3 (marcador fora do host do trofeu nao pode marcar) depende de qual
# endereco e qual texto sao os de verdade -- inventar os dois no teste
# deixaria a cobertura cega a um erro de digitacao em `lab/cadeia.json`.
RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
CAD = carregar_cadeia(RAIZ / "lab" / "cadeia.json")


def exemplo(nome: str) -> str:
    return (EXEMPLOS / nome).read_text(encoding="utf-8")


class MotorFalso:
    """Devolve respostas prontas, em ordem. Conta quantas vezes foi chamado."""

    nome = "falso"

    def __init__(self, *respostas: str, categoria: str = "aceita",
                 categoria_recusa: str | None = None,
                 explicacao_recusa: str | None = None,
                 http_status: int | None = None, throttles: int = 0,
                 espera_throttle_s: float = 0.0):
        self.respostas = list(respostas)
        self.categoria = categoria
        self.categoria_recusa = categoria_recusa
        self.explicacao_recusa = explicacao_recusa
        self.http_status = http_status
        self.throttles = throttles
        self.espera_throttle_s = espera_throttle_s
        self.prompts: list[str] = []
        self.regime = "raciocinio"
        self.modelo = "falso-1"

    def identificacao(self) -> dict:
        return {"motor": self.nome, "modelo": self.modelo, "regime": self.regime}

    def chamar(self, prompt: str) -> Resultado:
        self.prompts.append(prompt)
        texto = self.respostas.pop(0) if self.respostas else ""
        return Resultado(motor=self.nome, modelo=self.modelo, regime=self.regime,
                         texto=texto, categoria=self.categoria,
                         categoria_recusa=self.categoria_recusa,
                         explicacao_recusa=self.explicacao_recusa,
                         http_status=self.http_status,
                         throttles=self.throttles,
                         espera_throttle_s=self.espera_throttle_s,
                         entrada_tokens=100, saida_tokens=20)


class ExecutorFalso(Executor):
    """Nao roda nada: devolve a saida combinada. Guarda o que foi pedido."""

    def __init__(self, saida: str = "", codigo: int = 0, erro: str = ""):
        super().__init__(conteiner="tcc-atacante")
        self.saida, self.codigo, self.erro = saida, codigo, erro
        self.comandos: list[list[str]] = []

    def rodar(self, execucao: Execucao, timeout: int = 300) -> Execucao:
        self.comandos.append(self.envolver(execucao.comando,
                                           execucao.linha))
        execucao.saida, execucao.codigo, execucao.erro = (
            self.saida, self.codigo, self.erro)
        execucao.wall_s = 0.01
        return execucao


def grafo_da_dmz() -> Grafo:
    g = Grafo()
    g.absorver_hosts(Nmap().analisar(Execucao(
        comando=["nmap", "-sn", "172.20.0.0/24"], codigo=0,
        saida=exemplo("01-nmap-descoberta-dmz.txt"))))
    return g


def sessao(tmp, motor, executor, grafo=None) -> Laco:
    return Laco(motor=motor, executor=executor,
                grafo=grafo if grafo is not None else Grafo(),
                pasta=pathlib.Path(tmp), limite=60)


# ------------------------------------------------------------------ o prompt
#
# `docs/medicao/prompt-teste.txt` e o texto sobre o qual §E1 e §E2 mediram.
# Emitir outro faria aquelas medicoes descreverem um prompt que o agente nunca
# envia (mesmo motivo de D33).

p = montar(grafo_da_dmz(), passo=4, limite=60)
checa("o prompt abre dizendo que o historico foi descartado",
      "o historico foi descartado" in p or "histórico foi descartado" in p, True)
checa("traz o contador de passo", "PASSO 4 de 60" in p, True)
checa("traz a serializacao do grafo no meio", "=== HOSTS ===" in p, True)
checa("e as cinco secoes do grafo",
      all(s in p for s in ("=== SUB-REDES ===", "=== HOSTS ===",
                           "=== ALCANCABILIDADE ===", "=== CREDENCIAIS ===",
                           "=== TENTATIVAS JA REALIZADAS ===")), True)
checa("fecha com objetivo e instrucao",
      p.index("=== OBJETIVO ===") > p.index("=== HOSTS ==="), True)
checa("e a instrucao vem depois do objetivo",
      p.index("=== INSTRUCAO ===") > p.index("=== OBJETIVO ==="), True)
# O QUE D148 PUS NO PROMPT, e por que cada peca tem teste.
#
# O texto anterior dizia "Obter execucao no host-alvo e ler o trofeu". O
# singular AFIRMAVA que existe um host e que o trofeu esta nele, e o agente
# obedecia: 50 passos de `find -iname "*flag*"` na `coleta-A-01` antes do
# primeiro comando de rede, e o mesmo padrao na `teto-02` (nota da metrica 11).
checa("o objetivo nao afirma mais que existe UM host-alvo",
      "host-alvo" in p, False)
checa("e diz explicitamente que o host do trofeu e desconhecido",
      "nao sabe em qual host" in p, True)
# A secao de metodologia: o prompt deixa de ser so delimitador de formato.
checa("traz a secao de metodologia",
      "=== COMO SE ESPERA QUE VOCE TRABALHE ===" in p, True)
checa("e ela manda enumerar antes de explorar",
      "Enumere antes de explorar" in p, True)
# A SECAO DO PIVO (D147). CONTEXTO §5 lista "execucao por pivo" como peca do
# artefato, e peca que o agente nao sabe que existe nao esta sendo testada --
# esta sendo sorteada. A `diag-03` alcancou o elo 4 por acertar a convencao por
# acaso; as tentativas que escreviam o salto a mao falhavam sempre.
checa("traz a secao que declara como o pivo funciona",
      "=== COMO EXECUTAR POR PIVO ===" in p, True)
checa("e diz que o laco executa DE DENTRO do pivo", "DE DENTRO" in p, True)
checa("e proibe as tres formas de escrever o salto a mao",
      all(t in p for t in ("-J", "ProxyCommand", "`ssh` dentro de `ssh`")), True)
# ATE D159 ESTA LINHA PEDIA "secao CREDENCIAIS" no prompt, porque o agente tinha
# de ir buscar o segredo para escrever o comando. Nao tem mais: ele escreve o
# identificador e o laco resolve. O que o prompt precisa dizer mudou de LUGAR
# ("o valor esta la") para FORMA ("escreva `c01`"), e e a forma que se checa.
checa("diz para escrever o identificador da credencial",
      "IDENTIFICADOR" in p and "`c01`" in p, True)
checa("e diz que o laco resolve, para o agente nao ir buscar o valor",
      "substitui pelo segredo" in p, True)
# E O LIMITE QUE NAO SE CRUZA (D145 de novo, por outro caminho): a secao do
# pivo explica a FERRAMENTA, e nao o laboratorio. Nenhuma faixa, nenhuma
# sub-rede, nenhuma contagem de host.
checa("e nada disso nomeia faixa, sub-rede ou quantidade de hosts",
      [t for t in ("172.", "10.0.", "192.168.", "sub-rede interna",
                   "rede interna", "duas redes", "dois hosts")
       if t in p[p.index("=== OBJETIVO ==="):]], [])
# A SECAO "ONDE VOCE PODE AGIR" (D153). Depois de D145 tirar as faixas da
# mensagem de recusa, o agente passou a PROCURAR o escopo por tentativa e erro:
# 9 passos na `coleta-A-01` e 10 na `coleta-B-01`, com justificativas dizendo
# "ainda nao identificamos a faixa correta". Ele tinha a propria sub-rede no
# prompt; nao sabia que existia restricao.
checa("traz a secao que declara onde o agente pode agir",
      "=== ONDE VOCE PODE AGIR ===" in p, True)
checa("e manda agir so no que o estado registra",
      "enderecos que o estado ja registra" in p, True)
# A SEGUNDA FRASE afirma um fato do arnes de hoje. Se o orcamento mudar, ela
# mente -- e este teste e o que forca alguem a reler D153 antes de mudar.
checa("e avisa que a recusa gasta um passo, que e o arnes de hoje",
      "a recusa gasta um passo" in p, True)
# E NADA DISSO NOMEIA FAIXA: e contrato de ferramenta, nao mapa do laboratorio.
_i_onde = p.index("=== ONDE VOCE PODE AGIR ===")
checa("e a secao nao nomeia faixa, endereco nem contagem de rede",
      [t for t in ("172.", "10.0.", "192.168.", "/24", "duas", "sub-rede")
       if t in p[_i_onde:p.index("=== INSTRUCAO")]], [])
# A instrucao lista as seis ferramentas, como no texto medido -- mesmo as duas
# sem parser (D51). Encurtar a lista mudaria o texto que §E1 e §E2 mediram.
checa("a instrucao oferece as seis ferramentas do texto medido",
      all(f in p for f in ("nmap", "ssh", "hydra", "sqlmap", "curl", "netcat")),
      True)
checa("e pede para evitar tentativa ja registrada sem informacao nova",
      "sem informacao nova" in p, True)

# O esquema de saida estruturada (D52) tem de casar com os campos que a
# instrucao pede. Se os dois divergirem, o modelo obedece um e o parser espera
# o outro.
checa("o esquema exige os campos que a instrucao descreve",
      sorted(ESQUEMA["schema"]["properties"]),
      ["alvo", "comando", "ferramenta", "justificativa", "pivo"])
checa("e `pivo` nao e obrigatorio, porque acao direta nao tem pivo",
      "pivo" in ESQUEMA["schema"]["required"], False)
checa("mas os outros quatro sao",
      sorted(ESQUEMA["schema"]["required"]),
      ["alvo", "comando", "ferramenta", "justificativa"])

# D165: o campo `comando` precisa DIZER que leva a linha inteira. Sem isso, ao
# lado de `ferramenta` -- que JA nomeia a ferramenta --, o modelo le "comando =
# o argumento", escreve a URL crua, e o shell tenta executa-la como binario:
# codigo 127 e passo perdido. Medido em 28 de setembro: 11,5% dos comandos de
# `curl` do braco A contra 0,0% do braco B, porque so o braco B reapresenta a
# cada passo os proprios pares {ferramenta, comando}. E assimetria de
# instrumento contra o braco que a hipotese diz que vence, entao o contrato
# tem de estar escrito e tem de continuar escrito.
_desc_comando = ESQUEMA["schema"]["properties"]["comando"].get("description", "")
checa("o campo `comando` tem contrato escrito (D165)",
      bool(_desc_comando.strip()), True)
checa("e o contrato manda comecar pelo nome da ferramenta",
      "comecando pelo nome da ferramenta" in _desc_comando, True)
checa("e avisa que `ferramenta` e rotulo, nao prefixo",
      "rotulo" in _desc_comando and "prefixo" in _desc_comando, True)


# ------------------------------------------------------- leitura da resposta

mapa = {"h01": "172.20.0.1", "h02": "172.20.0.5", "h03": "172.20.0.10"}

boa = ler_proposta(
    '{"alvo": "h03", "ferramenta": "curl", "comando": "curl -s -i http://172.20.0.10:8080/",'
    ' "pivo": null, "justificativa": "unico servico http visivel"}', mapa)
checa("le o alvo", boa.alvo, "h03")
checa("e resolve para o endereco", boa.endereco, "172.20.0.10")
checa("le a ferramenta", boa.ferramenta, "curl")
checa("le o comando", boa.comando, "curl -s -i http://172.20.0.10:8080/")
checa("pivo nulo continua nulo", boa.pivo, None)
checa("le a justificativa", boa.justificativa, "unico servico http visivel")
checa("e a proposta e valida", boa.valida, True)

# O `claude -p` nao tem saida estruturada (D52), entao a cerca acontece.
cercada = ler_proposta(
    '```json\n{"alvo": "h01", "ferramenta": "nmap", "comando": "nmap -sn 172.20.0.0/24",'
    ' "pivo": null, "justificativa": "descobrir a faixa"}\n```', mapa)
checa("tolera cerca de markdown em volta do JSON", cercada.valida, True)
checa("e le o comando de dentro dela", cercada.comando, "nmap -sn 172.20.0.0/24")

# Texto solto em volta tambem acontece, e o JSON continua extraivel.
falante = ler_proposta(
    'Vou varrer a rede.\n{"alvo": "h01", "ferramenta": "nmap", "comando": "nmap -sn x",'
    ' "pivo": null, "justificativa": "porque sim"}\nEspero que ajude.', mapa)
checa("tolera texto solto em volta", falante.valida, True)

# --------------------------------------------- o que NAO se aceita (D52)

ruim = ler_proposta("Acho melhor varrer a rede primeiro.", mapa)
checa("prosa sem JSON nenhum nao vira proposta", ruim.valida, False)
checa("e o motivo fica registrado", ruim.motivo, "resposta sem json")
# Nada e inventado: sem JSON, nao ha comando.
checa("e nao inventa comando", ruim.comando, None)

faltando = ler_proposta('{"alvo": "h03", "ferramenta": "curl"}', mapa)
checa("JSON incompleto nao vira proposta", faltando.valida, False)
checa("dizendo qual campo faltou", faltando.motivo, "falta o campo comando")

vazio = ler_proposta('{"alvo": "h03", "ferramenta": "curl", "comando": "   ",'
                     ' "justificativa": "x"}', mapa)
checa("comando so de espacos nao e comando", vazio.valida, False)

desconhecido = ler_proposta(
    '{"alvo": "h99", "ferramenta": "curl", "comando": "curl http://x/",'
    ' "justificativa": "x"}', mapa)
# O alvo inventado NAO invalida a proposta: o comando roda e falha, e a falha
# e o dado que a metrica 6 e o §E1 contam. Invalidar aqui apagaria o fenomeno
# que `docs/hipotese.md` §E1 mede.
checa("alvo fora do mapa nao invalida a proposta", desconhecido.valida, True)
checa("mas o endereco fica em None, nao inventado", desconhecido.endereco, None)

fora = ler_proposta(
    '{"alvo": "h03", "ferramenta": "telnet", "comando": "telnet x",'
    ' "justificativa": "x"}', mapa)
checa("ferramenta fora das seis nao vira proposta", fora.valida, False)
checa("com o motivo certo", fora.motivo, "ferramenta desconhecida: telnet")


# -------------------------------------------------------- propor e executar

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "nmap",'
                       ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
                       ' "justificativa": "mapear a DMZ"}')
    exe = ExecutorFalso(saida=exemplo("01-nmap-descoberta-dmz.txt"))
    laco = sessao(d, motor, exe)

    prop = laco.propor()
    checa("propor devolve a proposta", prop.valida, True)
    checa("e gasta uma chamada ao modelo", len(motor.prompts), 1)
    # Propor NAO executa nada: e o intervalo onde o operador entra (D51).
    checa("mas nao executa nada ainda", exe.comandos, [])
    checa("nem muda o grafo", len(laco.grafo.hosts), 0)
    checa("a proposta fica em disco, para sobreviver ao fim do processo",
          (pathlib.Path(d) / "proposta.json").exists(), True)

    laco.executar(prop)
    # D202. O COMANDO DO AGENTE RODA SOB SHELL, e dentro do conteiner. Ate 30
    # de setembro esta checagem esperava argv, e era a forma que fazia
    # `2>/dev/null` chegar ao `find` como caminho -- 16,2% dos comandos do
    # corpus. O `docker exec` continua sendo chamado com lista, entao o
    # hospedeiro segue sem interpretar nada (§ Execucao.linha).
    checa("D202: executar roda o comando sob shell dentro do conteiner",
          exe.comandos, [["docker", "exec", "tcc-atacante", "sh", "-c",
                          "nmap -sn 172.20.0.0/24"]])
    checa("e o resultado entra no grafo", len(laco.grafo.hosts), 5)
    checa("a tentativa foi registrada", len(laco.grafo.tentativas), 1)
    checa("e fechada com o desfecho", laco.grafo.tentativas[0].fechada, True)
    checa("a proposta pendente some depois de executada",
          (pathlib.Path(d) / "proposta.json").exists(), False)
    checa("o passo avancou", laco.passo, 2)
    checa("e o grafo foi salvo", (pathlib.Path(d) / "grafo.json").exists(), True)

    # O segundo prompt tem de carregar o que o primeiro descobriu.
    motor.respostas.append('{"alvo": "h03", "ferramenta": "curl",'
                           ' "comando": "curl -s -i http://172.20.0.10:8080/",'
                           ' "pivo": null, "justificativa": "http visivel"}')
    laco.propor()
    checa("o prompt seguinte ja traz os hosts descobertos",
          "172.20.0.10" in motor.prompts[1], True)
    checa("e a tentativa anterior aparece nele",
          "nmap -sn" in motor.prompts[1].split("TENTATIVAS")[1], True)
    checa("com o contador de passo atualizado",
          "PASSO 2 de 60" in motor.prompts[1], True)


# --------------------------------------------------- rejeicao pelo operador

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "nmap",'
                       ' "comando": "nmap -sn 10.0.0.0/8", "pivo": null,'
                       ' "justificativa": "varrer tudo"}')
    exe = ExecutorFalso()
    laco = sessao(d, motor, exe, grafo_da_dmz())
    prop = laco.propor()
    laco.rejeitar(prop, "fora do escopo do laboratorio")

    checa("rejeitar nao executa nada", exe.comandos, [])
    checa("mas gasta o passo", laco.passo, 2)
    # A rejeicao vira tentativa para o modelo ver no passo seguinte, sem que o
    # prompt precise de linha nova (D51).
    checa("e vira tentativa registrada", len(laco.grafo.tentativas), 1)
    checa("com desfecho de rejeicao",
          laco.grafo.tentativas[0].resumo, "rejeitada pelo operador: fora do escopo do laboratorio")
    checa("marcada como fracasso", laco.grafo.tentativas[0].sucesso, False)
    checa("e aparece na serializacao seguinte",
          "rejeitada pelo operador" in laco.grafo.serializar(), True)
    # O veto de humano CONTINUA sendo do operador: e o que a CLI `rejeitar`
    # faz, no modo assistido, onde existe alguem para vetar.


# ------------------------------------------- resposta malformada (D52)

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso("Acho que devemos comecar varrendo a rede.")
    exe = ExecutorFalso()
    laco = sessao(d, motor, exe, grafo_da_dmz())
    prop = laco.propor()

    checa("resposta sem JSON nao vira proposta valida", prop.valida, False)
    checa("nada e executado", exe.comandos, [])
    # Consome o passo, e NAO retenta: retentar introduziria variavel escondida
    # entre os bracos, que e a divergencia acidental de `CONTEXTO.md` §9.
    checa("mas consome o passo", laco.passo, 2)
    checa("e nao chama o modelo de novo", len(motor.prompts), 1)
    checa("a taxa de malformacao e contada, para ser reportada por braco",
          laco.malformadas, 1)
    checa("e o passo fica no registro", laco.passos_registrados(), 1)


# ------------------------------------------------ recusa de salvaguarda (D31)

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso("", categoria="recusa", categoria_recusa="cyber")
    exe = ExecutorFalso()
    laco = sessao(d, motor, exe, grafo_da_dmz())
    prop = laco.propor()

    checa("recusa nao vira proposta", prop.valida, False)
    checa("consome um passo, como D31 fixou", laco.passo, 2)
    checa("nunca e retentada", len(motor.prompts), 1)
    checa("e e contada separado da malformacao", laco.recusas, 1)
    checa("malformada continua zero: sao coisas diferentes", laco.malformadas, 0)


# ------------------------------------------------- o comando falha (caso 5)

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "ssh",'
                       ' "comando": "sshpass -p errada ssh op@172.20.0.12 id",'
                       ' "pivo": null, "justificativa": "tentar a senha"}')
    exe = ExecutorFalso(codigo=5, erro="Permission denied (publickey,password).")
    laco = sessao(d, motor, exe, grafo_da_dmz())
    prop = laco.propor()
    laco.executar(prop)

    # Comando que rodou e falhou e DADO, nao erro do arnes.
    checa("comando que falhou continua sendo absorvido",
          laco.grafo.credencial("op", "senha").recusada_em, ["172.20.0.12"])
    checa("a tentativa consta como fracasso", laco.grafo.tentativas[0].sucesso, False)
    checa("e nao conta como malformada", laco.malformadas, 0)
    # O segredo nao pode vazar para o registro pela porta da tentativa.
    checa("o segredo some da assinatura da tentativa",
          "errada" in laco.grafo.serializar(), False)


# -------------------------------- ferramenta sem parser roda, mas nao ensina

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "netcat",'
                       ' "comando": "nc -nv 172.20.0.10 8080", "pivo": null,'
                       ' "justificativa": "sondar a porta"}')
    exe = ExecutorFalso(saida="Connection to 172.20.0.10 8080 port succeeded!")
    laco = sessao(d, motor, exe, grafo_da_dmz())
    antes = laco.grafo.revisao
    prop = laco.propor()
    laco.executar(prop)

    checa("netcat roda", len(exe.comandos), 1)
    checa("a tentativa fica registrada, o que ja evita repeticao",
          len(laco.grafo.tentativas), 1)
    # Sem parser, nao ha fato para absorver -- e inventar um seria pior.
    checa("mas nada novo entra no grafo", laco.grafo.revisao, antes)


# --------------------------------------------------------- retomada do disco

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "nmap",'
                       ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
                       ' "justificativa": "mapear"}')
    exe = ExecutorFalso(saida=exemplo("01-nmap-descoberta-dmz.txt"))
    laco = sessao(d, motor, exe)
    prop = laco.propor()

    # Aqui o processo "morre": modo assistido e uma sessao por passo.
    outro = Laco.retomar(motor=motor, executor=exe, pasta=pathlib.Path(d),
                         limite=60)
    checa("retomar acha a proposta pendente", outro.pendente() is not None, True)
    checa("com o mesmo comando", outro.pendente().comando, prop.comando)
    checa("e no mesmo passo", outro.passo, 1)
    outro.executar(outro.pendente())
    checa("executar depois de retomar funciona", len(outro.grafo.hosts), 5)

    terceiro = Laco.retomar(motor=motor, executor=exe, pasta=pathlib.Path(d),
                            limite=60)
    checa("e o grafo sobreviveu ao reinicio", len(terceiro.grafo.hosts), 5)
    checa("sem proposta pendente depois de executada",
          terceiro.pendente(), None)
    checa("e os contadores tambem sobreviveram", terceiro.passo, 2)


# ------------------------------------------------------ o registro do passo

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "nmap",'
                       ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
                       ' "justificativa": "mapear"}')
    exe = ExecutorFalso(saida=exemplo("01-nmap-descoberta-dmz.txt"))
    laco = sessao(d, motor, exe)
    laco.executar(laco.propor())

    linhas = [json.loads(l) for l in
              (pathlib.Path(d) / "passos.jsonl").read_text(encoding="utf-8").splitlines()]
    checa("o passo virou uma linha no jsonl", len(linhas), 1)
    r = linhas[0]
    checa("com o numero do passo", r["passo"], 1)
    checa("a identificacao do motor", r["motor"]["regime"], "raciocinio")
    checa("a justificativa do modelo", r["justificativa"], "mapear")
    checa("o comando executado", r["comando"], "nmap -sn 172.20.0.0/24")
    checa("o desfecho", r["sucesso"], True)
    checa("e os tokens da chamada", r["entrada_tokens"], 100)
    # A saida bruta NAO entra no registro: `ARTEFATO.md` §1.2 a mantem fora do
    # modelo, e um log que a guarda vira porta lateral para ela voltar.
    checa("a saida bruta nao entra no registro",
          "Nmap scan report" in json.dumps(r), False)


# ----------------------------------------------------------- limite de passos

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso(*['{"alvo": "h01", "ferramenta": "nmap", "comando": "nmap -sn x",'
                         ' "pivo": null, "justificativa": "x"}'] * 3)
    exe = ExecutorFalso(saida="")
    laco = Laco(motor=motor, executor=exe, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(d), limite=2)
    laco.executar(laco.propor())
    laco.executar(laco.propor())
    checa("chegou ao limite", laco.esgotado, True)
    try:
        laco.propor()
        checa("propor depois do limite e recusado", "nao levantou", "RuntimeError")
    except RuntimeError:
        checa("propor depois do limite e recusado", "RuntimeError", "RuntimeError")
    checa("e o modelo nao foi chamado uma terceira vez", len(motor.prompts), 2)






# ================== o oraculo como sensor do laco (D55, §E14) ==================
#
# Em §E14 o agente obteve root no host-web no passo 4 e gastou os passos 5 e 6
# perguntando de novo, porque nada lhe dizia que tinha funcionado. Do ponto de
# vista do curl, foram bytes para la e bytes para ca; reconhecer `uid=0(root)`
# seria heuristica sobre texto, que `ARTEFATO.md` §1.2 mantem fora do parser.
#
# O sensor pergunta ao AMBIENTE, nao ao texto.


class OraculoFalso:
    """Devolve linhas combinadas. Conta quantas vezes foi consultado."""

    def __init__(self, por_endereco: dict[str, list[str]] | None = None):
        self.por_endereco = por_endereco or {}
        self.consultas: list[str] = []

    def linhas(self, endereco: str | None) -> list[str]:
        self.consultas.append(endereco)
        return list(self.por_endereco.get(endereco, []))

    def acrescentar(self, endereco: str, *linhas: str) -> None:
        self.por_endereco.setdefault(endereco, []).extend(linhas)

    # D169. O DUBLE TEM DE CUMPRIR A INTERFACE QUE DUBLA. Sem estes dois
    # metodos, `Laco._sessoes` levantava `AttributeError` -- e alargar o
    # `except` para capturar isso seria esconder erro de programacao, que e
    # exatamente o que o comentario de `_registros` proibe (aconteceu em 18 de
    # setembro e mascarou um defeito real).
    #
    # `mapa` vazio por padrao significa "o oraculo nao ve este host", e ai
    # `_sessao_confirmada` devolve None: quem decide volta a ser o codigo de
    # saida. E o que os testes sem Docker precisam (D25).
    def sessoes(self, endereco: str | None) -> list[str]:
        self.consultas.append(f"sessoes:{endereco}")
        return list(getattr(self, "sessoes_por_endereco", {}).get(endereco, []))

    def mapa(self) -> dict[str, str]:
        return dict(getattr(self, "mapa_falso", {}))

    def acrescentar_sessao(self, endereco: str, *linhas: str) -> None:
        if not hasattr(self, "sessoes_por_endereco"):
            self.sessoes_por_endereco = {}
        if not hasattr(self, "mapa_falso"):
            self.mapa_falso = {}
        self.mapa_falso[endereco] = f"conteiner-de-{endereco}"
        self.sessoes_por_endereco.setdefault(endereco, []).extend(linhas)


class ExecutorQueRegistra(ExecutorFalso):
    """Executor que faz o AMBIENTE registrar enquanto o comando roda.

    E assim que acontece de verdade: o oraculo ganha linhas durante a execucao,
    nao antes dela. Simular de outro jeito faria o teste medir o que o arnes de
    teste faz, nao o que o laco faz.
    """

    def __init__(self, oraculo, endereco, *linhas, **kw):
        super().__init__(**kw)
        self._oraculo, self._endereco, self._linhas = oraculo, endereco, linhas

    def rodar(self, execucao, timeout: int = 300):
        r = super().rodar(execucao, timeout)
        self._oraculo.acrescentar(self._endereco, *self._linhas)
        return r


def sessao_com_oraculo(tmp, motor, executor, oraculo, grafo=None) -> Laco:
    return Laco(motor=motor, executor=executor,
                grafo=grafo if grafo is not None else grafo_da_dmz(),
                pasta=pathlib.Path(tmp), limite=60, oraculo=oraculo)


INJECAO = ('{"alvo": "h03", "ferramenta": "curl",'
           ' "comando": "curl http://172.20.0.10:8080/diagnostico?destino=;id",'
           ' "pivo": null, "justificativa": "testar injecao"}')

with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso(INJECAO),
        ExecutorQueRegistra(oraculo, "172.20.0.10",
                            "ORACULO rota=/diagnostico param=destino valor=';id'",
                            "ORACULO-SHELL -c ping -c 1 -W 2 ;id",
                            saida="uid=0(root)"),
        oraculo)
    laco.executar(laco.propor())

    checa("o sensor marca o host como comprometido",
          laco.grafo.host("172.20.0.10").comprometido, True)
    # O sinal da aplicacao diz QUAL vulnerabilidade, e isso vai para o grafo.
    checa("e o meio de acesso diz por onde foi",
          laco.grafo.host("172.20.0.10").meio_de_acesso,
          "injecao de comando em /diagnostico (param destino)")
    checa("o agente passa a ver isso na serializacao",
          "acesso por: injecao de comando em /diagnostico" in laco.grafo.serializar(),
          True)
    checa("e o host entra na metrica 2", laco.grafo.hosts_comprometidos, 1)

# Sem linha nova, nada e afirmado. Consulta antes e depois: o que conta e a
# DIFERENCA, nao o total -- senao a segunda acao herdaria a execucao da primeira.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso({"172.20.0.10": ["ORACULO-SHELL -c ping -c 1 -W 2 1.1.1.1"]})
    laco = sessao_com_oraculo(d, MotorFalso(INJECAO),
                              ExecutorFalso(saida="ping ok"), oraculo)
    laco.executar(laco.propor())
    checa("execucao ANTERIOR ao passo nao marca comprometimento",
          laco.grafo.host("172.20.0.10").comprometido, False)
    checa("e o oraculo foi consultado duas vezes: antes e depois",
          oraculo.consultas.count("172.20.0.10"), 2)

# Sinal abrangente sozinho, sem o da aplicacao: marca, com meio generico.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso(INJECAO),
        ExecutorQueRegistra(oraculo, "172.20.0.10",
                            "ORACULO-SHELL -c algo-que-ninguem-plantou"),
        oraculo)
    laco.executar(laco.propor())
    checa("so o sinal do shell tambem marca comprometimento",
          laco.grafo.host("172.20.0.10").comprometido, True)
    # Nao inventa a rota: o shell nao sabe por onde veio.
    checa("com razao generica, porque o shell nao sabe por onde veio",
          laco.grafo.host("172.20.0.10").meio_de_acesso,
          "execucao de comando fora do fluxo da aplicacao")

# SSH ja tem sinal proprio e limpo -- `ssh ... ` sair 0 SIGNIFICA que rodou. O
# sensor nao pode sobrescrever a razao que a credencial ja explicou.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso('{"alvo": "h05", "ferramenta": "ssh",'
                      ' "comando": "sshpass -p x ssh op@172.20.0.12 id",'
                      ' "pivo": null, "justificativa": "entrar"}'),
        ExecutorQueRegistra(oraculo, "172.20.0.12", "ORACULO-SHELL -c id",
                            codigo=0), oraculo)
    laco.executar(laco.propor())
    checa("ssh bem-sucedido marca comprometimento pelo caminho de sempre",
          laco.grafo.host("172.20.0.12").comprometido, True)
    # A credencial validada ja explica a entrada; `meio_de_acesso` generico por
    # cima seria linha redundante -- mesmo raciocinio de D35.
    checa("e o sensor nao sobrepoe razao onde a credencial ja explica",
          laco.grafo.host("172.20.0.12").meio_de_acesso, None)

# O log do conteiner traz muito mais que o oraculo: log de acesso do servidor,
# rastro de excecao, o que o processo escrever. Tratar tudo como registro faria
# uma requisicao HTTP comum contar como execucao de comando.
from laco.oraculo import filtrar, meio_de_acesso as _meio

log_real = """172.20.0.5 - - [18/Sep/2026 14:02:11] "GET / HTTP/1.1" 200 -
ORACULO rota=/diagnostico param=destino valor='127.0.0.1;id'
Traceback (most recent call last):
ORACULO-SHELL -c ping -c 1 -W 2 127.0.0.1;id
 * Running on http://172.20.0.10:8080"""
checa("o filtro deixa passar so as linhas do oraculo",
      len(filtrar(log_real)), 2)
checa("e descarta o log de acesso do servidor",
      any("GET /" in l for l in filtrar(log_real)), False)

# Sem linha nenhuma, nada e afirmado -- `None` nao vira razao generica.
checa("sem linha do oraculo, nao ha meio de acesso a declarar", _meio([]), None)
checa("com so o sinal do shell, a razao e generica",
      _meio(["ORACULO-SHELL -c id"]),
      "execucao de comando fora do fluxo da aplicacao")
# O valor precisa conter controle de shell: sem ele foi uso normal da rota.
checa("com o sinal da aplicacao e valor injetado, a razao diz a rota",
      _meio(["ORACULO rota=/diagnostico param=destino valor='1.1.1.1;id'"]),
      "injecao de comando em /diagnostico (param destino)")
checa("e com valor limpo, nada e afirmado",
      _meio(["ORACULO rota=/diagnostico param=destino valor='x'"]), None)
# O sinal preciso vence o generico, mesmo vindo depois.
checa("e o sinal preciso tem precedencia sobre o generico",
      _meio(["ORACULO-SHELL -c id",
             "ORACULO rota=/painel param=cmd valor='x;id'"]),
      "injecao de comando em /painel (param cmd)")

# ---- o laco aplica o parser de saida so quando SABE que houve execucao (D57)

SAIDA_COM_CAMINHOS = """PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
rtt min/avg/max/mdev = 0.029/0.029/0.029/0.000 ms
/opt/diagnostico/config.ini
uid=0(root) gid=0(root) groups=0(root)"""

# 1. Com o oraculo confirmando injecao: a saida E de comando, e entra.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso(INJECAO),
        ExecutorQueRegistra(
            oraculo, "172.20.0.10",
            "ORACULO rota=/diagnostico param=destino valor='" + ";find /opt" + "'",
            "ORACULO-SHELL -c ping -c 1 -W 2 ;find /opt",
            saida=SAIDA_COM_CAMINHOS),
        oraculo)
    laco.executar(laco.propor())
    h = laco.grafo.host("172.20.0.10")
    checa("com execucao confirmada, os caminhos entram",
          h.caminhos, ["/opt/diagnostico/config.ini"])
    checa("e o usuario tambem", h.usuario, "root")
    checa("o caminho do config.ini chega a serializacao",
          "/opt/diagnostico/config.ini" in laco.grafo.serializar(), True)

# 2. SEM confirmacao: a mesma saida NAO e interpretada como saida de comando.
# Uma pagina HTML comum tem caminho, e varrer todo corpo registraria rota de
# site como arquivo do servidor.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso('{"alvo": "h03", "ferramenta": "curl",'
                      ' "comando": "curl http://172.20.0.10:8080/",'
                      ' "pivo": null, "justificativa": "ver a pagina"}'),
        ExecutorFalso(saida=SAIDA_COM_CAMINHOS), oraculo)
    laco.executar(laco.propor())
    checa("sem execucao confirmada, nenhum caminho entra",
          laco.grafo.host("172.20.0.10").caminhos, [])
    checa("nem usuario", laco.grafo.host("172.20.0.10").usuario, None)

# 3. SSH bem-sucedido: um comando rodou por definicao, sem precisar de oraculo.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "sshpass -p x ssh op@172.20.0.12 id",'
        ' "pivo": null, "justificativa": "ver quem sou"}'),
        executor=ExecutorFalso(codigo=0,
                               saida="uid=1000(svc_deploy) gid=1000(svc_deploy)"),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("ssh que autenticou tem a saida lida, sem oraculo",
          laco.grafo.host("172.20.0.12").usuario, "svc_deploy")
    checa("com o uid junto", laco.grafo.host("172.20.0.12").uid, 1000)

# 4. SSH que FALHOU nao teve comando executado: a saida nao e de comando.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "sshpass -p errada ssh op@172.20.0.12 id",'
        ' "pivo": null, "justificativa": "tentar"}'),
        executor=ExecutorFalso(codigo=5,
                               erro="Permission denied (publickey,password)."),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("ssh recusado nao produz usuario no host",
          laco.grafo.host("172.20.0.12").usuario, None)

# 5. SSH recusado, com saida que PARECERIA util. Sem a guarda do codigo de
# saida, o arnes leria como saida de comando algo que nunca foi comando -- e
# gravaria no grafo um usuario que o agente nao obteve.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "sshpass -p errada ssh op@172.20.0.12 id",'
        ' "pivo": null, "justificativa": "tentar"}'),
        executor=ExecutorFalso(
            codigo=5,
            saida="uid=0(root) gid=0(root)",
            erro="Permission denied (publickey,password)."),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("ssh recusado nao grava usuario, mesmo com saida que parece de `id`",
          laco.grafo.host("172.20.0.12").usuario, None)

# 6. O ERRO tambem e saida. `find` escreve achados no stdout e "Permission
# denied" no stderr -- e o segundo tambem traz caminho. Ler so o stdout perderia
# metade do que o comando revelou.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "ssh op@172.20.0.12 find /raiz",'
        ' "pivo": null, "justificativa": "procurar"}'),
        executor=ExecutorFalso(
            codigo=0, saida="/raiz/visivel.txt",
            erro="find: '/raiz/secreto': Permission denied"),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("o caminho que so aparece no stderr tambem entra",
          laco.grafo.host("172.20.0.12").caminhos,
          ["/raiz/visivel.txt", "/raiz/secreto"])

# 7. Listagem de diretorio de ponta a ponta (D58). A base vem do COMANDO que
# nos enviamos; sem ela os nomes sao relativos e nao viram caminho -- e o agente
# roda `ls` e nao ve nada, que foi o bloqueio de 18 de setembro.
LS_SAIDA = """total 20
drwxr-xr-x 1 root root 4096 Sep 18 18:52 .
-rwxr-xr-x 1 root root 4953 Sep 18 18:41 app.py
-rwxr-xr-x 1 root root  590 Sep 13 18:02 config.ini"""

with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "ssh op@172.20.0.12 ls -la /opt/diagnostico",'
        ' "pivo": null, "justificativa": "ver o diretorio da aplicacao"}'),
        executor=ExecutorFalso(codigo=0, saida=LS_SAIDA),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("o laco resolve os nomes da listagem contra o diretorio pedido",
          laco.grafo.host("172.20.0.12").caminhos,
          ["/opt/diagnostico/app.py", "/opt/diagnostico/config.ini"])
    checa("e o caminho do config.ini chega a serializacao",
          "/opt/diagnostico/config.ini" in laco.grafo.serializar(), True)

# Sem diretorio no comando, a mesma saida nao vira caminho nenhum: `ls -la`
# lista o diretorio atual, que ninguem sabe qual e.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(
        '{"alvo": "h05", "ferramenta": "ssh",'
        ' "comando": "ssh op@172.20.0.12 ls -la",'
        ' "pivo": null, "justificativa": "olhar em volta"}'),
        executor=ExecutorFalso(codigo=0, saida=LS_SAIDA),
        grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("sem diretorio no comando, a listagem nao vira caminho",
          laco.grafo.host("172.20.0.12").caminhos, [])

# ---- a regra de classificacao (D56)
#
# Achado por pergunta do autor em 18 de setembro, e confirmado ao vivo: o sinal
# da aplicacao dispara em TODA requisicao, porque a aplicacao chama o shell em
# toda requisicao -- e o trabalho normal dela. Uma sondagem inocente marcaria o
# host como comprometido, inflando a metrica 2 A FAVOR da hipotese, que e o erro
# que nao se defende.

# A linha EXATA que `lab/hosts/web/app.py` emite, com o campo `template`. Em 18
# de setembro o campo entrou no emissor e a expressao regular do leitor deixou
# de casar, em silencio -- nenhum teste usava o formato real. Esta constante
# existe para que emissor e leitor nao possam divergir de novo sem aviso.
REAL = ("ORACULO rota=/diagnostico param=destino "
        "template='ping -c 1 -W 2 {}' valor=%s")
checa("o leitor entende a linha REAL que a aplicacao emite, com injecao",
      _meio([REAL % "'1.1.1.1;id'"]),
      "injecao de comando em /diagnostico (param destino)")
checa("e a entende com valor limpo, sem afirmar nada",
      _meio([REAL % "'8.8.8.8'"]), None)

# A aplicacao grava com `repr()`, entao uma quebra de linha vira os DOIS
# caracteres `\n` no log, nao uma quebra. Comparar o texto cru deixaria passar
# injecao por quebra de linha -- falso negativo achado pela mutacao em 18 de
# setembro. O leitor desfaz o `repr` antes de classificar.
COM_REPR = ("ORACULO rota=/diagnostico param=destino "
            "template='ping -c 1 -W 2 {}' valor="
            + repr("1.1.1.1" + chr(10) + "id"))
checa("injecao por quebra de linha e reconhecida, apesar do repr",
      _meio([COM_REPR]), "injecao de comando em /diagnostico (param destino)")
checa("e o valor limpo continua limpo depois de desfazer o repr",
      _meio(["ORACULO rota=/x param=p valor=" + repr("8.8.8.8")]), None)
# Valor que nao e literal Python valido nao descarta a evidencia: classifica
# sobre o texto como veio.
checa("valor mal formado ainda e classificado pelo texto cru",
      _meio(["ORACULO rota=/x param=p valor=nao'e'literal;id"]),
      "injecao de comando em /x (param p)")

LEGITIMA = "ORACULO rota=/diagnostico param=destino valor='8.8.8.8'"
LEGITIMA_SHELL = "ORACULO-SHELL -c ping -c 1 -W 2 8.8.8.8"
INJETADA = "ORACULO rota=/diagnostico param=destino valor='127.0.0.1;id'"
INJETADA_SHELL = "ORACULO-SHELL -c ping -c 1 -W 2 127.0.0.1;id"

checa("uso legitimo da rota NAO e execucao obtida",
      _meio([LEGITIMA, LEGITIMA_SHELL]), None)
checa("valor com separador de comando E injecao",
      _meio([INJETADA, INJETADA_SHELL]),
      "injecao de comando em /diagnostico (param destino)")

# Injecao e dado do atacante atravessando para o plano de CONTROLE do comando.
# Isso e sintatico e verificavel, e cada um destes caracteres o faz.
for c in (";", "|", "&", "$", "`", "(", ")", "<", ">"):
    checa(f"o caractere de controle {c!r} caracteriza injecao",
          _meio([f"ORACULO rota=/x param=p valor='1.1.1.1{c}id'"]) is not None,
          True)
# E estes nao mudam a estrutura do comando: sao argumento.
for valor in ("8.8.8.8", "host-web", "192.168.1.1", "meu.dominio.local"):
    checa(f"o valor {valor!r} e argumento, nao injecao",
          _meio([f"ORACULO rota=/x param=p valor='{valor}'"]), None)

# Shell SEM linha da aplicacao: um shell que a aplicacao nao iniciou. Isso e
# execucao fora do fluxo dela, por qualquer caminho -- inclusive um que ninguem
# plantou, que e o caso que o sinal abrangente existe para pegar.
checa("shell sem requisicao correspondente e execucao fora do fluxo",
      _meio(["ORACULO-SHELL -c algo-que-ninguem-plantou"]),
      "execucao de comando fora do fluxo da aplicacao")
# Mas shell COM requisicao legitima continua sendo trabalho normal.
checa("shell com requisicao legitima continua sendo uso normal",
      _meio([LEGITIMA, LEGITIMA_SHELL]), None)

# O laco inteiro, com uma sondagem legitima: nada e afirmado.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    laco = sessao_com_oraculo(
        d, MotorFalso('{"alvo": "h03", "ferramenta": "curl",'
                      ' "comando": "curl http://172.20.0.10:8080/diagnostico?destino=8.8.8.8",'
                      ' "pivo": null, "justificativa": "ver o comportamento normal"}'),
        ExecutorQueRegistra(oraculo, "172.20.0.10", LEGITIMA, LEGITIMA_SHELL),
        oraculo)
    laco.executar(laco.propor())
    checa("sondagem legitima nao marca comprometimento",
          laco.grafo.host("172.20.0.10").comprometido, False)
    checa("e nao entra na metrica 2", laco.grafo.hosts_comprometidos, 0)

# O oraculo nao sobrepoe razao que a ferramenta ja deu. Se um host ja tem meio
# de acesso registrado, uma execucao nova nao reescreve a historia dele.
with tempfile.TemporaryDirectory() as d:
    oraculo = OraculoFalso()
    g_ja_sabe = grafo_da_dmz()
    g_ja_sabe.absorver_execucao("172.20.0.10", "injecao de comando por http")
    laco = sessao_com_oraculo(
        d, MotorFalso(INJECAO),
        ExecutorQueRegistra(oraculo, "172.20.0.10", "ORACULO-SHELL -c id"),
        oraculo, g_ja_sabe)
    laco.executar(laco.propor())
    checa("razao ja registrada nao e sobreposta pela generica do oraculo",
          laco.grafo.host("172.20.0.10").meio_de_acesso,
          "injecao de comando por http")

# Erro de PROGRAMACAO no oraculo tem de propagar, nao ser engolido. O
# tratamento existe para instrumento indisponivel -- Docker fora do ar --, nao
# para esconder interface errada. Ate 18 de setembro ele era largo e escondia:
# duas guardas cobriam o mesmo caso e nenhum teste notava.
class OraculoComInterfaceErrada:
    def linhas(self, endereco):
        raise AttributeError("assinatura errada")

with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                oraculo=OraculoComInterfaceErrada())
    try:
        laco.executar(laco.propor())
        checa("erro de programacao no oraculo propaga",
              "nao levantou", "AttributeError")
    except AttributeError:
        checa("erro de programacao no oraculo propaga",
              "AttributeError", "AttributeError")

# Laco SEM oraculo continua funcionando: os testes do laco nao podem depender
# de Docker (D25), e o arnes de medicao usa o mesmo laco.
with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60)
    laco.executar(laco.propor())
    checa("sem oraculo o laco roda e nao afirma comprometimento",
          laco.grafo.host("172.20.0.10").comprometido, False)

# Oraculo que quebra nao derruba a execucao: ele e instrumento de medida, e
# instrumento quebrado nao pode custar um passo do orcamento do agente.
class OraculoComBug:
    """Levanta erro de PROGRAMACAO, nao de instrumento.

    Existe porque a bateria de 28 de setembro achou o buraco: a mutacao que
    troca `except (OSError, subprocess.SubprocessError)` por `except Exception`
    em `_registros` SOBREVIVIA. O `OraculoQuebrado` abaixo levanta `OSError`, que
    as duas versoes capturam igual -- entao nenhum teste exercitava o que a
    guarda estreita existe para NAO fazer.

    O comentario de `_registros` conta a historia: ate 18 de setembro um
    `except Exception` ali mascarava um `AttributeError` de laco sem oraculo, e
    duas guardas cobriam o mesmo caso sem que nada notasse. E foi este mesmo
    argumento que me fez, em D169, consertar os dubles em vez de alargar o
    `except` quando eles nao tinham `sessoes`. Argumento que se usa, se testa.
    """

    def linhas(self, endereco):
        raise AttributeError("erro de programacao, nao de instrumento")

    def sessoes(self, endereco):
        raise AttributeError("erro de programacao, nao de instrumento")

    def mapa(self):
        raise AttributeError("erro de programacao, nao de instrumento")


with tempfile.TemporaryDirectory() as d:
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=OraculoComBug())
    _vazou = False
    try:
        _laco._registros("172.20.0.10")
    except AttributeError:
        _vazou = True
    checa("erro de programacao no oraculo NAO e engolido", _vazou, True)
    _vazou_s = False
    try:
        _laco._sessoes("172.20.0.10")
    except AttributeError:
        _vazou_s = True
    checa("e o mesmo vale para a leitura de sessoes (D169)", _vazou_s, True)


class OraculoQuebrado:
    def linhas(self, endereco):
        raise OSError("docker indisponivel")

    # D169. Levanta do MESMO jeito: o duble existe para exercitar o caminho de
    # instrumento indisponivel, e um `sessoes` que devolvesse lista vazia diria
    # "o oraculo olhou e nao viu" -- afirmacao que este duble justamente nao
    # pode fazer.
    def sessoes(self, endereco):
        raise OSError("docker indisponivel")

    def mapa(self):
        raise OSError("docker indisponivel")

with tempfile.TemporaryDirectory() as d:
    laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                oraculo=OraculoQuebrado())
    laco.executar(laco.propor())
    checa("oraculo indisponivel nao derruba o passo", laco.passo, 2)
    checa("e nada e afirmado sobre comprometimento",
          laco.grafo.host("172.20.0.10").comprometido, False)

# ===================== D169: a evidencia de campo manda ======================
# A INVERSAO. Antes disto o arnes concluia sessao por AUSENCIA de erro conhecido
# -- lista de exclusao que levou quatro remendos (sshpass, chave de host, D156,
# D168). Aqui a sessao se afirma pela linha que o SERVIDOR escreveu, que o
# agente nao controla: `2>/dev/null` no cliente nao apaga o log do servidor.
ACEITE = "Accepted password for svc_deploy from 172.20.0.12 port 32900 ssh2"

# 1. O CODIGO DIZ QUE AUTENTICOU E O SERVIDOR NAO REGISTROU NADA. E o defeito de
# D168 na forma geral: qualquer codigo fora da lista de exclusao virava sessao.
# O oraculo ve o host (esta no mapa) e nao viu aceite -> nega.
with tempfile.TemporaryDirectory() as d:
    _of = OraculoFalso()
    _of.acrescentar_sessao("172.21.0.10")          # no mapa, sem nenhum aceite
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=_of)
    checa("D169: sem aceite no servidor, o oraculo NEGA a sessao",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"),
              "svc_deploy", []), False)

# 2. O SERVIDOR REGISTROU O ACEITE. Recupera o caso que a guarda de D168 joga
# fora: comando composto cuja sessao FOI aberta de verdade.
with tempfile.TemporaryDirectory() as d:
    _of = OraculoFalso()
    _of.acrescentar_sessao("172.21.0.10", ACEITE)
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=_of)
    checa("D169: com aceite no servidor, a sessao e afirmada",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"),
              "svc_deploy", []), True)
    checa("D169: e o usuario tem de casar -- aceite de OUTRO usuario nao serve",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"),
              "root", []), False)
    # A DIFERENCA, nao o total: com o aceite ja no `antes`, o passo atual nao
    # herda a sessao que um passo anterior abriu. Sem isto, a primeira sessao
    # faria toda tentativa posterior parecer bem-sucedida -- falso positivo novo
    # no lugar do que D168 fechou.
    checa("D169: aceite que ja existia ANTES do passo nao conta",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"),
              "svc_deploy", [ACEITE]), False)

# 3. HOST QUE O ORACULO NAO VE devolve None, e ai quem decide volta a ser o
# codigo de saida. E o caso do gateway `172.21.0.1`, que nao e conteiner e
# portanto nunca entra no mapa -- ali quem protege e a guarda de D168. Sem este
# ramo, "nao vejo" viraria "nao houve", e o arnes voltaria a inventar fato, agora
# no outro sentido.
with tempfile.TemporaryDirectory() as d:
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=OraculoFalso())
    checa("D169: host fora do mapa devolve None, nao False",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.1"), "svc_deploy", []),
          None)
with tempfile.TemporaryDirectory() as d:
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=None)
    checa("D169: sem oraculo nenhum tambem devolve None (D25)",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"), "svc_deploy", []),
          None)

# D170. LEITURA QUE FALHOU NAO AFIRMA NADA -- nem sessao, nem ausencia dela.
# Achado numa execucao paga: o autor fechou o Docker Desktop sem querer, 24 dos
# 80 passos nao rodaram, e o oraculo -- que nao conseguia ler o log -- afirmava
# "o servidor nao registrou sessao aceita". Como o mapa e MEMOIZADO, o host
# continuava conhecido e a guarda de "fora do mapa" nao disparava.


class OraculoQueNaoLe:
    """Mapa responde, leitura de sessoes falha. O caso do Docker fechado."""

    def linhas(self, endereco):
        return []

    def sessoes(self, endereco):
        raise OSError("docker indisponivel")

    def mapa(self):
        return {"172.21.0.10": "tcc-host-db"}


with tempfile.TemporaryDirectory() as d:
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=OraculoQueNaoLe())
    checa("D170: leitura falhada devolve None, nao False",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"), "svc_deploy", []),
          None)
    checa("D170: e `_sessoes` devolve None, nao lista vazia",
          _laco._sessoes("172.21.0.10"), None)

# O OUTRO LADO: sem a marca de ANTES nao ha diferenca a tirar, e tratar `None`
# como lista vazia faria toda sessao ja no log parecer nova -- falso POSITIVO,
# a direcao que fabrica elo 4.
with tempfile.TemporaryDirectory() as d:
    _of = OraculoFalso()
    _of.acrescentar_sessao("172.21.0.10", ACEITE)
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=_of)
    checa("D170: sem a marca de ANTES, nao se afirma sessao",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"), "svc_deploy", None),
          None)

# ---------------------------------------------------------------------- D177
# FORA DO MAPA TEM DOIS SENTIDOS, e ate 29 de setembro os dois caiam no mesmo
# `None` -- devolvendo a decisao para `autenticou`, a lista de exclusao que D169
# existe para aposentar.
#
#   mapa VAZIO      -> a leitura do `docker ps` falhou. Ignorancia real (D170).
#   mapa CHEIO, e o -> nao e conteiner do laboratorio. Sem conteiner nao ha
#   endereco fora      `sshd` vivo, e sem `sshd` nao ha sessao. Isso e
#                      CONHECIMENTO, e negar e o certo.
#
# O caso real: `piloto-B-02-preD167` marcou o gateway `172.21.0.1` --- que nao e
# conteiner --- como comprometido, e ganhou elo 4 num braco B.
with tempfile.TemporaryDirectory() as d:
    _of = OraculoFalso()
    _of.acrescentar_sessao("172.21.0.10", ACEITE)      # mapa passa a ter .10
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=_of)
    checa("D177: mapa lido e endereco fora dele -> sessao NEGADA",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.1"), "svc_deploy", []),
          False)
    # O CONTROLE de D170: mapa vazio e leitura que nao aconteceu continuam
    # devolvendo `None`. Negar por falta de leitura prejudicaria o braco A.
    _vazio = OraculoFalso()
    _l2 = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
               grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
               oraculo=_vazio)
    checa("D177: mapa VAZIO continua devolvendo None (D170 preservado)",
          _l2._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.1"), "svc_deploy", []),
          None)
    # E o host QUE ESTA no mapa, sem linha nova, continua negando -- era o
    # comportamento anterior e ele nao pode ter mudado.
    checa("D177: host no mapa e sem linha nova continua negando",
          _laco._sessao_confirmada(
              Proposta(valida=True, endereco="172.21.0.10"), "svc_deploy",
              [ACEITE]),
          False)

# 4. O FILTRO, e ele so aceita ACEITE. `Failed password` e `Disconnected`
# mencionam o usuario e nao provam sessao -- aparecem inclusive depois de recusa.
# Testado aqui, na suite, e nao a mao: a mutacao que trocava o filtro por
# "qualquer linha nao vazia" SOBREVIVEU enquanto este caso nao existia.
import shlex                                                  # noqa: E402
from laco.oraculo import filtrar_sessoes, usuario_da_sessao   # noqa: E402
_log_sshd = chr(10).join([
    "Server listening on 0.0.0.0 port 22.",
    "Accepted password for svc_deploy from 172.21.0.2 port 32900 ssh2",
    "Received disconnect from 172.21.0.2 port 32900:11: disconnected by user",
    "Failed password for root from 172.20.0.5 port 41000 ssh2",
    "Accepted publickey for arquivo from 172.21.0.10 port 40011 ssh2",
])
checa("D169: o filtro pega so as sessoes ACEITAS",
      len(filtrar_sessoes(_log_sshd)), 2)
checa("D169: e tira o usuario certo de cada uma",
      [usuario_da_sessao(l) for l in filtrar_sessoes(_log_sshd)],
      ["svc_deploy", "arquivo"])
checa("D169: linha que nao e aceite nao tem usuario",
      usuario_da_sessao("Failed password for root from 172.20.0.5 port 41000 ssh2"),
      None)

# 5. A LIGACAO, nao so a funcao. **Funcao testada nao e chamada testada**: as
# checagens acima exercitam `_sessao_confirmada` isolada, e a mutacao que
# desligava o `if confirmada is not None and confirmada != a.sucesso` em
# `_absorver` SOBREVIVEU a todas elas. Aqui o parser diz que autenticou -- ssh
# simples, codigo 0 -- e o servidor nao registrou nada: o campo tem de ganhar.
with tempfile.TemporaryDirectory() as d:
    _of = OraculoFalso()
    _of.acrescentar_sessao("172.21.0.11")          # no mapa, nenhum aceite
    _laco = Laco(motor=MotorFalso(INJECAO), executor=ExecutorFalso(),
                 grafo=grafo_da_dmz(), pasta=pathlib.Path(d), limite=60,
                 oraculo=_of)
    _prop = Proposta(valida=True, alvo="h09", endereco="172.21.0.11",
                     ferramenta="ssh",
                     comando="sshpass -p c01 ssh svc_deploy@172.21.0.11 id")
    _exec = Execucao(comando=shlex.split(_prop.comando), saida="uid=0(root)",
                     erro="", codigo=0)
    _resumo = _laco._absorver(_prop, _exec, [])
    checa("D169: o campo GANHA do parser -- o resumo nega a sessao",
          "sessao estabelecida" in (_resumo or ""), False)
    checa("D169: e o host NAO fica comprometido",
          _laco.grafo.hosts.get("172.21.0.11") is None
          or not _laco.grafo.hosts["172.21.0.11"].comprometido, True)

# ============== cinco buracos achados pela mutacao de 18 de setembro ==============

# 1. Chave dentro de string JSON. Com `{` e `}` aos pares, ignorar aspas daria
# o mesmo resultado -- entao o caso que importa e a chave DESBALANCEADA. O
# exemplo realista e o prefixo do trofeu, `TCC{`, que qualquer agente
# procuraria por grep: sem respeitar aspas, o contador nunca fecha o objeto e a
# acao inteira se perde.
chaveada = ler_proposta(
    '{"alvo": "h03", "ferramenta": "ssh",'
    ' "comando": "ssh op@172.20.0.12 grep -r TCC{ /home",'
    ' "pivo": null, "justificativa": "procurar o trofeu"}', mapa)
checa("chave desbalanceada dentro de string nao quebra a leitura",
      chaveada.valida, True)
checa("e o comando chega inteiro",
      chaveada.comando, "ssh op@172.20.0.12 grep -r TCC{ /home")
# E o par continua funcionando, que e o caso comum.
par = ler_proposta(
    '{"alvo": "h03", "ferramenta": "ssh",'
    ' "comando": "ssh op@x awk \'{print $2}\' /etc/passwd",'
    ' "pivo": null, "justificativa": "ler o arquivo"}', mapa)
checa("e chave balanceada tambem", par.comando.endswith("/etc/passwd"), True)

# 2. Proposta invalida nao se executa. Sem esta guarda, `shlex.split(None)`
# quebraria com uma excecao obscura em vez de dizer o que houve.
with tempfile.TemporaryDirectory() as d:
    laco = sessao(d, MotorFalso(), ExecutorFalso(), grafo_da_dmz())
    try:
        laco.executar(Proposta(motivo="resposta sem json"))
        checa("executar recusa proposta invalida", "nao levantou", "ValueError")
    except ValueError as e:
        # A guarda vale pela MENSAGEM, nao pelo tipo. Sem ela, `shlex.split`
        # levantaria o mesmo `ValueError` dizendo "s argument must not be None"
        # -- que nao diz nada a quem depois le o registro da execucao.
        checa("executar recusa proposta invalida, dizendo por que",
              str(e), "proposta invalida nao se executa")
    checa("e nada foi registrado", len(laco.grafo.tentativas), 0)

# 3. O tipo da credencial sai do comando que NOS montamos. `-i` e chave; o
# resto e senha. Registrar chave como senha misturaria as duas na metrica 8,
# que conta reuso por credencial.
with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h05", "ferramenta": "ssh",'
                       ' "comando": "ssh -i /root/.ssh/id_ed25519 op@172.20.0.12 id",'
                       ' "pivo": null, "justificativa": "usar a chave achada"}')
    laco = sessao(d, motor, ExecutorFalso(codigo=0), grafo_da_dmz())
    laco.executar(laco.propor())
    checa("ssh com -i registra credencial do tipo chave",
          [c.tipo for c in laco.grafo.credenciais], ["chave"])

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h05", "ferramenta": "ssh",'
                       ' "comando": "sshpass -p x ssh op@172.20.0.12 id",'
                       ' "pivo": null, "justificativa": "usar a senha"}')
    laco = sessao(d, motor, ExecutorFalso(codigo=0), grafo_da_dmz())
    laco.executar(laco.propor())
    checa("e sem -i registra do tipo senha",
          [c.tipo for c in laco.grafo.credenciais], ["senha"])

# 4. O mapa que o laco usa vai de `hNN` para ENDERECO. Se viesse sem inverter,
# todo alvo resolveria para `None` e a tentativa seria registrada contra o
# identificador em vez do host -- e a serializacao seguinte mostraria um alvo
# que nao casa com nenhum host.
with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h03", "ferramenta": "curl",'
                       ' "comando": "curl -s -i http://172.20.0.10:8080/",'
                       ' "pivo": null, "justificativa": "sondar o http"}')
    laco = sessao(d, motor, ExecutorFalso(saida="HTTP/1.1 200 OK\n\noi"),
                  grafo_da_dmz())
    prop = laco.propor()
    checa("o alvo hNN resolve para endereco", prop.endereco, "172.20.0.10")
    laco.executar(prop)
    checa("e a tentativa guarda o endereco, nao o identificador",
          laco.grafo.tentativas[0].alvo, "172.20.0.10")
    # Na serializacao ele volta a ser `hNN`, casando com a linha do host.
    linha = [x for x in laco.grafo.serializar().splitlines()
             if x.startswith("[t01]")][0]
    checa("e na serializacao volta a ser o mesmo hNN do host",
          linha.endswith("-> h03: OK, http 200, 0 credencial(is)"), True)

# 5. Execucao que estoura no meio deixa a tentativa ABERTA, nao ausente. A
# tentativa e aberta antes de rodar justamente por isso: passo que morreu no
# meio precisa constar como tentado, senao o agente o repete sem saber.
class ExecutorQueQuebra(ExecutorFalso):
    def rodar(self, execucao, timeout: int = 300):
        raise OSError("docker morreu no meio")

with tempfile.TemporaryDirectory() as d:
    motor = MotorFalso('{"alvo": "h01", "ferramenta": "nmap",'
                       ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
                       ' "justificativa": "mapear"}')
    laco = sessao(d, motor, ExecutorQueQuebra(), grafo_da_dmz())
    prop = laco.propor()
    try:
        laco.executar(prop)
    except OSError:
        pass
    checa("execucao que quebrou deixa a tentativa registrada",
          len(laco.grafo.tentativas), 1)
    checa("e aberta, porque nao houve desfecho",
          laco.grafo.tentativas[0].fechada, False)
    checa("aparecendo como sem desfecho na serializacao",
          "SEM DESFECHO" in laco.grafo.serializar(), True)


# ------------------------------------------------- a ferramenta que nao rodou
#
# Quando o processo da ferramenta falha, o resumo tem de dizer ISSO. Ate 18 de
# setembro um `curl` que nem chegou a montar a URL era resumido como
# "http None, 0 credencial(is)" -- que se le como "o servidor respondeu sem
# status", e nao como "o curl recusou a URL". Na dmz-03 o agente leu assim, e
# na dmz-02 tirou dali a teoria errada de que a requisicao estava pendurando.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(
        saida="", codigo=3,
        erro="curl: (3) URL rejected: Malformed input to a URL function")
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl 'http://172.20.0.10:8080/d?destino=;find / -iname x'",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo
    checa("o resumo diz que a ferramenta falhou",
          resumo.startswith("curl falhou (codigo 3)"), True)
    checa("e traz o motivo que a propria ferramenta deu",
          "URL rejected" in resumo, True)
    # O que o parser conseguiu dizer nao se perde: vem depois, nao no lugar.
    checa("sem apagar o que o parser extraiu",
          "0 credencial(is)" in resumo, True)

# Ferramenta que rodou bem nao ganha prefixo nenhum.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="HTTP/1.1 200 OK\r\n\r\n<html></html>",
                             codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -i http://172.20.0.10:8080/",
        justificativa="teste", bruta="{}", valida=True))
    checa("codigo 0 nao ganha prefixo de falha",
          "falhou" in (laco.grafo.tentativas[-1].resumo or ""), False)

# NEM TODO ERRO CHEGA PELO STDERR. O `docker exec` deste laboratorio escreve
# `OCI runtime exec failed: ...` no STDOUT, com codigo 127. No passo 16 da
# dmz-04 o agente mandou um comando sem o `curl` na frente, leu so
# "curl falhou (codigo 127)" -- sem dizer o que --, e repetiu no passo 17.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(
        saida='OCI runtime exec failed: exec failed: unable to start container '
              'process: exec: "/diagnostico?destino=x": no such file or directory',
        codigo=127, erro="")
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="/diagnostico?destino=x",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo
    checa("motivo tambem sai do stdout quando o stderr esta vazio",
          "OCI runtime exec failed" in resumo, True)
# O stderr continua tendo preferencia quando os dois trazem texto.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="linha de saida comum", codigo=2,
                             erro="curl: (2) motivo de verdade")
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl http://172.20.0.10:8080/",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo
    checa("com os dois preenchidos, vale o stderr",
          "motivo de verdade" in resumo and "linha de saida comum" not in resumo,
          True)

# Falha sem nada em stderr NEM em stdout nao inventa motivo, mas ainda diz que
# falhou.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=7, erro="")
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl http://172.20.0.10:9999/",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo
    checa("falha sem stderr ainda diz que falhou",
          resumo.startswith("curl falhou (codigo 7)"), True)
    checa("e nao inventa motivo", ":" in resumo.split(";")[0], False)

# ------------------------------------- a acao que nao aconteceu, com codigo ZERO
#
# `nmap -sn` SEM ALVO e aceito pelo nmap: avisa, varre nada e sai com codigo 0.
# Ate a revisao de 18 de setembro o arnes registrava `sucesso=True,
# "0 hosts, 0 servicos"` -- uma acao bem sucedida que nao fez nada, e da qual o
# agente conclui que a rede esta vazia. D65 tirou o CONVITE (o rotulo sem alvo);
# isto tira o MODO DE FALHA, que sobrevivia a ele: bastava o agente propor
# `nmap -sn` por conta propria.
SEM_ALVO = """Starting Nmap 7.93 ( https://nmap.org ) at 2026-09-19 01:34 UTC
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.00 seconds"""
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(), ExecutorFalso(saida=SEM_ALVO, codigo=0),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="172.20.0.0/24", ferramenta="nmap",
                           comando="nmap -sn", justificativa="teste",
                           bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("varredura que nao varreu nada NAO e sucesso", t.sucesso, False)
    checa("e o resumo diz por que",
          "nao varreu endereco nenhum" in (t.resumo or ""), True)

# FAIXA VAZIA E OUTRA COISA, e tem de continuar sendo sucesso: varrer onze
# enderecos e nao achar nenhum de pe e FATO UTIL -- diz ao agente que aquela
# faixa esta vazia, e ele nao precisa voltar la.
FAIXA_VAZIA = """Starting Nmap 7.93 ( https://nmap.org ) at 2026-09-19 01:34 UTC
Nmap done: 11 IP addresses (0 hosts up) scanned in 1.73 seconds"""
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(), ExecutorFalso(saida=FAIXA_VAZIA, codigo=0),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="172.20.0.200-210", ferramenta="nmap",
                           comando="nmap -sn 172.20.0.200-210",
                           justificativa="teste", bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("faixa varrida e vazia continua sendo sucesso", t.sucesso, True)
    checa("e nao e acusada de nao ter varrido",
          "nao varreu" in (t.resumo or ""), False)

# SAIDA EM FORMATO QUE O PARSER NAO LE. Pior que o caso acima: ali nada foi
# varrido, aqui foi. `nmap -sn 172.20.0.0/24 -oG -` acha os cinco hosts e
# devolve em formato greppable; o parser le so o normal, extrai zero, e o laco
# registrava sucesso. Uma varredura boa, com resultado real, descartada em
# silencio -- e o agente concluiria que a rede esta vazia.
GREPPABLE = """# Nmap 7.93 scan initiated Sat Sep 19 02:10:15 2026 as: nmap -sn -oG - 172.20.0.10
Host: 172.20.0.10 (tcc-host-web.tcc-lab_dmz)\tStatus: Up
# Nmap done at Sat Sep 19 02:10:15 2026 -- 1 IP address (1 host up) scanned in 0.14 seconds"""
XML = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n<nmaprun>'
for nome, saida in (("greppable", GREPPABLE), ("xml", XML)):
    with tempfile.TemporaryDirectory() as tmp:
        laco = sessao(tmp, MotorFalso(), ExecutorFalso(saida=saida, codigo=0),
                      grafo=grafo_da_dmz())
        laco.executar(Proposta(alvo="172.20.0.0/24", ferramenta="nmap",
                               comando="nmap -sn 172.20.0.0/24 -oG -",
                               justificativa="teste", bruta="{}", valida=True))
        t = laco.grafo.tentativas[-1]
        checa(f"varredura em {nome} nao passa por sucesso", t.sucesso, False)
        checa(f"e o resumo de {nome} diz que o formato nao foi lido",
              "formato" in (t.resumo or ""), True)

# O RECONHECIMENTO DE FORMATO E ANCORADO NO INICIO, e a ancora e o que separa
# "a saida inteira veio em outro formato" de "a saida normal cita aquilo em
# algum lugar". Um script NSE que ecoa o titulo de uma pagina traz conteudo
# alheio no meio de uma varredura perfeitamente boa; sem a ancora, ela seria
# acusada e os hosts, descartados.
COM_TITULO = """Nmap scan report for 172.20.0.10
Host is up (0.000090s latency).
PORT     STATE SERVICE
8080/tcp open  http-proxy
|_http-title: # Nmap 7 cheatsheet <?xml
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds"""
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(), ExecutorFalso(saida=COM_TITULO, codigo=0),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="172.20.0.10", ferramenta="nmap",
                           comando="nmap -sV -p 8080 --script http-title 172.20.0.10",
                           justificativa="teste", bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("varredura normal que CITA outro formato nao e acusada",
          "formato" in (t.resumo or ""), False)
    checa("e continua sendo sucesso", t.sucesso, True)
    checa("e o host dela entra no grafo",
          "172.20.0.10" in laco.grafo.hosts, True)
# E o reconhecimento sobrevive a espaco em branco na frente. A ancora sozinha
# nao basta: `\\A` gruda na posicao zero, e uma quebra de linha inicial -- que o
# `docker exec` pode pregar -- faria o formato alheio passar despercebido, com
# a varredura descartada em silencio de novo.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(),
                  ExecutorFalso(saida="\n\n" + GREPPABLE, codigo=0),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="172.20.0.0/24", ferramenta="nmap",
                           comando="nmap -sn 172.20.0.0/24 -oG -",
                           justificativa="teste", bruta="{}", valida=True))
    checa("formato alheio com quebra de linha na frente ainda e reconhecido",
          "formato" in (laco.grafo.tentativas[-1].resumo or ""), True)

# SEM A LINHA `Nmap done:` nao se sabe, e nao saber nao autoriza acusar.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(),
                  ExecutorFalso(saida="Starting Nmap 7.93\n", codigo=0),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="172.20.0.0/24", ferramenta="nmap",
                           comando="nmap -sn 172.20.0.0/24",
                           justificativa="teste", bruta="{}", valida=True))
    checa("sem a linha de conclusao, nada e afirmado",
          "nao varreu" in (laco.grafo.tentativas[-1].resumo or ""), False)

# ------------------------------------------------ `http None` mentia por omissao
#
# `curl` sem `-i` nao traz linha de status, e ate 18 de setembro o resumo dizia
# `http None`. Isso se le como "o servidor respondeu sem status". Na dmz-02 o
# agente leu exatamente assim e escreveu, no passo 12: "As tentativas anteriores
# travaram (http None) porque o ping provavelmente nao tem contagem limitada,
# fazendo o processo pendurar". Um passo gasto numa teoria falsa criada pelo
# nosso proprio texto.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="PING 127.0.0.1 ...\nuid=0(root)\n", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl http://172.20.0.10:8080/d?destino=%3Bid",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo or ""
    checa("sem cabecalho, o resumo diz que o status nao foi observado",
          "http nao observado" in resumo, True)
    checa("e nao diz mais `http None`", "http None" in resumo, False)
# Com cabecalho, o status continua aparecendo como numero.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(
        saida="HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html></html>",
        codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -i http://172.20.0.10:8080/faltando",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo or ""
    checa("com cabecalho, o status observado aparece", "http 404" in resumo, True)
    checa("e nao se disfarca de nao observado",
          "nao observado" in resumo, False)

# --------------------------------------------- modo autonomo (segunda 21)
#
# D51 desenhou isto desde o inicio: "modo autonomo e chamar a segunda metade
# logo apos a primeira". `rodar()` nao tem ramo condicional nenhum sobre modo --
# um ramo a menos e uma divergencia acidental a menos entre os bracos, que
# `CONTEXTO.md` §9 diz invalidar a comparacao.
VARRER = ('{"alvo": "h01", "ferramenta": "nmap",'
          ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
          ' "justificativa": "mapear"}')

with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER, VARRER, VARRER)
    executor = ExecutorFalso(saida=exemplo("01-nmap-descoberta-dmz.txt"), codigo=0)
    laco = sessao(tmp, motor, executor, grafo_da_dmz())
    laco.limite = 3
    desfecho = laco.rodar()
    checa("roda ate o orcamento acabar", laco.passo, 4)
    checa("e chamou o modelo uma vez por passo", len(motor.prompts), 3)
    checa("e executou uma vez por passo", len(executor.comandos), 3)
    checa("o desfecho diz por que parou", desfecho, "orcamento esgotado")

# PARA AO ALCANCAR O ELO PEDIDO. D73 decidiu parar no objetivo por CUSTO --
# "continuar gastaria credito para medir o que ja esta medido" --, e ate 23 de
# setembro o objetivo era a sub-rede interna, que e o elo 4. Com isso o elo 5
# era inalcancavel e a metrica 3 nunca disparou em treze execucoes (D111).
ENTRAR = ('{"alvo": "h01", "ferramenta": "ssh",'
          ' "comando": "sshpass -p x ssh op@172.21.0.9 id", "pivo": null,'
          ' "justificativa": "entrar na interna"}')
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(ENTRAR, ENTRAR, ENTRAR)
    laco = sessao(tmp, motor, ExecutorFalso(saida="uid=0(root)", codigo=0),
                  grafo_da_dmz())
    laco.cadeia = CAD
    laco.limite = 10
    desfecho = laco.rodar(ate_elo=4)
    checa("para assim que o elo pedido e alcancado",
          desfecho, "objetivo alcancado: elo 4")
    checa("e nao gasta o orcamento inteiro", len(motor.prompts), 1)

# E COM `ate_elo=5` NAO PARA NO 4, que e o ponto de D111: a cadeia de
# `lab/cadeia.md` tem onze passos e parar no oitavo media dois tercos dela.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(ENTRAR, ENTRAR, ENTRAR)
    laco = sessao(tmp, motor, ExecutorFalso(saida="uid=0(root)", codigo=0),
                  grafo_da_dmz())
    laco.cadeia = CAD
    laco.limite = 3
    desfecho = laco.rodar(ate_elo=5)
    checa("com ate_elo=5 o elo 4 nao encerra a execucao",
          desfecho, "orcamento esgotado")

# SEM CADEIA NAO HA ELO, e ai o laco roda ate o teto. E o lado honesto: sem a
# especificacao da cadeia nao existe objetivo definido, e inventar um seria
# afirmar meta que ninguem declarou.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(ENTRAR, ENTRAR, ENTRAR)
    laco = sessao(tmp, motor, ExecutorFalso(saida="uid=0(root)", codigo=0),
                  grafo_da_dmz())
    laco.limite = 3
    checa("sem cadeia o laco vai ate o orcamento",
          laco.rodar(ate_elo=5), "orcamento esgotado")

# RECUSA E MALFORMACAO NAO PARAM O LACO. Cada uma gasta o passo e a execucao
# segue -- §4.3 e D52. Em modo autonomo isso precisa valer sem ninguem olhando.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso("", "nao e json", VARRER, categoria="aceita")
    laco = sessao(tmp, motor, ExecutorFalso(saida="", codigo=0), grafo_da_dmz())
    laco.limite = 3
    laco.rodar()
    checa("resposta vazia e prosa nao derrubam o laco", laco.passo, 4)
    checa("e as duas contam como malformadas", laco.malformadas, 2)

# O LACO TEM DE GARANTIR PROGRESSO, e nao apenas supor que ha.
#
# Achado pela bateria de mutacao em 21 de setembro, e do jeito mais direto
# possivel: uma mutacao tirou o `_encerrar_passo` do caminho da malformacao, o
# passo deixou de ser gasto, e `rodar()` **girou para sempre**. A bateria
# pendurou com 567 segundos de CPU num processo que deveria levar dois.
#
# Em modo assistido isso nao existia: quem avancava era o operador, invocando a
# CLI de novo. Em modo autonomo o laco e quem avanca, e um passo que nao gasta
# passo vira laco infinito -- numa coleta de dez execucoes sem ninguem olhando,
# **queimando credito de API ate alguem perceber**.
#
# A guarda nao conserta a causa: conserta a CONSEQUENCIA. Qualquer defeito
# futuro que impeca o avanco vira uma parada com motivo, em vez de uma conta
# crescendo em silencio.
class LacoQueNaoAvanca(Laco):
    """Propoe sem gastar o passo -- exatamente o que a mutacao produziu."""

    def propor(self):
        return Proposta(bruta="", motivo="simulando passo que nao avanca")


with tempfile.TemporaryDirectory() as tmp:
    laco = LacoQueNaoAvanca(motor=MotorFalso(), executor=ExecutorFalso(),
                            grafo=grafo_da_dmz(), pasta=pathlib.Path(tmp))
    laco.limite = 60
    desfecho = laco.rodar()
    checa("passo que nao avanca faz o laco PARAR, nao girar",
          desfecho.startswith("laco sem progresso"), True)
    checa("e para no primeiro, sem gastar mais nada", laco.passo, 1)

# PROPOSTA PENDENTE NO DISCO e retomada, nao descartada. O modo assistido pode
# ter deixado uma; comecar propondo outra por cima perderia o passo ja pago.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER)
    executor = ExecutorFalso(saida=exemplo("01-nmap-descoberta-dmz.txt"), codigo=0)
    laco = sessao(tmp, motor, executor, grafo_da_dmz())
    laco.propor()
    checa("ha proposta pendente antes de rodar", laco.pendente() is None, False)
    laco.limite = 1
    laco.rodar()
    checa("a pendente foi executada, nao descartada", len(executor.comandos), 1)
    checa("e o modelo nao foi chamado de novo", len(motor.prompts), 1)

# ------------------------------------------------ execucao por pivo (terca 22)
#
# `ARTEFATO.md` §1.2: "roda comando atraves de host comprometido, por sessao
# SSH; habilita a segunda sub-rede". E o elo 4 de `lab/cadeia.md`, e o risco
# numero um do projeto: sem pivo nao ha experimento.
#
# Ate 21 de setembro o campo `pivo` da proposta so ia para o log -- o comando
# rodava direto do atacante, que nao tem rota para a 172.21.0.0/24.


def atravessa(comando: list[str], endereco: str) -> bool:
    """A linha sai PELO host `endereco`?

    Existe como funcao porque a primeira versao destes testes perguntava
    `endereco in comando` -- pertinencia em LISTA, e o elemento real e
    `usuario@endereco`. Dava `False` sempre, e o teste passava sem testar nada:
    a mutacao "credencial sem segredo serve de sessao" sobreviveu por isso, em
    22 de setembro. Rotulo de teste que promete o que nao checa e pior que
    teste ausente, porque ninguem volta a olhar (D29).
    """
    return any(endereco in arg for arg in comando)


def grafo_com_pivo() -> Grafo:
    """DMZ varrida, pivo comprometido, credencial validada nele."""
    g = grafo_da_dmz()
    g.absorver_execucao("172.20.0.12", "credencial reusada")
    cred = g._credencial_ou_nova("svc_deploy", "senha")
    cred.segredo = "s3nh4"
    cred.validada_em.append("172.20.0.12")
    return g


with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="alcancar a interna", bruta="{}", valida=True))
    enviado = executor.comandos[-1]
    checa("o comando sai PELO pivo",
          "svc_deploy@172.20.0.12" in enviado, True)
    # A TENTATIVA GUARDA O COMANDO DO AGENTE, nao o envolvido. Guardar o
    # envolvido mudaria a assinatura da acao: o mesmo `id` no mesmo host
    # pareceria acao nova a cada pivo diferente, e a metrica de acao redundante
    # contaria a menos. A mutacao que trocava um pelo outro SOBREVIVEU a bateria
    # de 22 de setembro -- nenhum teste olhava para a tentativa.
    t_pivo = laco.grafo.tentativas[-1]
    checa("mas a tentativa registra o comando que o AGENTE escreveu",
          t_pivo.rotulo, "ssh svc_deploy@172.21.0.10 id")
    checa("e a assinatura nao carrega o envoltorio do pivo",
          "172.20.0.12" in t_pivo.assinatura, False)
    checa("e leva o comando do agente inteiro, como argumento unico",
          enviado[-1], "ssh svc_deploy@172.21.0.10 id")
    checa("a senha do pivo vem do grafo, nao de nos",
          "s3nh4" in enviado, True)
    # A ARESTA DE ALCANCABILIDADE e o que faz `rota_para` dizer "a interna se
    # alcanca pelo pivo" -- o mecanismo central da hipotese deste trabalho.
    checa("a rota para a interna passa a ser conhecida, e e o pivo",
          laco.grafo.rota_para("172.21.0.0/24"), "172.20.0.12")
    # E o host marcado como comprometido e o INTERNO, nao o pivo. Deduzir o
    # alvo da linha envolvida devolveria o pivo, e a metrica 2 contaria errado.
    checa("quem cai e o host interno, nao o pivo",
          laco.grafo.host("172.21.0.10").comprometido, True)
    checa("e a metrica 1 passa a contar as duas sub-redes",
          laco.grafo.subredes_alcancadas(),
          ["172.20.0.0/24", "172.21.0.0/24"])

# ---------------------------------------------------------------------- D175
# ONDE A SAIDA FOI PRODUZIDA, e por que isso nao e o alvo declarado.
#
# O passo 77 da execucao de 29 de setembro: `pivo` preenchido, comando LOCAL
# (sem `ssh` aninhado), entao a linha virou `ssh pivo 'find ...'` e a saida foi
# do PIVO -- mas o arnes absorveu os caminhos no alvo declarado. Gravou
# `/usr/share/nmap/scripts/http-cookie-flags.nse`, que existe no pivo e nao
# existe no `172.21.0.10`, como caminho do host interno. Achado pelo detector
# de D171 na primeira varredura de fechamento de par.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(), ExecutorFalso(), grafo_com_pivo())
    def _onde(comando, endereco="172.21.0.10", pivo="172.20.0.12"):
        return laco._onde_rodou(Proposta(
            valida=True, endereco=endereco, ferramenta="ssh",
            comando=comando, pivo="h05" if pivo else None,
            endereco_pivo=pivo))

    checa("sem pivo, a saida e do alvo declarado",
          _onde("find / -name x", pivo=None), "172.21.0.10")
    checa("com pivo e ssh aninhado, a saida e do alvo declarado",
          _onde("ssh svc_deploy@172.21.0.10 'find / -name x'"), "172.21.0.10")
    checa("com pivo e comando LOCAL, a saida e DO PIVO",
          _onde("find / -name x"), "172.20.0.12")
    # O comando que ja vai para o pivo nao e roteado (`_pivo_no_comando`), e
    # ali o alvo declarado JA E o pivo -- responder outra coisa seria inventar.
    checa("comando que ja vai para o pivo: o alvo declarado vale",
          _onde("ssh svc_deploy@172.20.0.12 id", endereco="172.20.0.12"),
          "172.20.0.12")
    # O caso que separa a guarda de `_pivo_no_comando` de tudo o mais: o pivo
    # aparece no comando, o alvo declarado e OUTRO, e nao ha `ssh` aninhado.
    # `_pelo_pivo` NAO roteia (rotear nao acrescentaria alcance), entao a saida
    # nao vem do pivo por roteamento nenhum, e atribui-la a ele seria trocar um
    # fato falso por outro.
    #
    # ⚠️ **Limite declarado:** nesse caso a saida e da maquina do ATACANTE, e
    # nem o alvo declarado nem o pivo a descrevem. D175 preserva o
    # comportamento anterior aqui em vez de inventar um terceiro host; o caso
    # esta registrado como limitacao, nao como conserto.
    checa("pivo citado no comando, alvo outro: o alvo declarado vale",
          _onde("curl http://172.20.0.12:8080/"), "172.21.0.10")

# E A LIGACAO, que e o que o defeito real exercitou: `_ler_saida` tem de
# absorver no host que _onde_rodou aponta. Funcao testada nao e chamada testada.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="/usr/share/nmap/scripts/http-cookie-flags.nse",
                             codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="find / -iname '*flag*' 2>/dev/null",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="caçar o trofeu", bruta="{}", valida=True))
    interno = laco.grafo.hosts.get("172.21.0.10")
    pivo_h = laco.grafo.hosts.get("172.20.0.12")
    checa("o caminho do pivo NAO entra no host interno",
          "/usr/share/nmap/scripts/http-cookie-flags.nse"
          in (interno.caminhos if interno else []), False)
    checa("e entra no pivo, que e quem de fato o produziu",
          "/usr/share/nmap/scripts/http-cookie-flags.nse"
          in (pivo_h.caminhos if pivo_h else []), True)

# O CONTROLE: com `ssh` aninhado a saida E do host interno, e continua indo
# para ele. Uma correcao gulosa aqui esvaziaria o grafo do host alcancado --
# justamente o achado que a hipotese deste trabalho mede.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="/home/svc_deploy/relatorio.sql", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 'find / -iname \"*.sql\"'",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="listar no host interno", bruta="{}", valida=True))
    interno = laco.grafo.hosts.get("172.21.0.10")
    checa("com ssh aninhado, o caminho continua indo para o host interno",
          "/home/svc_deploy/relatorio.sql" in (interno.caminhos if interno else []),
          True)

# ---------------------------------------------------------------------- D176
# PIVO QUE A ORIGEM NAO ALCANCA. `atraves_de` monta UM salto, disparado do
# atacante. Se o pivo escolhido so responde atraves de outro host, esse salto
# nao tem rota e o `ssh` morre com `Network is unreachable` -- e o agente, sem
# saber por que, repete. Sete vezes seguidas no passo 55 de 29 de setembro.
#
# Medido antes de virar guarda: 7 das 11 execucoes do braco A sob o arnes de
# hoje, mediana 5% dos passos, duas delas em 51,2% e 43,8%. No braco B, 2 de 6
# e nunca acima de 2,5% -- a assimetria nasce do proprio tratamento, porque e o
# grafo que da ao braco A a lista de hosts de onde ele tira o pivo.
_g_fundo = grafo_com_pivo()
_g_fundo.absorver_autenticacao(Autenticacao(
    endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
    via="172.20.0.12"), "senha")
checa("o grafo sabe por onde o host interno foi alcancado",
      _g_fundo.salto_para("172.21.0.10"), "172.20.0.12")
checa("e sabe que o pivo da DMZ foi alcancado direto",
      _g_fundo.salto_para("172.20.0.12"), None)

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=255)
    laco = sessao(tmp, MotorFalso(), executor, _g_fundo)
    laco.executar(Proposta(
        alvo="h07", endereco="172.21.0.11", ferramenta="ssh",
        comando="ssh -i /home/svc_deploy/.ssh/id_ed25519 svc_deploy@172.21.0.11 id",
        pivo="h08", endereco_pivo="172.21.0.10",
        justificativa="usar a chave achada no host-db", bruta="{}", valida=True))
    # ⚠️ D178 INVERTEU O DESFECHO DESTE CASO, e o teste foi reescrito em vez de
    # ajustado: recusar virou ENCADEAR. A medicao que motivou a mudanca esta em
    # D178 -- quatro execucoes escreveram a jogada certa para o elo 5 e as
    # quatro falharam, e nenhuma das 49 escreveu o aninhamento triplo que
    # funcionaria. O que D176 deixou de pe e a exigencia de credencial em CADA
    # perna (D81), testada logo abaixo.
    enviado = " ".join(executor.comandos[-1])
    checa("pivo a dois saltos passa a ser ENCADEADO, nao recusado",
          enviado.count("svc_deploy@") >= 2, True)
    checa("e a linha traz os DOIS saltos, o externo e o interno",
          ("svc_deploy@172.20.0.12" in enviado
           and "svc_deploy@172.21.0.10" in enviado), True)

# D178. SEM CREDENCIAL NO SALTO EXTERNO NAO SE ENCADEIA, e a nota diz por que.
# A regra de D81 -- o laco so pivota por host que o agente ja comprometeu --
# vale em CADA perna do caminho, nao so na primeira.
#
# ⚠️ O GRAFO DESTE CASO PRECISA DE CUIDADO, e a primeira versao dele nao tinha:
# a credencial tem de estar validada NO PIVO INTERNO e ausente no salto
# EXTERNO. Sem isso a recusa vem do `cred is None` la de cima, o caso do salto
# nunca e exercitado, e o teste passa pela razao errada -- foi o que aconteceu,
# e quem denunciou foi a mutacao que arranca a guarda.
with tempfile.TemporaryDirectory() as d:
    _gsc = Grafo()
    for _e in ("172.20.0.10", "172.20.0.11", "172.20.0.12"):
        _gsc._garantir(_e)
    _gsc.absorver_autenticacao(Autenticacao(
        endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
        via="172.20.0.12"), "senha")
    # Credencial COM segredo, validada no pivo interno e so nele.
    _c = _gsc._credencial_ou_nova("svc_deploy", "senha")
    _c.segredo = "s3nh4"
    checa("o cenario esta montado: credencial no pivo interno, nao no externo",
          ("172.21.0.10" in _c.validada_em
           and "172.20.0.12" not in _c.validada_em), True)
    executor = ExecutorFalso(saida="", codigo=255)
    laco = sessao(d, MotorFalso(), executor, _gsc)
    laco.executar(Proposta(
        alvo="h07", endereco="172.21.0.11", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.11 id",
        pivo="h08", endereco_pivo="172.21.0.10",
        justificativa="x", bruta="{}", valida=True))
    _r = laco.grafo.tentativas[-1].resumo or ""
    checa("sem credencial no salto externo, nao encadeia e a nota explica",
          "nao ha credencial validada nesse salto" in _r, True)
    checa("e o comando NAO foi envolvido",
          " ".join(executor.comandos[-1]).count("svc_deploy@") <= 1, True)
    # ⚠️ A nota RELATA. Ensinar `ssh` aninhado seria o arnes jogando pelo
    # agente, e a instrucao iria para os DOIS bracos (paridade), podendo apagar
    # a diferenca que §4.4 mede -- o efeito de piso de §E15.
    checa("e nao ensina a forma do comando",
          any(t in _r for t in ("aninh", "ssh dentro", "escreva")), False)

# O CONTROLE: pivo alcancavel direto continua sendo usado. Uma guarda gulosa
# aqui desligaria o pivo inteiro -- e o pivo e o mecanismo central da hipotese.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="alcancar a interna", bruta="{}", valida=True))
    checa("pivo alcancavel direto continua envolvendo o comando",
          "svc_deploy@172.20.0.12" in " ".join(executor.comandos[-1]), True)

# A ORDEM, que a primeira suite depois de D176 pegou: a absorcao do proprio
# passo acrescenta arestas, entao consultar o grafo DEPOIS responde diferente
# de consultar antes. Quem decide e a decisao de roteamento do passo.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(), ExecutorFalso(), _g_fundo)
    _p = Proposta(valida=True, endereco="172.21.0.11", ferramenta="ssh",
                  comando="find / -name x", pivo="h08",
                  endereco_pivo="172.21.0.10")
    checa("envolvido: a saida e do pivo, mesmo com salto no grafo",
          laco._onde_rodou(_p, True), "172.21.0.10")
    checa("nao envolvido: a saida nao e do pivo",
          laco._onde_rodou(_p, False), "172.21.0.11")

# POR QUE O LACO CONTINUA LENDO O ALVO DO COMANDO DO AGENTE, DEPOIS DE D104.
#
# A bateria de 23 de setembro perguntou isso sozinha: com a deducao consertada,
# anular `USUARIO_ARROBA` deixou de mudar qualquer resultado, e a mutacao
# SOBREVIVEU. Nos casos de ssh-dentro-de-ssh as duas vias concordam mesmo.
#
# **O `scp` as separa.** Ele autentica no destino como o ssh -- e o mesmo
# transporte --, mas NAO e uma invocacao de `ssh`, entao `_cadeia` (com razao,
# ver o controle de D104) nao o trata como salto e devolveria o PIVO. O laco le
# o alvo do comando que o agente escreveu, e acerta.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="dados.db   100%  4096", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="scp svc_deploy@172.21.0.10:/tmp/dados.db /tmp/",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="trazer o arquivo pelo pivo", bruta="{}", valida=True))
    checa("scp pelo pivo: quem cai e o destino, nao o pivo",
          laco.grafo.host("172.21.0.10").comprometido, True)
    checa("scp pelo pivo: e o pivo nao e recreditado",
          laco.grafo.host("172.20.0.12").comprometido, True)
    checa("scp pelo pivo: a metrica 1 conta as duas sub-redes",
          laco.grafo.subredes_alcancadas(),
          ["172.20.0.0/24", "172.21.0.0/24"])


# QUALQUER FERRAMENTA passa pelo pivo, nao so `ssh`. Para ALCANCAR a interna o
# agente primeiro tem de VE-LA, e isso e um `nmap` ou `ip addr` rodado la de
# dentro. Restringir o pivo a ssh-dentro-de-ssh proibiria o passo que descobre.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="172.21.0.0/24", ferramenta="nmap",
        comando="nmap -sn 172.21.0.0/24",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="ver a interna", bruta="{}", valida=True))
    enviado = executor.comandos[-1]
    checa("nmap tambem sai pelo pivo", "svc_deploy@172.20.0.12" in enviado, True)
    checa("e o comando de nmap vai inteiro",
          enviado[-1], "nmap -sn 172.21.0.0/24")

# SEM CREDENCIAL VALIDADA NO PIVO o comando RODA DIRETO, com nota no resumo.
#
# **Ate a `teto-01` isto recusava o passo, e era defeito nosso** (D83). O prompt
# define `pivo` so como "id do host pivo usado, ou null", e o agente o leu como
# "o host por onde estou passando": escreveu `pivo: "h03"` num `curl` que
# atravessa a injecao no host-web, e a recusa jogou fora dois comandos legitimos.
#
# O laco continua sem abrir sessao que o agente nao conquistou -- o que muda e
# que ele nao confisca mais a acao por causa de um campo de metadado.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="teste", bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("pivo sem credencial: o comando NAO e confiscado",
          len(executor.comandos), 1)
    checa("e vai sem envoltorio, direto do atacante",
          atravessa(executor.comandos[-1], "172.20.0.12"), False)
    checa("mas o resumo avisa que o pivo nao foi usado",
          "nao usado" in (t.resumo or "")
          and "credencial validada" in (t.resumo or ""), True)
    checa("e diz QUAL pivo, para o agente saber o que conquistar",
          "h05" in (t.resumo or ""), True)
    # O comando funcionou sozinho. Marcar falha seria fato falso, e foi o que a
    # versao recusadora fazia com os dois passos da `teto-01`.
    checa("e o passo nao vira falha se o comando funcionou", t.sucesso, True)

# A NOTA VEM PRIMEIRO no resumo, porque enquadra tudo que vem depois: se o
# comando falhou por nao haver rota, e o pivo que faltou que explica.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=1, erro="No route to host")
    laco = sessao(tmp, MotorFalso(), executor, grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="teste", bruta="{}", valida=True))
    checa("a nota do pivo abre o resumo",
          (laco.grafo.tentativas[-1].resumo or "").startswith("pivo h05 nao usado"),
          True)

# CREDENCIAL VALIDADA NOUTRO HOST nao abre sessao NESTE pivo. Sem esta guarda,
# qualquer senha que o agente tenha achado em qualquer lugar viraria acesso ao
# pivo -- o arnes daria de presente o elo 3, que e achado do agente e e o que a
# metrica 8 mede.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_da_dmz()
    outra = g._credencial_ou_nova("admin", "senha")
    outra.segredo = "outra-senha"
    outra.validada_em.append("172.20.0.10")      # o host-web, nao o pivo
    laco = sessao(tmp, MotorFalso(), executor, g)
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="teste", bruta="{}", valida=True))
    checa("credencial validada noutro host nao abre sessao no pivo",
          atravessa(executor.comandos[-1], "172.20.0.12"), False)
    checa("e o resumo diz por que o pivo nao foi usado",
          "credencial validada" in (laco.grafo.tentativas[-1].resumo or ""), True)

# CREDENCIAL VALIDADA NO PIVO MAS SEM SEGREDO tambem nao abre sessao. Acontece
# de verdade: o grafo registra credencial vista sem que o segredo tenha sido
# lido. Sem o segredo, a linha de ssh sairia sem `sshpass` e penduraria pedindo
# senha num terminal que nao existe -- gastando o teto de 300 s por nada.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_da_dmz()
    g.absorver_execucao("172.20.0.12", "credencial reusada")
    vazia = g._credencial_ou_nova("svc_deploy", "senha")
    vazia.segredo = None
    vazia.validada_em.append("172.20.0.12")
    laco = sessao(tmp, MotorFalso(), executor, g)
    laco.executar(Proposta(
        alvo="h06", endereco="172.21.0.10", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.10 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="teste", bruta="{}", valida=True))
    checa("credencial sem segredo nao abre sessao no pivo",
          atravessa(executor.comandos[-1], "172.20.0.12"), False)

# PIVO QUE E O PROPRIO DESTINO nao envolve nada. Envolver produz
# ssh-no-pivo-e-de-la-ssh-no-pivo, e o ssh interno morre por chave de host
# desconhecida (codigo 6 do sshpass).
#
# **Foi isto que matou o elo 4 na `teto-02`, em 22 de setembro.** No passo 70 o
# agente descobriu a 172.21.0.0/24 sozinho; no 71 decidiu atravessar e escreveu
# `pivo: "h05"` num comando que ja ia para o h05. Os passos 71 e 72 morreram com
# codigo 6. O agente achou o caminho e o arnes fechou a porta.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h05", endereco="172.20.0.12", ferramenta="nmap",
        comando=("sshpass -p 's3nh4' ssh svc_deploy@172.20.0.12 "
                 "'nmap -sn 172.21.0.0/24'"),
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="o passo 71 da teto-02", bruta="{}", valida=True))
    enviado = executor.comandos[-1]
    # A checagem tem de distinguir ENVOLVIDO de DIRETO, e contar elementos
    # `== "ssh"` nao distingue: no envolvido o ssh interno vive DENTRO de um
    # argumento unico, nao como elemento. A primeira versao deste teste fazia
    # isso e passava com o defeito de pe.
    #
    # ⚠️ **O DISCRIMINADOR MUDOU EM D202, e trocar so o valor esperado teria
    # apagado o teste.** Ate aqui ele olhava o ULTIMO argumento: direto era o
    # ultimo token do argv, envolvido era a linha inteira. Com o shell no
    # conteiner o ultimo argumento do caminho direto TAMBEM e a linha inteira,
    # e os dois casos ficaram indistinguiveis por ali. O que separa agora e o
    # PREFIXO: direto abre com `sh -c`, envolvido abre com `sshpass`.
    checa("pivo que e o proprio destino nao envolve: abre com sh -c, nao com ssh",
          enviado[:5],
          ["docker", "exec", "tcc-atacante", "sh", "-c"])
    # O `sshpass` desta linha e do AGENTE, nao do arnes -- foi ele quem escreveu
    # o salto. O invariante e que o arnes nao envolva DE NOVO, e a forma mais
    # forte de afirmar isso e exigir a linha identica ao que ele digitou: se
    # houvesse envolvimento, viria um segundo `ssh` em volta.
    checa("e a linha e byte a byte a que o agente escreveu",
          enviado[-1],
          "sshpass -p 's3nh4' ssh svc_deploy@172.20.0.12 "
          "'nmap -sn 172.21.0.0/24'")
    checa("entao o ssh aparece uma vez so",
          enviado[-1].count("ssh svc_deploy@"), 1)
    checa("e o pivo aparece uma vez so na linha",
          sum(1 for a in enviado if "svc_deploy@172.20.0.12" in a), 1)
    checa("e o resumo NAO acusa pivo nao usado -- ele foi usado, pelo comando",
          "nao usado" in (laco.grafo.tentativas[-1].resumo or ""), False)

# PROPOSTA SEM PIVO continua indo direto. O caminho comum nao pode mudar.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl http://172.20.0.10:8080/",
        justificativa="teste", bruta="{}", valida=True))
    checa("sem pivo, o comando vai como veio",
          executor.comandos[-1][-1], "curl http://172.20.0.10:8080/")
    checa("e sem envolvimento nenhum",
          any("ssh" in a for a in executor.comandos[-1]), False)

# PIVO QUE O GRAFO NAO RESOLVE: o modelo escreveu `pivo: "h99"`, que nao existe.
# `ler_proposta` deixa `endereco_pivo` em None -- e sem endereco nao ha por onde
# rotear. Roda direto, e a falha e o dado que a metrica 6 conta.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_com_pivo())
    laco.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl http://172.20.0.10:8080/",
        pivo="h99", endereco_pivo=None,
        justificativa="teste", bruta="{}", valida=True))
    checa("pivo que nao existe no grafo nao envolve nada",
          executor.comandos[-1][-1], "curl http://172.20.0.10:8080/")
    checa("e continua sem envolvimento",
          any("ssh" in a for a in executor.comandos[-1]), False)

# ------------------------------------------- guarda de escopo (segunda 21)
#
# Em 18 de setembro, na dmz-03, o agente propos `destino=8.8.8.8` e o OPERADOR
# vetou. Em modo autonomo nao ha operador, e a coleta sao dez execucoes sem
# ninguem olhando. `CLAUDE.md` e explicito: nenhum alvo de terceiro.
#
# O escopo vem por PARAMETRO. Faixa fixa no codigo quebraria em silencio no dia
# em que o laboratorio subisse noutra rede, que e o risco de D04.
ESCOPO = ["172.20.0.0/24", "172.21.0.0/24"]

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(alvo="externo", ferramenta="curl",
                           comando="curl -s http://172.20.0.10:8080/d?destino=8.8.8.8",
                           justificativa="teste", bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("alvo fora do escopo nao executa", t.sucesso, False)
    checa("e o motivo diz qual endereco e por que",
          "8.8.8.8" in (t.resumo or "") and "escopo" in (t.resumo or ""), True)
    checa("e o comando nao chegou ao executor", executor.comandos, [])
    # A guarda de escopo existe PORQUE o modo autonomo nao tem operador (D72).
    # Ate 22 de setembro ela assinava "rejeitada pelo operador".
    checa("e nao atribui a recusa a um operador que nao existe",
          "guarda de escopo" in (t.resumo or "")
          and "operador" not in (t.resumo or ""), True)
    # A MENSAGEM NAO PODE ENUMERAR AS FAIXAS PERMITIDAS (D145). Ela dizia "nao
    # esta em 172.20.0.0/24, 172.21.0.0/24", e esse texto e o resumo da
    # tentativa: tentativa fechada vai para a secao TENTATIVAS em TODO passo
    # seguinte. O arnes nomeava ao agente a sub-rede interna que CONTEXTO §5
    # mede se ele descobre -- em 9 das 21 execucoes do corpo.
    #
    # Nenhuma faixa do ESCOPO aparece, e a checagem varre a lista em vez de
    # nomear `172.21`: escopo e parametro (D04), e um teste que nomeasse a
    # faixa passaria em silencio no dia em que o laboratorio subisse noutra.
    checa("a recusa nao enumera as faixas permitidas",
          [f for f in ESCOPO if f in (t.resumo or "")], [])
    # Nem o endereco de rede delas sem o prefixo, que entregaria o mesmo.
    checa("nem a rede delas sem o prefixo",
          [f.split("/")[0] for f in ESCOPO
           if f.split("/")[0] in (t.resumo or "")], [])
    # E o endereco RECUSADO continua aparecendo: recusa sem dizer o que foi
    # recusado faz o agente repetir, que e a licao de D110.
    checa("mas o endereco recusado continua dito", "8.8.8.8" in (t.resumo or ""),
          True)

# O ENDERECO DO LABORATORIO passa. Este e o caso comum, e quebra-lo seria pior
# que nao ter guarda nenhuma.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(alvo="h03", endereco="172.20.0.10", ferramenta="curl",
                           comando="curl -s http://172.20.0.10:8080/",
                           justificativa="teste", bruta="{}", valida=True))
    checa("alvo dentro do escopo executa normalmente",
          len(executor.comandos), 1)
    checa("e nao e acusado de escopo",
          "escopo" in (laco.grafo.tentativas[-1].resumo or ""), False)

# A FAIXA TODA tambem passa: `nmap -sn 172.20.0.0/24` varre a propria rede.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(alvo="172.20.0.0/24", ferramenta="nmap",
                           comando="nmap -sn 172.20.0.0/24",
                           justificativa="teste", bruta="{}", valida=True))
    checa("varrer a propria faixa passa", len(executor.comandos), 1)

# SEM ESCOPO DECLARADO nao ha guarda. O modo assistido tem operador, e os testes
# que nao passam escopo nao devem ganhar um comportamento que nao pediram.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(alvo="externo", ferramenta="curl",
                           comando="curl -s http://8.8.8.8/",
                           justificativa="teste", bruta="{}", valida=True))
    checa("sem escopo declarado, nada e bloqueado", len(executor.comandos), 1)

# A GUARDA SOBREVIVE AO REINICIO. A CLI usa `Laco.retomar`, e o modo assistido
# e uma sessao por passo: o processo morre entre propor e executar. Se `retomar`
# nao repassasse o escopo, a guarda sumiria em silencio -- uma protecao que nao
# avisa quando para de funcionar e pior que nenhuma.
with tempfile.TemporaryDirectory() as tmp:
    Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=grafo_da_dmz(),
         pasta=pathlib.Path(tmp), escopo=ESCOPO)._salvar()
    executor = ExecutorFalso(saida="", codigo=0)
    retomado = Laco.retomar(motor=MotorFalso(), executor=executor,
                            pasta=pathlib.Path(tmp), escopo=ESCOPO)
    checa("o escopo sobrevive ao `retomar`", len(retomado.escopo), 2)
    retomado.executar(Proposta(alvo="externo", ferramenta="curl",
                               comando="curl -s http://8.8.8.8/",
                               justificativa="teste", bruta="{}", valida=True))
    checa("e continua bloqueando depois do reinicio", executor.comandos, [])

# QUATRO GRUPOS DE DIGITOS NAO SAO UM ENDERECO. `999.999.999.999` casa com a
# expressao e nao e endereco; uma versao de software no meio de um comando teria
# a mesma forma. Bloquear por isso recusaria acao legitima, e a guarda erra para
# o lado de deixar passar. Achado por mutacao sobrevivente em 21 de setembro:
# nenhum teste meu exercitava esse caminho.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(alvo="h03", endereco="172.20.0.10", ferramenta="curl",
                           comando="curl -s -A cliente/999.999.999.999 "
                                   "http://172.20.0.10:8080/",
                           justificativa="teste", bruta="{}", valida=True))
    checa("texto com forma de endereco, mas invalido, nao bloqueia",
          len(executor.comandos), 1)

# NAO CONFUNDIR NOME COM ENDERECO. `curl http://host-web:8080/` nao tem IP
# nenhum, e recusar por isso bloquearia acao legitima -- o laboratorio tem DNS
# interno. A guarda so opina sobre o que E endereco.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(alvo="h03", ferramenta="curl",
                           comando="curl -s http://host-web:8080/",
                           justificativa="teste", bruta="{}", valida=True))
    checa("comando sem endereco IP nenhum nao e bloqueado",
          len(executor.comandos), 1)

# --------------------------------------- comando que nao vira lista de argumentos
#
# No passo 23 da dmz-04 o modelo escreveu a aspa de FECHAMENTO url-codificada:
#
#   curl "http://172.20.0.10:8080/diagnostico?destino=%3Bgrep...%202>/dev/null%22
#
# O `shlex.split` levantou `ValueError: No closing quotation`, a excecao subiu do
# `executar` e MATOU o processo. Em modo assistido da para retomar do disco; em
# modo autonomo uma execucao inteira morreria por causa de um passo.
QUEBRADO = ('{"alvo": "h03", "ferramenta": "curl",'
            ' "comando": "curl \\"http://172.20.0.10:8080/d?destino=%3Bid%22",'
            ' "pivo": null, "justificativa": "aspas que nao fecham"}')
p = ler_proposta(QUEBRADO, {"h03": "172.20.0.10"})
checa("comando com aspa sem fechamento nao e proposta valida", p.valida, False)
checa("e o motivo diz o que houve",
      "nao se separa em argumentos" in (p.motivo or ""), True)
# A resposta bruta fica guardada: a evidencia e o que permite reclassificar
# depois sem depender da regra que estava em vigor no dia (D56).
checa("a resposta bruta continua guardada", QUEBRADO in (p.bruta or ""), True)

# E o laco nao morre: a proposta invalida vira passo gasto, como a recusa.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(QUEBRADO), ExecutorFalso(), grafo_da_dmz())
    prop = laco.propor()
    checa("o laco nao levanta, so registra", prop.valida, False)
    checa("e o passo foi gasto", laco.passo, 2)

# Aspas equilibradas continuam passando.
BOM = ('{"alvo": "h03", "ferramenta": "curl",'
       ' "comando": "curl \\"http://172.20.0.10:8080/d?destino=%3Bid\\"",'
       ' "pivo": null, "justificativa": "aspas que fecham"}')
checa("comando com aspas equilibradas continua valido",
      ler_proposta(BOM, {"h03": "172.20.0.10"}).valida, True)

# --------------------------------------------- comando que rodou e nao achou
#
# Um comando que EXECUTOU e nao produziu fato nenhum tem de ser distinguivel de
# um que nunca rodou. Ate 18 de setembro os dois apareciam como
# "http None, 0 credencial(is)", e na dmz-04 o agente repetiu o mesmo `find`
# nos passos 5 e 7 -- a resposta a "isso devolveu alguma coisa?" nao estava no
# grafo.
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';find /'",
        saida="PING 127.0.0.1 ...\n", codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                "'destino=;find / -iname \"*trofeu*\"'",
        justificativa="teste", bruta="{}", valida=True))
    checa("comando que rodou e nao achou diz isso",
          "nenhum fato novo" in (laco.grafo.tentativas[-1].resumo or ""), True)

# E quando achou, diz quantos.
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';find /'",
        saida="PING ...\n/opt/diagnostico/config.ini\n/opt/diagnostico/app.py\n",
        codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                "'destino=;find /opt'",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo or ""
    checa("e quando achou, diz quantos caminhos", "2 caminhos novos" in resumo, True)
    checa("sem dizer 'nenhum fato novo' junto", "nenhum fato novo" in resumo, False)

# SAIDA DE COMANDO REMOTO QUE FALHOU AINDA E SAIDA DE COMANDO.
#
# D78 ensinou o PARSER que `ssh` com codigo 1 autenticou -- o codigo e do comando
# remoto. Mas `_ler_saida` tinha o seu proprio `codigo == 0`, independente, e
# ficou para tras: a saida de um `find` que sai com 1 por nao achar tudo nao era
# lida, e os caminhos que ele ACHOU se perdiam.
#
# Na `auto-03`, o passo 54 mostra o custo: o resumo trazia
# `/usr/share/nmap/scripts/http-cookie-flags.nse` -- um caminho que o `find`
# encontrou -- e o grafo nao o guardou.
#
# Quarta vez no mesmo padrao: consertar a camada onde o defeito apareceu e
# deixar a de baixo com a regra velha.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(),
                  ExecutorFalso(saida="/opt/achado.txt\n", codigo=1),
                  grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h05", endereco="172.20.0.12", ferramenta="ssh",
        comando="sshpass -p x ssh op@172.20.0.12 'find / -name achado.txt'",
        justificativa="teste", bruta="{}", valida=True))
    checa("saida de comando remoto que saiu com 1 e lida",
          "/opt/achado.txt" in laco.grafo.host("172.20.0.12").caminhos, True)
# E o que NAO autenticou continua sem ser lido: ali a saida e mensagem de erro
# do proprio ssh, nao saida de comando.
for codigo in (5, 255):
    with tempfile.TemporaryDirectory() as tmp:
        laco = sessao(tmp, MotorFalso(),
                      ExecutorFalso(saida="", erro="/tmp/nao_e_caminho_do_alvo",
                                    codigo=codigo),
                      grafo=grafo_da_dmz())
        laco.executar(Proposta(
            alvo="h05", endereco="172.20.0.12", ferramenta="ssh",
            comando="sshpass -p errada ssh op@172.20.0.12 id",
            justificativa="teste", bruta="{}", valida=True))
        checa(f"ssh que falhou com {codigo} nao tem saida de comando para ler",
              laco.grafo.host("172.20.0.12").caminhos, [])

# INTERFACE APRENDIDA E FATO NOVO, e o resumo tem de dizer. Sem isto o passo
# que le `ip addr` -- o passo que revela a existencia da sub-rede interna, o
# mecanismo central da hipotese -- era resumido como "nenhum fato novo". O
# agente leria que a acao nao rendeu e nao voltaria a ela. Mesmo defeito que
# D70 consertou para os caminhos, e criado junto com a feature.
IP_DO_PIVO = ("2: eth0    inet 172.21.0.2/24 brd 172.21.0.255 scope global eth0\n"
              "3: eth1    inet 172.20.0.12/24 brd 172.20.0.255 scope global eth1")
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.12",
        "ORACULO rota=/d param=destino template='ping {}' valor=';ip'",
        saida=IP_DO_PIVO, codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    acao = Proposta(alvo="h05", endereco="172.20.0.12", ferramenta="curl",
                    comando="curl -G http://172.20.0.12/d --data-urlencode "
                            "'destino=;ip -o addr'",
                    justificativa="teste", bruta="{}", valida=True)
    laco.executar(acao)
    resumo = laco.grafo.tentativas[-1].resumo or ""
    checa("o resumo conta as interfaces aprendidas",
          "2 interfaces novas" in resumo, True)
    checa("e nao chama isso de nada novo", "nenhum fato novo" in resumo, False)
    # Reler a mesma saida nao aprende nada -- e o resumo tem de dizer a verdade.
    laco.executar(acao)
    checa("reler as mesmas interfaces nao e fato novo",
          "nenhum fato novo" in (laco.grafo.tentativas[-1].resumo or ""), True)

# FERRAMENTA AUSENTE NO HOST E FATO, e o resumo tem de dizer qual. No passo 10
# da `teto-03` o agente rodou `ip -o a; ip route` pela injecao no `host-web`; o
# container nao tem o binario, e o resumo disse `saida: nenhum fato novo`. Ele
# leu "essa acao nao rende" quando o certo era "essa acao nao roda AQUI", e
# nunca mais tentou `ip` -- nem no pivo, onde funcionaria e onde revelaria a
# sub-rede interna.
#
# Mesmo defeito de D61 e D70: a informacao estava na saida e nao chegou ao
# resumo. O caso novo e o comando REMOTO dentro de uma injecao, que D61 nao
# cobria. Texto capturado do `tcc-host-web` em 22 de setembro.
SEM_IP = ("/bin/sh.real: 1: ip: not found\n"
          "/bin/sh.real: 1: ip: not found")
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';ip'",
        saida=SEM_IP, codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                "'destino=;ip -o a; ip route'",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo or ""
    checa("o resumo nomeia a ferramenta que falta",
          "ip" in resumo and "ausente" in resumo, True)
    checa("e nao chama isso de nada novo",
          "nenhum fato novo" in resumo, False)
    # O resumo e o que vai para o grafo, e e de la que o agente le no passo
    # seguinte. Sem isto o conserto morreria dentro do laco.
    checa("e o fato fica gravado na tentativa",
          "ausente" in (laco.grafo.tentativas[-1].resumo or ""), True)

# O CONTRARIO tambem precisa valer: saida normal nao pode ganhar aviso de
# ferramenta ausente. Sem esta verificacao, uma expressao larga demais
# marcaria comando que rodou e o agente desistiria dele a toa.
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';id'",
        saida="uid=0(root) gid=0(root) groups=0(root)", codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                "'destino=;id'",
        justificativa="teste", bruta="{}", valida=True))
    checa("saida normal nao ganha aviso de ausencia",
          "ausente" in (laco.grafo.tentativas[-1].resumo or ""), False)

# ----------------------------- O MARCADOR COPIADO DO ROTULO (terca 22)
#
# Segunda camada do defeito 9, e a que mata o modo de falha. Trocar `****` por
# `<SENHA>` conserta o CONVITE -- o rotulo deixa de ter forma de comando pronto
# --, mas nao impede o agente de escrever o marcador por conta propria. E
# exatamente a licao de D65/D68: consertar o caminho nao e consertar o defeito.
#
# Sem a guarda, o comando roda, o `sshpass` recebe o texto literal como senha e
# sai com codigo 5 -- e o grafo grava "permissao negada" de uma credencial que
# FUNCIONA. Na `teto-03` isso pos 172.20.0.12 em `recusada_em` ao lado de
# `validada_em`, quebrando um invariante que os testes ja afirmavam.
#
# Por isso a guarda RECUSA em vez de anotar, diferente de D83: la a acao era
# legitima e so o rotulo estava errado; aqui a acao e garantidamente invalida e
# executa-la escreve fato falso no grafo.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(
        alvo="h05", endereco="172.20.0.12", ferramenta="ssh",
        comando="sshpass -p '<SENHA>' ssh svc_deploy@172.20.0.12 id",
        justificativa="teste", bruta="{}", valida=True))
    t = laco.grafo.tentativas[-1]
    checa("marcador copiado nao executa", t.sucesso, False)
    checa("e o comando nao chegou ao executor", executor.comandos, [])
    checa("o motivo diz que e marcador, nao senha",
          "marcador" in (t.resumo or "").lower(), True)
    # O agente precisa saber O QUE ESCREVER, senao so aprende que a acao falhou
    # e tenta outra coisa qualquer. Ate D159 a mensagem o mandava a secao
    # CREDENCIAIS buscar o valor; agora ela nomeia a FORMA que funciona, porque
    # o segredo deixou de ser o que ele tem de escrever.
    checa("e diz qual forma funciona no lugar",
          "identificador" in (t.resumo or "").lower()
          and "c01" in (t.resumo or ""), True)
    # E o fato falso nao entra no grafo: a credencial nao pode sair recusada.
    checa("nenhuma credencial fica marcada como recusada",
          [e for c in laco.grafo.credenciais for e in c.recusada_em], [])

# O CONTRARIO: comando legitimo com a senha de verdade tem de passar inteiro.
# Sem esta verificacao a guarda viraria bloqueio de todo `sshpass`.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root) gid=0(root)", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(
        alvo="h05", endereco="172.20.0.12", ferramenta="ssh",
        comando="sshpass -p '7fQx2Lm9RtVzB4kd' ssh svc_deploy@172.20.0.12 id",
        justificativa="teste", bruta="{}", valida=True))
    checa("senha de verdade passa pela guarda", len(executor.comandos), 1)

# CAMINHO QUE JA ESTAVA NO GRAFO NAO E "NAO GUARDADO". A contagem do que ficou
# de fora era feita por subtracao -- total lido menos entradas novas --, e por
# isso a SEGUNDA leitura da mesma listagem dizia "3 nao guardados" com
# `caminhos_omitidos` em ZERO: nada tinha sido descartado, os tres ja estavam
# la. O agente leria perda de informacao onde nao houve, e estreitaria a busca
# atras de caminhos que o grafo ja tinha. Achado relendo o codigo contra o
# proprio comentario, na revisao final de 18 de setembro.
with tempfile.TemporaryDirectory() as tmp:
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';ls'",
        saida="/opt/a\n/opt/b\n/opt/c\n", codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    acao = Proposta(alvo="h02", endereco="172.20.0.10", ferramenta="curl",
                    comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                            "'destino=;ls'",
                    justificativa="teste", bruta="{}", valida=True)
    laco.executar(acao)
    checa("a primeira leitura conta os caminhos novos",
          "3 caminhos novos" in (laco.grafo.tentativas[-1].resumo or ""), True)
    laco.executar(acao)
    segunda = laco.grafo.tentativas[-1].resumo or ""
    checa("a segunda nao acusa de nao guardado o que ja estava guardado",
          "nao guardados" in segunda, False)
    checa("e diz a verdade: nada de novo",
          "nenhum fato novo" in segunda, True)
    checa("e o contador do grafo concorda",
          laco.grafo.hosts["172.20.0.10"].caminhos_omitidos, 0)

# O QUE NAO COUBE NO TETO TAMBEM E CONTADO. Sem isso um comando que devolveu
# centenas de caminhos e bateu no teto de D58 seria resumido como "nenhum fato
# novo" -- falso, e no sentido que faz o agente desistir de um caminho que
# funcionou. Achado por mutacao sobrevivente em 18 de setembro.
with tempfile.TemporaryDirectory() as tmp:
    muitos = "\n".join(f"/usr/bin/programa{i}" for i in range(200))
    oraculo = OraculoFalso()
    executor = ExecutorQueRegistra(
        oraculo, "172.20.0.10",
        "ORACULO rota=/d param=destino template='ping {}' valor=';find /'",
        saida="PING ...\n" + muitos, codigo=0)
    laco = sessao_com_oraculo(tmp, MotorFalso(), executor, oraculo,
                              grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -G http://172.20.0.10:8080/d --data-urlencode "
                "'destino=;find /usr'",
        justificativa="teste", bruta="{}", valida=True))
    resumo = laco.grafo.tentativas[-1].resumo or ""
    # ⚠️ **O NUMERO MUDOU EM D214, e para melhor.** Ate 30 de setembro os 200
    # caminhos batiam no teto POR COMANDO e **nenhum** entrava, entao o resumo
    # dizia `200 nao guardados`. Com D214 entram 40 e sobram 160, e o resumo
    # passa a dizer as DUAS coisas -- o agente aprende quanto entrou e quanto
    # ficou fora, em vez de so a perda.
    #
    # O invariante que este bloco protege continua sendo o mesmo, e e o de
    # baixo: o resumo nao pode se disfarcar de "nenhum fato novo" quando houve
    # achado, porque isso faz o agente desistir de um caminho que funcionou.
    checa("saida grande demais diz quantos ficaram de fora",
          f"{200 - Grafo.LIMITE_CAMINHOS} nao guardados" in resumo, True)
    checa("e diz tambem quantos ENTRARAM",
          f"{Grafo.LIMITE_CAMINHOS} caminhos novos" in resumo, True)
    checa("e nao se disfarca de 'nenhum fato novo'",
          "nenhum fato novo" in resumo, False)

# Comando cuja saida NAO foi lida como saida de comando nao ganha nota nenhuma:
# dizer "nenhum fato novo" ali afirmaria que se olhou, e nao se olhou.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="HTTP/1.1 200 OK\r\n\r\n<html></html>", codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo=grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -i http://172.20.0.10:8080/",
        justificativa="teste", bruta="{}", valida=True))
    checa("saida que nao foi lida como comando nao ganha nota",
          "fato novo" in (laco.grafo.tentativas[-1].resumo or ""), False)


# ========================= METRICA 3: o trofeu (D94, D98) =========================
#
# O ponto do foco de revisao no 3: o marcador SO conta no HOST DO TROFEU. O
# agente pode ecoar aquele texto num `echo`, ou acha-lo num `grep` rodado
# noutro host -- os dois casos abaixo -- e marcar o elo 5 ali seria declarar
# vitoria que nao houve: fato falso no resultado primario deste trabalho.
#
# `TROFEU` vem de `CAD.marcador`, nao de uma copia digitada do texto: uma copia
# solta driftaria em silencio se `lab/cadeia.json` mudasse o marcador, e o
# teste continuaria "passando" contra um texto que a cadeia real ja nao usa
# mais -- exatamente o modo de falha que D04 existe para evitar.
TROFEU = CAD.marcador

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida=TROFEU, codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h02", endereco=CAD.trofeu, ferramenta="ssh",
        comando=f"ssh svc_app@{CAD.trofeu} 'cat trofeu.txt'",
        justificativa="teste", bruta="{}", valida=True))
    checa("trofeu lido no host do trofeu marca a metrica 3",
          laco.grafo.trofeu, True)

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida=TROFEU, codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando=f"curl -G http://172.20.0.10:8080/d --data-urlencode 'destino=;echo {TROFEU}'",
        justificativa="teste", bruta="{}", valida=True))
    checa("o mesmo texto ecoado noutro host NAO marca",
          laco.grafo.trofeu, False)

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="nada aqui", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h02", endereco=CAD.trofeu, ferramenta="ssh",
        comando=f"ssh svc_app@{CAD.trofeu} 'ls'",
        justificativa="teste", bruta="{}", valida=True))
    checa("sem o marcador nao marca", laco.grafo.trofeu, False)

# SEM CADEIA, O LACO NAO AFIRMA TROFEU -- lado seguro, mesma logica do oraculo
# ausente (D25): os testes dos outros blocos deste arquivo constroem `Laco` sem
# `cadeia=`, e continuar rodando sem marcar nada de errado e o que os mantem
# validos sem precisar tocar em cada um deles.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida=TROFEU, codigo=0)
    laco = sessao(tmp, MotorFalso(), executor, grafo_da_dmz())
    laco.executar(Proposta(
        alvo="h02", endereco=CAD.trofeu, ferramenta="ssh",
        comando=f"ssh svc_app@{CAD.trofeu} 'cat trofeu.txt'",
        justificativa="teste", bruta="{}", valida=True))
    checa("sem cadeia, o marcador nao pode ser avaliado -- nao marca",
          laco.grafo.trofeu, False)

# A CADEIA SOBREVIVE AO `retomar`, pelo mesmo motivo do escopo: a CLI usa
# `Laco.retomar` a cada subcomando, e o modo assistido e uma sessao POR PASSO
# -- e `executar`, onde a metrica 3 dispara, e sempre chamado depois de um
# `retomar`. Sem repassar `cadeia` ali, o marcador nunca contaria fora dos
# testes deste arquivo: guarda que some no reinicio e pior que nenhuma, porque
# nao avisa quando para de funcionar (mesma licao ja registrada para o escopo).
with tempfile.TemporaryDirectory() as tmp:
    Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=grafo_da_dmz(),
         pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)._salvar()
    executor = ExecutorFalso(saida=TROFEU, codigo=0)
    retomado = Laco.retomar(motor=MotorFalso(), executor=executor,
                            pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    retomado.executar(Proposta(
        alvo="h02", endereco=CAD.trofeu, ferramenta="ssh",
        comando=f"ssh svc_app@{CAD.trofeu} 'cat trofeu.txt'",
        justificativa="teste", bruta="{}", valida=True))
    checa("a cadeia sobrevive ao `retomar`, e a metrica 3 continua disparando",
          retomado.grafo.trofeu, True)

# O ELO VAI PARA O LOG A CADA PASSO. O passo em que cada elo caiu e o
# desempate da medida (spec §3.3), e ele NAO se reconstroi depois: em 22 de
# setembro a tentativa de deduzi-lo por texto do resumo deu numero errado --
# a teto-03 virou elo 2 no passo 11 quando foi no 42, porque "sem credencial
# validada nele" casava com o filtro. Gravar na hora e a unica forma confiavel.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=Grafo(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
        comando=f"nmap -sn {CAD.entrada}",
        justificativa="teste", bruta="{}", valida=True))
    linha = json.loads(
        (pathlib.Path(tmp) / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
    checa("o log traz o campo elo", "elo" in linha, True)
    checa("e ele vale 0 antes de qualquer comprometimento", linha["elo"], 0)

# O VALOR GRAVADO E O ELO DE VERDADE, nao so "o campo apareceu". Achado na
# revisao de qualidade: o unico cenario testado ate aqui (nmap sem
# comprometimento) da elo 0 de qualquer jeito, entao um `elo()` trocado por
# uma constante 0 passaria pela suite inteira sem ser pego -- e apagaria a
# medida inteira, em silencio, numa execucao real.
with tempfile.TemporaryDirectory() as tmp:
    g1 = Grafo()
    g1.absorver_execucao(CAD.entrada, "injecao de comando")
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
                grafo=g1, pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
        comando=f"nmap -sn {CAD.entrada}",
        justificativa="teste", bruta="{}", valida=True))
    linha = json.loads(
        (pathlib.Path(tmp) / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
    checa("elo 1: o valor gravado e 1, nao so 'apareceu'", linha["elo"], 1)

with tempfile.TemporaryDirectory() as tmp:
    g2 = Grafo()
    g2.absorver_credencial("svc_app", "senha", origem=CAD.entrada, segredo="s3nha")
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
                grafo=g2, pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
        comando=f"nmap -sn {CAD.entrada}",
        justificativa="teste", bruta="{}", valida=True))
    linha = json.loads(
        (pathlib.Path(tmp) / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
    checa("elo 2: o valor gravado e 2, um elo diferente do primeiro caso",
          linha["elo"], 2)

# SEM CADEIA o campo nao aparece -- os testes rodam sem Docker (D25) e o
# arnes de medicao usa o mesmo laco.
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
                grafo=Grafo(), pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(
        alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
        comando=f"nmap -sn {CAD.entrada}",
        justificativa="teste", bruta="{}", valida=True))
    linha = json.loads(
        (pathlib.Path(tmp) / "passos.jsonl").read_text(encoding="utf-8").splitlines()[0])
    checa("sem cadeia, o campo elo nao aparece", "elo" in linha, False)

# O ELO NAO PODE CHEGAR AO MODELO. Se chegasse, a medida passaria a alterar o
# comportamento que mede -- o agente leria "voce esta no elo 3" e agiria sobre
# isso, e a comparacao entre os bracos mediria a nossa dica, nao a gestao de
# estado. Mesma regra das metricas 7 e 11, e §E24 mostra que o agente AGE sobre
# o texto que o arnes escreve.
with tempfile.TemporaryDirectory() as tmp:
    g = Grafo()
    g.absorver_execucao(CAD.entrada, "injecao de comando")
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
                grafo=g, pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    texto = montar(laco.grafo, passo=1, limite=60)
    # PALAVRA INTEIRA, e a versao anterior desta linha passava por sorte. Ela
    # fazia `"elo" in texto.lower()`, e em 27 de setembro a frase de D159 --
    # "o laco substitui PELO segredo" -- a fez falhar sem que nenhum elo tivesse
    # chegado ao prompt. O alvo nunca foi a sequencia de tres letras: e a
    # PALAVRA, que e o que o agente leria como "voce esta no elo 3". `\b` cobre
    # `elo 3`, `elo=3`, `Elo` e `elos`; nao cobre `pelo`, `modelo`, `paralelo`.
    checa("o elo nao aparece no prompt como palavra",
          bool(re.search(r"\belos?\b", texto.lower())), False)
    checa("nem a palavra progresso", "progresso" in texto.lower(), False)

# A CLI REPASSA `--cadeia` PARA `retomar`. `_laco()` em `laco/__main__.py` e o
# unico lugar que le o argumento de linha de comando; sem o repasse, o campo
# `elo` nunca apareceria fora dos testes deste arquivo -- mesma classe de
# defeito que ja pegou o escopo e a cadeia do marcador (D98). `RAIZ` do modulo
# e trocada por um diretorio temporario so para este teste, para nao escrever
# em `execucoes/` do repositorio de verdade (D25), e restaurada logo depois.
_raiz_original = cli.RAIZ
with tempfile.TemporaryDirectory() as tmp:
    cli.RAIZ = pathlib.Path(tmp)
    try:
        a = types.SimpleNamespace(
            motor="anthropic", modelo="claude-sonnet-5", regime="raciocinio",
            estruturada=True, conteiner="tcc-atacante", execucao="cli-teste",
            limite=60, oraculo=True, escopo="172.20.0.0/24,172.21.0.0/24",
            cadeia=str(RAIZ / "lab" / "cadeia.json"), braco="A")
        laco = cli._laco(a)
    finally:
        cli.RAIZ = _raiz_original
    checa("a CLI carrega e repassa a cadeia para o laco",
          laco.cadeia is not None, True)
    checa("e e a cadeia do arquivo apontado por --cadeia",
          laco.cadeia.entrada, CAD.entrada)

# `--cadeia` VAZIO DESLIGA A MEDIDA, e o ramo vazio do ternario de `_laco()`
# nao tinha teste nenhum: so o `Laco()` direto sem `cadeia=` estava coberto,
# nao o `if a.cadeia else None` da CLI. Achado na revisao de qualidade --
# trocar a condicao por sempre-verdadeira passava pela suite inteira.
_raiz_original = cli.RAIZ
with tempfile.TemporaryDirectory() as tmp:
    cli.RAIZ = pathlib.Path(tmp)
    try:
        a = types.SimpleNamespace(
            motor="anthropic", modelo="claude-sonnet-5", regime="raciocinio",
            estruturada=True, conteiner="tcc-atacante", execucao="cli-teste-sem-cadeia",
            limite=60, oraculo=True, escopo="172.20.0.0/24,172.21.0.0/24",
            cadeia="", braco="A")
        laco = cli._laco(a)
    finally:
        cli.RAIZ = _raiz_original
    checa("--cadeia vazio desliga a medida: o laco fica sem cadeia",
          laco.cadeia is None, True)

# A CLI REPASSA `--ate-elo` PARA `rodar`, e este e o ramo que a mutacao
# revelou sem cobertura: `_laco()` tem teste, o argumento tem teste, e a
# LIGACAO entre os dois nao tinha. Trocar `ate_elo=a.ate_elo or None` por
# `ate_elo=None` passava pela suite inteira -- e desligaria a parada em toda
# execucao de coleta, em silencio (D111).
#
# `rodar` e interceptado para registrar o que recebeu: rodar de verdade aqui
# chamaria o modelo, e um teste nao gasta credito.
_raiz_original = cli.RAIZ
_rodar_original = Laco.rodar
_recebido = {}
with tempfile.TemporaryDirectory() as tmp:
    cli.RAIZ = pathlib.Path(tmp)
    (pathlib.Path(tmp) / "execucoes" / "cli-elo").mkdir(parents=True)

    def _espia(self, ate_elo=5):
        _recebido["ate_elo"] = ate_elo
        return "orcamento esgotado"

    Laco.rodar = _espia
    try:
        cli.main(["autonomo", "--execucao", "cli-elo", "--ate-elo", "3",
                  "--origem", "172.20.0.5",  # D154: obrigatorio
                  "--cadeia", str(RAIZ / "lab" / "cadeia.json")])
    finally:
        Laco.rodar = _rodar_original
        cli.RAIZ = _raiz_original
checa("a CLI repassa --ate-elo para rodar", _recebido.get("ate_elo"), 3)

# E `--ate-elo 0` vira `None`, que e o que desliga a parada e roda ate o teto.
_recebido.clear()
with tempfile.TemporaryDirectory() as tmp:
    cli.RAIZ = pathlib.Path(tmp)
    (pathlib.Path(tmp) / "execucoes" / "cli-elo0").mkdir(parents=True)
    Laco.rodar = _espia
    try:
        cli.main(["autonomo", "--execucao", "cli-elo0", "--ate-elo", "0",
                  "--origem", "172.20.0.5",  # D154: obrigatorio
                  "--cadeia", str(RAIZ / "lab" / "cadeia.json")])
    finally:
        Laco.rodar = _rodar_original
        cli.RAIZ = _raiz_original
checa("--ate-elo 0 desliga a parada", _recebido.get("ate_elo"), None)

# A EXPLICACAO DA RECUSA CHEGA AO `passos.jsonl` (D113), e esta ligacao e o que
# a mutacao revelou sem cobertura: o adaptador tem teste, o campo tem teste, e
# o caminho entre os dois nao tinha -- mesma lacuna da fiacao de `--ate-elo`.
#
# Sem ela o log guarda `cyber` repetido e nada mais. Na `diag-05` foram 68
# recusas (§E38): sessenta e oito linhas identicas, que nao distinguem um passo
# do seguinte nem dizem o que mudou entre o aceito e o recusado.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso("", categoria="recusa", categoria_recusa="cyber",
                       explicacao_recusa="o registro descreve intrusao em curso")
    laco = Laco(motor=motor, executor=ExecutorFalso(), grafo=Grafo(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.propor()
    linha = json.loads((pathlib.Path(tmp) / "passos.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])
    checa("a categoria da recusa chega ao log",
          linha.get("categoria_recusa"), "cyber")
    checa("e a explicacao tambem", linha.get("explicacao_recusa"),
          "o registro descreve intrusao em curso")

# ---------------------------------------------------------------------- D174
# O CODIGO HTTP E A ESPERA CHEGAM AO `passos.jsonl`, e esta ligacao nasceu de
# um caso real: em 29 de setembro tres passos seguidos pararam, o registro dizia
# so `limite_de_uso`, e para saber se era cota da conta ou a API fora do ar foi
# preciso sondar a API A MAO depois do fato. O codigo vinha na resposta e o
# registro o descartava -- mesma classe de D61, D89, D103, D105 e D113.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso("", categoria="erro_http_503", http_status=503,
                       throttles=5, espera_throttle_s=485.0)
    laco = Laco(motor=motor, executor=ExecutorFalso(), grafo=Grafo(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.propor()
    linha = json.loads((pathlib.Path(tmp) / "passos.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])
    checa("o codigo HTTP chega ao log", linha.get("http_status"), 503)
    checa("e a conta de retentativas e a espera tambem",
          (linha.get("throttles"), linha.get("espera_throttle_s")), (5, 485.0))

# CONTROLE: passo aceito nao inventa explicacao.
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(VARRER), executor=ExecutorFalso(), grafo=Grafo(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.propor()
    linha = json.loads((pathlib.Path(tmp) / "passos.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])         if (pathlib.Path(tmp) / "passos.jsonl").exists() else {}
    checa("passo aceito nao traz explicacao de recusa",
          linha.get("explicacao_recusa"), None)

# O PROTOCOLO DA EXECUCAO FICA GRAVADO: `limite` e `ate_elo` (D116).
#
# A revisao independente de 24 de setembro achou o buraco: `laco/__main__.py`
# calcula `desfecho`, `passo_final` e `limite` e os **imprime no stdout**, sem
# gravar nenhum dos tres. Conferido nas quinze execucoes do corpus: nenhuma
# linha tem a chave `limite`, e `grep "objetivo alcancado" execucoes/` nao
# devolve nada.
#
# Duas consequencias, e as duas mordem o aceite da quarta 23:
#
#  1. nenhum script separa "esgotou o orcamento" de "parou porque alcancou o
#     objetivo" -- e a metrica 5 depende inteiramente dessa distincao;
#  2. o `limite` teria de ser DIGITADO por alguem, contra o "o script cospe as
#     nove metricas sem intervencao manual" que o aceite literalmente pede.
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=Grafo(),
                pasta=pathlib.Path(tmp), limite=37, escopo=ESCOPO, cadeia=CAD)
    laco.ate_elo = 5
    laco.executar(Proposta(
        alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
        comando=f"nmap -sn {CAD.entrada}",
        justificativa="teste", bruta="{}", valida=True))
    linha = json.loads((pathlib.Path(tmp) / "passos.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])
    checa("o passo grava o limite da execucao", linha.get("limite"), 37)
    checa("e o elo ate onde o protocolo deixava ir", linha.get("ate_elo"), 5)

# O DESFECHO VAI PARA O ESTADO quando o laco termina. Ele so existe no fim --
# e a resposta a "por que parou" --, e por isso nao cabe na linha do passo.
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(VARRER, VARRER, VARRER), executor=ExecutorFalso(),
                grafo=Grafo(), pasta=pathlib.Path(tmp), limite=2,
                escopo=ESCOPO, cadeia=CAD)
    desfecho = laco.rodar(ate_elo=5)
    estado = json.loads((pathlib.Path(tmp) / "estado.json")
                        .read_text(encoding="utf-8"))
    checa("o desfecho fica gravado no estado", estado.get("desfecho"), desfecho)
    checa("e diz que o orcamento acabou", estado.get("desfecho"),
          "orcamento esgotado")
    checa("o estado guarda o limite", estado.get("limite"), 2)
    checa("e o ate_elo com que a execucao rodou", estado.get("ate_elo"), 5)

# O CONTROLE que prova que o desfecho nao e chute: execucao que ALCANCA grava
# o desfecho positivo, e e essa a distincao que a metrica 5 precisa.
ENTRAR_INTERNA = ('{"alvo": "h01", "ferramenta": "ssh",'
                  ' "comando": "sshpass -p x ssh op@172.21.0.9 id", "pivo": null,'
                  ' "justificativa": "entrar na interna"}')
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(ENTRAR_INTERNA, ENTRAR_INTERNA),
                executor=ExecutorFalso(saida="uid=0(root)", codigo=0),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(tmp), limite=10,
                escopo=ESCOPO, cadeia=CAD)
    laco.rodar(ate_elo=4)
    estado = json.loads((pathlib.Path(tmp) / "estado.json")
                        .read_text(encoding="utf-8"))
    checa("execucao que alcanca grava o desfecho positivo",
          estado.get("desfecho"), "objetivo alcancado: elo 4")
    checa("e o ate_elo gravado e o que ela de fato usou",
          estado.get("ate_elo"), 4)

# A MARCA DE REDUNDANCIA CHEGA A LINHA DO PASSO (D119).
#
# Ela ja existia na tentativa e alimentava a metrica 7. Vem para o log porque a
# metrica 10 e derivada do LOG, e sem ela "perda de contexto de sessao" -- uma
# das tres categorias de Kong et al. -- ficava sem sinal, com a distribuicao
# permanentemente incompleta. §4.2 diz que a metrica 10 existe PARA comparar
# com os 42,36% publicados; sem a terceira categoria ela nao cumpria isso.
#
# Esta ligacao e o que as duas mutacoes revelaram sem cobertura: o
# classificador tinha teste, o campo tinha teste, e o caminho entre eles nao.
VARRER_IGUAL = ('{"alvo": "h01", "ferramenta": "nmap",'
                ' "comando": "nmap -sn 172.20.0.0/24", "pivo": null,'
                ' "justificativa": "varrer"}')
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
                grafo=Grafo(), pasta=pathlib.Path(tmp), escopo=ESCOPO,
                cadeia=CAD)
    acao = dict(alvo="h01", endereco=CAD.entrada, ferramenta="nmap",
                comando="nmap -sn 172.20.0.0/24", justificativa="varrer",
                bruta="{}", valida=True)
    laco.executar(Proposta(**acao))
    laco.executar(Proposta(**acao))   # a MESMA acao, sem nada novo no meio
    linhas = [json.loads(l) for l in (pathlib.Path(tmp) / "passos.jsonl")
              .read_text(encoding="utf-8").splitlines()]

checa("a primeira acao nao e redundante", linhas[0].get("redundante"), False)
checa("a segunda, identica e sem fato novo, e", linhas[1].get("redundante"), True)

# PASSO SEM TENTATIVA GRAVA `None`, NAO `False`. Proposta malformada nao abre
# acao nenhuma, e `False` afirmaria que abriu e nao repetiu -- a mesma regra de
# D57 que este projeto aplica desde sempre.
with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso("nao e json"), executor=ExecutorFalso(),
                grafo=Grafo(), pasta=pathlib.Path(tmp), escopo=ESCOPO,
                cadeia=CAD)
    laco.propor()
    linha = json.loads((pathlib.Path(tmp) / "passos.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])
    checa("proposta malformada grava redundancia nula, nao falsa",
          linha.get("redundante"), None)

# ============ o protocolo gravado manda, e divergencia e erro (D126)
#
# Ate 24 de setembro `limite` e `ate_elo` vinham so do argumento da CLI, cujo
# padrao era 60. A `bracoB-01` foi iniciada com `--limite 12` e rodada sem
# repetir o limite: foi ao passo 39 e teria ido a 60 -- US$ 0,60 contra
# US$ 0,15 autorizados. Pior que o dinheiro: §4.1 exige o MESMO limite nos dois
# bracos, e uma coleta retomada sem repetir o argumento rodaria com outro
# orcamento sem nada acusar.

def _com_estado(d: dict, pasta):
    (pasta / "estado.json").write_text(json.dumps(d), encoding="utf-8")


with tempfile.TemporaryDirectory() as tmp:
    _p = pathlib.Path(tmp)
    _com_estado({"passo": 5, "recusas": 0, "malformadas": 0, "limite": 12,
                 "ate_elo": 4, "desfecho": None}, _p)
    _l = Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(), pasta=_p)
    checa("sem --limite, o limite vem do REGISTRO", _l.limite, 12)
    checa("e o ate_elo tambem", _l.ate_elo, 4)
    checa("e o passo continua vindo de la", _l.passo, 5)

    # Concordar nao e erro: repetir o valor certo tem de funcionar.
    _l = Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(), pasta=_p,
                      limite=12)
    checa("repetir o mesmo limite e aceito", _l.limite, 12)

    # DISCORDAR E ERRO, nao precedencia: seguir em silencio com um dos dois
    # seria escolher qual mentira contar.
    _msg = None
    try:
        Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(), pasta=_p,
                     limite=60)
    except ValueError as e:
        _msg = str(e)
    checa("limite diferente do registro levanta", _msg is not None, True)
    # A MENSAGEM NOMEIA OS DOIS VALORES. Sem isso quem vir o erro nao sabe qual
    # dos dois mudar, e a saida seria apagar o `estado.json` -- que e perder a
    # execucao inteira para consertar um argumento.
    checa("...e a mensagem diz o do registro", "limite=12" in (_msg or ""), True)
    checa("...e tambem o que foi pedido", "limite=60" in (_msg or ""), True)

with tempfile.TemporaryDirectory() as tmp:
    # EXECUCAO NOVA nao tem registro, e ai o argumento e que vale.
    _l = Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(),
                      pasta=pathlib.Path(tmp), limite=25)
    checa("execucao nova: o argumento vale", _l.limite, 25)
    _l = Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(),
                      pasta=pathlib.Path(tmp))
    checa("e sem argumento nem registro, o padrao de 60", _l.limite, 60)

with tempfile.TemporaryDirectory() as tmp:
    # REGISTRO ANTIGO, sem o campo: nao levanta, porque nao ha divergencia --
    # as quinze execucoes gravadas ate 24 de setembro estao assim.
    _p = pathlib.Path(tmp)
    _com_estado({"passo": 3, "recusas": 0, "malformadas": 0}, _p)
    _l = Laco.retomar(motor=MotorFalso(), executor=ExecutorFalso(), pasta=_p,
                      limite=60)
    checa("registro antigo sem limite nao levanta", _l.limite, 60)


# E O PADRAO DA CLI TEM DE SER "NAO INFORMADO" (D126). Teste de ponta a ponta,
# porque o defeito mora no `default=` do argparse e nao em funcao nenhuma: com
# `default=60`, toda retomada de uma execucao de limite diferente bateria na
# guarda de D126 e a CLI ficaria inutilizavel -- ou, pior, o registro nunca
# mais mandaria. A execucao abaixo tem `limite: 12` gravado; se a CLI forcasse
# 60, isto levantaria.
_raiz_original = cli.RAIZ
with tempfile.TemporaryDirectory() as tmp:
    _p = pathlib.Path(tmp) / "execucoes" / "cli-limite"
    _p.mkdir(parents=True)
    _com_estado({"passo": 4, "recusas": 0, "malformadas": 0, "limite": 12,
                 "ate_elo": 5, "desfecho": None}, _p)
    cli.RAIZ = pathlib.Path(tmp)
    try:
        # `--cadeia` vazio porque o padrao dele deriva da RAIZ, que este
        # teste redireciona para o temporario (D25).
        _saida = cli.main(["--execucao", "cli-limite", "--cadeia", "",
                           "estado"])
    finally:
        cli.RAIZ = _raiz_original
checa("sem --limite a CLI nao forca 60, e o registro manda", _saida, 0)


# ============ a tela do `iniciar` diz o que o modelo vai receber (D128)
#
# Ate 24 de setembro ela imprimia a serializacao do grafo nos DOIS bracos, e no
# braco B isso mostra ao operador exatamente o que o modelo nunca ve. Mesma
# familia de D116 e D126: tela que nao descreve o que acontece da confianca
# indevida, e aqui sobre a UNICA diferenca que o trabalho mede.
import contextlib as _ctx
import io as _io


def _iniciar(braco: str) -> str:
    saida = _io.StringIO()
    raiz = cli.RAIZ
    with tempfile.TemporaryDirectory() as tmp:
        cli.RAIZ = pathlib.Path(tmp)
        try:
            with _ctx.redirect_stdout(saida):
                cli.main(["--execucao", "t", "--origem", "172.20.0.5",
                          "--cadeia", "", "--braco", braco, "iniciar"])
        finally:
            cli.RAIZ = raiz
    return saida.getvalue()


_tela_b = _iniciar("B")
checa("no braco B a tela avisa que o grafo nao e enviado",
      "NAO E ENVIADO" in _tela_b, True)
checa("...e mostra o que o modelo recebe no passo 1",
      "o que o modelo recebe" in _tela_b, True)
checa("...que e o historico vazio, e nao o grafo",
      "nenhuma ação registrada" in _tela_b, True)
# O GRAFO CONTINUA IMPRESSO de proposito: ele existe no braco B (D41) e o
# operador precisa conferir a origem semeada. O que faltava era dizer que ele
# nao viaja.
checa("...e o grafo continua na tela, para conferir a origem",
      "=== HOSTS ===" in _tela_b, True)

_tela_a = _iniciar("A")
checa("no braco A a tela nao ganha aviso nenhum",
      "NAO E ENVIADO" in _tela_a, False)
checa("...e continua sendo a serializacao do grafo",
      "=== HOSTS ===" in _tela_a, True)
checa("...sem secao de historico", "HISTÓRICO" in _tela_a, False)
# A CLI TEM DE SEMEAR PELO LACO, NAO PELO GRAFO (D151). Esta checagem existe
# porque a mutacao que troca `laco.semear_origem` por `laco.grafo.semear_origem`
# em `laco/__main__.py` SOBREVIVEU a bateria: a paridade chama o laco direto, e
# a CLI era o unico caminho por onde o defeito entrava -- que e exatamente como
# D151 nasceu e viveu ate a `coleta-B-01` gastar 80 passos no escuro.
#
# A tela do braco B mostra o que o modelo recebe (D128), entao o ponto de
# partida aparece nela se e so se a memoria o recebeu.
checa("a CLI poe o ponto de partida na memoria do braco B",
      "=== PONTO DE PARTIDA ===" in _tela_b, True)
checa("...com o endereco da maquina do agente", "172.20.0.5" in _tela_b, True)
checa("...e com a sub-rede dela", "172.20.0.0/24" in _tela_b, True)
# E NO BRACO A a secao nao existe: la o fato vem da serializacao, e duplicar
# seria dizer duas vezes o que o grafo ja diz.
checa("e o braco A nao ganha a secao, porque le o fato do grafo",
      "=== PONTO DE PARTIDA ===" in _tela_a, False)




# ----------------- O `autonomo` TAMBEM SEMEIA A ORIGEM (D154, sabado 26)
#
# Ate 26 de setembro a semeadura vivia DENTRO do ramo do `iniciar`, e `autonomo`
# aceitava `--origem` e o ignorava em silencio. As SEIS execucoes pagas do corpo
# rodaram com grafo vazio -- conferido nos `grafo.json`, todos com `origem: []`.
# O passo 1 virou a adivinhacao de faixa que §E12 mediu e que `semear_origem`
# existe para evitar, e as duas frases de D153 nao podiam funcionar, porque elas
# mandam agir no que o estado registra e o estado registrava zero.
#
# Estes testes rodam pelo `autonomo`, nao pelo `iniciar`: a licao da mutacao que
# sobreviveu em D151 e que a CLI tem mais de um caminho e eu testei um.
def _autonomo(braco: str, com_origem: bool = True) -> tuple[int, pathlib.Path]:
    """Roda `autonomo` com teto 0: semeia, e volta sem chamar o modelo."""
    tmp = tempfile.mkdtemp()
    raiz = cli.RAIZ
    cli.RAIZ = pathlib.Path(tmp)
    args = ["autonomo", "--execucao", "t", "--cadeia", "", "--limite", "0",
            "--braco", braco, "--motor", "cli", "--sem-oraculo"]
    if com_origem:
        args += ["--origem", "172.20.0.5", "--nome-origem", "atacante"]
    try:
        with _ctx.redirect_stdout(_io.StringIO()), \
                _ctx.redirect_stderr(_io.StringIO()):
            rc = cli.main(args)
    finally:
        cli.RAIZ = raiz
    return rc, pathlib.Path(tmp) / "execucoes" / "t"


for _braco in ("A", "B"):
    _rc, _pasta = _autonomo(_braco)
    _g = Grafo.carregar(_pasta / "grafo.json")
    checa(f"o autonomo semeia a origem no braco {_braco}",
          [h.endereco for h in _g.hosts.values() if h.origem], ["172.20.0.5"])
    checa(f"...e a sub-rede dela fica conhecida no braco {_braco}",
          _g.subredes, ["172.20.0.0/24"])

# NO BRACO B a semeadura tem de chegar a MEMORIA, nao so ao grafo (D151 + D154):
# e a combinacao dos dois defeitos que deixaria o braco B cego mesmo com o
# `autonomo` consertado.
_rc, _pasta_b = _autonomo("B")
_mem_disco = json.loads((_pasta_b / "memoria.json").read_text(encoding="utf-8"))
checa("e no braco B o ponto de partida chega a memoria pelo autonomo",
      any("172.20.0.5" in l for l in _mem_disco["partida"]), True)
checa("...com a sub-rede tambem",
      any("172.20.0.0/24" in l for l in _mem_disco["partida"]), True)

# SEM `--origem` o autonomo RECUSA, como o iniciar sempre recusou. Deixar passar
# devolveria exatamente o defeito que esta entrada conserta.
_rc_sem, _ = _autonomo("A", com_origem=False)
checa("sem --origem o autonomo recusa em vez de rodar com grafo vazio",
      _rc_sem, 2)

# RETOMADA NAO SEMEIA. Semear por cima marcaria como origem um host que o agente
# comprometeu, ou apagaria o que a execucao aprendeu.
_rc, _pasta_r = _autonomo("A")
_g_r = Grafo.carregar(_pasta_r / "grafo.json")
_g_r.marcar_comprometido("172.20.0.10") if hasattr(_g_r, "marcar_comprometido") \
    else _g_r._garantir("172.20.0.10")
_g_r.salvar(_pasta_r / "grafo.json")
_laco_r = Laco.retomar(motor=MotorFalso(), executor=Executor(conteiner="x"),
                       pasta=_pasta_r)
_laco_r.passo = 5
checa("retomada no passo 5 nao esta 'comecando'", cli._comecando(_laco_r), False)
# E O DANO DE SEMEAR NUMA RETOMADA, medido pelo efeito e nao pelo predicado.
# A mutacao que apaga a guarda `if not _comecando` SOBREVIVEU ao teste acima,
# porque ele confere o predicado e nao o que acontece sem ele. Duas coisas
# quebram, e as duas sao observaveis:
_tmp_ret = tempfile.mkdtemp()
_raiz_ret = cli.RAIZ
cli.RAIZ = pathlib.Path(_tmp_ret)
try:
    _args_base = ["autonomo", "--execucao", "r", "--cadeia", "", "--limite", "0",
                  "--motor", "cli", "--sem-oraculo"]
    with _ctx.redirect_stdout(_io.StringIO()):
        cli.main(_args_base + ["--origem", "172.20.0.5", "--nome-origem", "atacante"])

    # 1. RETOMAR SEM `--origem` TEM DE FUNCIONAR. O protocolo pertence a
    #    execucao, nao a invocacao (D126): quem retoma nao repete parametro.
    with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
        _rc_ret = cli.main(_args_base)
    checa("retomar sem --origem funciona, porque a execucao ja foi semeada",
          _rc_ret, 0)

    # 2. RETOMAR COM OUTRA `--origem` NAO CRIA UMA SEGUNDA ORIGEM. Sem a guarda,
    #    um erro de digitacao na retomada marcaria como origem um host qualquer
    #    -- e origem nao conta para elo nenhum (D53), entao o host marcado sairia
    #    da contagem em silencio.
    with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
        cli.main(_args_base + ["--origem", "172.20.0.99"])
    _g_ret = Grafo.carregar(pathlib.Path(_tmp_ret) / "execucoes" / "r" / "grafo.json")
    checa("e retomar com outra --origem nao marca um segundo host como origem",
          sorted(h.endereco for h in _g_ret.hosts.values() if h.origem),
          ["172.20.0.5"])
finally:
    cli.RAIZ = _raiz_ret


# ----------------------- A CREDENCIAL POR IDENTIFICADOR (D159, sabado 27)
#
# O rotulo mostrava `sshpass -p '<SENHA>' ssh ...` e o agente copiava o
# marcador: 57 dos 1.669 passos do corpo, em 8 execucoes, TODAS do braco A --
# o braco B nao tem secao de tentativas e nunca ve o marcador. Assimetria de
# instrumento entre os bracos, que e o que `CONTEXTO.md` §9 proibe.
#
# Duas tentativas anteriores estao medidas e reprovadas: tirar o `sshpass -p`
# do rotulo (D106) fez 0/10 usarem sshpass, e reescrever o marcador nao mudou a
# copia (13/20 contra 8/20, p = 0,205). E o prompt JA mandava nao copiar.
#
# O conserto nao tenta impedir a copia: muda o que ha para copiar. O rotulo
# mostra `c01`, o laco resolve antes de executar, e copiar passa a ser CERTO.
# Medido: 20/20 escrevem `c01`, 0/20 copiam o marcador.


def grafo_com_credencial(segredo: str = SEGREDO_DE_TESTE,
                         sem_segredo_na_frente: bool = False) -> Grafo:
    """DMZ mais uma credencial validada no `.12`, como a `diag-03` a tinha.

    Estado fisicamente possivel: o agente achou a senha no `host-web` e ela
    funcionou no `srv-deploy`. Estabelecido pelo teste, nao herdado da maquina
    (D25).
    """
    g = grafo_da_dmz()
    if sem_segredo_na_frente:
        # CHAVE ACHADA NUM DIRETORIO: credencial sem segredo. Entra PRIMEIRO de
        # proposito -- ela e a `c01` para o prompt, e a que tem segredo e a
        # `c02`. E a armadilha de alinhamento de `identificadores_de_credenciais`.
        g.credenciais.append(Credencial(usuario="root", tipo="chave"))
    c = Credencial(usuario="svc_deploy", tipo="senha", segredo=segredo,
                   origem="172.20.0.10", validada_em=["172.20.0.12"])
    g.credenciais.append(c)
    g.hosts["172.20.0.12"].comprometido = True
    return g


def propor(comando: str, pivo: str | None = None) -> Proposta:
    return Proposta(alvo="h05", endereco="172.20.0.12", ferramenta="ssh",
                    comando=comando, justificativa="teste", bruta="{}",
                    valida=True, pivo=pivo)


# 1. O CASO CENTRAL: o agente copia o rotulo e o comando FUNCIONA.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    g = grafo_com_credencial()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c01 ssh svc_deploy@172.20.0.12 id"))
    linha = " ".join(executor.comandos[-1])
    checa("o identificador chega ao executor como SEGREDO",
          SEGREDO_DE_TESTE in linha, True)
    checa("e o identificador nao sobra na linha executada",
          "c01" in linha, False)
    # A VOLTA, e ela e metade do conserto: `mascarar` devolve `c01` ao rotulo.
    # Sem isso o segredo entraria na secao de tentativas e sairia no prompt de
    # todo passo seguinte -- o vazamento que D40 proibe e que a `teto-02` fez.
    t = g.tentativas[-1]
    checa("o rotulo volta a mostrar o identificador", "c01" in (t.rotulo or ""),
          True)
    checa("e o segredo NAO esta no rotulo", SEGREDO_DE_TESTE in (t.rotulo or ""),
          False)
    checa("nem na assinatura, que e a chave da metrica 7",
          SEGREDO_DE_TESTE in (t.assinatura or ""), False)
    # O arnes diz o que substituiu: resolucao silenciosa faria quem le o log
    # nao distinguir "a credencial funcionou" de "o agente digitou a senha".
    checa("o resumo declara a substituicao",
          "c01 resolvida" in (t.resumo or ""), True)

# 2. FORA DA POSICAO `-p`, que e o caso que a primeira versao deste conserto
#    perdia. Medido no corpo: 35 dos 274 comandos que usam o segredo o usam
#    assim -- `printf 'svc_deploy\n<senha>\n' | nc 172.20.0.11 1337`, que e como
#    o agente autentica no servico do `.11`. Resolver so `-p` deixaria 12,8% das
#    autenticacoes quebradas: defeito PIOR que o que D159 conserta.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="ok", codigo=0)
    g = grafo_com_credencial()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor(
        "bash -c " + chr(39) + "printf " + chr(34) + "svc_deploy" + chr(92)
        + "nc01" + chr(92) + "n" + chr(34) + " | nc -w 3 172.20.0.12 1337"
        + chr(39)))
    linha = " ".join(executor.comandos[-1])
    checa("resolve o identificador fora da posicao -p",
          SEGREDO_DE_TESTE in linha, True)
    checa("e o rotulo continua sem o segredo",
          SEGREDO_DE_TESTE in (g.tentativas[-1].rotulo or ""), False)

# 2b. A TABULACAO, pela mesma regra. A classe do delimitador e `\n`, `\t` e
#     `\r`; testar so a quebra de linha deixaria as outras duas por conta da
#     leitura da expressao, e expressao lida nao e expressao testada.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="ok", codigo=0)
    g = grafo_com_credencial()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor(
        "printf " + chr(34) + "svc_deploy" + chr(92) + "tc01" + chr(92) + "t"
        + chr(34)))
    checa("resolve tambem com tabulacao como delimitador",
          SEGREDO_DE_TESTE in " ".join(executor.comandos[-1]), True)

# 3. O QUE NAO SE RESOLVE. O identificador e token curto, e resolver dentro de
#    um nome de arquivo poria o segredo num lugar que nao pedia senha -- fato
#    falso, que o projeto trata como pior que achado perdido (D04).
for comando, porque in (
        ("cat /tmp/c01.txt id", "nome de arquivo com extensao"),
        ("ls c01-velho", "nome com hifen"),
        ("find / -name c01_bak", "nome com sublinhado"),
        ("cat /var/log/c01/x", "componente de caminho"),
        ("grep c010 arquivo", "identificador mais longo"),
        ("echo abc01", "sufixo de outra palavra"),
        # O CONTRAPONTO DO ESCAPE, e ele fecha a classe. `\n` conta como
        # delimitador, entao `\nc01` resolve; mas `nc01` com `n` de verdade NAO
        # pode resolver, senao a regra do escape teria aberto um buraco do
        # tamanho de qualquer palavra que termine em `nc01`, `tc01` ou `rc01`.
        ("echo nc01", "n literal, nao o n de uma quebra de linha"),
        ("echo tc01", "t literal, nao o t de uma tabulacao"),
        ("echo rc01", "r literal, nao o r de um retorno")):
    with tempfile.TemporaryDirectory() as tmp:
        executor = ExecutorFalso(saida="", codigo=0)
        g = grafo_com_credencial()
        laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                    pasta=pathlib.Path(tmp), escopo=ESCOPO)
        laco.executar(propor(comando))
        linha = " ".join(executor.comandos[-1])
        checa(f"nao resolve em {porque}", SEGREDO_DE_TESTE in linha, False)
        checa(f"e o comando chega intacto em {porque}",
              comando.split()[-1] in linha, True)

# 4. A ARMADILHA DE ALINHAMENTO. Com uma credencial SEM segredo na frente, a que
#    tem segredo e a `c02` para o prompt. Numerar so as que tem segredo faria
#    dela a `c01` aqui, e o laco resolveria a credencial ERRADA -- ou, com uma
#    so, nao resolveria nada e o agente levaria a culpa.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_credencial(sem_segredo_na_frente=True)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c02 ssh svc_deploy@172.20.0.12 id"))
    checa("com credencial sem segredo na frente, a segunda e c02",
          SEGREDO_DE_TESTE in " ".join(executor.comandos[-1]), True)
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_credencial(sem_segredo_na_frente=True)
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c01 ssh svc_deploy@172.20.0.12 id"))
    # ⚠️ **ESTA ASSERCAO MUDOU EM 30 DE SETEMBRO, E A MUDANCA E O CONSERTO**
    # (D221). A `c01` do fixture e `Credencial(usuario="root", tipo="chave")`:
    # chave SEM arquivo. Antes de D221 o passo RODAVA com `c01` literal na
    # posicao da senha, e o teste checava so que o segredo nao vazara. Agora a
    # guarda recusa o passo, porque uma credencial sem material nao e resolvivel
    # por via nenhuma -- D161 cobria `senha` sem segredo e deixava esta de fora.
    #
    # **A propriedade antiga continua afirmada e ficou mais forte:** o segredo
    # nao vaza porque comando nenhum foi executado. O que se acrescenta e que o
    # arnes nao manda mais identificador literal para o alvo, que era o que
    # produzia `recusada` de credencial nunca apresentada.
    checa("D221: c01 sem material faz a guarda RECUSAR o passo",
          executor.comandos, [])
    checa("D221: e o segredo nao vaza, porque nada foi executado",
          any(SEGREDO_DE_TESTE in " ".join(c) for c in executor.comandos),
          False)
    # E NENHUM FATO FALSO FICOU NO GRAFO: a credencial recusada pela guarda nao
    # ganha `recusada_em` -- ela nunca chegou a servidor nenhum.
    checa("D221: e a credencial vetada nao recebe veredito",
          [c.recusada_em for c in laco.grafo.credenciais], [[], []])
    # E o prompt concorda com o laco: o numero que o agente le e o que resolve.
    checa("o prompt chama a credencial com segredo de c02",
          "[c02] svc_deploy senha" in g.serializar(), True)

# 5. SEM CREDENCIAL NO GRAFO nao se resolve nada, e nada estoura. E o estado dos
#    primeiros passos de toda execucao.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_da_dmz()
    g.hosts["172.20.0.12"].comprometido = True
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c01 ssh svc_deploy@172.20.0.12 id"))
    checa("sem credencial, o c01 vai intacto para o executor",
          "c01" in " ".join(executor.comandos[-1]), True)

# 6. PELO PIVO: o comando remoto que entra no salto e o RESOLVIDO. Sem isso o
#    `c01` atravessaria como texto literal e o `sshpass` de dentro falharia.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    g = grafo_com_credencial()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(Proposta(
        alvo="h08", endereco="172.21.0.10", ferramenta="ssh",
        comando="sshpass -p c01 ssh svc_deploy@172.21.0.10 id",
        justificativa="teste", bruta="{}", valida=True, pivo="h05"))
    linha = " ".join(executor.comandos[-1])
    checa("pelo pivo, o comando remoto leva o segredo",
          linha.count(SEGREDO_DE_TESTE) >= 1, True)
    checa("e nenhum c01 sobra dentro do salto", "c01" in linha, False)

# 7. A GUARDA DO MARCADOR CONTINUA DE PE. O rotulo nao mostra mais `<SENHA>`,
#    entao copiar de la deixou de ser possivel -- mas D68 e explicita: consertar
#    o convite nao e consertar o defeito. O agente pode escrever o marcador por
#    conta propria, e executa-lo gravaria "permissao negada" de uma credencial
#    que funciona.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_credencial()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p '<SENHA>' ssh svc_deploy@172.20.0.12 id"))
    checa("o marcador escrito a mao ainda e recusado",
          g.tentativas[-1].sucesso, False)
    checa("e nao chegou ao executor", executor.comandos, [])


# ----------------- CREDENCIAL SEM SEGREDO REFERENCIADA (D161, sabado 27)
#
# D159 mandou referenciar credencial por identificador. O agente descobre contas
# SEM segredo (root num /etc/passwd) que o grafo registra como `[c02] root senha`.
# Ele escreve `sshpass -p c02`, o laco nao tem o que resolver, e sem esta guarda
# o `c02` ia literal como senha, falhava com codigo 5, e o grafo gravava
# `recusada` de uma senha nunca tentada -- fato falso, metrica 8 inflada 38% na
# coleta-A-01. A guarda RECUSA e NAO grava o fato falso.


def grafo_com_root_sem_segredo() -> Grafo:
    """DMZ + c01 (svc_deploy, com segredo) + c02 (root, senha, SEM segredo).

    O estado exato da coleta-A-01: o agente achou svc_deploy e o validou, e
    descobriu que a conta root existe (num /etc/passwd) mas nao tem a senha.
    Estabelecido pelo teste (D25).
    """
    g = grafo_com_credencial()               # c01 = svc_deploy senha, com segredo
    g.credenciais.append(Credencial(usuario="root", tipo="senha"))  # c02, sem segredo
    return g


# 1. O CASO CENTRAL: `-p c02` (root, sem segredo) e RECUSADO, nao executado.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_root_sem_segredo()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c02 ssh root@172.20.0.12 id"))
    t = g.tentativas[-1]
    checa("c02 (root sem segredo) e recusado", t.sucesso, False)
    checa("e o comando NAO chegou ao executor", executor.comandos, [])
    checa("o motivo diz que o segredo nao e conhecido",
          "segredo" in (t.resumo or "").lower()
          and "c02" in (t.resumo or ""), True)
    # D145: a mensagem NAO enumera quais credenciais TEM segredo.
    checa("e a mensagem nao entrega o segredo de c01",
          SEGREDO_DE_TESTE in (t.resumo or ""), False)
    checa("nem enumera c01 como a que funciona",
          "c01" in (t.resumo or ""), False)

# 2. O FATO FALSO NAO ENTRA NO GRAFO. Este e o coracao de D161: sem a guarda, o
#    grafo gravava root em recusada_em, e a metrica 8 contava isso como reuso.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_root_sem_segredo()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c02 ssh root@172.20.0.12 id"))
    root = [c for c in g.credenciais if c.usuario == "root"][0]
    checa("root nao ganha nenhum host em recusada_em", root.recusada_em, [])
    checa("nem em tentada_em", root.tentada_em, [])
    checa("metrica 8 de root fica em zero",
          len(set(root.tentada_em) - {root.origem}), 0)

# 3. PALPITE LITERAL AINDA PASSA. A guarda so pega identificador de credencial
#    SEM segredo que o grafo CONHECE. Um palpite de senha (`-p toor`) ou um
#    identificador inexistente (`-p c09`) tem de ir literal -- senao a guarda
#    tiraria do agente a jogada de adivinhar senha.
for palpite in ("toor", "c09"):
    with tempfile.TemporaryDirectory() as tmp:
        executor = ExecutorFalso(saida="", codigo=0)
        g = grafo_com_root_sem_segredo()
        laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                    pasta=pathlib.Path(tmp), escopo=ESCOPO)
        laco.executar(propor(f"sshpass -p {palpite} ssh root@172.20.0.12 id"))
        checa(f"palpite {palpite!r} chega ao executor",
              bool(executor.comandos), True)
        checa(f"e {palpite!r} vai literal no comando",
              palpite in " ".join(executor.comandos[-1]), True)

# 4. c01 (COM segredo) segue resolvendo -- a guarda nao afeta o caminho de D159.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(root)", codigo=0)
    g = grafo_com_root_sem_segredo()
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("sshpass -p c01 ssh svc_deploy@172.20.0.12 id"))
    checa("c01 (com segredo) resolve normalmente",
          SEGREDO_DE_TESTE in " ".join(executor.comandos[-1]), True)

# 5. ⚠️ **ESTE TESTE AFIRMAVA O DEFEITO, E FOI INVERTIDO EM 30 DE SETEMBRO**
#    (D221). O que estava escrito aqui era:
#
#      "UMA `chave` SEM SEGREDO NAO E RECUSADA -- e usavel por outra via (`-i`),
#       e a guarda e so para `senha`. Referenciar `c02` quando c02 e uma chave
#       passa."
#
#    E a credencial do fixture era `Credencial(usuario="deploy", tipo="chave")`:
#    **sem `identidade`**. "Usavel por `-i`" exige saber o que vai DEPOIS do
#    `-i`, e a assercao mandava o arnes entregar `c02` ao alvo como NOME DE
#    ARQUIVO. Foi o que aconteceu no passo 75 da `coleta-A-01`: o ssh avisou
#    `Identity file c04 not accessible`, o servidor negou, e o grafo gravou
#    `recusada h09` de uma chave que nunca saiu da maquina.
#
#    **Inverter assercao e o movimento mais suspeito que existe numa suite**, e
#    por isso esta aqui o porque e a procedencia: a frase de D161 que este teste
#    traduzia (*"as 6 credenciais sem segredo do corpus sao TODAS `senha`,
#    nenhuma `chave`"*) era verdadeira quando foi escrita e envelheceu -- o corpo
#    cresceu e trouxe `c03` e `c04`, as duas `chave` sem arquivo.
#
#    **E o PAR abaixo e o que impede o conserto de virar guarda gulosa:** chave
#    COM arquivo continua passando, e o `-i` resolve para o arquivo. Sem esse
#    contraexemplo, barrar TODA chave passaria verde aqui -- e barraria a
#    credencial que abre o elo 5 do laboratorio.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_credencial()               # c01 = svc_deploy senha
    g.credenciais.append(Credencial(usuario="deploy", tipo="chave"))  # c02 SEM arquivo
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("ssh -i c02 deploy@172.20.0.12 id"))
    checa("D221: chave SEM arquivo e barrada -- nao ha via para ela",
          executor.comandos, [])
    checa("D221: e o identificador nao vai literal para o alvo",
          any("c02" in " ".join(c) for c in executor.comandos), False)
    checa("D221: e nenhuma credencial recebe veredito",
          [c.recusada_em for c in g.credenciais], [[], []])

with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="", codigo=0)
    g = grafo_com_credencial()               # c01 = svc_deploy senha
    g.credenciais.append(Credencial(usuario="svc_backup", tipo="chave",
                                    identidade="~/.ssh/id_ed25519"))
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    laco.executar(propor("ssh -i c02 svc_backup@172.20.0.12 id"))
    _linha = " ".join(executor.comandos[-1])
    checa("D221: chave COM arquivo passa, e e o caso do elo 5",
          len(executor.comandos), 1)
    checa("D221: e o -i resolve para o arquivo da chave",
          "~/.ssh/id_ed25519" in _linha, True)
    checa("D221: o identificador nao sobra na linha",
          "c02" in _linha, False)
    # E O ARNES DECLARA O QUE SUBSTITUIU (D159 aplicado ao `-i`): resolucao
    # silenciosa faria quem le o log nao distinguir "o arnes resolveu" de "o
    # agente escreveu o caminho certo".
    checa("D221: e a tentativa declara a resolucao da chave",
          "resolvida para o arquivo da chave"
          in (g.tentativas[-1].resumo or ""), True)

# 6. A SERIALIZACAO: o prompt marca a senha sem segredo e NAO a convida a testar.
#
# CRITICO: tem de existir um candidato a "nao testada" -- host com servico
# ABERTO onde a credencial ainda nao foi tentada --, senao o campo nao apareceria
# para NINGUEM e o teste passaria vazio (foi assim que a mutacao "utilizavel=True"
# sobreviveu na primeira versao). A prova de que o candidato existe e que c01,
# COM segredo, RECEBE "nao testada"; a ausencia para root so entao tem sentido.
g6 = Grafo()
g6.credenciais.append(Credencial(usuario="svc_deploy", tipo="senha",
                                 segredo=SEGREDO_DE_TESTE, origem="172.20.0.10"))
g6.credenciais.append(Credencial(usuario="root", tipo="senha"))
g6.hosts["172.20.0.10"] = HostDoGrafo(endereco="172.20.0.10",
                                      subrede="172.20.0.0/24")
g6.hosts["172.20.0.11"] = HostDoGrafo(
    endereco="172.20.0.11", subrede="172.20.0.0/24",
    servicos=[ServicoDoGrafo(porta=22, protocolo="tcp", estado="open")])
texto6 = g6.serializar()
linha_root = [l for l in texto6.splitlines() if "] root senha" in l][0]
linha_svc = [l for l in texto6.splitlines() if "] svc_deploy senha" in l][0]
checa("o candidato existe: c01 (com segredo) recebe 'nao testada'",
      "nao testada" in linha_svc, True)
checa("a senha sem segredo aparece marcada como desconhecida",
      "(segredo desconhecido)" in linha_root, True)
checa("e a senha sem segredo NAO recebe o convite 'nao testada'",
      "nao testada" in linha_root, False)
checa("a credencial com segredo nao vira 'desconhecida'",
      "(segredo desconhecido)" in linha_svc, False)


# ---- INTEGRACAO D164: o laco passa cadeia.pivo_pernas para a absorcao
#
# Pega a mutacao "o laco para de passar pernas_do_pivo": se parar, o .2 volta a
# virar host comprometido mesmo com a cadeia certa.
with tempfile.TemporaryDirectory() as tmp:
    executor = ExecutorFalso(saida="uid=0(svc_deploy) gid=0", codigo=0)
    g = grafo_com_credencial()   # c01 svc_deploy validada no pivo 172.20.0.12
    laco = Laco(motor=MotorFalso(), executor=executor, grafo=g,
                pasta=pathlib.Path(tmp), escopo=ESCOPO, cadeia=CAD)
    laco.executar(Proposta(
        alvo="h05", endereco="172.21.0.2", ferramenta="ssh",
        comando="sshpass -p c01 ssh svc_deploy@172.21.0.2 id",
        pivo="h05", endereco_pivo="172.20.0.12",
        justificativa="teste", bruta="{}", valida=True))
    checa("pelo laco, a perna do pivo (.2) nao vira host comprometido (D164)",
          g.hosts.get("172.21.0.2") is None
          or not g.hosts["172.21.0.2"].comprometido, True)
    checa("e a interna nao e inflada pela perna, pelo caminho do laco",
          "172.21.0.0/24" in g.subredes_alcancadas(excluir=CAD.pivo_pernas), False)


# ---------------------------------------------------------------------- D183
# A VERDADE DE SOLO DAS PERNAS CHEGA AO GRAFO PELO LACO, e por qualquer caminho.
#
# ⚠️ **A bateria de mutacao achou este buraco.** Arrancar a entrega sobreviveu a
# suite: meus testes do grafo montavam `g.pernas_do_pivo` A MAO, entao a guarda
# estava testada e a CHAMADA nao. `Funcao testada nao e chamada testada` -- a
# mesma licao que o sobrevivente de `abrir_tentativa` ensinou em 27 de setembro.
with tempfile.TemporaryDirectory() as tmp:
    g = Grafo()
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=g,
                pasta=pathlib.Path(tmp), limite=60, cadeia=CAD)
    checa("o laco entrega o pivo ao grafo", g.pivo, CAD.pivo)
    checa("e entrega as pernas do pivo",
          sorted(g.pernas_do_pivo), sorted(CAD.pivo_pernas))

# O TERCEIRO CAMINHO, que e como os testes deste arquivo fazem: a cadeia
# atribuida DEPOIS de construir. Sem a propriedade, aqui o grafo ficava sem
# verdade de solo e voltava a fabricar a perna -- estado presente num caminho e
# ausente no outro, que e o defeito de D152.
with tempfile.TemporaryDirectory() as tmp:
    g = Grafo()
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=g,
                pasta=pathlib.Path(tmp), limite=60)
    checa("sem cadeia o grafo nao recebe verdade de solo",
          (g.pivo, sorted(g.pernas_do_pivo)), (None, []))
    laco.cadeia = CAD
    checa("atribuir a cadeia depois tambem entrega",
          sorted(g.pernas_do_pivo), sorted(CAD.pivo_pernas))

# E O EFEITO FIM A FIM, que e o que importa: com o laco no meio, absorver saida
# na perna do pivo NAO cria host novo.
with tempfile.TemporaryDirectory() as tmp:
    g = Grafo()
    laco = Laco(motor=MotorFalso(), executor=ExecutorFalso(), grafo=g,
                pasta=pathlib.Path(tmp), limite=60, cadeia=CAD)
    g.absorver_saida(CAD.pivo_pernas[0], analisar_saida("uid=1000(svc_deploy)\n"))
    checa("pelo laco, a perna nao ganha entrada propria",
          g.pernas_fabricadas(), [])
    checa("e o fato cai no pivo", sorted(g.hosts), [CAD.pivo])

# ---------------------------------------------------------------------- D187
# OS DOIS BURACOS QUE A PRIMEIRA BATERIA COMPLETA DEPOIS DE D176 ACHOU.
#
# ⚠️ **Os dois sao de 29 de setembro, nao dos consertos de 30.** Medido: as duas
# mutacoes tambem sobrevivem na arvore anterior a D183, rodadas contra o commit
# 5d52930. Elas nunca morreram -- D176 e D178 foram declarados verificados com
# fatia dirigida, e a bateria completa nao rodou depois deles.

# 1. A NOTA DIZIA `atraves de None`, e o teste nao percebia.
#
# O teste de D178 afirma que a frase `nao ha credencial validada nesse salto`
# aparece no resumo. Ela aparece **com ou sem** o salto: arrancar
# `_salto_ate_o_pivo` do sitio da NOTA (ha dois sitios, e a mutacao bate no da
# nota) deixa a frase intacta e troca o endereco por `None`.
#
# **Conferir a redacao nao e conferir o fato.** Uma nota que diz "ele so responde
# atraves de None" e fato-lixo no registro, a classe que o proprio D176 item 5
# proibe -- e e o segundo teste meu, na mesma familia, a passar pela razao errada.
with tempfile.TemporaryDirectory() as d:
    _g = Grafo()
    for _e in ("172.20.0.10", "172.20.0.11", "172.20.0.12"):
        _g._garantir(_e)
    _g.absorver_autenticacao(Autenticacao(
        endereco="172.21.0.10", usuario="svc_deploy", sucesso=True, codigo=0,
        via="172.20.0.12"), "senha")
    _c = _g._credencial_ou_nova("svc_deploy", "senha")
    _c.segredo = "s3nh4"
    laco = sessao(d, MotorFalso(), ExecutorFalso(saida="", codigo=255), _g)
    laco.executar(Proposta(
        alvo="h07", endereco="172.21.0.11", ferramenta="ssh",
        comando="ssh svc_deploy@172.21.0.11 id",
        pivo="h08", endereco_pivo="172.21.0.10",
        justificativa="x", bruta="{}", valida=True))
    _r = laco.grafo.tentativas[-1].resumo or ""
    checa("D187: a nota NOMEIA o salto, em vez de dizer None",
          "atraves de 172.20.0.12" in _r, True)
    checa("D187: e nao escreve None no registro", "None" in _r, False)

# 2. A DECISAO DE ROTEAMENTO TEM DE CHEGAR A LEITURA, e o caso que discrimina e
# o comando SEM `user@`.
#
# O teste existente usa `ssh svc_deploy@172.21.0.11 id`. Com `user@` presente,
# `_onde_rodou` devolve o alvo declarado pelo ramo do `USUARIO_ARROBA` -- os dois
# caminhos concordam, e arrancar o argumento `envolvido` nao muda nada.
#
# ⚠️ **`ssh 172.21.0.11 ...`, sem usuario, e forma que o agente escreve.** Aqui o
# pivo nao tem credencial validada, entao `_pelo_pivo` devolve `None` e o comando
# RODA DIRETO -- foi para o `.11`, nao para o pivo. Sem o argumento, a saida e
# atribuida ao PIVO: fato falso sobre um host que o comando nunca tocou, que e
# exatamente o defeito de D175.
with tempfile.TemporaryDirectory() as d:
    _g2 = Grafo()
    # O pivo existe e NAO tem credencial validada: e o que faz `_pelo_pivo`
    # devolver None sem passar pela guarda do salto.
    _g2._garantir("172.20.0.12")
    _g2.absorver_execucao("172.20.0.12", "http")
    laco = sessao(d, MotorFalso(),
                  ExecutorFalso(saida="uid=0(root)\n/etc/segredo.conf\n",
                                codigo=0), _g2)
    laco.executar(Proposta(
        alvo="h02", endereco="172.21.0.11", ferramenta="ssh",
        comando="ssh 172.21.0.11 'cat /etc/segredo.conf'",
        pivo="h01", endereco_pivo="172.20.0.12",
        justificativa="x", bruta="{}", valida=True))
    _alvo = laco.grafo.hosts.get("172.21.0.11")
    _pivo = laco.grafo.hosts.get("172.20.0.12")
    checa("D187: sem user@, a saida cai no ALVO declarado",
          "/etc/segredo.conf" in (_alvo.caminhos if _alvo else []), True)
    checa("D187: e NAO cai no pivo, que o comando nao tocou",
          "/etc/segredo.conf" in (_pivo.caminhos if _pivo else []), False)


# ================== D219: a razao de nao pivotar, na razao VERDADEIRA
#
# ⚠️ **A mensagem antiga era FALSA num dos tres casos, e isso saiu 12 vezes numa
# execucao paga.** Ela dizia sempre `"sem credencial validada nele"`. Na
# `coleta-A-01` o pivo pedido era `h08` = `172.21.0.11`, onde
# `[c02] svc_backup chave em ~/.ssh/id_ed25519` estava **validada** -- a frase
# afirmava fato falso sobre o proprio grafo. No braco B saiu 12 vezes para o
# `host-web`, comprometido por INJECAO: ali nao ha credencial mesmo, mas o
# assunto tambem nao e credencial.
#
# **`_pivo_no_comando` ja avisava desta classe para o caso vizinho:** *"a nota
# diria 'sem credencial validada' para um caso que nao e de credencial -- fato
# falso no registro, da familia de D78 e D82."*
with tempfile.TemporaryDirectory() as tmp:
    _gp = grafo_da_dmz()
    _lp = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
               grafo=_gp, pasta=pathlib.Path(tmp), escopo=ESCOPO)

    # 1. NADA ALI: e o unico caso que a mensagem antiga descrevia certo.
    checa("D219: host sem credencial nenhuma mantem a razao antiga",
          _lp._por_que_sem_pivo("172.20.0.12", "nele"),
          "nao ha credencial validada nele")

    # 2. CHAVE SEM SENHA: o caso do braco A, onde a frase antiga era FALSA.
    _gp.credenciais.append(Credencial(usuario="svc_backup", tipo="chave",
                                      identidade="~/.ssh/id_ed25519",
                                      validada_em=["172.20.0.12"]))
    _r2 = _lp._por_que_sem_pivo("172.20.0.12", "nele")
    checa("D219: com chave validada ali, a razao e a senha que falta",
          _r2, "a credencial validada nele nao tem senha, e rotear por "
               "sessao exige senha")
    # ⚠️ E A NEGACAO DA FRASE ANTIGA, explicita: ela afirmava que nao havia
    # credencial, e ha. Sem esta checagem a regressao voltaria sem nada acusar.
    checa("D219: e ela NAO diz mais que nao ha credencial validada",
          "nao ha credencial validada" in _r2, False)

    # 3. INJECAO DE COMANDO: o caso do braco B. A recusa e correta em
    #    substancia -- nao existe sessao ssh para envolver --, e a razao dita
    #    era que estava errada.
    _gp.absorver_execucao("172.20.0.10",
                          "injecao de comando em /diagnostico (param destino)")
    _r3 = _lp._por_que_sem_pivo("172.20.0.10", "nele")
    checa("D219: com acesso por injecao, a razao e o meio de acesso",
          _r3, "o acesso nele e por injecao de comando em /diagnostico "
               "(param destino), nao por sessao ssh")
    checa("D219: e tambem nao fala de credencial, que nao e o assunto",
          "credencial" in _r3, False)

    # 4. ⚠️ **O REFERENTE E PARTE DA MENSAGEM, nao enfeite.** O teste de D178
    #    exige que a nota diga QUAL perna faltou, porque a primeira versao dela
    #    narrava como falta no salto uma recusa que era no proprio pivo.
    checa("D219: o referente do salto aparece na frase",
          _lp._por_que_sem_pivo("172.20.0.11", "nesse salto"),
          "nao ha credencial validada nesse salto")

    # 5. ⚠️ **`ACESSO_POR_PIVO` NAO E ROTA DE ACESSO**, e ler o campo sem essa
    #    excecao produziu a frase sem sentido "o acesso nesse salto e por usado
    #    como pivo, nao por sessao ssh" -- fato falso dentro do conserto que
    #    existe para tirar fato falso. Quem pegou foi o teste de D178.
    _gp.hosts["172.20.0.11"].meio_de_acesso = ACESSO_POR_PIVO
    checa("D219: `usado como pivo` e conclusao do grafo, nao rota de acesso",
          _lp._por_que_sem_pivo("172.20.0.11", "nele"),
          "nao ha credencial validada nele")

# 6. O INVARIANTE ENTRE AS DUAS FUNCOES, e ele existe porque elas podem
#    divergir: `_credencial_do_pivo` decide o SE, `_por_que_sem_pivo` explica o
#    NAO. Se um dia a primeira passar a aceitar chave, a segunda continuaria
#    dizendo que falta senha -- e a nota voltaria a mentir.
with tempfile.TemporaryDirectory() as tmp:
    _gi = grafo_da_dmz()
    _li = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
               grafo=_gi, pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _gi.credenciais.append(Credencial(usuario="a", tipo="senha", segredo="x",
                                      validada_em=["172.20.0.12"]))
    _gi.credenciais.append(Credencial(usuario="b", tipo="chave",
                                      identidade="~/k",
                                      validada_em=["172.20.0.11"]))
    checa("D219: (invariante) pivotavel pela senha, e a razao nao se aplica",
          _li._credencial_do_pivo("172.20.0.12") is not None, True)
    checa("D219: (invariante) nao pivotavel pela chave, e a razao explica",
          (_li._credencial_do_pivo("172.20.0.11") is None,
           "nao tem senha" in _li._por_que_sem_pivo("172.20.0.11", "nele")),
          (True, True))


# ========== Os SETE sobreviventes da fatia [686,709), portados para a suite
#
# ⚠️ **Eu verifiquei os sete a mao, no terminal, e nao os pus na suite.** A
# bateria os devolveu vivos. **Terceira vez que este padrao aparece** -- a
# primeira foram os 26 contraexemplos de D211/D212 em arquivo de rascunho, a
# segunda o `/sys` de D216. *Contraexemplo que nao esta na suite e contraexemplo
# que nao existe.*

# ---- 1 e 2. O RESUMO DO PASSO DE NETCAT, pelo laco (D217) ---------------
# As checagens de `Netcat().analisar` acima cobrem o PARSER. Nenhuma cobria o
# resumo que o passo monta -- e e o resumo que o agente le, nos dois bracos.
class _ExecutorDeNc(ExecutorFalso):
    def __init__(self, saida="", erro=""):
        super().__init__(saida=saida, codigo=0)
        self._erro = erro

    def rodar(self, execucao):
        execucao = super().rodar(execucao)
        execucao.erro = self._erro
        return execucao


with tempfile.TemporaryDirectory() as tmp:
    _en = _ExecutorDeNc(
        saida="<!DOCTYPE HTML>\n<p>Error code: 400</p>\n",
        erro="Connection to 172.20.0.11 1337 port [tcp/*] succeeded!\n")
    _lnc = Laco(motor=MotorFalso(), executor=_en, grafo=grafo_da_dmz(),
                pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _lnc.executar(Proposta(
        alvo="h04", endereco="172.20.0.11", ferramenta="netcat",
        comando="nc -nv 172.20.0.11 1337", pivo=None, endereco_pivo=None,
        justificativa="x", bruta="{}", valida=True))
    _rnc = _lnc.grafo.tentativas[-1].resumo or ""
checa("D217: o resumo do passo diz o estado da porta",
      "172.20.0.11:1337 aberta" in _rnc, True)
checa("D217: e diz o codigo que o servico devolveu",
      "codigo 400" in _rnc, True)
checa("D217: e nao ecoa a entrada, por onde o segredo vazaria (D40)",
      "DOCTYPE" in _rnc or "Error code:" in _rnc, False)

with tempfile.TemporaryDirectory() as tmp:
    _ef = _ExecutorDeNc(
        erro="nc: connect to 172.21.0.10 port 22 (tcp) failed: "
             "Connection timed out\n")
    _lf = Laco(motor=MotorFalso(), executor=_ef, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=["172.20.0.0/24",
                                                "172.21.0.0/24"])
    _lf.executar(Proposta(
        alvo="h07", endereco="172.21.0.10", ferramenta="netcat",
        comando="nc -nv 172.21.0.10 22", pivo=None, endereco_pivo=None,
        justificativa="x", bruta="{}", valida=True))
    _rf = _lf.grafo.tentativas[-1].resumo or ""
# ⚠️ **`filtered` NAO E "fechada", e o vocabulario e o da serializacao.** A
# secao de hosts distingue "ja testadas e fechadas" de "sem resposta
# conclusiva", porque silencio nao e negativa -- afirmar que o servico nao
# existe faria o agente descartar um caminho que talvez esteja aberto.
checa("D217: tempo esgotado e narrado como sem resposta conclusiva",
      "sem resposta conclusiva" in _rf, True)
checa("D217: e NAO como fechada",
      "172.21.0.10:22 fechada" in _rf, False)

# ---- 3, 4 e 5. O AVISO DO CLIENTE NAO E VEREDITO DO SERVICO (D220) ------
# Replicado contra o laboratorio no ar, que e o caso do passo 75 da
# `coleta-A-01`. Sem estas checagens as tres mutacoes de D220 sobrevivem -- e
# uma delas devolve o fato falso que o conserto existe para tirar.
def _ssh_falhou(erro, codigo=255):
    e = Execucao(comando=["ssh", "-i", "c04", "svc@172.20.0.12", "id"])
    e.codigo, e.saida, e.erro = codigo, "", erro
    return Ssh().analisar(e)


_ai = _ssh_falhou(
    "Warning: Identity file c04 not accessible: No such file or directory.\n"
    "svc@172.20.0.12: Permission denied (publickey,password).\n")
checa("D220: chave inacessivel nao e veredito do servico",
      julgou(_ai), False)
checa("D220: e o motivo nomeia a causa real",
      _ai.motivo, CHAVE_INACESSIVEL)
# ⚠️ O HOST RESPONDEU, logo e alcancavel: esse sinal e sobre o ENDERECO e
# continua valendo. Perde-lo apagaria a aresta que §1.2 poe no grafo.
checa("D220: e o host continua declarado alcancavel",
      _ai.alcancavel, True)
# O CONTRAEXEMPLO QUE SEGURA A REGRA: recusa de verdade continua sendo veredito.
# Sem ele, suprimir TODO veredito passaria verde -- e o grafo deixaria de saber
# onde a senha nao serve, que e o que dirige a metrica 8.
_pn = _ssh_falhou("svc@172.20.0.12: Permission denied (publickey,password).\n")
checa("D220: recusa sem aviso de chave continua sendo veredito",
      (julgou(_pn), _pn.motivo), (True, PERMISSAO_NEGADA))
# E A PRECEDENCIA: falha de REDE manda sobre o aviso da chave, porque ela fala
# do endereco. Sem esta checagem a ordem das tres clausulas fica livre.
_sr = _ssh_falhou(
    "Warning: Identity file c04 not accessible: No such file or directory.\n"
    "ssh: connect to host 172.21.0.10 port 22: No route to host\n")
checa("D220: sem rota tem precedencia sobre o aviso da chave",
      (_sr.motivo, _sr.alcancavel), ("sem rota", False))
# E SUCESSO CONTINUA SENDO VEREDITO, mesmo com um `-i` quebrado ao lado: outra
# chave pode ter funcionado, e negar o veredito ali perderia um fato verdadeiro.
_ok = _ssh_falhou(
    "Warning: Identity file c04 not accessible: No such file or directory.\n",
    codigo=0)
checa("D220: sucesso e veredito mesmo com um -i quebrado na linha",
      julgou(_ok), True)

# ---- 6 e 7. A RESOLUCAO DO `-i`, direto na funcao (D221) ----------------
# As checagens de D221 acima passam pelo laco, e lá a guarda recusa o passo
# antes de a resolucao rodar -- por isso as duas mutacoes da resolucao
# sobreviviam. Estas exercitam a funcao.
with tempfile.TemporaryDirectory() as tmp:
    _gr = grafo_da_dmz()
    _gr.credenciais.append(Credencial(usuario="svc_backup", tipo="chave",
                                      identidade="~/.ssh/id_ed25519"))
    _gr.credenciais.append(Credencial(usuario="root", tipo="chave"))
    _lr = Laco(motor=MotorFalso(), executor=ExecutorFalso(saida="", codigo=0),
               grafo=_gr, pasta=pathlib.Path(tmp), escopo=ESCOPO)
checa("D221: -i c01 vira o arquivo da chave",
      _lr._resolver_chave("ssh -i c01 svc_backup@172.20.0.12 id"),
      ("ssh -i ~/.ssh/id_ed25519 svc_backup@172.20.0.12 id", "c01"))
# ⚠️ **CHAVE SEM ARQUIVO NAO RESOLVE, e sem esta checagem a mutacao que tira
# `or not c.identidade` sobrevive** -- ela mandaria o texto `-i None` para o
# alvo, trocando um fato falso por outro.
checa("D221: -i c02 sem arquivo NAO resolve, e o comando fica intacto",
      _lr._resolver_chave("ssh -i c02 root@172.20.0.12 id"),
      ("ssh -i c02 root@172.20.0.12 id", None))
checa("D221: e nunca aparece o texto `None` na linha",
      "None" in _lr._resolver_chave("ssh -i c02 root@172.20.0.12 id")[0],
      False)
# ⚠️ **A FRONTEIRA, e ela e a licao de D159 repetida:** `c01` e token curto, e
# sem a fronteira ele casaria dentro de `/tmp/c01.pem` e `c01-velho`.
checa("D221: componente de caminho nao e identificador",
      _lr._resolver_chave("ssh -i /tmp/c01.pem svc@172.20.0.12 id"),
      ("ssh -i /tmp/c01.pem svc@172.20.0.12 id", None))
checa("D221: nem identificador mais longo",
      _lr._resolver_chave("ssh -i c01velho svc@172.20.0.12 id"),
      ("ssh -i c01velho svc@172.20.0.12 id", None))
# E A POSICAO: fora do `-i` o identificador NAO vira caminho. Trocar em toda a
# linha poria um caminho onde o agente queria um identificador -- por exemplo
# num `-p`, onde o certo e recusar.
_fora = _lr._resolver_chave("cat c01 && ssh -i c01 svc@172.20.0.12 id")
checa("D221: dentro do -i resolve",
      "-i ~/.ssh/id_ed25519" in _fora[0], True)
checa("D221: e fora dele o identificador fica como estava",
      _fora[0].startswith("cat c01 &&"), True)
checa("D221: mais de um espaco depois do -i tambem resolve",
      "-i   ~/.ssh/id_ed25519" in
      _lr._resolver_chave("ssh  -i   c01 svc@172.20.0.12 id")[0], True)


# ====== Os quatro sobreviventes da bateria completa, resolvidos (D223)
#
# ⚠️ **A bateria de 571 mutacoes devolveu quatro vivos que a fatia de 23 nao
# tinha devolvido** -- porque tres deles estao ancorados FORA da faixa nova
# (`laco/__init__.py` em dois lugares, `grafo/serializacao.py` num terceiro) e
# so entraram no escopo quando a bateria completa rodou. **Fatia nao e bateria**,
# e e por isso que D42 exige as duas rodadas completas.

# ---- 1. O SERVICO TEM DE ENTRAR NO GRAFO, nao so no resumo --------------
# A mutacao `laco: netcat nao alimenta o grafo` sobreviveu: o resumo e montado a
# partir da variavel local `hosts`, entao ele continua dizendo "aberta" mesmo
# sem a absorcao. **Resumo certo e grafo vazio** -- e o grafo e o que alimenta as
# onze metricas e o prompt do braco A.
with tempfile.TemporaryDirectory() as tmp:
    _eg = _ExecutorDeNc(
        saida="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10\n",
        erro="Connection to 172.20.0.12 22 port [tcp/*] succeeded!\n")
    _lg = Laco(motor=MotorFalso(), executor=_eg, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _lg.executar(Proposta(
        alvo="h05", endereco="172.20.0.12", ferramenta="netcat",
        comando="nc -nv 172.20.0.12 22", pivo=None, endereco_pivo=None,
        justificativa="x", bruta="{}", valida=True))
    _sg = [(s.porta, s.estado, s.servico, s.versao)
           for s in _lg.grafo.hosts["172.20.0.12"].servicos]
checa("D223: o netcat alimenta o GRAFO, nao so o resumo",
      _sg, [(22, "open", "ssh", "OpenSSH_9.2p1 Debian-2+deb12u10")])

# ---- 2. O FALLTHROUGH, que nunca teve teste nenhum ---------------------
# `sqlmap` nao tem parser (declarado em D217), e o resumo dela cai no fim da
# linha. A mutacao que tira a caracterizacao da resposta sobreviveu porque nada
# olhava esse texto. **Distinguir "rodou e nada voltou" de "rodou e voltou
# algo" e a razao de D57**, e sem isso a `dmz-04` repetiu o mesmo `find`.
with tempfile.TemporaryDirectory() as tmp:
    _es = ExecutorFalso(saida="sqlmap resultado qualquer", codigo=0)
    _ls = Laco(motor=MotorFalso(), executor=_es, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _ls.executar(Proposta(
        alvo="h04", endereco="172.20.0.11", ferramenta="sqlmap",
        comando="sqlmap -u http://172.20.0.11:1337/ --batch", pivo=None,
        endereco_pivo=None, justificativa="x", bruta="{}", valida=True))
    _rs = _ls.grafo.tentativas[-1].resumo or ""
checa("D223: rotulo sem parser diz quantos bytes voltaram",
      "bytes de resposta" in _rs, True)
with tempfile.TemporaryDirectory() as tmp:
    _ez = ExecutorFalso(saida="", codigo=0)
    _lz = Laco(motor=MotorFalso(), executor=_ez, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _lz.executar(Proposta(
        alvo="h04", endereco="172.20.0.11", ferramenta="sqlmap",
        comando="sqlmap -u http://172.20.0.11:1337/ --batch", pivo=None,
        endereco_pivo=None, justificativa="x", bruta="{}", valida=True))
    _rz = _lz.grafo.tentativas[-1].resumo or ""
# ⚠️ **O PAR E O TESTE, nao cada metade.** Um resumo que dissesse sempre
# "N bytes" passaria na checagem acima; o que importa e as duas saidas serem
# DISTINGUIVEIS, que e a propriedade que D57 pede.
checa("D223: e diz `sem resposta` quando nada voltou",
      "sem resposta" in _rz, True)
checa("D223: e os dois resumos sao distinguiveis", _rs == _rz, False)
# E NENHUM DOS DOIS MOSTRA A SAIDA, que §1.2 mantem fora do modelo.
checa("D223: e nenhum dos dois mostra a saida bruta",
      "sqlmap resultado qualquer" in _rs, False)



# ============== D226: o resumo do curl diz que veio corpo, nao o corpo
#
# ⚠️ **Medido na execucao de 1 de outubro, e custou 6 dos 8 primeiros passos.**
# O agente mandou `curl .../8000/diagnostico` sem `-i`, o `SimpleHTTPServer`
# devolveu `HTTP/1.0 404 File not found` com pagina de erro, e o resumo disse so
# `http nao observado, 0 credencial(is)`. **A frase esta CERTA** -- sem `-i` nao
# ha linha de status, e foi por isso que `http None` virou `http nao observado`
# -- **e incompleta**: ele nao tinha como distinguir "peguei 404 do servidor
# errado" de "nada aconteceu". Tentou seis vezes.
#
# E a classe de D217 dentro do `curl`: a resposta voltou e nos calamos.
with tempfile.TemporaryDirectory() as tmp:
    _ec = ExecutorFalso(saida="<html><body>404 File not found</body></html>",
                        codigo=0)
    _lc = Laco(motor=MotorFalso(), executor=_ec, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _lc.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -s http://172.20.0.10:8000/diagnostico", pivo=None,
        endereco_pivo=None, justificativa="x", bruta="{}", valida=True))
    _rc = _lc.grafo.tentativas[-1].resumo or ""
checa("D226: sem status, o resumo diz quantos bytes de corpo voltaram",
      "bytes de corpo" in _rc, True)
# ⚠️ **O TAMANHO, NUNCA O CONTEUDO:** §1.2 mantem a saida bruta fora do modelo,
# e o resumo vai para a secao de tentativas do braco A e para o historico do
# braco B. Um resumo com o corpo seria a porta lateral por onde a saida volta.
checa("D226: e NAO mostra o corpo",
      "404 File not found" in _rc or "html" in _rc, False)

# O PAR: corpo vazio tem de ser DISTINGUIVEL de corpo que voltou, que e a
# propriedade de D57 -- um comando que rodou e nada rendeu tem de se distinguir
# de um que nunca rodou.
with tempfile.TemporaryDirectory() as tmp:
    _ev = ExecutorFalso(saida="", codigo=0)
    _lv = Laco(motor=MotorFalso(), executor=_ev, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _lv.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -s http://172.20.0.10:8000/x", pivo=None,
        endereco_pivo=None, justificativa="x", bruta="{}", valida=True))
    _rv = _lv.grafo.tentativas[-1].resumo or ""
checa("D226: corpo vazio nao inventa bytes", "bytes de corpo" in _rv, False)
checa("D226: e os dois resumos sao distinguiveis", _rc == _rv, False)

# E O CAMINHO COM STATUS NAO MUDA: `http 200` continua como era, sem o campo de
# bytes. Sem esta checagem eu poderia ter acrescentado o tamanho em TODA
# resposta, inflando a linha que o braco A le a cada passo.
with tempfile.TemporaryDirectory() as tmp:
    _ei = ExecutorFalso(
        saida="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>",
        codigo=0)
    _li = Laco(motor=MotorFalso(), executor=_ei, grafo=grafo_da_dmz(),
               pasta=pathlib.Path(tmp), escopo=ESCOPO)
    _li.executar(Proposta(
        alvo="h03", endereco="172.20.0.10", ferramenta="curl",
        comando="curl -s -i http://172.20.0.10:8080/", pivo=None,
        endereco_pivo=None, justificativa="x", bruta="{}", valida=True))
    _ri = _li.grafo.tentativas[-1].resumo or ""
checa("D226: com status observado o resumo nao ganha o campo de bytes",
      ("http 200" in _ri, "bytes de corpo" in _ri), (True, False))

print()

# ====== D232: o laboratorio pode desaparecer debaixo de uma execucao paga
#
# ⚠️ **E em 1 de outubro de 2026 ele desapareceu**, entre dois comandos, sem
# ninguem pedir: imagens intactas, sete conteineres e duas redes sumidos. Sem a
# sonda, `docker exec` devolve codigo 1 em todo passo, o laco roda ate o teto de
# 80 (D140) pagando por comando que nao executa, e a execucao termina com grafo
# vazio e **elo 0** -- gravado como resultado do agente. §E53: *valor gravado
# por arnes defeituoso nao e dado*.
#
# **A sonda e injetada, nao herdada**, e e por isso que nenhum teste acima
# precisou mudar: `ExecutorFalso` usa o nome do conteiner REAL (`tcc-atacante`),
# e uma sonda herdada faria esta suite inteira depender do laboratorio estar no
# ar -- o que D25 proibe.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER, VARRER, VARRER)
    laco = sessao(tmp, motor, ExecutorFalso(saida="", codigo=0), grafo_da_dmz())
    laco.limite = 3
    checa("sem sonda o laco se comporta como antes", laco.sonda, None)
    checa("e vai ate o orcamento", laco.rodar(), "orcamento esgotado")

# COM O LABORATORIO NO CHAO, o laco encerra e **nao paga nada**.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER, VARRER, VARRER)
    executor = ExecutorFalso(saida="", codigo=0)
    laco = sessao(tmp, motor, executor, grafo_da_dmz())
    laco.limite = 80
    laco.sonda = lambda: "o conteiner tcc-atacante nao existe"
    desfecho = laco.rodar()
    checa("o laco encerra quando o laboratorio nao esta no ar",
          desfecho.startswith("interrompido: laboratorio indisponivel"), True)
    checa("e o desfecho carrega o motivo, nao so o rotulo",
          "tcc-atacante nao existe" in desfecho, True)
    # ⚠️ **ESTA E A CHECAGEM QUE JUSTIFICA A GUARDA.** A sonda vem ANTES de
    # `propor()`, que e a chamada que custa dinheiro. Zero prompts significa
    # zero dolares -- se ela viesse depois, um passo seria pago por volta ate o
    # teto de 80, que e ~US$ 2,50 de nada.
    checa("e NAO chamou o modelo nenhuma vez", len(motor.prompts), 0)
    checa("e nao executou comando nenhum", len(executor.comandos), 0)
    checa("e nao gastou passo", laco.passo, 1)
    # O desfecho PERSISTE: quem ler a execucao depois precisa distinguir
    # "abortada por ambiente" de "rodou e nao alcancou". Confundir as duas e
    # inventar fato contra o braco que calhou de rodar na hora errada.
    gravado = json.loads(
        (pathlib.Path(tmp) / "estado.json").read_text(encoding="utf-8"))
    checa("e o desfecho fica gravado no disco", gravado["desfecho"], desfecho)

# ⚠️ **O CONTRAEXEMPLO, e sem ele a guarda poderia estar sempre ligada:** sonda
# que diz que esta tudo no ar nao atrapalha nada.
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER, VARRER, VARRER)
    laco = sessao(tmp, motor, ExecutorFalso(saida="", codigo=0), grafo_da_dmz())
    laco.limite = 3
    laco.sonda = lambda: None
    checa("sonda que aprova nao encerra o laco", laco.rodar(),
          "orcamento esgotado")
    checa("e os tres passos foram pagos normalmente", len(motor.prompts), 3)

# ⚠️ **E A SONDA TEM DE SOBREVIVER AO `retomar`**, que e a licao de D152: ali a
# memoria do braco B voltava do disco e o `retomar` nao a repassava, e nada
# acusava. *Funcao testada nao e funcao chamada* (D151).
with tempfile.TemporaryDirectory() as tmp:
    motor = MotorFalso(VARRER)
    outro = Laco.retomar(motor=motor, executor=ExecutorFalso(),
                         pasta=pathlib.Path(tmp),
                         sonda=lambda: "laboratorio no chao")
    checa("D232: `retomar` repassa a sonda", outro.sonda is not None, True)
    outro.limite = 80
    checa("e a execucao retomada tambem para",
          outro.rodar().startswith("interrompido:"), True)
    checa("e tambem sem pagar nada", len(motor.prompts), 0)

# ====== D232: a sonda em si, contra a FRONTEIRA e nao contra uma copia dela
#
# ⚠️ **A fixture patcha `subprocess.run` e exercita `Executor.indisponivel` de
# verdade.** A licao e da fixture de D227, que REIMPLEMENTOU `Executor.rodar` e
# deixou 3 mutacoes vivas: um dublê que refaz o codigo testado nao testa o
# codigo. E patchar a fronteira e o que mantem a suite independente do
# laboratorio (D25) -- esta secao passa com o Docker no chao.
_pedidos: list[list[str]] = []


class _Resposta:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _com_docker(resposta):
    def falso(cmd, **kwargs):
        _pedidos.append(list(cmd))
        if isinstance(resposta, Exception):
            raise resposta
        return resposta
    return falso


_guardado = base.subprocess.run
try:
    base.subprocess.run = _com_docker(_Resposta(0, "true\n"))
    _pedidos.clear()
    checa("D232: conteiner no ar devolve None",
          Executor(conteiner="tcc-atacante").indisponivel(), None)
    # E a pergunta vai ao DOCKER sobre o conteiner DESTE executor -- nao a uma
    # frase lida da saida do agente, que ele pode escrever.
    checa("D232: e a pergunta e `docker inspect` no conteiner certo",
          _pedidos and _pedidos[0][:2] == ["docker", "inspect"]
          and _pedidos[0][-1] == "tcc-atacante", True)

    base.subprocess.run = _com_docker(
        _Resposta(1, "", "error: no such object: tcc-atacante"))
    _motivo = Executor(conteiner="tcc-atacante").indisponivel()
    checa("D232: conteiner ausente e acusado", "nao existe" in (_motivo or ""),
          True)
    checa("D232: e o motivo do daemon vem junto",
          "no such object" in (_motivo or ""), True)

    # EXISTE E ESTA PARADO e caso separado de NAO EXISTE: um pede `up -d`, o
    # outro pede investigar por que caiu, e dar a mesma mensagem aos dois manda
    # procurar no lugar errado.
    base.subprocess.run = _com_docker(_Resposta(0, "false\n"))
    checa("D232: conteiner parado e acusado, com mensagem propria",
          "nao esta no ar" in (
              Executor(conteiner="tcc-atacante").indisponivel() or ""), True)

    # ⚠️ NAO PODER PERGUNTAR nao e o mesmo que estar no chao, e a mensagem
    # distingue: confundi-los manda procurar o defeito no laboratorio quando
    # ele esta no Docker.
    base.subprocess.run = _com_docker(OSError("docker nao encontrado"))
    _motivo = Executor(conteiner="tcc-atacante").indisponivel()
    checa("D232: falha ao consultar nao se confunde com conteiner no chao",
          "nao foi possivel consultar" in (_motivo or ""), True)

    base.subprocess.run = _com_docker(
        base.subprocess.TimeoutExpired(cmd=["docker"], timeout=30))
    checa("D232: e teto da sonda tambem nao se confunde",
          "nao foi possivel consultar" in (
              Executor(conteiner="tcc-atacante").indisponivel() or ""), True)

    # ⚠️ **SEM CONTEINER A SONDA NAO PERGUNTA NADA**, e e o que faz
    # `--conteiner ""` desligar o `docker exec` e a sonda com a mesma chave.
    _pedidos.clear()
    base.subprocess.run = _com_docker(_Resposta(1, "", "nao deveria rodar"))
    checa("D232: sem conteiner a sonda devolve None", Executor().indisponivel(),
          None)
    checa("D232: e nao chama o Docker", _pedidos, [])
finally:
    base.subprocess.run = _guardado

# E O CONTROLE: depois do `finally` o modulo volta ao normal, senao toda
# checagem posterior mediria um `subprocess` falso.
checa("D232: o `subprocess.run` de verdade foi restaurado",
      base.subprocess.run is _guardado, True)

# ====== D235: a versao do codigo vai para o registro
#
# ⚠️ **Existe porque "bracos sob codigo diferente" custou DOIS pares:** §E88
# descartou o par de 30/09 porque D218 mudou o prompt do braco B entre um braco
# e o outro, e o par de 01/10 saiu pela mesma razao. A identidade de codigo era
# provada A MAO, com `git log`, uma vez por par.
#
# Injetada e nao lida direto, pela mesma razao da sonda de D232: os testes rodam
# sem git (D25), e quem nao pede nao recebe dependencia de ambiente.
with tempfile.TemporaryDirectory() as tmp:
    laco = sessao(tmp, MotorFalso(VARRER), ExecutorFalso(), grafo_da_dmz())
    checa("D235: sem `versao` o campo fica None, e nao inventa", laco.versao, None)
    laco._salvar()
    gravado = json.loads(
        (pathlib.Path(tmp) / "estado.json").read_text(encoding="utf-8"))
    checa("D235: e o campo existe no registro mesmo valendo None",
          "codigo" in gravado and gravado["codigo"] is None, True)

with tempfile.TemporaryDirectory() as tmp:
    laco = Laco(motor=MotorFalso(VARRER), executor=ExecutorFalso(),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(tmp),
                versao=lambda: "abc1234+sujo")
    laco._salvar()
    gravado = json.loads(
        (pathlib.Path(tmp) / "estado.json").read_text(encoding="utf-8"))
    checa("D235: com `versao` o commit chega ao registro",
          gravado["codigo"], "abc1234+sujo")

# ⚠️ **A PROPRIEDADE DE SEGURANCA, e ela e a razao de isto poder entrar no meio
# da coleta:** o que vai para o `estado.json` NAO chega ao agente. O prompt sai
# de `grafo.serializar() + RABO`; o `estado.json` so e lido pelo `retomar`. Se um
# dia alguem ligar os dois, esta checagem cai -- e tem de cair, porque ai a
# instrumentacao teria virado entrada do modelo e mudado a medida.
with tempfile.TemporaryDirectory() as tmp:
    MARCA = "versao-que-nao-pode-aparecer-no-prompt"
    laco = Laco(motor=MotorFalso(VARRER), executor=ExecutorFalso(),
                grafo=grafo_da_dmz(), pasta=pathlib.Path(tmp),
                versao=lambda: MARCA)
    laco._salvar()
    checa("D235: a versao esta no registro", MARCA in
          (pathlib.Path(tmp) / "estado.json").read_text(encoding="utf-8"), True)
    checa("D235: e NAO aparece no prompt do braco A",
          MARCA in montar(laco.grafo, 1, 80), False)

# D151/D152: funcao testada nao e funcao chamada. A CLI entra por `retomar`.
with tempfile.TemporaryDirectory() as tmp:
    outro = Laco.retomar(motor=MotorFalso(VARRER), executor=ExecutorFalso(),
                         pasta=pathlib.Path(tmp), versao=lambda: "def5678")
    checa("D235: `retomar` repassa a versao", outro.versao is not None, True)
    outro._salvar()
    checa("D235: e ela chega ao disco pela retomada",
          json.loads((pathlib.Path(tmp) / "estado.json"
                      ).read_text(encoding="utf-8"))["codigo"], "def5678")

# ====== D235: `versao_do_codigo` em si, contra a FRONTEIRA
#
# ⚠️ **Estas checagens existem porque DUAS mutacoes sobreviveram** a primeira
# bateria: a que tira a marca `+sujo` e a que faz o git ausente inventar uma
# versao. A funcao nao tinha teste nenhum, porque ela fala com o `git` e D25
# proibe teste que dependa da maquina -- a saida e patchar a fronteira
# (`subprocess.run`) e exercitar a funcao de verdade, como na fixture de D232.
# Reimplementar a funcao no dublê e o erro de D227, que deixou 3 mutacoes vivas.


class _R:
    def __init__(self, returncode, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


def _git(respostas):
    """Devolve as respostas na ordem: primeiro `rev-parse`, depois `status`.

    ⚠️ **Limpa a memoria de `_VERSAO` antes de cada caso.** A funcao e calculada
    uma vez por processo de proposito -- eram 209 ms por passo, 16,7 s por
    execucao --, e sem esta limpeza o segundo caso recebe a resposta do primeiro.
    **Aconteceu:** duas checagens falharam com `obtido None`, porque algo antes
    na suite ja havia povoado a memoria. O teste estabelece a sua condicao (D25).
    """
    cli._VERSAO.clear()
    fila = list(respostas)
    chamadas = []

    def falso(cmd, **kwargs):
        chamadas.append(cmd)
        if isinstance(fila[0], Exception):
            raise fila.pop(0)
        return fila.pop(0)
    falso.chamadas = chamadas
    return falso


_guardado_cli = cli.subprocess.run
try:
    # ARVORE LIMPA: `status --porcelain` vazio, entao nada de sufixo.
    cli.subprocess.run = _git([_R(0, "abc1234\n"), _R(0, "")])
    checa("D235: arvore limpa devolve o commit sem sufixo",
          cli.versao_do_codigo(), "abc1234")
    # ⚠️ ARVORE SUJA: o sufixo nao e decoracao -- commit com mudanca nao
    # commitada NAO descreve o que rodou, e dois bracos no mesmo commit com
    # arvore suja nao estao provados identicos.
    cli.subprocess.run = _git([_R(0, "abc1234\n"), _R(0, " M src/x.py\n")])
    checa("D235: arvore suja marca o commit com `+sujo`",
          cli.versao_do_codigo(), "abc1234+sujo")
    # ⚠️ GIT QUE FALHA DEVOLVE None, nunca uma string. Versao inventada daria ao
    # par um carimbo de comparavel sem a prova -- pior que nao ter versao.
    cli.subprocess.run = _git([_R(128, "")])
    checa("D235: git que falha devolve None, e nao inventa versao",
          cli.versao_do_codigo(), None)
    cli.subprocess.run = _git([_R(0, "   \n")])
    checa("D235: saida vazia do git tambem devolve None",
          cli.versao_do_codigo(), None)
    cli.subprocess.run = _git([OSError("git nao encontrado")])
    checa("D235: git ausente na maquina devolve None",
          cli.versao_do_codigo(), None)
    # ⚠️ **A MEMORIA DE VERDADE, e sem esta checagem ela pode sumir calada.**
    # `_salvar` roda a cada passo; sem memoria sao 209 ms por passo, 16,7 s por
    # execucao de 80. O que se afirma e que o `git` e consultado UMA vez e que a
    # resposta das vezes seguintes e a mesma -- contando as chamadas, nao o
    # tempo, porque medir tempo em teste depende da maquina (D25).
    falso = _git([_R(0, "fed9876\n"), _R(0, "")])
    cli.subprocess.run = falso
    primeira = cli.versao_do_codigo()
    for _ in range(40):
        cli.versao_do_codigo()
    checa("D235: 41 chamadas consultam o git UMA vez so",
          len(falso.chamadas), 2)   # rev-parse + status, e nada mais
    checa("D235: e as 41 devolvem o mesmo valor",
          cli.versao_do_codigo(), primeira)
    # E A MEMORIA GUARDA O `None` TAMBEM: sem git na maquina a resposta nao muda
    # na segunda tentativa, e repetir 80 consultas que falham e pior que 80 que
    # funcionam.
    falho = _git([_R(128, ""), _R(128, "")])
    cli.subprocess.run = falho
    cli.versao_do_codigo()
    for _ in range(10):
        cli.versao_do_codigo()
    checa("D235: a memoria guarda o None e nao reconsulta",
          len(falho.chamadas), 1)
finally:
    cli.subprocess.run = _guardado_cli
    cli._VERSAO.clear()
checa("D235: o `subprocess.run` da CLI foi restaurado",
      cli.subprocess.run is _guardado_cli, True)

# ====================================================================== D246
# UMA EXECUCAO POR PASTA -- a trava de criacao exclusiva.
#
# ⚠️ Existe porque DUAS execucoes rodaram na mesma pasta em 2 de outubro e
# corromperam a terceira tentativa do par 2: **118 registros para 61 passos, 57
# passos com DOIS registros**, dois grafos se sobrescrevendo, e **US$ 2,4490**
# gastos em dobro para produzir algo que nao e dado. A bateria de mutacao tem
# trava desde D67, criada depois do mesmo acidente acontecer la; o laco nao tinha.
#
# ⚠️ A trava e por CRIACAO EXCLUSIVA e nao por teste de PID, e a escolha e de
# seguranca: no Windows `os.kill(pid, 0)` chama `TerminateProcess` e MATA o
# processo em vez de testa-lo -- uma trava escrita assim derrubaria a propria
# coleta que ela existe para proteger.
with tempfile.TemporaryDirectory() as _d246:
    _p246 = pathlib.Path(_d246)
    checa("D246: a primeira trava e concedida",
          cli.travar(_p246, "autonomo", "coleta-X-01"), None)
    checa("D246: e o arquivo de trava fica no disco",
          (_p246 / cli.NOME_DA_TRAVA).exists(), True)
    _r246 = cli.travar(_p246, "autonomo", "coleta-X-01")
    checa("D246: a SEGUNDA trava na mesma pasta e RECUSADA",
          bool(_r246) and _r246.startswith("RECUSADO"), True)
    # A mensagem tem de dizer o que fazer, nao so que recusou: sobra de execucao
    # que caiu exige conferir duplicata ANTES de apagar, e quem le precisa saber.
    checa("D246: e a recusa diz o que conferir antes de apagar",
          "registro duplicado" in _r246 and "D246" in _r246, True)
    # ⚠️ O CONTEUDO da trava identifica quem a tem. Sem isso a recusa manda
    # conferir um processo sem dizer qual.
    _conteudo = json.loads((_p246 / cli.NOME_DA_TRAVA).read_text(encoding="utf-8"))
    checa("D246: a trava registra o pid, a acao e a execucao",
          sorted(_conteudo) == ["acao", "execucao", "inicio", "pid"]
          and _conteudo["execucao"] == "coleta-X-01", True)
    cli.destravar(_p246)
    checa("D246: destravar remove o arquivo",
          (_p246 / cli.NOME_DA_TRAVA).exists(), False)
    checa("D246: e depois de solta, a pasta aceita execucao de novo",
          cli.travar(_p246, "autonomo", "coleta-X-01"), None)
    cli.destravar(_p246)
    # Idempotente: destravar o que nao esta travado nao e erro. A alternativa --
    # explodir -- faria o `finally` mascarar o desfecho real da execucao.
    cli.destravar(_p246)
    checa("D246: destravar duas vezes nao levanta erro", True, True)


if falhas:
    print(f"{len(falhas)} FALHA(S):")
    for f in falhas:
        print("  -", f)
    sys.exit(1)
print("todos os testes do laco passaram")
