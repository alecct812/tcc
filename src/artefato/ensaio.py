"""Ensaio geral da coleta: o pipeline inteiro, os dois bracos, sem modelo.

**Por que este arquivo existe.** Em 24 de setembro a primeira execucao paga do
braco B achou tres defeitos nossos (D126, D127, D128), e **dois deles so
apareceram porque havia dinheiro em jogo**. O padrao ja tinha nome: defeito
neste projeto nao aparece em teste, aparece quando o codigo encontra a
realidade -- e a realidade vinha custando credito.

`percorrer_cadeia.py` nasceu na quarta 23 para atacar isso, e resolveu metade:
ele roda o laco de verdade contra o laboratorio, sem modelo. Mas tem dez passos,
o braco B **nunca fecha uma fase** ali, e ele **nunca roda a tabela**. D127 --
a metrica 9 subcontando o braco B em 7,8% -- passou exatamente por esse buraco:
nenhuma verificacao gratuita ia do passo ate o numero publicado.

Este ensaio fecha o buraco. Ele percorre o caminho INTEIRO que a coleta vai
percorrer -- laco, registro, metricas, tabela -- nos dois bracos, com o braco B
**fechando fase de verdade**, e confere o que a coleta precisa que seja verdade.
Sem Docker e sem modelo: **US$ 0,00**.

**O que ele NAO e.** Nao substitui `percorrer_cadeia.py`, que vale por rodar
contra o laboratorio no ar -- ali as ferramentas existem e as saidas sao
verdadeiras. Aqui as saidas sao escritas a mao. Os dois cobrem coisas
diferentes: aquele prova que a cadeia funciona, este prova que o que a cadeia
produz chega inteiro ate a tabela.

Uso:  python ensaio.py
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import shutil
import sys
import tempfile

import tabela as _tabela
from cadeia import carregar_cadeia
from ferramentas import Execucao, Executor
from grafo import Grafo
from grafo.modelo import Host
from laco import Laco
from laco.memoria import MemoriaLinear
from metricas import carregar_passos, custo
from modelo.resultado import Resultado

RAIZ = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

problemas: list[str] = []


def checa(rotulo: str, obtido, esperado) -> None:
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        problemas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")


# --------------------------------------------------------------- os dublês
#
# O motor devolve propostas prontas e conta chamadas; o executor devolve saida
# combinada. Nenhum dos dois fala com o mundo -- o ensaio tem de rodar numa
# maquina sem Docker e sem chave de API, senao ele nao roda quando mais
# precisa, que e antes de gastar.


class MotorDeEnsaio:
    nome = "ensaio"

    def __init__(self, *respostas: str):
        self.respostas = list(respostas)
        self.chamadas = 0
        self.regime = "raciocinio"
        # O MOTOR DECLARADO E O DA COLETA, e tem de ser. `custo()` recusa motor
        # sem preco conferido (D92), e um nome ficticio faria o ensaio parar
        # antes de chegar na metrica 9 -- que e justamente onde morava o
        # defeito que este arquivo existe para pegar. O ensaio grava num
        # diretorio temporario que e apagado no fim, entao nada disto encosta
        # no corpus.
        self.modelo = "claude-sonnet-5"

    def identificacao(self) -> dict:
        return {"motor": self.nome, "modelo": self.modelo,
                "regime": self.regime, "saida_estruturada": True}

    def chamar(self, prompt: str) -> Resultado:
        self.chamadas += 1
        texto = self.respostas.pop(0) if self.respostas else "resumo da fase"
        return Resultado(motor=self.nome, modelo=self.modelo,
                         regime=self.regime, texto=texto, categoria="aceita",
                         entrada_tokens=1200, saida_tokens=180,
                         pensamento_tokens=90, wall_s=1.5)


class ExecutorDeEnsaio(Executor):
    def __init__(self):
        super().__init__(conteiner="ensaio")

    def rodar(self, execucao: Execucao) -> Execucao:
        execucao.codigo = 0
        execucao.saida = "Nmap scan report for alvo (172.20.0.10)\nHost is up.\n"
        execucao.erro = ""
        execucao.wall_s = 0.3
        return execucao


def _proposta(n: int) -> str:
    return json.dumps({"alvo": "h02", "ferramenta": "nmap",
                       "comando": f"nmap -sV -p{n} 172.20.0.10", "pivo": None,
                       "justificativa": "enumerar servicos do host de entrada"})


def _rodar(pasta: pathlib.Path, braco: str, passos: int, limite: int,
           teto_de_texto: int, cadeia) -> Laco:
    """Uma execucao completa, gravando em `pasta` como a coleta grava.

    **A `cadeia` vem junto, e nao e detalhe.** Sem ela o laco nao grava a
    coluna `elo` (D94), e as metricas 4 e 5 se RECUSAM a responder -- a tabela
    da coleta sairia com duas colunas vazias. A primeira versao deste ensaio
    esqueceu de passa-la, e o proprio ensaio pegou, na primeira execucao: um
    ensaio que nao espelha a configuracao da coleta ensaia outra coisa.
    """
    grafo = Grafo()
    grafo.absorver_hosts([Host(endereco="172.20.0.10")])
    memoria = (MemoriaLinear(MotorDeEnsaio(), teto=teto_de_texto)
               if braco == "B" else None)
    laco = Laco(motor=MotorDeEnsaio(*[_proposta(i) for i in range(passos)]),
                executor=ExecutorDeEnsaio(), grafo=grafo, pasta=pasta,
                limite=limite, memoria=memoria, cadeia=cadeia)
    # O PROTOCOLO INTEIRO, e nao so metade. `rodar()` define `ate_elo`; este
    # ensaio chama `executar` passo a passo e por isso tem de defini-lo a mao.
    # Sem ele a metrica 5 se RECUSA -- "o protocolo desta execucao parava no
    # elo 4" (D111) --, e a tabela da coleta sairia com a coluna do trofeu
    # vazia. Segunda divergencia que este ensaio pegou de si mesmo.
    laco.ate_elo = 5
    for _ in range(passos):
        laco.executar(laco.propor())
    laco._salvar()
    return laco


def main() -> int:
    cad = carregar_cadeia(RAIZ / "lab" / "cadeia.json")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ensaio-"))
    try:
        print("ensaio geral: o pipeline inteiro, os dois bracos, sem modelo\n")

        # O TETO DE TEXTO E APERTADO DE PROPOSITO. Com os 11.200 de producao
        # seriam precisos ~34 passos para fechar a primeira fase, e um ensaio
        # que so exercita o caminho feliz nao serve. Aqui a fase fecha, e e por
        # isso que este arquivo pega o que D127 escondeu.
        for braco, teto in (("A", 0), ("B", 900)):
            pasta = tmp / "execucoes" / f"ensaio-{braco}"
            pasta.mkdir(parents=True)
            shutil.copy(FIXTURES / "auto-03-grafo.json", pasta / "grafo.json")
            laco = _rodar(pasta, braco, passos=12, limite=120,
                          teto_de_texto=teto or 11200, cadeia=cad)
            laco.grafo.salvar(pasta / "grafo.json")
            print(f"  braco {braco}: 12 passos gravados em {pasta.name}")
            if braco == "B":
                checa("o braco B fechou fase de verdade no ensaio",
                      laco.memoria.chamadas_de_resumo > 0, True)

        print()
        # ------------------------------------- o que a COLETA precisa ser verdade
        raiz_tabela = _tabela.RAIZ
        try:
            _tabela.RAIZ = tmp
            linhas = {b: _tabela.medir(f"ensaio-{b}", cad) for b in ("A", "B")}
        finally:
            _tabela.RAIZ = raiz_tabela

        for b in ("A", "B"):
            checa(f"o braco {b} se declara no registro", linhas[b]["braco"], b)
            # O LIMITE TEM DE CHEGAR A TABELA SEM NINGUEM DIGITAR (D116). Sem
            # ele as metricas 4 e 5 se recusam, e a tabela da coleta sai com
            # duas colunas vazias.
            checa(f"o braco {b} grava o limite da coleta",
                  linhas[b]["limite"], 120)
            checa(f"o braco {b} tem custo afirmavel",
                  linhas[b]["m9_dolares"] is not None, True)
            checa(f"o braco {b} tem a metrica 4 afirmavel",
                  linhas[b]["m4_motivo"], None)
            checa(f"a metrica 10 do braco {b} se declara completa",
                  linhas[b]["m10_completa"], True)

        # D127: O CUSTO DO BRACO B TEM DE INCLUIR O FECHAMENTO DE FASE. Esta e
        # a verificacao que este arquivo existe para fazer -- ela custaria
        # US$ 0,60 para ser feita com modelo de verdade, e foi assim que o
        # defeito apareceu.
        c = custo(carregar_passos(tmp / "execucoes" / "ensaio-B" /
                                  "passos.jsonl"))
        checa("D127: o custo do braco B conta as chamadas de resumo",
              c.chamadas_de_resumo == linhas["B"]["m9_chamadas_de_resumo"]
              and c.chamadas_de_resumo > 0, True)
        sem_resumo = (c.somas["entrada_tokens"].total / 1_000_000
                      * c.preco.entrada
                      + c.somas["saida_tokens"].total / 1_000_000
                      * c.preco.saida)
        checa("D127: e o dolar e MAIOR que a soma so dos passos",
              c.dolares > sem_resumo, True)
        checa("D127: no braco A nao ha resumo nenhum a contar",
              custo(carregar_passos(tmp / "execucoes" / "ensaio-A" /
                                    "passos.jsonl")).chamadas_de_resumo, None)

        # E A TABELA TEM DE IMPRIMIR, sem estourar e sem celula orfã. Rodar a
        # tabela e o ultimo elo do pipeline: ate 24 de setembro nenhuma
        # verificacao gratuita ia do passo ate aqui.
        saida = io.StringIO()
        with contextlib.redirect_stdout(saida):
            _tabela.imprimir([linhas["A"], linhas["B"]])
        texto = saida.getvalue()
        checa("a tabela imprime as duas execucoes",
              texto.count("ensaio-") >= 2, True)
        # A CELULA DA METRICA 5 SAI CENSURADA, e isso esta certo: doze passos
        # nao chegam ao trofeu, e `>12` afirma "passou de 12", nao "nao mediu".
        # O que nao pode e celula vazia por FALTA DE REGISTRO -- e por isso a
        # verificacao olha o MOTIVO, e nao o tracinho.
        checa("nenhuma metrica fica sem resposta por falta de registro",
              [l["execucao"] for l in (linhas["A"], linhas["B"])
               if l["m4_motivo"] or l["m5_motivo"]], [])
        checa("e a metrica 5 sai CENSURADA, que e o instrumento certo",
              [l["m5_trofeu"] for l in (linhas["A"], linhas["B"])],
              [">12", ">12"])
        checa("e a ressalva do resumo do braco B aparece",
              "chamada(s) de resumo do braco B" in texto, True)

        print()
        if problemas:
            print(f"{len(problemas)} problema(s):")
            for x in problemas:
                print("  -", x)
            return 1
        print("o pipeline da coleta esta inteiro, do passo ate a tabela")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
