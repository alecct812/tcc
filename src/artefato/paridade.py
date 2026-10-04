"""Prova que os dois bracos diferem SO na estrategia de estado.

`CRONOGRAMA.md`, sexta 25, aceite: *"diff entre os dois bracos mostra apenas a
troca da estrategia de estado"*. `CONTEXTO.md` §9 diz por que isso e condicao
de existencia do experimento: *"os dois bracos compartilham tudo menos o grafo.
Mesmo modelo, mesmas ferramentas, mesmos prompts, mesmo limite de passos.
Qualquer divergencia acidental invalida o experimento."*

**"Qualquer divergencia acidental" e o ponto, e divergencia acidental nao se
acha lendo.** Este arquivo monta os dois prompts sobre O MESMO grafo e compara
linha a linha, classificando cada diferenca em uma de duas caixas:

    DECLARADA   a clausula do cabecalho que descreve o que o braco recebe,
                e a secao de estado em si -- grafo serializado contra
                historico. E a variavel independente.
    ACIDENTAL   qualquer outra. Uma so aqui invalida o experimento.

Se a caixa ACIDENTAL nao estiver vazia, este arquivo falha e diz qual linha.

**Por que comparar prompts montados, e nao ler o codigo.** Porque a divergencia
que importa e a que CHEGA AO MODELO. `laco/prompt.py` e `laco/memoria.py`
compartilham `RABO` por importacao hoje; se amanha alguem copiar o texto para
um dos dois, a leitura continuaria parecendo certa e o modelo passaria a
receber coisas diferentes. O diff pega isso; a revisao de codigo, talvez nao.

Sem Docker, sem modelo, sem chave de API. Roda em `testes.py`.

Uso:  python paridade.py          (o veredito)
      python paridade.py --diff   (o diff inteiro, para conferir a mao)
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import sys

from grafo import Grafo
from laco import prompt as _prompt
from laco.memoria import CABECALHO as CABECALHO_B
from laco.memoria import MemoriaLinear
from laco.prompt import CABECALHO as CABECALHO_A
from laco.prompt import ESQUEMA, FERRAMENTAS, RABO, montar

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

problemas: list[str] = []


def checa(rotulo: str, obtido, esperado) -> None:
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        problemas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")


# A CLAUSULA QUE PODE DIFERIR, e so ela. As duas frases sao espelhos: mesma
# estrutura, mesma promessa final ("o que voce ve e tudo que se sabe"), e o
# meio descrevendo o que cada braco de fato recebe. D125 declarou esta como a
# unica diferenca de redacao permitida.
CLAUSULA_A = "Abaixo está o estado do grafo; o histórico foi descartado:"
CLAUSULA_B = "Abaixo está o histórico da sessão; não há estado consolidado:"

# As secoes de estado. Tudo dentro delas e a variavel independente.
SECOES_DE_A = ("=== SUB-REDES ===", "=== HOSTS ===", "=== ALCANCABILIDADE ===",
               "=== CREDENCIAIS ===", "=== TENTATIVAS JA REALIZADAS ===")
SECOES_DE_B = ("=== RESUMO DAS FASES ANTERIORES ===", "=== HISTÓRICO ===")


def partir(prompt: str, cabecalho: str) -> tuple[str, str, str]:
    """Corta o prompt em [cabecalho][estado][rabo], POR POSICAO.

    Por posicao, e nao por conteudo -- que foi a primeira versao deste arquivo
    e estava errada. Ela perguntava "esta linha aparece no cabecalho ou no
    RABO?", e como `RABO` comeca com uma quebra de linha, TODA linha em branco
    do grafo respondia "sim, e do RABO" e virava divergencia acidental. Cinco
    falsos positivos de uma vez.

    Pior que o barulho: a mesma pergunta feita ao contrario deixaria passar o
    que importa. Uma linha nova acrescentada ao RABO de um so dos bracos
    "aparece no RABO" e seria absolvida -- exatamente a divergencia que este
    arquivo existe para pegar.
    """
    if not prompt.startswith(cabecalho):
        raise ValueError("o prompt nao comeca com o cabecalho esperado: "
                         "o corte por posicao deixou de valer")
    if not prompt.endswith(RABO):
        raise ValueError("o prompt nao termina com o RABO: um dos bracos "
                         "deixou de usar o texto compartilhado")
    return cabecalho, prompt[len(cabecalho):-len(RABO)], RABO


def comparar(cab_a: str, cab_b: str) -> tuple[list[str], list[str]]:
    """Divide as diferencas DO CABECALHO entre declaradas e acidentais.

    So o cabecalho e comparado linha a linha. O estado nao se compara -- ele E
    a variavel independente, e exigir semelhanca ali seria exigir que os dois
    bracos fossem o mesmo braco. O RABO nao se compara porque `partir` ja o
    provou identico nos dois, por construcao.
    """
    declaradas, acidentais = [], []
    for linha in difflib.unified_diff(cab_a.splitlines(), cab_b.splitlines(),
                                      lineterm="", n=0):
        if linha.startswith(("---", "+++", "@@")):
            continue
        corpo = linha[1:]
        if CLAUSULA_A in corpo or CLAUSULA_B in corpo:
            declaradas.append(linha)
        else:
            acidentais.append(linha)
    return declaradas, acidentais


class ResumidorProibido:
    """Resumidor que estoura se for chamado.

    O fechamento de fase NAO faz parte do que esta comparacao mede -- ela olha
    a FORMA do prompt, e um resumo escrito por modelo entraria como texto
    arbitrario no meio da secao de estado. Com o teto alto ele nao dispara; com
    este objeto, se um dia disparar, o arquivo estoura em vez de comparar um
    prompt que nao e o que ele pensa estar comparando.
    """

    def __getattr__(self, nome):
        raise AssertionError(
            f"a paridade nao deve fechar fase ({nome}): o teto esta alto de "
            f"proposito, e um resumo entraria no lugar do historico")


def _montar_os_dois(passo: int, limite: int) -> tuple[str, str]:
    """Os dois prompts, sobre o MESMO estado do mundo.

    O braco B recebe um turno por tentativa do grafo do braco A: os dois
    descrevem o mesmo mundo. Nao sao o mesmo TEXTO -- nao podem ser, e essa e
    a hipotese --, e o VOLUME tambem difere, o que nao atrapalha: tudo dentro
    das secoes de estado ja e diferenca declarada. O que esta comparacao
    procura esta FORA delas.
    """
    g = Grafo.carregar(FIXTURES / "auto-03-grafo.json")
    # Teto alto para nenhuma fase fechar -- ver `ResumidorProibido`.
    mem = MemoriaLinear(ResumidorProibido(), teto=10 ** 9)
    for i, t in enumerate(g.tentativas, start=1):
        mem.anotar(numero=i, ferramenta=t.ferramenta, comando=t.rotulo,
                   justificativa="acao do agente", resumo=t.resumo,
                   fatos=[])
    return (montar(g, passo=passo, limite=limite),
            mem.montar(passo=passo, limite=limite))


def _partida_dos_dois(passo: int, limite: int) -> tuple[str, str]:
    """Os dois prompts com a origem semeada PELO CAMINHO REAL (D151).

    Passa por `Laco.semear_origem`, e nao por reconstrucao a mao, porque o
    defeito de D151 vivia exatamente na diferenca entre os dois caminhos: o
    grafo era semeado e a memoria linear nao, e nenhuma checagem que montasse a
    memoria a mao podia ver isso.

    Nao toca Docker nem modelo: `Executor` so e construido, e o motor levanta se
    alguem o chamar (D25).
    """
    import tempfile

    from ferramentas import Executor
    from laco import Laco

    saida = []
    with tempfile.TemporaryDirectory() as tmp:
        for braco in ("A", "B"):
            mem = (MemoriaLinear(ResumidorProibido(), teto=10 ** 9)
                   if braco == "B" else None)
            laco = Laco(motor=ResumidorProibido(),
                        executor=Executor(conteiner="nao-usado"),
                        grafo=Grafo(), pasta=pathlib.Path(tmp) / braco,
                        limite=limite, memoria=mem)
            laco.semear_origem("172.20.0.5", "atacante")
            saida.append(mem.montar(passo=passo, limite=limite) if mem
                         else montar(laco.grafo, passo=passo, limite=limite))
    return saida[0], saida[1]


# ---------------------------------------------------------------- D215
# AS MARCAS DA CONSOLIDACAO, no nivel do modulo porque `conferir_execucao`
# tambem as usa (D215, terceira camada). Duas listas divergiriam -- a licao de
# 21 de setembro, quando `juntar` e `autenticou` em duas copias divergiram em
# menos de uma hora.
CONSOLIDACOES = (
    ("rota de sub-rede derivada da topologia", (" so via ",
                                                "alcancavel direto",
                                                "rota desconhecida")),
    ("secao de sub-redes", ("=== SUB-REDES ===",)),
    ("aresta de alcancabilidade", ("=== ALCANCABILIDADE ===",
                                   " via ssh em ", " direta",
                                   "nenhuma travessia registrada")),
    ("afirmacao sobre ausencia de dado (D167)", ("nao enumeradas",)),
    ("complemento de conjunto", ("nao testada",)),
    ("contabilidade de teto do grafo", ("nao listados", "nao listadas",
                                        "nenhum listado")),
)


SEGREDO_DO_LAB = "7fQx2Lm9RtVzB4kd"


def _credencial_nos_dois(passo: int, limite: int) -> tuple[str, str]:
    """Os dois prompts depois de UMA credencial entrar no grafo (D159).

    Pelo caminho real dos dois lados: o braco A ganha a secao CREDENCIAIS e o
    rotulo da tentativa pela serializacao; o braco B ganha o fato por
    `fatos_novos`, que e a diferenca entre o grafo antes e depois do passo.
    Montar a memoria do braco B a mao esconderia exatamente o que se quer
    verificar -- e a licao de D151, que passou por 24 checagens verdes.

    Nao toca Docker nem modelo (D25).
    """
    import tempfile

    from ferramentas import Executor
    from grafo.modelo import Credencial
    from laco import Laco
    from laco.memoria import fatos_novos

    saida = []
    with tempfile.TemporaryDirectory() as tmp:
        for braco in ("A", "B"):
            mem = (MemoriaLinear(ResumidorProibido(), teto=10 ** 9)
                   if braco == "B" else None)
            laco = Laco(motor=ResumidorProibido(),
                        executor=Executor(conteiner="nao-usado"),
                        grafo=Grafo(), pasta=pathlib.Path(tmp) / braco,
                        limite=limite, memoria=mem)
            laco.semear_origem("172.20.0.5", "atacante")
            # `derivados=False` NOS DOIS LADOS do diff, porque e o que o laco
            # faz (D215). Chamar sem a bandeira aqui compararia um braco B que
            # nao existe -- o defeito de D151, que passou por 24 checagens
            # verdes justamente por montar a memoria por fora do caminho real.
            antes = laco.grafo.serializar_ambiente(derivados=False)
            laco.grafo.credenciais.append(Credencial(
                usuario="svc_deploy", tipo="senha", segredo=SEGREDO_DO_LAB,
                origem="172.20.0.5", validada_em=["172.20.0.12"]))
            # O ROTULO, que e onde o braco A le o nome. Vai pelo grafo, com o
            # segredo na linha, para `mascarar` ter o que nomear.
            laco.grafo.abrir_tentativa(
                "ssh", ["sshpass", "-p", SEGREDO_DO_LAB, "ssh",
                        "svc_deploy@172.20.0.12", "id"])
            if mem is not None:
                mem.anotar(numero=max(1, passo - 1), ferramenta="ssh",
                           comando="sshpass -p c01 ssh svc_deploy@172.20.0.12",
                           fatos=fatos_novos(
                               antes,
                               laco.grafo.serializar_ambiente(
                                   derivados=False)))
            saida.append(mem.montar(passo=passo, limite=limite) if mem
                         else montar(laco.grafo, passo=passo, limite=limite))
    return saida[0], saida[1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="paridade")
    ap.add_argument("--diff", action="store_true",
                    help="imprime o diff inteiro, para conferir a mao")
    a = ap.parse_args(argv)

    print("paridade entre os bracos: o que difere, e o que nao pode diferir\n")
    pa, pb = _montar_os_dois(passo=7, limite=120)

    if a.diff:
        for l in difflib.unified_diff(pa.splitlines(), pb.splitlines(),
                                      "braco A", "braco B", lineterm=""):
            print(l)
        print()

    # O CORTE JA E METADE DA PROVA: ele so funciona se cada prompt comecar com
    # o proprio cabecalho e terminar com o RABO compartilhado. Se um dos dois
    # tiver copiado o texto em vez de importa-lo, `partir` levanta aqui.
    cab_a, estado_a, rabo_a = partir(pa, CABECALHO_A.format(passo=7,
                                                            limite=120))
    cab_b, estado_b, rabo_b = partir(pb, CABECALHO_B.format(passo=7,
                                                            limite=120))
    checa("os dois prompts terminam no MESMO RABO, byte a byte",
          (rabo_a == rabo_b == RABO), True)
    checa("e o estado e onde eles divergem, como tem de ser",
          estado_a != estado_b, True)
    checa("o estado do braco A traz as secoes do grafo",
          [s in estado_a for s in SECOES_DE_A], [True] * len(SECOES_DE_A))
    checa("e o do braco B traz o historico, sem secao de grafo",
          ("=== HISTÓRICO ===" in estado_b,
           any(s in estado_b for s in SECOES_DE_A)), (True, False))

    declaradas, acidentais = comparar(cab_a, cab_b)
    print(f"\n  cabecalho: {len(declaradas)} diferenca(s) DECLARADA(s), "
          f"{len(acidentais)} ACIDENTAL(is)\n")

    # ------------------------------------------------- o aceite da sexta 25
    checa("nenhuma divergencia acidental no cabecalho", acidentais, [])
    # E A DECLARADA TEM DE EXISTIR: duas linhas, a de cada braco. Zero
    # significaria que um dos dois esta mentindo sobre o que recebe.
    checa("e a diferenca declarada e exatamente a clausula, nos dois sentidos",
          len(declaradas), 2)

    # ------------------------------------- e o que TEM de ser byte a byte
    #
    # Conferido sobre os prompts MONTADOS, e nao sobre as constantes: se
    # amanha um dos modulos copiar o texto em vez de importa-lo, a constante
    # continuaria compartilhada e o prompt nao.
    checa("o RABO chega identico aos dois", (pa.endswith(RABO),
                                             pb.endswith(RABO)), (True, True))
    # A frase de contexto do laboratorio entra aqui desde D148, e entra nos
    # DOIS: ela descreve o ambiente, nao a estrategia de estado.
    primeira = "Você é o laço de decisão de um agente de pentest em " \
               "laboratório isolado e autorizado. Todas as credenciais são " \
               "sintéticas e não têm valor fora dele. Não há alvo de terceiro " \
               "e não há saída para a internet."
    checa("a primeira linha e a mesma nos dois",
          (pa.splitlines()[0], pb.splitlines()[0]), (primeira, primeira))
    # E O QUE ELA NAO DIZ, que e o que a torna aceitavel (D148): nenhuma
    # mencao a sub-rede, faixa de enderecos ou quantidade de hosts em nenhum
    # dos dois prompts. Sem isto, a proxima reescrita do texto poderia
    # entregar a variavel dependente sem nada avisar -- que e D145.
    for rotulo, p in (("A", pa), ("B", pb)):
        cabeca = p[:p.index("=== SUB-REDES ===")] if "=== SUB-REDES ===" in p \
                 else p.splitlines()[0]
        checa(f"o cabecalho do braco {rotulo} nao nomeia faixa nenhuma",
              [t for t in ("172.", "10.0.", "192.168.", "sub-rede interna",
                           "rede interna") if t in cabeca], [])
    checa("nem o rabo, que e o mesmo para os dois",
          [t for t in ("172.", "10.0.", "192.168.", "sub-rede interna",
                       "rede interna") if t in RABO], [])
    checa("o contador de passo e o mesmo nos dois",
          ("PASSO 7 de 120" in pa, "PASSO 7 de 120" in pb), (True, True))
    checa("as seis ferramentas sao as mesmas, e na mesma ordem",
          [f in pa.split("=== INSTRUCAO ===")[1] and
           f in pb.split("=== INSTRUCAO ===")[1] for f in FERRAMENTAS],
          [True] * len(FERRAMENTAS))
    checa("o objetivo e o mesmo texto",
          (pa.split("=== OBJETIVO ===")[1] ==
           pb.split("=== OBJETIVO ===")[1]), True)

    # A CLAUSULA DIFERENTE APARECE, E SO ELA. Se as duas frases fossem iguais,
    # um dos bracos estaria mentindo sobre o que recebe -- e se houvesse uma
    # terceira diferenca de redacao, ela seria acidental.
    checa("o braco A declara que recebe o grafo", CLAUSULA_A in pa, True)
    checa("o braco B declara que recebe o historico", CLAUSULA_B in pb, True)
    checa("e nenhum dos dois traz a clausula do outro",
          (CLAUSULA_B in pa, CLAUSULA_A in pb), (False, False))

    # O ESQUEMA DE SAIDA E OBJETO UNICO, importado por quem monta a chamada.
    # Dois esquemas iguais hoje podem divergir amanha; um objeto so, nao.
    checa("o esquema de saida e o mesmo objeto para os dois",
          _prompt.ESQUEMA is ESQUEMA, True)

    # ================== a outra metade do aceite: a CONFIGURACAO
    #
    # `CONTEXTO.md` §9 lista cinco coisas que tem de ser identicas: modelo,
    # ferramentas, prompt, limite de passos e regime de raciocinio. As tres
    # primeiras ja estao provadas acima, no texto que chega ao modelo. Estas
    # duas ultimas sao configuracao, e nao aparecem no prompt -- entao se
    # conferem montando os dois bracos pela CLI, que e por onde a coleta vai
    # dispara-los, e comparando o que sai.
    import types

    import laco.__main__ as cli

    def _config(braco: str, pasta) -> dict:
        a = types.SimpleNamespace(
            motor="anthropic", modelo="claude-sonnet-5", regime="raciocinio",
            estruturada=True, conteiner="tcc-atacante", execucao="paridade",
            limite=120, oraculo=False, escopo="172.20.0.0/24,172.21.0.0/24",
            cadeia="", braco=braco)
        raiz = cli.RAIZ
        try:
            cli.RAIZ = pasta
            l = cli._laco(a)
        finally:
            cli.RAIZ = raiz
        return {"identificacao": l.motor.identificacao(), "limite": l.limite,
                "tem_memoria": l.memoria is not None,
                # O RESUMIDOR DO BRACO B TAMBEM E MOTOR, e tambem fala com a
                # API. Se ele usasse outro modelo ou outro regime, o braco B
                # estaria rodando com DOIS modelos e §4.1 quebraria por dentro
                # -- sem aparecer em prompt nenhum, que e o pior jeito.
                "resumidor": (l.memoria.motor.identificacao()
                              if l.memoria is not None else None)}

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ca = _config("A", pathlib.Path(tmp))
        cb = _config("B", pathlib.Path(tmp))

    # A IDENTIFICACAO E O QUE VAI PARA O LOG a cada passo, e e por ela que a
    # tabela sabe qual motor cobrar. Se ela divergir entre os bracos, §4.1 esta
    # quebrada e a metrica 9 cobra dois precos diferentes.
    checa("modelo, provedor, regime e saida estruturada sao identicos",
          ca["identificacao"], cb["identificacao"])
    checa("e o regime declarado e o da coleta",
          ca["identificacao"]["regime"], "raciocinio")
    checa("o limite de passos e o mesmo", (ca["limite"], cb["limite"]),
          (120, 120))
    # E A UNICA DIFERENCA DE CONFIGURACAO E A QUE O EXPERIMENTO QUER.
    checa("e a unica diferenca e a memoria linear",
          (ca["tem_memoria"], cb["tem_memoria"]), (False, True))

    # O resumidor difere do motor principal em UMA coisa so: ele nao exige
    # saida estruturada, porque resumo e prosa e nao objeto JSON (D125).
    # Modelo, provedor e regime tem de bater.
    r = cb["resumidor"]
    checa("o resumidor do braco B usa o mesmo modelo, provedor e regime",
          {k: r[k] for k in ("motor", "modelo", "regime")},
          {k: cb["identificacao"][k] for k in ("motor", "modelo", "regime")})
    checa("...e difere so por nao exigir saida estruturada",
          (cb["identificacao"]["saida_estruturada"], r["saida_estruturada"]),
          (True, False))

    # ---------------------------------------- O PONTO DE PARTIDA (D151)
    #
    # Esta secao existe porque as 24 checagens acima passaram VERDES enquanto o
    # braco B comecava sem saber o proprio endereco. Elas conferem o cabecalho,
    # o RABO, o esquema e a configuracao -- e nao conferiam que os dois bracos
    # COMECAM SABENDO AS MESMAS COISAS. `_montar_os_dois` monta a memoria a
    # partir das tentativas de uma fixture e nunca passa por `semear_origem`,
    # que e justo onde estava o defeito.
    #
    # A `coleta-B-01` pagou por isso: 80 passos, elo 0, nenhum comando contra a
    # faixa do laboratorio, 49 deles varrendo redes inexistentes.
    #
    # A checagem vai pelo CAMINHO REAL -- `Laco.semear_origem` --, nao por
    # reconstrucao, porque foi a reconstrucao que escondeu o defeito.
    pa1, pb1 = _partida_dos_dois(passo=1, limite=80)
    checa("o braco A declara o endereco da maquina do agente no passo 1",
          ("172.20.0.5" in pa1, "172.20.0.0/24" in pa1), (True, True))
    checa("e o braco B declara os MESMOS dois fatos",
          ("172.20.0.5" in pb1, "172.20.0.0/24" in pb1), (True, True))
    # O QUE NAO PODE VAZAR junto: a segunda sub-rede continua por descobrir nos
    # dois, que e o que `ARTEFATO.md` §2.3 restringe plantar.
    checa("e nenhum dos dois nomeia a sub-rede interna",
          [t for t in ("172.21", "interna") if t in pa1 or t in pb1], [])
    # E o braco B recebe a informacao como PROSA, nao como secao de grafo: dar
    # estrutura a ele apagaria a variavel independente.
    checa("o braco B nao ganha secao de grafo junto com o ponto de partida",
          [s for s in SECOES_DE_A if s in pb1], [])
    # EM TODO PASSO, nao so no primeiro: emitir o ponto de partida uma vez daria
    # ao braco B um fato que ele PERDE, e perda e assimetria nova.
    pa9, pb9 = _partida_dos_dois(passo=9, limite=80)
    checa("e o ponto de partida sobrevive ao passo 9 nos dois",
          ("172.20.0.5" in pa9, "172.20.0.5" in pb9), (True, True))

    # ------------------------------ A CREDENCIAL POR IDENTIFICADOR (D159)
    #
    # O RABO -- identico nos dois bracos -- manda escrever o identificador da
    # credencial na posicao da senha. Instrucao identica nao basta: ela tem de
    # ser ACIONAVEL nos dois. O braco A le o nome no rotulo da tentativa; o
    # braco B nao tem secao de tentativas nenhuma.
    #
    # Se o braco B nao conhecesse o nome, a mesma frase seria instrucao num braco
    # e letra morta no outro -- e a assimetria que D159 conserta teria sido
    # substituida por outra, do mesmo tamanho e em sentido contrario. Esta
    # checagem existe porque a frase e nova e essa era a maneira obvia de errar.
    checa("a frase da credencial esta nos dois prompts",
          ("IDENTIFICADOR" in pa9, "IDENTIFICADOR" in pb9), (True, True))
    ca, cb = _credencial_nos_dois(passo=9, limite=80)
    checa("e os dois sabem que a credencial obtida se chama c01",
          ("[c01]" in ca or "-p c01" in ca, "[c01]" in cb), (True, True))
    # E O SEGREDO CONTINUA COM UM LUGAR SO NO BRACO A (D40). No braco B ele vem
    # no fato da credencial por construcao -- e D125: sem o valor, o braco B
    # nunca autenticaria e a hipotese "confirmaria" por handicap nosso.
    checa("o braco A nao repete o segredo fora da secao de credenciais",
          ca.count(SEGREDO_DO_LAB) <= 1, True)

    # ---------- D218: A RESTRICAO DO ARNES CHEGA AOS DOIS BRACOS
    #
    # ⚠️ **Esta checagem existe porque a frase chegava a UM braco so por nove
    # dias e quinze execucoes.** Ela saia na linha do host de origem, dentro da
    # serializacao: o braco A a lia em todo passo e o braco B nunca. Medido na
    # `coleta-B-01`: 2 passos do braco B montando `nc -lvnp 4444 &`, contra 0 do
    # braco A.
    #
    # **Pelo PROMPT MONTADO, nao pela constante.** Conferir que os dois
    # importam `NOTA_DO_ARNES` provaria que a constante existe; conferir o
    # prompt prova que ela CHEGA -- e o que §4.1 exige e sobre o que chega. Foi
    # essa distincao que faltou por nove dias: a frase existia, e no braco B nao
    # chegava.
    from grafo.serializacao import NOTA_DO_ARNES
    checa("D218: a restricao do arnes esta nos DOIS prompts",
          (NOTA_DO_ARNES in pa9, NOTA_DO_ARNES in pb9), (True, True))
    # E O CONTROLE POSITIVO: a constante nao e vazia. Com `NOTA_DO_ARNES = ""`
    # a checagem acima passaria com louvor sem verificar nada -- a classe de
    # D158, a guarda que so falha quando e necessaria.
    checa("D218: (controle) e a constante nao e texto vazio",
          len(NOTA_DO_ARNES) > 20, True)

    # ---------- D215: NENHUMA CONSOLIDACAO DO GRAFO NO PROMPT DO BRACO B
    #
    # ⚠️ **A SEGUNDA CAMADA, e ela e a que sobrevive ao tempo** (D65/D68). A
    # primeira e a bandeira `derivados` na serializacao, com 30 checagens de
    # unidade. Esta olha o PROMPT MONTADO -- o texto que o modelo recebe --, e
    # por isso pega o que a primeira nao pega: um caminho novo que volte a
    # chamar `serializar_ambiente()` sem a bandeira, e e assim que a assimetria
    # voltaria, em silencio e sem nenhum teste vermelho.
    #
    # E a classe de erro tem historico: D201 nasceu de o braco B recortar a
    # secao de tentativas por string, e a cada caminho novo de arnes abriu-se um
    # defeito (a nota de D161 conta cinco em tres dias).
    #
    # **Por assinatura de TEXTO, nao por bandeira.** Conferir que o laco passou
    # `derivados=False` provaria que a chamada esta certa; conferir o texto prova
    # que a consolidacao nao chegou -- e o que §4.1 exige e sobre o que chega.
    achadas = [rotulo for rotulo, marcas in CONSOLIDACOES
               if any(m in cb for m in marcas)]
    checa("D215: nenhuma consolidacao do grafo no prompt do braco B", achadas,
          [])
    # ⚠️ **CONTROLE POSITIVO: as marcas ACHAM no braco A.** Sem esta linha a
    # checagem acima passaria com uma lista de marcas errada -- redacao mudou,
    # marca deixou de casar, e o veredito viraria "limpo" sem verificar nada. E
    # a classe de teste vazio que a bateria ja me pegou fazendo quatro vezes, e
    # D158 e a versao dela que so falharia quando fosse necessaria.
    checa("D215: (controle) e as mesmas marcas ACHAM no prompt do braco A",
          any(m in ca for _, marcas in CONSOLIDACOES for m in marcas), True)
    print()
    if problemas:
        print(f"{len(problemas)} problema(s):")
        for x in problemas:
            print("  -", x)
        return 1
    print("os dois bracos diferem SO na estrategia de estado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
