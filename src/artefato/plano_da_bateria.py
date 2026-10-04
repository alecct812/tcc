"""Monta o plano da bateria escopada e paralela.

Escopo: mutacoes ancoradas nos arquivos tocados desde a ultima bateria COMPLETA
verde. Mutacao em arquivo intocado tem codigo identico e uma suite que so
cresceu -- teste novo mata mais, nunca ressuscita --, entao o resultado dela nao
pode ter mudado.

Saida: quatro grupos equilibrados de faixas contiguas, um por worktree.
"""
import ast
import pathlib
import subprocess

# ⚠️ **O ESCOPO VEM DO GIT, E A LISTA FIXA E SO O PISO (D222).**
#
# Ate 30 de setembro `RISCO` era uma lista escrita a mao, e o comentario do
# modulo dizia que o escopo eram "as mutacoes ancoradas nos arquivos tocados
# desde a ultima bateria COMPLETA verde". **Lista a mao nao sabe o que foi
# tocado.** Naquele dia nasceram `ferramentas/netcat.py` (11 mutacoes) e 3
# mutacoes novas em `ferramentas/ssh.py`, nenhum dos dois na lista: **3 das 23
# mutacoes novas ficaram FORA do escopo, em silencio**, e a bateria teria
# declarado verde sem as ter rodado.
#
# E o modo de falha era o pior possivel: escopo que ENCOLHE sem avisar produz
# "bateria completa verde" sobre codigo nunca mutado. Mesma familia de D209
# (silencio nao e sucesso) e da classe que §E53 nomeia -- o rotulo "completa"
# ficaria falso.
#
# **A FALHA AGORA ERRA PARA O LADO DE RODAR TUDO.** Se o git nao responder, se o
# marco nao existir, se a derivacao vier vazia -- o escopo passa a ser o arquivo
# inteiro. Nunca o contrario.
#
# O marco e `.ultima-bateria-verde`, um arquivo com um commit dentro, escrito a
# mao depois de uma bateria completa verde. Preferi arquivo a tag porque ele
# aparece no `git status` quando muda, e porque quem o atualiza esta declarando
# "a partir daqui esta conferido" -- o que e uma afirmacao, nao automacao.
PISO_DE_RISCO = {"grafo/__init__.py", "grafo/serializacao.py", "grafo/modelo.py",
                 "laco/__init__.py", "laco/memoria.py", "ferramentas/saida.py",
                 "ferramentas/base.py", "metricas.py",
                 "conferir_caminhos.py", "conferir_hosts.py"}
MARCO = pathlib.Path(".ultima-bateria-verde")


def _tocados_desde_o_marco() -> set[str] | None:
    """Arquivos de `src/artefato` mexidos desde o marco. `None` = nao sei.

    `None` nao e "nenhum": e a diferenca entre nao saber e saber que nao ha, e
    quem chama trata as duas coisas de formas opostas -- nao saber roda tudo.
    """
    if not MARCO.exists():
        return None
    ref = MARCO.read_text(encoding="utf-8").strip()
    if not ref:
        return None
    tocados: set[str] = set()
    for args in (["git", "diff", "--name-only", f"{ref}..HEAD"],
                 ["git", "diff", "--name-only"],          # nao commitado
                 ["git", "diff", "--name-only", "--cached"]):
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               encoding="utf-8", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        for linha in r.stdout.splitlines():
            # A RAIZ DO REPOSITORIO E `produção/`, entao o git devolve
            # `src/artefato/...`. O prefixo errado fazia a derivacao vir
            # VAZIA e o escopo cair no piso -- em silencio, que e o modo
            # de falha que este conserto existe para tirar. Conferido
            # exigindo que `ferramentas/netcat.py` apareca.
            prefixo = "src/artefato/"
            if linha.startswith(prefixo):
                tocados.add(linha[len(prefixo):])
    return tocados


_tocados = _tocados_desde_o_marco()
if _tocados is None:
    # NAO SEI o que mudou: roda tudo. O escopo vazio seria a resposta
    # conveniente e e exatamente a que produz rotulo falso.
    RISCO = None
    print("escopo: NAO derivavel do git -- a bateria roda COMPLETA")
else:
    RISCO = PISO_DE_RISCO | _tocados
    novos = sorted(_tocados - PISO_DE_RISCO)
    if novos:
        print("escopo: o git acrescentou " + ", ".join(novos))
# ⚠️ **QUATRO, e o numero foi MEDIDO -- doze ficou pior** (D208).
#
# A maquina tem 16 CPUs, e a conta obvia diz que 12 grupos seriam 3x mais
# rapidos que 4. Medido em 30 de setembro, os dois em sequencia:
#
#    4 grupos  ->  ~31 mutacoes/min   (431 mutacoes em 14 min)
#   12 grupos  ->   12 mutacoes/min   (5 -> 47 em 210 s)
#
# **Doze foi 2,6x mais LENTO.** O gargalo nao e o nucleo: `-B` e
# `PYTHONDONTWRITEBYTECODE` (D42) fazem cada rodada recompilar ~30 modulos do
# codigo-fonte, entao doze processos concorrem por DISCO. Escalar o paralelismo
# alem do que o disco aguenta so acrescenta espera.
#
# Quem mudar este numero mede antes, e mede os dois lados.
GRUPOS = 4

t = pathlib.Path("mutacoes.py").read_text(encoding="utf-8")
arqs = []
for no in ast.walk(ast.parse(t)):
    if isinstance(no, ast.Assign) and getattr(no.targets[0], "id", "") == "MUTACOES":
        arqs = [ast.literal_eval(el.elts[1]) for el in no.value.elts]

idx = (list(range(len(arqs))) if RISCO is None
       else [i for i, a in enumerate(arqs) if a in RISCO])

# faixas contiguas, para pagar a partida do arnes uma vez por faixa
faixas = []
ini = ant = idx[0]
for i in idx[1:]:
    if i == ant + 1:
        ant = i
        continue
    faixas.append((ini, ant + 1))
    ini = ant = i
faixas.append((ini, ant + 1))

# ⚠️ **FAIXA GRANDE E CORTADA, e sem isto os grupos nao adiantam** (D208). O
# repartidor distribui faixas INTEIRAS: uma faixa contigua de 106 mutacoes vai
# toda para um grupo, e o relogio da bateria passa a ser o dela -- 106 x 9,3 s =
# 16 min -- por mais grupos que existam. Foi o que aconteceu em 30 de setembro:
# as mutacoes novas nasceram todas no fim do arquivo, viraram uma faixa so, e o
# GRUPO1 ficou com 106 enquanto o GRUPO2 ficava com 49.
#
# Cortar em pedacos de 20 da granularidade para o repartidor equilibrar. O preco
# e uma partida do arnes por pedaco a mais, que e barata perto de 20 rodadas da
# suite.
TETO_DE_FAIXA = 20
cortadas = []
for a, b in faixas:
    for i in range(a, b, TETO_DE_FAIXA):
        cortadas.append((i, min(i + TETO_DE_FAIXA, b)))
faixas = cortadas

# reparte equilibrando pelo NUMERO DE MUTACOES, nao pelo numero de faixas
grupos = [[] for _ in range(GRUPOS)]
carga = [0] * GRUPOS
for f in sorted(faixas, key=lambda f: f[1] - f[0], reverse=True):
    menor = carga.index(min(carga))
    grupos[menor].append(f)
    carga[menor] += f[1] - f[0]

print(f"mutacoes em escopo: {len(idx)}   faixas: {len(faixas)}")
for n, (g, c) in enumerate(zip(grupos, carga), start=1):
    args = " ".join(f"{a} {b}" for a, b in sorted(g))
    print(f"GRUPO{n} {c} {args}")
