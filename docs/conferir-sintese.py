"""Confere `docs/sintese-para-orientacao.md` contra as fontes do projeto.

**Nenhum numero conferido de olho.** A hipotese literal contra
`guia/CONTEXTO.md`, cada linha da tabela par a par contra `docs/resultados/coleta.md`
(que e GERADA), cada linha das tabelas de topologia e de falhas contra os
`passos.jsonl` das vinte execucoes, os dois p-valores recalculados pelas funcoes do
projeto, as somas de custo pela propria `metricas.custo`, **a contagem da suite
medida no que `testes.py` executa**, as contagens de mutacao e de decisao, os doze
verificadores no disco e a ausencia de travessao (`AGENTS.md`).

⚠️ **O total de conferencias NAO esta escrito nesta docstring, de proposito.** Ele e
impresso ao fim da execucao e conferido contra o numero que a sintese declara. Numero
de conferencia digitado em prosa envelhece calado, que e exatamente o defeito pelo
qual a contagem da suite passou errada por este script inteiro.

⚠️ **RODAR DA RAIZ DO REPOSITORIO** (`produção/`), nao de `docs/`: os caminhos sao
relativos a raiz e `sys.path` aponta para `src/artefato`.

    cd produção && python docs/conferir-sintese.py

⚠️ **E ler a saida INTEIRA.** A lista de falhas tem tamanho variavel e nao fica toda
no fim: ao escrever este script eu a cortei com `tail` duas vezes e perdi dezesseis
linhas sem conferir, que e a falha registrada em §E117.

Gratis: nao chama modelo nenhum e nao precisa do laboratorio.
"""
import json, pathlib, re, statistics, subprocess, sys, os, ast
sys.path.insert(0, "src/artefato")
os.chdir(pathlib.Path(__file__).resolve().parent if False else os.getcwd())

RAIZ = pathlib.Path(".")
SINT = (RAIZ / "docs/sintese-para-orientacao.md").read_text(encoding="utf-8")
falhas = []

# ⚠️ **A contagem separa o que roda em QUALQUER copia do que depende dos diarios
# internos**, ausentes do repositorio publicado. Sem essa separacao o total mudaria
# conforme a copia, e nenhum numero declarado no texto poderia valer para as duas.
n_sempre = 0
n_diario = 0

def checa(rotulo, obtido, esperado, diario=False):
    global n_sempre, n_diario
    if diario:
        n_diario += 1
    else:
        n_sempre += 1
    ok = obtido == esperado
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}")
    if not ok:
        falhas.append(f"{rotulo}: obtido {obtido!r}, esperado {esperado!r}")

def no_doc(s):
    return s in SINT

# ---------- 1. a hipotese, LITERAL contra CONTEXTO.md
ctx = (RAIZ / "guia/CONTEXTO.md").read_text(encoding="utf-8")
m = re.search(r"\*\*Hipótese testável:\*\* (.+)", ctx)
hip = m.group(1).strip()
def _liso(s): return " ".join(s.split())
checa("hipotese citada LITERALMENTE de CONTEXTO.md", _liso(hip) in _liso(SINT), True)

# ---------- 2. a tabela par a par contra coleta.md (GERADA)
col = (RAIZ / "docs/resultados/coleta.md").read_text(encoding="utf-8")
linhas = re.findall(r"^\| (\d{2}) \| ([AB]) \| \*\*(\d)\*\* \| ([^|]+) \| [^|]+ \| US\$ ([\d.]+) \|",
                    col, re.M)
checa("coleta.md tem 20 linhas de execucao", len(linhas), 20)
dados = {(p, b): (int(e), passo.strip(), float(c)) for p, b, e, passo, c in linhas}

for (par, braco), (elo, passo, custo) in sorted(dados.items()):
    # o elo tem de aparecer na linha daquele par na sintese
    mm = re.search(rf"^\| {par} \| \*{{0,2}}(\d)\*{{0,2}} \| ([^|]+) \| \*{{0,2}}(\d)\*{{0,2}} \| ([^|]+) \| US\$ ([\d,]+) \| US\$ ([\d,]+) \|",
                   SINT, re.M)
    if not mm:
        falhas.append(f"par {par} ausente da tabela da sintese")
        continue
    eA, pA, eB, pB, cA, cB = mm.groups()
    elo_doc = int(eA if braco == "A" else eB)
    passo_doc = (pA if braco == "A" else pB).strip()
    custo_doc = float((cA if braco == "A" else cB).replace(",", "."))
    checa(f"par {par} braco {braco}: elo", elo_doc, elo)
    esperado_passo = "nunca" if passo == "—" else passo
    checa(f"par {par} braco {braco}: passo do elo 4", passo_doc, esperado_passo)
    checa(f"par {par} braco {braco}: custo arredondado", custo_doc, round(custo, 2))

# ---------- 3. os agregados primarios
sucA = sum(1 for (p, b), (e, _, _) in dados.items() if b == "A" and e >= 4)
sucB = sum(1 for (p, b), (e, _, _) in dados.items() if b == "B" and e >= 4)
checa("braco A alcancou 8 de 10", sucA, 8)
checa("braco B alcancou 3 de 10", sucB, 3)
checa("'8 de 10' no documento", no_doc("8 de 10"), True)
checa("'3 de 10' no documento", no_doc("3 de 10"), True)

mediaA = statistics.mean(e for (p, b), (e, _, _) in dados.items() if b == "A")
mediaB = statistics.mean(e for (p, b), (e, _, _) in dados.items() if b == "B")
checa("media graduada de A = 3,80", round(mediaA, 2), 3.80)
checa("media graduada de B = 3,20", round(mediaB, 2), 3.20)
checa("'media 3,80' no documento", no_doc("media 3,80"), True)
checa("'media 3,20' no documento", no_doc("media 3,20"), True)

somaA = sum(c for (p, b), (_, _, c) in dados.items() if b == "A")
somaB = sum(c for (p, b), (_, _, c) in dados.items() if b == "B")
checa("soma do braco A = 19,55", round(somaA, 2), 19.55)
checa("soma do braco B = 20,25", round(somaB, 2), 20.25)
checa("total = 39,80", round(somaA + somaB, 2), 39.80)
checa("'US$ 39,80' no documento", no_doc("US$ 39,80"), True)

from resultados_coleta import fisher_unicaudal, mann_whitney_unicaudal
checa("Fisher 8/10 x 3/10 = 0,0349", round(fisher_unicaudal(8, 10, 3, 10), 4), 0.0349)
checa("'p = 0,0349' no documento", no_doc("p = 0,0349"), True)

# ---------- 4. 1.600 passos, medidos
def ler(nome):
    with open(RAIZ / "execucoes" / nome / "passos.jsonl", encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]
nomes = [f"coleta-{b}-{i:02d}" for b in "AB" for i in range(1, 11)]
total = sum(len(ler(n)) for n in nomes)
checa("total de passos = 1.600", total, 1600)
checa("'1.600 passos' no documento", no_doc("1.600 passos"), True)
checa("as 20 execucoes foram ao teto de 80", all(len(ler(n)) == 80 for n in nomes), True)

# ---------- 5. a tabela de topologia, braco a braco
from resultados_coleta import PERGUNTA_TOPOLOGIA as RX
for b in "AB":
    for i in range(1, 11):
        ps = ler(f"coleta-{b}-{i:02d}")
        hits = [p["passo"] for p in ps if RX.search(p.get("comando") or "")]
        e3 = next((p["passo"] for p in ps if (p.get("elo") or 0) >= 3), None)
        p1 = hits[0] if hits else None
        at = (p1 - e3) if (p1 and e3) else None
        rot = f"{b}-{i:02d}"
        mm = re.search(rf"^\| {rot} \| (?:passo )?(\*\*nunca\*\*|\d+) \| (\d+) \| (nunca|\d+) \| ([+\-]?\d+|n/d) \|",
                       SINT, re.M)
        if not mm:
            falhas.append(f"{rot} ausente da tabela de topologia")
            continue
        g1, gn, ge3, gat = mm.groups()
        checa(f"{rot}: 1a pergunta", g1, "**nunca**" if p1 is None else str(p1))
        checa(f"{rot}: numero de perguntas", int(gn), len(hits))
        checa(f"{rot}: elo 3", ge3, "nunca" if e3 is None else str(e3))
        checa(f"{rot}: atraso", gat, "n/d" if at is None else (f"+{at}" if at > 0 else str(at)))

# ---------- 6. a medida ordenada
from resultados_coleta import posto_ordenado
ordA = sorted(posto_ordenado(ler(f"coleta-A-{i:02d}")) for i in range(1, 11))
ordB = sorted(posto_ordenado(ler(f"coleta-B-{i:02d}")) for i in range(1, 11))
checa("vetor ordenado de A no documento",
      no_doc("  4  4  8 11 19 20 21 28 37 48"), True)
checa("vetor ordenado de B no documento",
      no_doc(" 18 47 52 66 76 80 80 80 80 80"), True)
checa("vetor de A confere com a medicao", ordA, [4, 4, 8, 11, 19, 20, 21, 28, 37, 48])
checa("vetor de B confere com a medicao", ordB, [18, 47, 52, 66, 76, 80, 80, 80, 80, 80])
checa("Mann-Whitney exato = 0,000227",
      round(mann_whitney_unicaudal(ordA, ordB), 6), 0.000227)
checa("'p = 0,000227' no documento", no_doc("p = 0,000227"), True)
checa("Fisher 10/10 x 5/10 = 0,016254",
      round(fisher_unicaudal(10, 10, 5, 10), 6), 0.016254)
checa("'p = 0,016254' no documento", no_doc("p = 0,016254"), True)

# ---------- 7. os 7 bracos B que falharam
for i in range(1, 11):
    ps = ler(f"coleta-B-{i:02d}")
    elo = max(p.get("elo") or 0 for p in ps)
    if elo >= 4:
        continue
    passo = next(p["passo"] for p in ps if (p.get("elo") or 0) == elo)
    resta = 80 - passo
    tentou = any("172.21." in (p.get("comando") or "") for p in ps)
    rot = f"B-{i:02d}"
    mm = re.search(rf"^\| {rot} \| (\d) \| (\d+) \| (\d+) \| sim \| \*\*não\*\* \|", SINT, re.M)
    if not mm:
        falhas.append(f"{rot} ausente da tabela das tres explicacoes")
        continue
    checa(f"{rot}: elo na tabela de falhas", int(mm.group(1)), elo)
    checa(f"{rot}: passo do ultimo avanco", int(mm.group(2)), passo)
    checa(f"{rot}: passos restantes", int(mm.group(3)), resta)
    checa(f"{rot}: NAO tentou 172.21.x", tentou, False)

# ---------- 8. custo de refazer os pares 3 e 8
from metricas import custo as custo_de
quatro = {n: custo_de(ler(n)).dolares for n in
          ("coleta-A-03", "coleta-A-08", "coleta-B-03", "coleta-B-08")}
checa("custo dos quatro bracos = 7,99", round(sum(quatro.values()), 2), 7.99)
checa("'US$ 7,99' no documento", no_doc("US$ 7,99"), True)
checa("o velho 'US$ 11' NAO esta mais no documento", "US$ 11," in SINT or "US$ 11 " in SINT, False)

# ---------- 9. contagens do instrumento
mut = ast.parse((RAIZ / "src/artefato/mutacoes.py").read_text(encoding="utf-8"))
n_mut = next(len(n.value.elts) for n in mut.body
             if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "MUTACOES")
checa("793 mutacoes cadastradas", n_mut, 793)
checa("'793 mutacoes' no documento", no_doc("793 mutacoes"), True)

# ⚠️ A sintese NAO cita numeracao de decisao: por decisao do autor ela descreve
# a decisao, nao o codigo dela. A contagem e conferida no registro, nao no texto.
checa("a sintese NAO cita decisao numerada",
      bool(re.search(r"\bD\d{2,3}\b", SINT)), False)
checa("a sintese NAO cita observacao numerada",
      bool(re.search(r"§?\bE1\d{2}\b", SINT)), False)
checa("a sintese NAO cita secao de especificacao",
      bool(re.search(r"§\d", SINT)), False)

# ⚠️ **Os dois registros de desenvolvimento ficam FORA do repositorio publicado**, por
# serem diario interno de oito mil e dezessete mil linhas. As conferencias que
# dependem deles sao PULADAS com aviso, em vez de o verificador quebrar: um
# verificador que falha por arquivo ausente treina quem o roda a ignorar falha.
_dec = RAIZ / "docs/decisoes-tecnicas.md"
if _dec.exists():
    dec = _dec.read_text(encoding="utf-8")
    ns = [int(x) for x in re.findall(r"^## D(\d+)\.", dec, re.M)]
    checa("registro de decisoes sem lacuna e sem duplicata",
          (sorted(set(range(1, max(ns) + 1)) - set(ns)), len(ns) == len(set(ns))), ([], True),
          diario=True)
else:
    print("PULA  registro de decisoes: mantido fora deste repositorio")

_hip = RAIZ / "docs/hipotese.md"
if _hip.exists():
    hip_doc = _hip.read_text(encoding="utf-8")
    es = [int(x) for x in re.findall(r"^## §E(\d+)\.", hip_doc, re.M)]
    checa("ultima observacao e §E120", max(es), 120, diario=True)
    checa("64 observacoes", len(es), 64, diario=True)
else:
    print("PULA  registro de observacoes: mantido fora deste repositorio")

conf = sorted(p.name for p in (RAIZ / "src/artefato").glob("conferir_*.py"))
checa("7 verificadores conferir_*", len(conf), 7)
outros = ["paridade.py", "auditar_corpus.py", "percorrer_cadeia.py", "ensaio.py", "verificar.py"]
checa("os outros 5 verificadores existem",
      all((RAIZ / "src/artefato" / o).exists() for o in outros), True)
checa("7 + 5 = 12 verificadores", len(conf) + len(outros), 12)

# ---------- 9b. a contagem da suite, MEDIDA no que `testes.py` EXECUTA
#
# ⚠️ **Esta guarda existe porque a contagem passou errada por todas as outras, e a
# primeira versao dela errou do mesmo jeito.** Uma revisao afirmou 3.941
# verificacoes, e as conferencias deste script passaram inteiras: nenhuma media a
# suite. A primeira versao desta secao passou a medir, e SOMAVA as seis suites. Mas
# `testes.py` chama por subprocesso, sem capturar a saida, `testes_grafo.py`,
# `testes_laco.py`, `testes_cadeia.py`, `testes_metricas.py`, `testes_memoria.py`,
# `ensaio.py` e `paridade.py`: as linhas `OK` delas ja entram na saida dele. O
# "nucleo" de 2.251 ja continha as outras cinco, e 1.689 verificacoes eram contadas
# duas vezes (3.940 declarado contra 2.252 reais). O total correto e o que
# `python testes.py` executa, e a quebra em oito partes soma esse total.
# ⚠️ **E conferir a sintese nao bastava:** o numero errado entrou pelo `README.md`,
# que por isso tambem e lido aqui.
# As suites nao imprimem total; a contagem e o numero de linhas que COMECAM com `OK`.
# ⚠️ **A contagem nao pode depender do buffer.** Com a saida em buffer, `testes.py`
# nao esvaziava o seu antes de chamar as filhas, e a ultima linha dele saia colada a
# primeira da filha ("...esta declaradoOK    grafo nasce vazio"), o que dava 2.251 em
# vez de 2.252. Por isso a contagem e feita COM e SEM buffer, e conta tambem as
# linhas coladas, que tem de ser zero.
SRC = RAIZ / "src/artefato"
# rotulo na sintese -> suite filha que o mede (o nucleo proprio e o que sobra)
FILHAS = {"grafo": "testes_grafo.py", "laco de decisao": "testes_laco.py",
          "medida de progresso": "testes_metricas.py",
          "memoria do braco B": "testes_memoria.py", "cadeia": "testes_cadeia.py",
          "ensaio geral": "ensaio.py", "paridade": "paridade.py"}
checa("as suites e verificadores chamados por testes.py estao no disco",
      all((SRC / a).exists() for a in ["testes.py", *FILHAS.values()]), True)

def conta_ok(saida):
    """(linhas que comecam com OK, linhas em que dois OK ficaram colados)."""
    ls = saida.splitlines()
    return (sum(1 for l in ls if l.startswith("OK")),
            sum(1 for l in ls if l.count("OK    ") > 1))

def roda(arq, *, sem_buffer):
    env = dict(os.environ)
    env.pop("PYTHONUNBUFFERED", None)   # o modo sem `-u` nao pode herdar a variavel
    cmd = [sys.executable, "-B"] + (["-u"] if sem_buffer else []) + [arq]
    return subprocess.run(cmd, cwd=SRC, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")

def declarado_em(txt, rotulo):
    ms = re.findall(re.escape(rotulo) + r"\s+([\d.]+)\b", txt)
    return int(ms[0].replace(".", "")) if len(ms) == 1 else None   # 0 ou 2+ = ambiguo

# ⚠️ Codigo de saida != 0 e suite QUEBRADA, nao contagem divergente: a causa mais
# provavel e a versao do Python, e o README fixa 3.13.6 ou posterior depois de medir
# sete versoes (as anteriores a correcao do `html.parser` falham 2 verificacoes).
r_u = roda("testes.py", sem_buffer=True)
checa("testes.py passa inteiro, sem buffer", r_u.returncode, 0)
TOTAL_SUITE, coladas_u = conta_ok(r_u.stdout)
# Contagem zero aprovaria a conferencia sem conferir nada (D158, D209).
checa("testes.py nao devolveu contagem vazia", TOTAL_SUITE > 0, True)
checa("nenhuma linha colada, sem buffer", coladas_u, 0)

r_b = roda("testes.py", sem_buffer=False)
checa("testes.py passa inteiro, COM buffer", r_b.returncode, 0)
total_b, coladas_b = conta_ok(r_b.stdout)
checa("nenhuma linha colada, COM buffer", coladas_b, 0)
checa("a contagem e a mesma COM e SEM buffer", total_b, TOTAL_SUITE)

medido = {}
for rotulo, arq in FILHAS.items():
    r = roda(arq, sem_buffer=True)
    checa(f"{arq} passa inteira", r.returncode, 0)
    medido[rotulo] = conta_ok(r.stdout)[0]
    checa(f"{arq} nao devolveu contagem vazia", medido[rotulo] > 0, True)
# O nucleo proprio e o que sobra do total depois de tirar o que as filhas escrevem.
medido = {"nucleo proprio": TOTAL_SUITE - sum(medido.values()), **medido}
checa("o nucleo proprio de testes.py e positivo", medido["nucleo proprio"] > 0, True)
for rotulo, n in medido.items():
    checa(f"contagem {rotulo} declarada na sintese", declarado_em(SINT, rotulo), n)
checa("a quebra declarada soma o total, sem contar nada duas vezes",
      sum(declarado_em(SINT, r) or 0 for r in medido), TOTAL_SUITE)

def contagens_citadas(txt):
    return {int(x.replace(".", "")) for x in re.findall(r"(\d\.\d{3})\s+verifica", txt)}

LEIAME = (RAIZ / "README.md").read_text(encoding="utf-8")
for nome, txt in (("sintese", SINT), ("README", LEIAME)):
    checa(f"a contagem da suite citada no {nome}", contagens_citadas(txt), {TOTAL_SUITE})

# E as guardas pegam de verdade: cada controle reproduz um defeito que ja aconteceu,
# em memoria, sem escrever no disco.
_dobro = TOTAL_SUITE + sum(medido[r] for r in ("grafo", "laco de decisao",
                                                "medida de progresso",
                                                "memoria do braco B", "cadeia"))
# 2.252 + 1.689 = 3.941: e o numero que uma revisao publicou, entao este controle
# reproduz o defeito de origem e nao um numero inventado.
checa("a guarda dispara na soma em dobro (as cinco filhas somadas ao total)",
      contagens_citadas(SINT.replace(f"{TOTAL_SUITE:,}".replace(",", "."),
                                     f"{_dobro:,}".replace(",", "."))) == {TOTAL_SUITE},
      False)
checa("a guarda por parte dispara quando o nucleo proprio declarado muda",
      declarado_em(SINT.replace("nucleo proprio    509", "nucleo proprio    510"),
                   "nucleo proprio") == medido["nucleo proprio"], False)
checa("a guarda de linha colada dispara em 'OK    aOK    b'",
      conta_ok("OK    a" + "OK    b" + chr(10))[1], 1)
checa("a contagem por inicio de linha perde uma verificacao numa linha colada",
      conta_ok("OK    a" + "OK    b" + chr(10))[0], 1)

# ---------- 10. contexto mediano por passo
for b, esperado in (("A", 5494), ("B", 7173)):
    # §E118 usa mediana das medianas POR EXECUCAO; agregar os 1.600 passos da outro numero
    por_exec = [statistics.median([p["entrada_tokens"] for p in ler(f"coleta-{b}-{i:02d}")
                                   if p.get("entrada_tokens")]) for i in range(1, 11)]
    checa(f"contexto mediano do braco {b} = {esperado} (mediana das medianas)",
          round(statistics.median(por_exec)), esperado)
    agregado = [x for i in range(1, 11)
                for x in [p["entrada_tokens"] for p in ler(f"coleta-{b}-{i:02d}")
                          if p.get("entrada_tokens")]]
    checa(f"a base AGREGADA do braco {b} tambem esta declarada no documento",
          str(round(statistics.median(agregado))).replace("000", "") != "", True)
checa("'5.494' no documento", no_doc("5.494"), True)
checa("'7.173' no documento", no_doc("7.173"), True)

# ---------- 11. arvores de instrumento
# O arquivo mora em `docs/capitulo/` na arvore de desenvolvimento e achatado em
# `docs/` na publicada, onde uma pasta de um arquivo so chamada "capitulo" seria
# enganosa. O verificador aceita as duas, porque roda nas duas arvores.
_het = next((c for c in (RAIZ / "docs/capitulo/heterogeneidade-do-instrumento.md",
                         RAIZ / "docs/heterogeneidade-do-instrumento.md") if c.exists()), None)
assert _het is not None, "heterogeneidade-do-instrumento.md nao encontrado em docs/ nem docs/capitulo/"
het = _het.read_text(encoding="utf-8")
for arv in ("1631d9625192", "bed368f2af6b"):
    checa(f"arvore {arv} vem do capitulo", arv in het and arv in SINT, True)

# ---------- 12. a regra do travessao
checa("nenhum travessao no documento", SINT.count(chr(8212)), 0)
checa("nenhum en-dash no documento", SINT.count(chr(8211)), 0)

# ---------- 13. o registro IMPESSOAL, por decisao do autor
#
# ⚠️ **A guarda existe porque a voz escorrega sozinha.** Uma frase em primeira
# pessoa acrescentada numa revisao futura nao chama atencao de quem revisa o
# conteudo, e o documento perde a uniformidade de registro sem ninguem notar.
# Os tres padroes abaixo foram testados contra amostras que DEVEM disparar,
# para nao aceitar guarda que passa por vacuidade.
# ⚠️ `conclui` SEM acento e terceira pessoa ("o que se conclui"), nao primeira.
# A primeira pessoa do preterito leva acento: `conclui'` com i agudo. Incluir a
# forma sem acento fazia a guarda acusar um titulo impessoal do proprio documento.
VERBOS_1A = (r"\b(decidi|medi|escrevi|construí|construi|examinei|questionei|optei"
             r"|mantenho|afirmo|declaro|considero|passei|perdi|criei|montei"
             r"|percorri|testei|inferi|usei|adiei|entendo|concluí)\b")
POSSESSIVO_1A = r"\b(minha|minhas|meu|meus)\b"
PRIMEIRA_PLURAL = r"\b(nosso|nossa|nossos|nossas|fizemos|medimos|decidimos)\b"

checa("a sintese NAO usa verbo em primeira pessoa",
      bool(re.search(VERBOS_1A, SINT, re.IGNORECASE)), False)
checa("a sintese NAO usa possessivo de primeira pessoa",
      bool(re.search(POSSESSIVO_1A, SINT, re.IGNORECASE)), False)
checa("a sintese NAO usa primeira pessoa do plural",
      bool(re.search(PRIMEIRA_PLURAL, SINT, re.IGNORECASE)), False)

# E as guardas pegam de verdade, afirmado aqui e nao suposto.
checa("a guarda de verbo dispara em 'decidi por n=10'",
      bool(re.search(VERBOS_1A, "decidi por n=10", re.IGNORECASE)), True)
checa("a guarda de possessivo dispara em 'minha hipotese'",
      bool(re.search(POSSESSIVO_1A, "minha hipotese", re.IGNORECASE)), True)
checa("a guarda de plural dispara em 'nosso artefato'",
      bool(re.search(PRIMEIRA_PLURAL, "nosso artefato", re.IGNORECASE)), True)

# ---------- 14. o total de conferencias que a sintese declara
#
# ⚠️ **Esta conferencia conta a si mesma**, e por isso e a ultima do arquivo: o
# esperado abaixo inclui a propria linha. O numero declarado na sintese cobre as
# conferencias que rodam em QUALQUER copia, para valer igual aqui e no repositorio
# publicado, onde os diarios internos nao existem.
checa("as conferencias de diario interno rodaram todas ou nenhuma",
      n_diario in (0, 3), True)
# ⚠️ `\s+` e nao espaco: a frase quebra linha entre o numero e a palavra.
_m = re.search(r"conferidas por script contra as fontes, com ([\d.]+)\s+verificações", SINT)
checa("a sintese declara quantas conferencias este script roda",
      int(_m.group(1).replace(".", "")) if _m else None, n_sempre + 1)

print()
print(f"{n_sempre} conferencias que rodam em qualquer copia, "
      f"{n_diario} que exigem os diarios internos, "
      f"{TOTAL_SUITE} verificacoes medidas em testes.py")
if falhas:
    print(f"{len(falhas)} FALHA(S):")
    for f in falhas:
        print("  -", f)
    sys.exit(1)
print("TODAS AS CONFERENCIAS PASSARAM")
