"""Pontua TODAS as execucoes gravadas. Roda a mao, nao e teste.

Separado dos testes de proposito: varrer `execucoes/` depende de quantos
arquivos existem na maquina, e D25 proibe teste condicionado ao ambiente --
ele passa em silencio com a pasta vazia. Os testes usam fixture congelada; esta
varredura e para olhar o corpus inteiro quando ele cresce.

Uso:  python auditar_corpus.py
"""

from __future__ import annotations

import json
import pathlib
import sys

from cadeia import carregar_cadeia, elo
from grafo import Grafo

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent
CAD = carregar_cadeia(RAIZ / "lab" / "cadeia.json")

problemas: list[str] = []
print(f"{'execucao':10s} {'passos':>6s} {'elo':>4s}  invariante")
for p in sorted((RAIZ / "execucoes").glob("*/grafo.json")):
    g = Grafo.carregar(p)
    n = len(json.loads(p.read_text(encoding="utf-8")).get("tentativas", []))
    e = elo(g, CAD)
    # O binario de §4.4 tem de ser exatamente `elo >= 4`. Se discordar da
    # metrica 1, uma das duas esta errada -- e as duas saem do mesmo grafo,
    # entao discordar e impossivel por construcao. Conferir mesmo assim: foi
    # justamente um invariante nunca conferido contra dado real que escondeu o
    # defeito de D90 por dias.
    ok = (e >= 4) == (len(g.subredes_alcancadas(excluir=CAD.pivo_pernas)) == 2)
    if not ok:
        problemas.append(p.parent.name)
    print(f"{p.parent.name:10s} {n:6d} {e:4d}  {'ok' if ok else 'VIOLADO'}")

if problemas:
    print(f"\ninvariante violado em: {', '.join(problemas)}", file=sys.stderr)
    sys.exit(1)
print("\ninvariante vale em todas as execucoes")
