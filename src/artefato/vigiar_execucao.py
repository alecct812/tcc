"""Vigia de execucao PAGA: emite linha so quando ha marco ou FATO FALSO.

**Por que existe, e o pedido que o criou.** Em 29 de setembro duas execucoes pagas
foram descartadas por defeito de arnes, e nos dois casos quem achou fui eu LENDO
o grafo no meio da corrida -- no passo 31 das duas vezes. Isso economizou ~US$ 3
por vez e foi sorte de leitura, nao metodo. O autor pediu explicitamente:
`tente encontrar erros para correcao dentro da primeira execucao para eu nao ter
tanto gasto de dinheiro`.

Entao as invariantes que antes rodavam DEPOIS passam a rodar DURANTE, a cada
passo novo. O objetivo e o defeito aparecer no passo 5, nao no 31.

**O que ele NAO faz:** julgar se o agente vai bem. Elo baixo nao e alarme -- e a
medicao. Alarme e so fato falso no grafo.

Sai com 1 quando levantou alarme, para quem chama saber que a execucao deve
parar.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time

ARTEFATO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ARTEFATO))

from cadeia import carregar_cadeia, elo          # noqa: E402
from grafo import Grafo                          # noqa: E402
from laco import Oraculo                         # noqa: E402

PASTA = pathlib.Path(sys.argv[1])
RAIZ = ARTEFATO.parents[1]
CAD = carregar_cadeia(RAIZ / "lab" / "cadeia.json")
# O mapa se le UMA vez: `docker ps` a cada passo poluiria o log de evidencia que
# o proprio oraculo usa (a licao de D171 sobre `sh -c`).
MAPA = Oraculo().mapa()

PROIBIDOS = {"172.21.0.1", *CAD.pivo_pernas}


def alarme(texto: str) -> None:
    print("ALARME  " + texto, flush=True)


def invariantes(g) -> list[str]:
    """As que se afirmam SEM Docker e sem custo, a cada passo."""
    falhas = []
    # D183. Uma maquina aparecendo como duas.
    for e in g.pernas_fabricadas():
        falhas.append(f"D183: a perna do pivo {e} virou host no grafo")
    # D163/D177. Comprometer significa ter rodado comando ali.
    for e, h in g.hosts.items():
        if not h.comprometido or h.origem:
            continue
        if e in PROIBIDOS:
            falhas.append(f"D163: {e} nao podia estar comprometido")
        elif MAPA and e not in MAPA:
            falhas.append(f"D177: {e} esta comprometido e NAO e conteiner")
    return falhas


def main() -> int:
    passos_vistos = 0
    melhor = -1
    cats: set[str] = set()
    levantou = False

    while True:
        arq = PASTA / "passos.jsonl"
        try:
            linhas = [l for l in arq.read_text(encoding="utf-8").splitlines()
                      if l.strip()]
        except OSError:
            linhas = []
        passos = []
        for l in linhas:
            try:
                passos.append(json.loads(l))
            except json.JSONDecodeError:
                pass  # linha a meio de gravacao

        if len(passos) > passos_vistos:
            for p in passos[passos_vistos:]:
                n = p.get("passo")
                e = p.get("elo")
                if e is not None and e > melhor:
                    melhor = e
                    print(f"ELO {e} no passo {n}", flush=True)
                c = p.get("categoria")
                if c and c != "aceita" and c not in cats:
                    cats.add(c)
                    print(f"categoria nova: {c} no passo {n}", flush=True)
            passos_vistos = len(passos)

            # AS INVARIANTES, a cada passo novo. Recarregar o grafo do disco e
            # barato e le exatamente o que o laco acabou de gravar.
            try:
                g = Grafo.carregar(PASTA / "grafo.json")
            except (OSError, json.JSONDecodeError):
                g = None
            if g is not None:
                for f in invariantes(g):
                    alarme(f"passo {passos_vistos}: {f}")
                    levantou = True
                if levantou:
                    return 1
                # O elo recalculado tem de casar com o gravado (§E53).
                recalc = elo(g, CAD)
                gravado = max((p.get("elo") or 0) for p in passos)
                if recalc != gravado:
                    alarme(f"passo {passos_vistos}: o elo do grafo ({recalc}) "
                           f"nao casa com o gravado ({gravado})")
                    return 1

            if passos_vistos % 15 == 0:
                print(f"passo {passos_vistos} -- maior elo {melhor}", flush=True)
                # A SONDA DE CAMINHOS (D171/D184), a cada 15 passos e nao a cada
                # passo: ela fala com o Docker uma vez por caminho gravado, e a
                # cada passo isso viraria centenas de chamadas por minuto.
                #
                # E a classe que passou batido hoje: 11 caminhos inexistentes no
                # grafo, e o detector rodava so no fim. Aqui ele roda durante.
                r = subprocess.run(
                    [sys.executable, "-B", "conferir_caminhos.py", PASTA.name],
                    cwd=str(ARTEFATO), capture_output=True, text=True)
                if r.returncode == 1:
                    alarme(f"passo {passos_vistos}: D171 -- caminho do pivo "
                           "gravado em outro host")
                    return 1
                if r.returncode == 3:
                    # ⚠️ NAO para a execucao: caminho inexistente e fato falso,
                    # mas nao fabrica topologia e nao concede elo. Quem decide
                    # parar e quem le o alarme, com o caso na mao -- parar aqui
                    # por um `/etc/profile.` truncado seria caro e errado.
                    for linha in r.stdout.splitlines():
                        if "ausente " in linha:
                            print("  AVISO " + linha.strip(), flush=True)
                    print(f"AVISO passo {passos_vistos}: ha caminho gravado que "
                          "nao existe (D184). Nao para a execucao; olhar.",
                          flush=True)

        try:
            est = json.loads((PASTA / "estado.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            est = {}
        if est.get("desfecho"):
            print(f"DESFECHO: {est['desfecho']} no passo {passos_vistos}",
                  flush=True)
            return 0
        if est.get("passo") and est["passo"] > est.get("limite", 10 ** 6):
            print("teto de passos atingido", flush=True)
            return 0

        time.sleep(15)


if __name__ == "__main__":
    sys.exit(main())
