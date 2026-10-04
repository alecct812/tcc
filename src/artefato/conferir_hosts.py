"""Confronta cada host COMPROMETIDO com o laboratorio no ar. Roda a mao.

Irmao de `conferir_caminhos.py`, e nasceu da mesma constatacao: **fato sobre o
mundo so se confere contra o mundo.** Suite, bateria de mutacao e paridade
conferem o que o codigo faz; nenhuma delas pode dizer que o grafo afirmou algo
que o ambiente nega.

**O que ele pergunta.** Comprometer um host significa ter executado comando
nele. Um endereco que nao e conteiner do laboratorio nao roda comando nenhum --
nao tem processo, nao tem `sshd`, nao tem shell. Entao:

    host comprometido que nao esta no `docker ps`  ->  FATO FALSO

**Por que isso nao e hipotetico** (D177). A `piloto-B-02-preD167` marcou o
gateway `172.21.0.1` como comprometido e ganhou **elo 4 num braco B** -- a
metrica primaria do trabalho, inventada, no braco que a hipotese diz que NAO
alcanca. O caminho era um comando composto cujo codigo de saida era do `mount`,
nao do `ssh`. D168 fechou aquele caminho e D177 fechou a familia; esta
verificacao existe para o dia em que houver um caminho que nenhum dos dois
previu.

**A origem e excecao declarada.** A maquina do atacante entra no grafo ja
comprometida, por semeadura, antes de qualquer injecao (D53) -- ela nao e
achado e nao se confere como tal.

⚠️ **So vale com o laboratorio no ar**, pela mesma razao de
`conferir_caminhos.py`: o mapa vem do `docker ps`. Com o lab no chao o script
se recusa a rodar em vez de sair verde, porque numero que ele nao pode garantir
nao e evidencia (D42).

Uso:  python conferir_hosts.py                (todas as execucoes)
      python conferir_hosts.py coleta-A-01    (so essa)
"""

from __future__ import annotations

import pathlib
import sys

from cadeia import carregar_cadeia
from grafo import Grafo
from laco import Oraculo

RAIZ = pathlib.Path(__file__).resolve().parents[2]


def julgar(comprometido: bool, origem: bool, no_mapa: bool) -> str:
    """O veredito de um host. Funcao pura, testavel sem Docker (D25).

    `ok` tambem cobre o host NAO comprometido: sobre ele o grafo nao afirmou
    nada que o ambiente possa negar.
    """
    if not comprometido:
        return "ok"
    if origem:
        return "origem"
    return "ok" if no_mapa else "FANTASMA"


def e_perna(endereco: str, pernas: "frozenset[str]") -> bool:
    """O endereco e uma interface da MESMA maquina do pivo? (D183)

    Funcao pura, pelo mesmo motivo de `julgar`: a verdade de solo entra como
    dado e o veredito se testa sem Docker (D25).

    **Host aqui e sempre defeito, comprometido ou nao.** D163 ja impede a perna
    de conceder o elo 4 e D164 ja impede a autenticacao de fabrica-la, mas a
    absorcao de SAIDA nao tinha guarda: em 29 de setembro isso pos
    `172.21.0.2 srv-deploy 172.21.0.0/24 nao comprometido` na serializacao, ao
    lado do proprio pivo, e o agente gastou nove das dez tentativas seguintes
    num host que nao existe. `nao comprometido` e justamente o que o torna
    atraente, entao esperar por `comprometido` seria olhar o caso menos grave.
    """
    return endereco in pernas


def veredito(fantasmas: int, pernas: int) -> int:
    """O codigo de saida a partir das duas contagens. Pura, testavel (D25).

    Existe como funcao porque a bateria de mutacao mostrou o buraco: com o
    codigo dentro de `main`, trocar o `return 4` por `return 0` **sobreviveu** --
    nenhum teste alcancava a decisao, e `main` precisa de Docker para rodar. O
    veredito e a parte que nao pode errar, entao e a parte que fica pura.

    Fantasma tem precedencia por ser a afirmacao mais grave: host comprometido
    que nao e conteiner nenhum. As duas reprovam, com codigos distintos, para
    quem chama saber qual classe apareceu.
    """
    if fantasmas:
        return 1
    if pernas:
        return 4
    return 0


def conferir(caminho_grafo: pathlib.Path, mapa: dict[str, str],
             pernas: "frozenset[str]" = frozenset()) -> tuple[list[str], list[str]]:
    """Confere uma execucao. Devolve (fantasmas, pernas fabricadas)."""
    g = Grafo.carregar(caminho_grafo)
    fantasmas: list[str] = []
    fabricadas: list[str] = []
    contagem = {"ok": 0, "origem": 0, "FANTASMA": 0}
    for endereco, h in sorted(g.hosts.items()):
        v = julgar(bool(h.comprometido), bool(h.origem), endereco in mapa)
        contagem[v] += 1
        if v == "FANTASMA":
            fantasmas.append(endereco)
        if e_perna(endereco, pernas):
            fabricadas.append(endereco)

    nome = caminho_grafo.parent.name
    print(f"{nome:30s} ok {contagem['ok']:3d}   origem {contagem['origem']:2d}   "
          f"FANTASMA {contagem['FANTASMA']:2d}   PERNA {len(fabricadas):2d}")
    for e in fantasmas:
        h = g.hosts[e]
        print(f"    FANTASMA {e:15s} meio={h.meio_de_acesso} "
              f"subrede={h.subrede}")
    for e in fabricadas:
        h = g.hosts[e]
        print(f"    PERNA    {e:15s} nome={h.nome} "
              f"comprometido={h.comprometido}")
    return fantasmas, fabricadas


def main(argv: list[str]) -> int:
    mapa = Oraculo().mapa()
    if not mapa:
        print("nenhum conteiner do laboratorio no ar: a conferencia so vale "
              "com o lab de pe", file=sys.stderr)
        return 2

    alvos = sorted((RAIZ / "execucoes").glob("*/grafo.json"))
    if argv:
        alvos = [p for p in alvos if p.parent.name in argv]
        if not alvos:
            print(f"nenhuma execucao casa com {argv}", file=sys.stderr)
            return 2

    pernas = frozenset(carregar_cadeia(RAIZ / "lab" / "cadeia.json").pivo_pernas)

    total: list[tuple[str, str]] = []
    pernas_vistas: list[tuple[str, str]] = []
    for p in alvos:
        fantasmas, fabricadas = conferir(p, mapa, pernas)
        for e in fantasmas:
            total.append((p.parent.name, e))
        for e in fabricadas:
            pernas_vistas.append((p.parent.name, e))

    print()
    if total:
        print(f"FATO FALSO: {len(total)} host(s) comprometido(s) que nao sao "
              "conteiner do laboratorio. Comprometer significa ter executado "
              "comando ali, e ali nao roda comando nenhum.", file=sys.stderr)
        for nome, e in total:
            print(f"   {nome}: {e}", file=sys.stderr)
        return veredito(len(total), len(pernas_vistas))
    if pernas_vistas:
        # Codigo proprio (D183) para quem chama distinguir as duas classes: host
        # que nao e conteiner e host que e a SEGUNDA INTERFACE de um conteiner
        # que ja esta no grafo. As duas sao fato falso sobre a topologia, que e
        # justamente o que a hipotese mede.
        print(f"FATO FALSO: {len(pernas_vistas)} host(s) que sao interface do "
              "PIVO e ganharam entrada propria. E uma maquina aparecendo como "
              "duas, e o agente persegue a que nao existe.", file=sys.stderr)
        for nome, e in pernas_vistas:
            print(f"   {nome}: {e}", file=sys.stderr)
        return veredito(len(total), len(pernas_vistas))
    print("todo host comprometido e conteiner do laboratorio, e nenhuma perna "
          "do pivo virou host")
    return veredito(len(total), len(pernas_vistas))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
