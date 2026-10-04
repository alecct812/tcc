"""Os DOIS braços de um par são comparáveis? -- campo por campo.

⚠️ **Existe porque "braços sob código diferente" custou DOIS pares** (D235).
`CONTEXTO.md` §9 diz que divergência acidental entre os braços invalida a
comparação, e foi isso duas vezes: **§E88** descartou o par de 30 de setembro
porque D218 mudou o prompt do braço B **entre** um braço e o outro, e o par de
1 de outubro saiu pela mesma razão, depois do conserto de D234.

**Até aqui eu provava isso à mão**, rodando `git log` uma vez por par e lendo o
`estado.json` com os olhos. Para os nove pares que faltam, a disciplina de quem
opera é o elo fraco -- e o custo de esquecer é um par descartado, US$ 4 a 6.

**O que se afirma aqui é identidade, não semelhança.** §4.1 exige modelo,
prompt, ferramentas, limite de passos e regime **idênticos**. Então a checagem
compara por igualdade exata e falha em qualquer diferença, inclusive numa que
pareça inofensiva: foi uma diferença de aparência inofensiva (uma constante de
nota do arnês) que descartou um par.

Grátis: não chama modelo nenhum e não precisa do laboratório.

Uso:  python conferir_par.py coleta-A-01 coleta-B-01
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[2]

# ⚠️ **OS CAMINHOS DE QUE O AGENTE DEPENDE (D238), e a lista e deliberadamente
# curta.** §4.1 exige modelo, prompt, ferramentas, limite e regime identicos, e
# isso mora aqui: o laco, os involucros, o grafo, o adaptador de modelo, a cadeia
# e a definicao do laboratorio.
#
# **O que NAO entra, e e o ponto:** `docs/`, `execucoes/`, os testes, as mutacoes
# e os proprios verificadores -- inclusive este arquivo. Commitar um
# `ONDE-PARAMOS.md` ou consertar um `conferir_*.py` entre um braco e o outro nao
# muda uma virgula do que o agente ve, e reprovar o par por isso seria descartar
# dinheiro por contabilidade de repositorio.
CAMINHOS_DE_EXECUCAO = (
    "src/artefato/laco",
    "src/artefato/ferramentas",
    "src/artefato/grafo",
    "src/artefato/modelo",
    "src/artefato/cadeia.py",
    "lab",
)

problemas: list[str] = []
notas: list[str] = []


def checa(rotulo: str, ok: bool, detalhe: str = "") -> None:
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}" + (f"   {detalhe}" if detalhe else ""))
    if not ok:
        problemas.append(f"{rotulo}: {detalhe}")


def nota(texto: str) -> None:
    print(f"      .. {texto}")
    notas.append(texto)


def ler(nome: str) -> tuple[dict, list[dict]]:
    pasta = RAIZ / "execucoes" / nome
    if not pasta.is_dir():
        print(f"execucao inexistente: {nome}", file=sys.stderr)
        sys.exit(2)
    estado = json.loads((pasta / "estado.json").read_text(encoding="utf-8"))
    passos = [json.loads(l) for l in
              (pasta / "passos.jsonl").read_text(encoding="utf-8").splitlines()
              if l.strip()]
    return estado, passos


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    nome_a, nome_b = argv
    ea, pa = ler(nome_a)
    eb, pb = ler(nome_b)

    print(f"=== {nome_a}  x  {nome_b} ===")
    # Os papeis tem de ser os que o nome promete. Rotulo falso e a pior classe
    # deste projeto (§E53), e um par A-contra-A nao e par.
    checa("um braco e A e o outro e B",
          {ea.get("braco"), eb.get("braco")} == {"A", "B"},
          f"{nome_a}={ea.get('braco')} {nome_b}={eb.get('braco')}")

    # ---------------------------------------------------- 1. o que §4.1 exige
    for campo in ("limite", "ate_elo"):
        checa(f"§4.1: `{campo}` identico nos dois bracos",
              ea.get(campo) == eb.get(campo),
              f"A={ea.get(campo)} B={eb.get(campo)}")

    if not pa or not pb:
        checa("as duas execucoes gravaram passos", False,
              f"{nome_a}={len(pa)} passos, {nome_b}={len(pb)} passos")
        return 1

    ma, mb = pa[0].get("motor") or {}, pb[0].get("motor") or {}
    # ⚠️ `saida_estruturada` ENTRA nesta lista, e isso e deliberado: o esquema
    # vale para o motor que PROPOE o passo, e ali os dois bracos sao iguais. O
    # que D125 deixa sem esquema e o SEGUNDO motor, o que resume -- exclusivo do
    # braco B, porque resumo de fase e prosa e nao objeto JSON. Eu mesmo quase
    # li isso como divergencia em 1 de outubro.
    for campo in ("modelo", "regime", "versao_api", "saida_estruturada"):
        checa(f"§4.1: `{campo}` identico no motor que propoe",
              ma.get(campo) == mb.get(campo),
              f"A={ma.get(campo)} B={mb.get(campo)}")

    # ------------------------------------------- 2. o MESMO CODIGO DE EXECUCAO
    va, vb = ea.get("codigo"), eb.get("codigo")
    if va is None or vb is None:
        # ⚠️ NAO AFIRMAR nao e o mesmo que afirmar igual. Execucao gravada antes
        # de D235 nao tem o campo, e ai a identidade de codigo se prova a mao,
        # como foi feito no par 1.
        nota(f"versao de codigo nao registrada (A={va}, B={vb}) -- execucao "
             "anterior a D235; a identidade de codigo precisa de prova a mao")
    elif va == vb:
        checa("D238: os dois bracos rodaram no mesmo commit", True)
    else:
        # ⚠️ **COMMIT DIFERENTE NAO E CODIGO DIFERENTE (D238), e comparar a
        # string reprovava par bom.** Em 1 de outubro o braco A do par 2 gravou
        # `79215c6` e o HEAD virou `fa769ac` -- e entre os dois mudaram **dois
        # documentos e os arquivos da propria execucao**, nada mais. O ultimo
        # commit a tocar `src/` ou `lab/` era anterior aos dois.
        #
        # §4.1 exige modelo, prompt, ferramentas, limite e regime identicos. Isso
        # mora no CODIGO DE EXECUCAO, nao no historico do repositorio: commitar
        # um `ONDE-PARAMOS.md` entre um braco e o outro nao muda o que o agente
        # ve. Comparar `HEAD` reprovaria por isso; comparar `HEAD:src` tambem,
        # porque `src/` contem os proprios verificadores.
        #
        # Entao a pergunta certa e feita sobre os caminhos de que o agente
        # DEPENDE, e o git responde exatamente isso: a arvore de cada um.
        iguais, diferentes = [], []
        for alvo in CAMINHOS_DE_EXECUCAO:
            arvores = []
            for v in (va, vb):
                commit = v.removesuffix("+sujo")
                try:
                    r = subprocess.run(
                        ["git", "-C", str(RAIZ), "rev-parse", f"{commit}:{alvo}"],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=30)
                except (OSError, subprocess.SubprocessError):
                    arvores.append(None)
                    continue
                arvores.append((r.stdout or "").strip() if r.returncode == 0 else None)
            if None in arvores:
                # Sem resposta do git nao se afirma identidade -- a mesma logica
                # de D55: nao saber nao e saber que esta igual.
                diferentes.append(f"{alvo} (o git nao respondeu)")
            elif arvores[0] == arvores[1]:
                iguais.append(alvo)
            else:
                diferentes.append(alvo)
        checa("D238: os caminhos do CAMINHO DE EXECUCAO sao identicos nos dois "
              "bracos", not diferentes,
              f"A={va} B={vb}; difere em: {diferentes}" if diferentes else "")
        if not diferentes:
            nota(f"os commits diferem (A={va}, B={vb}) mas os "
                 f"{len(iguais)} caminhos de execucao estao identicos -- entre "
                 "os dois commits mudou so o que o agente nao ve")
    # ⚠️ ARVORE SUJA: o commit nao descreve o que rodou. **Mas a sujeira pode
    # estar fora do caminho de execucao** -- no par 2 ela estava em `docs/`, e
    # isso se prova: nenhum commit posterior ao do braco A tocou `src/` ou
    # `lab/`, entao nao havia fonte pendente naquele momento. A nota diz o que
    # se sabe e o que nao se sabe, em vez de reprovar ou absolver.
    for nome, v in ((nome_a, va), (nome_b, vb)):
        if v and v.endswith("+sujo"):
            nota(f"{nome} rodou com arvore suja ({v}): o commit nao descreve "
                 "tudo o que estava no disco. Conferir `git log -- src lab` "
                 "para saber se a pendencia era de codigo ou so de documento")

    # ------------------------------------------- 3. nenhum dos dois abortado
    for nome, e in ((nome_a, ea), (nome_b, eb)):
        d = e.get("desfecho") or ""
        checa(f"{nome}: desfecho nao e interrupcao de ambiente (D232)",
              not d.startswith("interrompido:"),
              f"desfecho {d!r}" if d.startswith("interrompido:") else "")

    print()
    print("=" * 70)
    if problemas:
        print(f"{len(problemas)} PROBLEMA(S) -- este par NAO e comparavel:")
        for p in problemas:
            print("  -", p)
        return 1
    if notas:
        print(f"{len(notas)} nota(s), nenhuma e falha")
    print("o par e comparavel: os dois bracos diferem SO na estrategia de estado")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
