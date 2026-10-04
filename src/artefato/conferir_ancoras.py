"""Confere TODOS os ancoradouros de mutacao de uma vez, sem rodar nenhuma.

Rodar a bateria para descobrir ancoradouro morto custa ~14 minutos por fatia.
Isto responde em milissegundos, e existe por causa de 26 de setembro: SEIS
ancoradouros quebraram pelos meus proprios consertos daquele dia (D148, D154,
D156 e D157), e cada um foi descoberto por uma fatia de bateria inteira.

**Nao importa `mutacoes.py`** -- le com `ast.parse`, que e o que D67 e D93
exigem: importar aquele arquivo executa a bateria.

Tres coisas que ele acusa, e cada uma e um jeito de a bateria mentir:

  ancoradouro MORTO      o trecho nao existe mais no fonte. A mutacao nao muda
                         nada e a bateria a conta como sobrevivente -- ou, pior,
                         antes de D120, como no-op calado.
  ancoradouro AMBIGUO    o trecho casa mais de uma vez. A troca atinge os dois
                         lugares, e a mutacao mede outra coisa que nao a que o
                         nome diz.
  NO-OP                  `antes` igual a `depois`. Foi o defeito D120: eu
                         reancorei uma mutacao e ela virou uma insercao de chave
                         duplicada, que o dicionario resolve ficando com a
                         ultima -- comportamento identico ao original.

Uso:  python conferir_ancoras.py     (gratis, milissegundos)
"""

import ast, pathlib

t = pathlib.Path('mutacoes.py').read_text(encoding='utf-8')
lista = [x for x in ast.walk(ast.parse(t)) if isinstance(x, ast.Assign)
         and getattr(x.targets[0], 'id', '') == 'MUTACOES'][0].value

fontes: dict[str, str] = {}
mortos, no_op, multiplos = [], [], []
for i, e in enumerate(lista.elts):
    nome, arq, antes, depois = (x.value for x in e.elts[:4])
    if arq not in fontes:
        fontes[arq] = pathlib.Path(arq).read_text(encoding='utf-8')
    n = fontes[arq].count(antes)
    if n == 0:
        mortos.append((i, nome, arq))
    elif n > 1:
        multiplos.append((i, nome, arq, n))
    if antes == depois:
        no_op.append((i, nome))

print(f'{len(lista.elts)} mutacoes conferidas')
print(f'  ancoradouro MORTO (trecho nao encontrado): {len(mortos)}')
for i, nome, arq in mortos:
    print(f'     {i:4d} [{arq}] {nome[:62]}')
print(f'  ancoradouro AMBIGUO (casa mais de uma vez): {len(multiplos)}')
for i, nome, arq, n in multiplos:
    print(f'     {i:4d} [{arq}] casa {n}x  {nome[:52]}')
print(f'  mutacao que e NO-OP (antes == depois): {len(no_op)}')
for i, nome in no_op:
    print(f'     {i:4d} {nome[:62]}')

# =============== D222: TODA MUTACAO TEM DE ESTAR NO ESCOPO DE ALGUMA FAIXA
#
# ⚠️ **Em 30 de setembro tres mutacoes novas ficaram FORA do escopo da bateria,
# em silencio.** `plano_da_bateria.RISCO` era lista escrita a mao, e o codigo
# novo do dia (`ferramentas/netcat.py`, novo; `ferramentas/ssh.py`, tocado) nao
# estava nela. A bateria teria dito "completa verde" sobre mutacao nunca rodada
# -- e o rotulo "completa" seria falso, a classe que §E53 nomeia como a pior.
#
# D222 passou a derivar o escopo do git. Esta checagem e a SEGUNDA CAMADA
# (D65/D68): ela confere o RESULTADO da derivacao, nao a derivacao. Se o prefixo
# de caminho estiver errado -- foi o meu primeiro erro, e ele fazia a derivacao
# vir vazia sem reclamar --, ou se o marco apontar para o commit errado, aqui
# acusa.
#
# **Nao e checagem de ancora, e mora aqui de proposito:** este script roda em
# milissegundos e o CLAUDE.md manda roda-lo SEMPRE depois de mexer em fonte,
# antes de gastar uma fatia de bateria. E o unico lugar em que ela e vista a
# tempo de servir.
def _escopo_do_plano():
    """`(faixas, risco)` do plano, ou `(_, None)` quando ele decide rodar tudo."""
    import contextlib
    import importlib
    import io
    quieto = io.StringIO()
    with contextlib.redirect_stdout(quieto):
        plano = importlib.import_module("plano_da_bateria")
        importlib.reload(plano)
    return [f for g in plano.grupos for f in g], plano.RISCO


def _tocados_por_conta_propria(arquivos) -> set[str] | None:
    """Quais `arquivos` o git diz que mudaram desde o marco. `None` = nao sei.

    ⚠️ **Deriva de novo, e NAO reaproveita o resultado do plano** -- foi esse
    reaproveitamento que tornou a primeira versao desta guarda circular. E
    compara por **sufixo**, nao por prefixo: prefixo errado no plano continua
    encolhendo o escopo, e aqui o sufixo casa de todo modo. As duas derivacoes
    so concordam quando as duas estao certas.
    """
    import subprocess
    marco = pathlib.Path(".ultima-bateria-verde")
    if not marco.exists() or not marco.read_text(encoding="utf-8").strip():
        return None
    ref = marco.read_text(encoding="utf-8").strip()
    linhas: list[str] = []
    for args in (["git", "diff", "--name-only", f"{ref}..HEAD"],
                 ["git", "diff", "--name-only"],
                 ["git", "diff", "--name-only", "--cached"]):
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               encoding="utf-8", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        linhas += r.stdout.splitlines()
    return {a for a in arquivos
            if any(l.endswith("/" + a) or l == a for l in linhas)}


_faixas, _risco = _escopo_do_plano()
_total = len(lista.elts)
_coberto = {i for a, b in _faixas for i in range(a, b)}
_arqs = [e.elts[1].value for e in lista.elts]
_tocados = _tocados_por_conta_propria(set(_arqs))

print()
if _risco is None:
    print(f"escopo da bateria: COMPLETO, {_total} mutacoes "
          "(o plano nao derivou nada do git e errou para o lado de rodar tudo)")
elif _tocados is None:
    print("escopo da bateria: NAO CONFERIVEL -- o git nao respondeu aqui, "
          "e o plano escopou de todo modo")
    print("  ⚠️ rodar a bateria COMPLETA, ou conferir `.ultima-bateria-verde`")
else:
    # ⚠️ **O INVARIANTE E ESTREITO DE PROPOSITO.** Mutacao em arquivo NAO tocado
    # ficar fora do escopo e o desenho da bateria escopada -- o codigo e
    # identico e a suite so cresceu, entao teste novo mata mais e nunca
    # ressuscita. O que nao pode acontecer e mutacao em arquivo TOCADO ficar
    # fora: ai o rotulo "bateria completa verde" fica falso sobre codigo que
    # mudou. Foi o que quase aconteceu em 30 de setembro com
    # `ferramentas/netcat.py`, novo no dia e ausente da lista a mao.
    faltando = sorted({_arqs[i] for i in range(_total)
                       if i not in _coberto and _arqs[i] in _tocados})
    fora = sum(1 for i in range(_total) if i not in _coberto)
    print(f"escopo da bateria: {_total - fora} de {_total} mutacoes, "
          f"{fora} fora por estarem em arquivo nao tocado")
    print(f"  o git aponta {len(_tocados)} arquivo(s) com mutacao tocado(s) "
          "desde o marco")
    if faltando:
        print(f"  ⚠️ ARQUIVO TOCADO COM MUTACAO FORA DO ESCOPO: {faltando}")
        print("  (escopo que encolhe em silencio produz 'bateria completa")
        print("   verde' sobre codigo que mudou -- conferir o prefixo de")
        print("   caminho em `plano_da_bateria` e o `.ultima-bateria-verde`)")
    else:
        print("  todo arquivo tocado desde o marco esta coberto")
