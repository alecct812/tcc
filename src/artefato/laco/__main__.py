"""Interface de linha de comando do laco, nos dois modos.

O modo ASSISTIDO e uma sessao POR PASSO: o operador entra entre propor e
executar, e o processo morre no intervalo. Dai os subcomandos separados, cada um
uma invocacao independente que le o estado do disco:

    python -m laco iniciar   --execucao dmz-01 --origem 172.20.0.5
    python -m laco propor    --execucao dmz-01
    python -m laco executar  --execucao dmz-01
    python -m laco rejeitar  --execucao dmz-01 --motivo "fora do escopo"
    python -m laco estado    --execucao dmz-01

Modo AUTONOMO, desde a segunda 21 -- as MESMAS duas metades, sem operador no
intervalo. Uma invocacao so, que roda ate o orcamento acabar ou o objetivo ser
alcancado, e imprime o resumo no fim:

    python -m laco autonomo  --execucao dmz-05

O passo a passo dele nao vai ao stdout: ja esta em `execucoes/<nome>/passos.jsonl`,
uma linha por passo, que e a fonte que as metricas leem. Duplicar no terminal
criaria uma segunda versao da verdade.

A chave da API vem do ambiente, nunca de argumento (regra em `CLAUDE.md`).
"""

from __future__ import annotations

import argparse
import os
import json
import pathlib
import subprocess
import sys
from datetime import datetime

from cadeia import carregar_cadeia
from ferramentas import Executor
from laco import Laco, Oraculo
from laco.memoria import MemoriaLinear
from laco.prompt import ESQUEMA
from modelo import criar_motor

RAIZ = pathlib.Path(__file__).resolve().parents[3]

_VERSAO: list[str | None] = []


def versao_do_codigo() -> str | None:
    """O commit que produziu esta execucao, com marca se a arvore estava suja.

    ⚠️ **CALCULADA UMA VEZ POR PROCESSO, e isso foi medido.** `_salvar` roda a
    cada passo, e sem a memoria abaixo os dois `git` custavam **209 ms por
    passo -- 16,7 s por execucao de 80**. Conferido que aquilo nao poluia numero
    nenhum (o `wall_s` registrado e o da chamada ao MODELO, e o `_salvar`
    acontece depois do registro do passo), mas 80 consultas onde uma basta e
    desperdicio: **a versao do codigo nao muda durante uma execucao**, e se
    mudasse isso seria catastrofe, nao dado a acompanhar passo a passo.

    ⚠️ **Existe porque "bracos sob codigo diferente" custou DOIS pares** (D235).
    §E88 descartou o par de 30/09 porque D218 mudou o prompt do braco B entre um
    braco e o outro; o par de 01/10 saiu pela mesma razao. Ate aqui eu provava a
    identidade de codigo **a mao**, com `git log`, uma vez por par -- e para nove
    pares a disciplina de quem opera e o elo fraco.

    Devolve `None` quando nao se sabe: sem git no caminho, fora de repositorio,
    ou se o comando falhar. **Nao afirmar e o lado seguro** -- a mesma logica do
    oraculo e da cadeia (D55). Inventar uma versao seria pior que nao ter
    nenhuma, porque daria ao par um carimbo de comparavel sem a prova.

    O sufixo `+sujo` nao e decoracao: arvore com mudanca nao commitada significa
    que o commit **nao descreve** o que rodou, e dois bracos no mesmo commit mas
    com arvore suja nao estao provados identicos.
    """
    # A memoria guarda TAMBEM o `None`, de proposito: sem git na maquina a
    # resposta nao muda na segunda tentativa, e repetir 80 vezes uma consulta
    # que falha e pior que repetir uma que funciona.
    if _VERSAO:
        return _VERSAO[0]
    try:
        r = subprocess.run(["git", "-C", str(RAIZ), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30)
        if r.returncode != 0:
            _VERSAO.append(None)
            return None
        commit = (r.stdout or "").strip()
        if not commit:
            _VERSAO.append(None)
            return None
        s = subprocess.run(["git", "-C", str(RAIZ), "status", "--porcelain"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30)
        sujo = s.returncode == 0 and bool((s.stdout or "").strip())
        _VERSAO.append(commit + ("+sujo" if sujo else ""))
        return _VERSAO[0]
    except (OSError, subprocess.SubprocessError):
        _VERSAO.append(None)
        return None


def _laco(a) -> Laco:
    motor = criar_motor(a.motor, a.modelo, a.regime,
                        formato=ESQUEMA if a.estruturada else None)
    # BRACO B (D125): MESMO modelo, MESMO regime, MESMO provedor -- so sem o
    # esquema de saida estruturada, porque o resumo de fase e prosa e nao
    # objeto JSON, e `Motor.chamar` nao aceita formato por chamada. Um segundo
    # motor e a forma honesta de dizer isso; reaproveitar o primeiro exigiria o
    # modelo devolver o resumo dentro do esquema da proposta, o que mudaria o
    # contrato de saida que §4.1 manda manter identico entre os bracos.
    memoria = None
    if a.braco == "B":
        memoria = MemoriaLinear(
            criar_motor(a.motor, a.modelo, a.regime, formato=None))
    # D232. UM executor, e a sonda dele. Construir dois seria duas verdades
    # sobre onde o comando roda, e elas divergiriam no dia em que `--conteiner`
    # mudasse -- a licao de D79, onde `juntar` e `autenticou` viveram duplicadas
    # e divergiram em menos de uma hora.
    executor = Executor(conteiner=a.conteiner)
    return Laco.retomar(motor=motor,
                        executor=executor,
                        # A GUARDA DE AMBIENTE, e so aqui: e a CLI que fala com
                        # o Docker de verdade. Os testes nao a recebem, porque
                        # `ExecutorFalso` usa o nome do conteiner real e herdar
                        # a sonda faria a suite medir a maquina (D25).
                        # `--conteiner ""` desliga o `docker exec` e a sonda
                        # junto, que e o que mantem a chave unica.
                        sonda=executor.indisponivel,
                        # D235. A versao do codigo vai para o `estado.json`,
                        # para a identidade entre os bracos ser provavel pelo
                        # DADO e nao pela minha memoria de ter rodado `git log`.
                        versao=versao_do_codigo,
                        pasta=RAIZ / "execucoes" / a.execucao,
                        limite=a.limite,
                        # O oraculo le do ambiente se houve execucao de comando
                        # (D55). `--sem-oraculo` existe para rodar sem Docker;
                        # sem ele, o laco simplesmente nao afirma comprometimento
                        # por HTTP, que e o lado seguro.
                        oraculo=Oraculo() if a.oraculo else None,
                        # Substitui o veto do operador, que o modo autonomo nao
                        # tem. Vazio desliga a guarda.
                        escopo=[f.strip() for f in a.escopo.split(",") if f.strip()],
                        # A cadeia do laboratorio, para a medida de progresso
                        # (D94). Vazio desliga a medida: os testes rodam sem
                        # Docker (D25) e o arnes de medicao usa o mesmo laco.
                        cadeia=carregar_cadeia(pathlib.Path(a.cadeia)) if a.cadeia else None,
                        memoria=memoria)


def _mostrar(p, laco: Laco) -> None:
    print(json.dumps({
        "passo": laco.passo - 1 if not p.valida else laco.passo,
        "valida": p.valida, "motivo": p.motivo,
        "alvo": p.alvo, "endereco": p.endereco, "ferramenta": p.ferramenta,
        "comando": p.comando, "pivo": p.pivo,
        "justificativa": p.justificativa,
        "recusas": laco.recusas, "malformadas": laco.malformadas,
    }, ensure_ascii=False, indent=1))


def _comecando(laco: Laco) -> bool:
    """A execucao esta no passo 1 e com grafo vazio?"""
    return laco.passo == 1 and not laco.grafo.hosts


def _semear(laco: Laco, a) -> int:
    """Semeia a origem se a execucao esta comecando. Devolve codigo de saida.

    **UM caminho de semeadura para os DOIS modos (D154).** Ate 26 de setembro
    isto vivia dentro do ramo do `iniciar`, e `autonomo` aceitava `--origem` e o
    ignorava em silencio: as seis execucoes pagas do corpo rodaram com grafo
    vazio. Duplicar o trecho nos dois ramos resolveria hoje e voltaria a
    divergir; uma funcao chamada pelos dois nao volta.

    E o mesmo raciocinio de D151, onde `Laco.semear_origem` passou a atender os
    dois bracos porque `grafo.semear_origem` atendia so um.

    **Retomada nao semeia.** Ali `_comecando` e falso, e semear por cima
    apagaria o que a execucao aprendeu -- ou pior, marcaria como origem um host
    que o agente comprometeu.
    """
    if not _comecando(laco):
        return 0
    if not a.origem:
        print("--origem e obrigatorio: sem ela o grafo comeca vazio e o "
              "passo 1 vira adivinhacao de faixa (§E12)", file=sys.stderr)
        return 2
    # PELO LACO, nao pelo grafo (D151): o laco atende os dois bracos, e
    # `grafo.semear_origem` atendia so o A.
    laco.semear_origem(a.origem, a.nome_origem)
    laco._salvar()
    return 0


NOME_DA_TRAVA = ".em-andamento"


def travar(pasta: pathlib.Path, acao: str, execucao: str) -> str | None:
    """Reserva a pasta para UMA execucao. Devolve a recusa, ou `None` se travou.

    ⚠️ **Existe porque DUAS execucoes rodaram na mesma pasta e corromperam a
    terceira tentativa do par 2** (2 de outubro). O disparo saiu com um `&`
    aninhado dentro de um comando ja em segundo plano; a tarefa reportou
    "concluida, codigo 0" e a pasta estava vazia, entao se concluiu que nao havia
    comecado e disparou-se de novo. O primeiro estava apenas pendurado no
    `conferir_lab.py` -- varredura nmap leva minutos -- e arrancou depois.
    Resultado: **118 registros para 61 passos, 57 passos com DOIS registros**,
    dois grafos se sobrescrevendo, e **US$ 2,4490** gastos em dobro para produzir
    algo que nao e dado. A bateria de mutacao tem trava desde D67, criada depois
    do mesmo acidente acontecer la; o laco nao tinha.

    ⚠️ **CRIACAO EXCLUSIVA, e NAO teste de PID -- a escolha e de seguranca.** O
    obvio seria gravar o PID e testar se esta vivo com `os.kill(pid, 0)`, como se
    faz em POSIX. **No Windows isso MATA o processo:** `os.kill` ali chama
    `TerminateProcess`, e o sinal 0 vira codigo de saida 0. Uma trava escrita
    assim derrubaria a propria coleta que ela existe para proteger. `open(..., "x")`
    e atomico, nao precisa saber nada sobre processos, e vale nos dois sistemas.

    **Sobra de execucao que caiu NAO e limpa em silencio**, e isso e de proposito:
    o arquivo que ficou e a unica prova de que uma execucao morreu no meio. Limpar
    sozinho esconderia isso -- a mesma razao por que D67 exige conferir a arvore a
    mao antes de apagar a trava dela.

    Nao toca em nada que §4.1 exige identico: age UMA vez, antes do passo 1, e so
    decide se a execucao comeca. O agente nao a ve -- nao entra no prompt nem no
    grafo, e nenhum verificador varre a pasta por arquivo solto (conferido: todos
    os globs sao `*/grafo.json` ou `*/passos.jsonl`).
    """
    trava = pasta / NOME_DA_TRAVA
    try:
        with open(trava, "x", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(),
                       "inicio": datetime.now().astimezone().isoformat(),
                       "acao": acao, "execucao": execucao}, f)
    except FileExistsError:
        try:
            quem = trava.read_text(encoding="utf-8")
        except OSError:
            quem = "(ilegivel)"
        return (f"RECUSADO: ja existe execucao em andamento em {pasta}\n"
                f"  trava: {quem}\n"
                f"  Se aquele processo MORREU, confira o `passos.jsonl` por\n"
                f"  registro duplicado antes de apagar {NOME_DA_TRAVA} -- duas\n"
                f"  execucoes na mesma pasta corrompem as duas (D246).")
    return None


def destravar(pasta: pathlib.Path) -> None:
    """So quem criou a trava a remove; sumico silencioso nao e erro aqui."""
    try:
        (pasta / NOME_DA_TRAVA).unlink()
    except OSError:
        pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="laco")
    p.add_argument("acao",
                   choices=("iniciar", "propor", "executar", "rejeitar",
                            "estado", "autonomo"))
    p.add_argument("--execucao", required=True)
    p.add_argument("--motor", default="anthropic")
    p.add_argument("--modelo", default="claude-sonnet-5")
    p.add_argument("--regime", default="raciocinio")
    p.add_argument("--conteiner", default="tcc-atacante")
    # SEM PADRAO (D126): `None` significa "nao informado", e e o que
    # permite ao `retomar` distinguir "o autor pediu 60" de "o autor nao
    # disse nada". Com 60 fixo aqui, toda retomada discordaria do
    # registro e a guarda de D126 seria impossivel de satisfazer.
    p.add_argument("--limite", type=int, default=None)
    p.add_argument("--motivo", default="")
    # Endereco da maquina de onde o agente executa (D53). Parametro, e nao
    # constante no codigo: o laboratorio pode ser recriado com outra faixa (D04),
    # e um endereco fixo quebraria em silencio.
    p.add_argument("--origem", default="")
    p.add_argument("--nome-origem", default="atacante")
    # As faixas onde o agente pode agir, separadas por virgula. Substitui o veto
    # do operador, que o modo autonomo nao tem: em 18 de setembro o agente
    # propos `destino=8.8.8.8` e foi vetado a mao (D71). Vazio desliga a guarda.
    p.add_argument("--escopo", default="172.20.0.0/24,172.21.0.0/24")
    # A sub-rede que fecha o criterio de sucesso de `ARTEFATO.md` §4.4. Vazio
    # faz o laco rodar ate o orcamento acabar, que e o que a coleta de medicao
    # de teto precisa.
    # O OBJETIVO E UM ELO (D111). Ate 23 de setembro era a sub-rede interna,
    # que e o elo 4 -- e por isso o elo 5 nunca era alcancado e a metrica 3
    # nunca disparava. 5 e a cadeia inteira de `lab/cadeia.md`; 4 reproduz o
    # comportamento anterior; 0 desliga a parada e roda ate o teto.
    p.add_argument("--ate-elo", dest="ate_elo", type=int, default=5,
                   choices=(0, 1, 2, 3, 4, 5))
    # A cadeia do laboratorio, para a medida de progresso (D94). Vazio desliga
    # a medida: os testes rodam sem Docker e o arnes de medicao usa o mesmo
    # laco. Enderecos vivem no arquivo, nunca aqui (D04).
    p.add_argument("--cadeia", default=str(RAIZ / "lab" / "cadeia.json"))
    # O BRACO. "A" e o padrao porque e o artefato; "B" liga a memoria linear.
    # Por parametro e nao por variavel de ambiente: `ARTEFATO.md` §2.3 exige
    # reexecucao, e o comando que rodou tem de dizer qual braco rodou.
    p.add_argument("--braco", choices=("A", "B"), default="A",
                   help="A = grafo serializado (padrao); B = memoria linear")
    p.add_argument("--sem-saida-estruturada", dest="estruturada",
                   action="store_false")
    p.add_argument("--sem-oraculo", dest="oraculo", action="store_false")
    a = p.parse_args(argv)

    laco = _laco(a)

    if a.acao == "iniciar":
        if not _comecando(laco):
            print("execucao ja comecou; use outro nome", file=sys.stderr)
            return 2
        erro = _semear(laco, a)
        if erro:
            return erro
        # A TELA TEM DE DIZER O QUE O MODELO VAI RECEBER (D128). Ate aqui ela
        # imprimia a serializacao do grafo nos DOIS bracos, e no braco B isso
        # mostra ao operador exatamente o que o modelo nunca ve -- a tela
        # contando uma historia e o experimento rodando outra. O grafo continua
        # sendo mantido no braco B (D41), e por isso continua impresso: o que
        # muda e a linha que diz que ele nao viaja.
        if laco.memoria is not None:
            print("=== BRACO B: o grafo abaixo E MANTIDO e NAO E ENVIADO ===")
            print(laco.grafo.serializar())
            print("=== o que o modelo recebe no passo 1 ===")
            print(laco.memoria.montar(passo=laco.passo, limite=laco.limite))
        else:
            print(laco.grafo.serializar())
        return 0

    # ====================================================================== D246
    # UMA EXECUCAO POR PASTA, e a trava e de criacao exclusiva.
    #
    # ⚠️ **Existe porque DUAS execucoes rodaram na mesma pasta e corromperam a
    # terceira tentativa do par 2** (2 de outubro). Eu disparei com um `&`
    # aninhado dentro de um comando ja em segundo plano; a tarefa reportou
    # "concluida, codigo 0" e a pasta estava vazia, entao eu conclui que nao
    # havia comecado e disparei de novo. O primeiro disparo estava apenas
    # pendurado no `conferir_lab.py` -- varredura nmap leva minutos -- e arrancou
    # depois. Resultado: **118 registros para 61 passos, 57 passos com DOIS
    # registros**, dois grafos se sobrescrevendo, e **US$ 2,4490** gastos em
    # dobro para produzir uma execucao que nao e dado.
    #
    # A bateria de mutacao tem trava desde D67, criada depois deste mesmo
    # acidente acontecer la. O laco nao tinha.
    #
    # ⚠️ **CRIACAO EXCLUSIVA, e NAO teste de PID -- e a escolha e de seguranca.**
    # O obvio seria gravar o PID e testar se esta vivo com `os.kill(pid, 0)`,
    # como se faz em POSIX. **No Windows isso MATA o processo:** `os.kill` ali
    # chama `TerminateProcess`, e o sinal 0 vira codigo de saida 0. Uma trava
    # escrita assim derrubaria a propria coleta que ela existe para proteger.
    # `open(..., "x")` e atomico, nao precisa saber nada sobre processos, e
    # funciona igual nos dois sistemas.
    #
    # **Sobra de execucao que caiu NAO e limpa em silencio**, e isso e de
    # proposito: o arquivo que ficou e a unica prova de que uma execucao morreu
    # no meio. Limpar sozinho esconderia isso -- a mesma razao por que D67 exige
    # conferir a arvore a mao antes de apagar a trava dela.
    #
    # Nao toca em nada que §4.1 exige identico: age UMA vez, antes do passo 1, e
    # so decide se a execucao comeca. O agente nao a ve -- nao entra no prompt
    # nem no grafo, e nenhum verificador varre a pasta por arquivo solto
    # (conferido: todos os globs sao `*/grafo.json` ou `*/passos.jsonl`).
    ACOES_QUE_TRAVAM = ("autonomo", "iniciar", "propor", "executar")
    recusa = None
    if a.acao in ACOES_QUE_TRAVAM:
        recusa = travar(laco.pasta, a.acao, a.execucao)
    if recusa:
        print(recusa, file=sys.stderr)
        return 3

    try:
        return _executar(laco, a)
    finally:
        # ⚠️ So quem CRIOU a trava a remove. Se a criacao foi recusada, o `return
        # 3` acima ja saiu e nao chega aqui -- senao o segundo processo apagaria
        # a trava do primeiro, que e o defeito ao contrario.
        if a.acao in ACOES_QUE_TRAVAM:
            destravar(laco.pasta)


def _executar(laco, a) -> int:
    if a.acao == "autonomo":
        # SEMEIA SE ESTIVER COMECANDO (D154). Ate 26 de setembro so o `iniciar`
        # semeava, e `autonomo` aceitava `--origem` e o IGNORAVA -- todas as seis
        # execucoes pagas do corpo rodaram com grafo vazio, e o passo 1 virou a
        # adivinhacao de faixa que §E12 mediu e que `semear_origem` existe para
        # evitar. Retomada nao semeia: ali `_comecando` e falso.
        erro = _semear(laco, a)
        if erro:
            return erro
        # Nada aqui espera resposta: e essa a diferenca entre os dois modos, e
        # e so essa. O passo a passo vai para `passos.jsonl`, nao para o
        # terminal -- e de la que as metricas saem, e duplicar no stdout criaria
        # uma segunda versao da verdade.
        inicio = laco.passo
        desfecho = laco.rodar(ate_elo=a.ate_elo or None)
        print(json.dumps({
            "desfecho": desfecho,
            "passos_gastos": laco.passo - inicio,
            "passo_final": laco.passo - 1, "limite": laco.limite,
            "comprometidos": laco.grafo.hosts_comprometidos,
            "subredes_alcancadas": laco.grafo.subredes_alcancadas(
                excluir=laco.cadeia.pivo_pernas if laco.cadeia else ()),
            "subredes_conhecidas": laco.grafo.subredes,
            "acoes_redundantes": laco.grafo.acoes_redundantes,
            "passos_improdutivos": laco.grafo.passos_improdutivos,
            "reuso_de_credencial": laco.grafo.reuso_de_credencial,
            "recusas": laco.recusas, "malformadas": laco.malformadas,
        }, ensure_ascii=False, indent=1))
        return 0

    if a.acao == "estado":
        print(json.dumps({
            "passo": laco.passo, "limite": laco.limite,
            "hosts": len(laco.grafo.hosts),
            # `hosts_comprometidos` e a metrica 2, que EXCLUI o host de
            # origem (D53). Contar a mao aqui repetia a expressao antiga e
            # relatava um a mais -- e relatorio errado sobre metrica primaria e
            # pior que codigo errado, porque ninguem o testa.
            "comprometidos": laco.grafo.hosts_comprometidos,
            "subredes_alcancadas": laco.grafo.subredes_alcancadas(
                excluir=laco.cadeia.pivo_pernas if laco.cadeia else ()),
            "acoes_redundantes": laco.grafo.acoes_redundantes,
            "passos_improdutivos": laco.grafo.passos_improdutivos,
            "reuso_de_credencial": laco.grafo.reuso_de_credencial,
            "recusas": laco.recusas, "malformadas": laco.malformadas,
            "pendente": laco.pendente().comando if laco.pendente() else None,
        }, ensure_ascii=False, indent=1))
        return 0

    if a.acao == "propor":
        if laco.pendente():
            print("ja ha proposta pendente; execute ou rejeite antes",
                  file=sys.stderr)
            return 2
        _mostrar(laco.propor(), laco)
        return 0

    pendente = laco.pendente()
    if pendente is None:
        print("nao ha proposta pendente", file=sys.stderr)
        return 2

    if a.acao == "rejeitar":
        laco.rejeitar(pendente, a.motivo or "sem motivo declarado")
        print(json.dumps({"rejeitada": pendente.comando,
                          "motivo": a.motivo, "passo": laco.passo},
                         ensure_ascii=False, indent=1))
        return 0

    execucao = laco.executar(pendente)
    linha = json.loads(
        (laco._passos_jsonl).read_text(encoding="utf-8").splitlines()[-1])
    print(json.dumps({"codigo": execucao.codigo,
                      "resumo": linha["resumo"],
                      "sucesso": linha["sucesso"],
                      "revisao_do_grafo": linha["revisao_do_grafo"],
                      "passo_seguinte": laco.passo}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
