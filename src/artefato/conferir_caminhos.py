"""Confronta cada caminho GRAVADO num host com o laboratorio no ar. Roda a mao.

**Por que existe** (D171). O arnes roteia por `pivo`: uma proposta com `pivo`
preenchido e alvo interno executa NO PIVO -- e o contrato documentado, e o
agente escreve assim de proposito quando quer olhar o pivo. Mas o passo e
gravado com `endereco` igual ao ALVO DECLARADO, nao ao host onde o comando
rodou. Se a saida desse comando trouxer caminhos, eles entram no host errado, e
o grafo passa a AFIRMAR que o host interno tem arquivos que sao do pivo.

Fato falso gravado e a falha que `docs/hipotese.md` §E53 nomeia -- "valor
gravado por arnes defeituoso nao e dado" -- e que D04 poe acima de perder
achado. Medido em 29 de setembro sobre o corpus inteiro, o mecanismo NAO tinha
produzido fato falso: todo caminho gravado para o `172.21.0.10` existia mesmo
la, porque os conteineres compartilham imagem-base e caminho generico absorvido
do pivo tambem e verdade no host interno. Isto e **risco medido em zero uma
vez**, nao impossibilidade. Este arquivo transforma o risco em VERIFICACAO: se
um dia a atribuicao gravar fato falso, ele aparece no fechamento do par, e nao
tres reinicios depois.

**Quando rodar: no fechamento do par, com o laboratorio AINDA NO AR.** A
comparacao e contra os conteineres que produziram a execucao. Depois de
`docker compose down` o que o agente porventura criou desaparece junto, e
caminho legitimo passa a parecer ausente.

**O veredito de cada caminho**, e por que so um deles derruba a execucao:

    ok            existe no host. Nada a dizer.
    ATRIBUICAO    nao existe no host, EXISTE no pivo. E a assinatura exata do
                  mecanismo acima: caminho do pivo gravado noutro host. Unico
                  que sai com codigo 1.
    ausente       nao existe em lugar nenhum dos dois. Nao e o mecanismo do
                  pivo; as causas conhecidas sao arquivo que o proprio agente
                  criou, lab recriado desde a execucao, e texto de resposta
                  HTTP lido como caminho. Sai em bloco de ATENCAO, para um
                  humano olhar, sem derrubar o fechamento -- crer que toda
                  ausencia e defeito nosso faria o instrumento gritar em toda
                  coleta e ninguem mais olharia.
    ?             a sonda nao respondeu. D170: leitura que falhou nao afirma
                  nada, nem presenca nem ausencia.

**A sonda nao passa por `/bin/sh`, e isso e deliberado.** A imagem do
laboratorio substitui o shell para emitir `ORACULO-SHELL` (`laco/oraculo.py`),
entao `docker exec ... sh -c` escreveria linha de oraculo no log -- a
verificacao sujaria a evidencia que ela existe para proteger. `ls` e binario e
executa direto, sem shell no meio.

Uso:  python conferir_caminhos.py                (todas as execucoes)
      python conferir_caminhos.py coleta-A-01    (so essa)
"""

from __future__ import annotations

import datetime
import pathlib
import re
import subprocess
import sys

from cadeia import carregar_cadeia
from grafo import Grafo
from laco import Oraculo

RAIZ = pathlib.Path(__file__).resolve().parents[2]

OK = "ok"
ATRIBUICAO = "ATRIBUICAO"
AUSENTE = "ausente"
INDETERMINADO = "?"


# ⚠️ CAMINHO EFEMERO (§E116). O kernel cria e destroi estes sozinho: `/dev/pts/0`
# existe enquanto um pty esta alocado e desaparece quando a sessao fecha; o
# conteudo de `/proc` e `/sys` depende de processo vivo. A sonda roda DEPOIS da
# execucao, entao "nao esta la agora" nao diz nada sobre o que havia na hora.
#
# Nasceu de uma reprovacao real: em 3 de outubro o braco A do par 10 saiu com
# ATRIBUICAO em `/dev/pts/0` gravado em 172.21.0.10 -- o veredito mais grave que
# este arquivo tem, a assinatura de D171. Medido com o laboratorio limpo:
# `/dev/pts/0` esta AUSENTE no pivo e no host interno, e `/dev/pts` contem so
# `ptmx`. O grafo estava certo quando gravou (o agente rodou `ssh -tt` e o pty
# existia); quem errou foi a conferencia, que achou o caminho no pivo porque a
# propria conferencia abre terminal la.
#
# A docstring deste arquivo ja lista duas causas da mesma natureza -- "arquivo
# que o proprio agente criou" e "lab recriado desde a execucao" --, as duas sendo
# "era verdade na hora, nao e mais". Efemero de dispositivo e a terceira.
#
# **Vira INDETERMINADO e nao `ausente`**, pela regra de D170: leitura que nao
# autoriza afirmar nada nao afirma nem presenca nem ausencia. Classificar como
# `ausente` seria mais barato (nao derruba o fechamento) e seria errado: diria
# "conferi e nao estava la", quando o certo e "nao da para conferir isto depois".
PREFIXOS_EFEMEROS = ("/dev/pts/", "/proc/", "/sys/")


def efemero(caminho: str) -> bool:
    """O kernel cria e destroi este caminho sozinho? Funcao pura.

    Existe separada por ser a UNICA fonte da regra, pelo mesmo motivo de
    `autenticou` em `ferramentas/ssh.py`: regra repetida em dois lugares e regra
    que vai divergir. `/dev/pts` sem a barra final fica FORA de proposito -- o
    diretorio em si e estavel, so as entradas numeradas dentro dele e que nao
    sao.
    """
    return caminho.startswith(PREFIXOS_EFEMEROS)


def classificar(no_host: bool | None, no_pivo: bool | None,
                e_o_proprio_pivo: bool = False,
                caminho: str = "") -> str:
    """O veredito de um caminho, a partir das duas sondas. Funcao pura.

    Separada do Docker para ser testavel de graca (D25): a tabela de vereditos
    e o juizo do instrumento, e juizo nao conferido e a origem de §E53.

    `e_o_proprio_pivo` diz que o host conferido **e a maquina do pivo** (o
    endereco dele ou uma perna, D163). Ali o mecanismo de D171 e impossivel por
    construcao -- caminho do pivo gravado no pivo esta no lugar certo --, entao
    ausencia e ausencia, e nao falta de leitura.

    ⚠️ **Este parametro nasceu de um defeito do proprio instrumento**, achado na
    primeira varredura ao vivo (29/09). Sem ele, `no_pivo` carregava dois
    sentidos incompativeis -- "a sonda falhou" e "nao se consultou porque nao
    faria sentido" --, e os 15 caminhos gravados no pivo sairam como `?` em vez
    de `ausente`. Confundir os dois e exatamente o que D170 proibe, agora na
    direcao de nao afirmar o que se sabe.

    `caminho` entrou em 3 de outubro, por §E116, e so serve a guarda de efemero
    acima. O padrao vazio mantem os chamadores antigos -- e os testes que
    chamam `classificar(True, None)` -- valendo sem mudanca: caminho vazio nao
    casa prefixo nenhum, entao a tabela de vereditos e identica a de antes para
    todo caminho que nao seja de dispositivo.
    """
    # ⚠️ ANTES de tudo: se o caminho e efemero, nenhuma das duas sondas afirma
    # nada util, e insistir na tabela produziria ATRIBUICAO -- o alarme mais
    # grave do instrumento -- a partir de ruido.
    if caminho and efemero(caminho):
        return INDETERMINADO
    if no_host is None:
        return INDETERMINADO
    if no_host:
        return OK
    if e_o_proprio_pivo:
        return AUSENTE
    # Ausente noutro host. So o pivo distingue o mecanismo de D171 do resto -- e
    # uma sonda que falhou no pivo NAO autoriza concluir "nao e atribuicao".
    if no_pivo is None:
        return INDETERMINADO
    return ATRIBUICAO if no_pivo else AUSENTE


def existe(conteiner: str, caminho: str) -> bool | None:
    """O caminho existe nesse conteiner? `None` se a sonda nao respondeu.

    `--` antes do caminho para que um caminho comecando com `-` seja operando,
    nunca opcao. Sem `shell=True` em lugar nenhum: a lista vai direto ao
    `docker`, entao nada do arquivo gravado chega a um shell, nem aqui nem la.
    """
    try:
        proc = subprocess.run(["docker", "exec", conteiner, "ls", "-d", "--",
                               caminho],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode == 0:
        return True
    # `ls` sai 2 para "nao existe" e tambem para erro de uso. Distinguir pelo
    # texto seria heuristica; o sinal seguro e que o processo RODOU e nao achou.
    if "No such file" in proc.stderr or "cannot access" in proc.stderr:
        return False
    return None


def conferir(caminho_grafo: pathlib.Path, cad, mapa: dict[str, str],
             sonda=existe) -> dict:
    """Confere uma execucao. Devolve a contagem por veredito.

    `sonda` e injetada para que a LIGACAO -- quem e perguntado sobre o que, e
    quando o pivo entra -- possa ser exercitada sem Docker. A licao esta no
    proprio projeto: *"funcao testada nao e chamada testada"*, de uma mutacao
    que sobreviveu porque os testes exercitavam a funcao isolada e nunca a
    linha que a usa.
    """
    g = Grafo.carregar(caminho_grafo)
    conteiner_pivo = mapa.get(cad.pivo)
    contagem = {OK: 0, ATRIBUICAO: 0, AUSENTE: 0, INDETERMINADO: 0}
    achados: list[str] = []
    nao_conferiveis: list[str] = []

    # O pivo e suas pernas sao A MESMA MAQUINA (D163): conferir o pivo contra
    # si mesmo seria circular, e a atribuicao de D171 nao pode existir ali.
    do_pivo = {cad.pivo, *cad.pivo_pernas}

    for endereco, h in sorted(g.hosts.items()):
        if not h.caminhos:
            continue
        conteiner = mapa.get(endereco)
        if not conteiner:
            # Gateway `172.21.0.1` nao e conteiner; host de fora do lab tampouco.
            nao_conferiveis.append(f"{endereco} ({len(h.caminhos)})")
            continue
        e_o_pivo = endereco in do_pivo
        for c in h.caminhos:
            no_host = sonda(conteiner, c)
            no_pivo = None
            if no_host is False and conteiner_pivo and not e_o_pivo:
                no_pivo = sonda(conteiner_pivo, c)
            # `caminho` vai junto desde §E116: a guarda de efemero mora
            # dentro de `classificar`, que e a unica fonte da tabela.
            v = classificar(no_host, no_pivo, e_o_pivo, c)
            contagem[v] += 1
            if v != OK:
                achados.append(f"    {v:11s} {endereco:15s} {c}")

    nome = caminho_grafo.parent.name
    print(f"{nome:16s} ok {contagem[OK]:4d}   "
          f"atribuicao {contagem[ATRIBUICAO]:3d}   "
          f"ausente {contagem[AUSENTE]:3d}   "
          f"indeterminado {contagem[INDETERMINADO]:3d}")
    for linha in achados:
        print(linha)
    for n in nao_conferiveis:
        print(f"    nao conferivel (host fora do lab): {n}")
    return contagem


def veredito(atribuicao: int, ausente: int) -> int:
    """O codigo de saida a partir das duas contagens. Pura, testavel (D25).

    Existe como funcao pelo mesmo motivo de `conferir_hosts.veredito`: com a
    decisao dentro de `main`, trocar o `return 3` por `return 0` **sobreviveu a
    bateria** -- `main` precisa do laboratorio no ar e nenhum teste a alcancava.
    E era justamente esta decisao que falhava antes de D184, devolvendo sucesso
    sobre execucao com fato falso dentro.

    `atribuicao` tem precedencia por ser o mecanismo de D171 nomeado; `ausente` e
    caminho inexistente por outra causa. As duas reprovam.
    """
    if atribuicao:
        return 1
    if ausente:
        return 3
    return 0


# ⚠️ **O LABORATORIO AINDA E O DA EXECUCAO? (D237)** Sem esta pergunta a
# conferencia produz alarme falso, e em 1 de outubro ela produziu: eu rodei esta
# ferramenta sobre a `coleta-A-01` DEPOIS de recriar o laboratorio quatro vezes,
# e ela acusou `FALSO FATO` num caminho que era **verdadeiro** quando a execucao
# rodou -- `/home/svc_deploy/.ssh/known_hosts.old` no `host-db`, arquivo que o
# PROPRIO ssh cria ao atualizar o `known_hosts`. A recriacao o apagou, e ai o
# unico lugar onde ele existe hoje e o pivo: a assinatura exata de D171, sem o
# mecanismo de D171.
#
# **Eu quase descartei um par valido por causa desse alarme.** A verificacao
# original daquela execucao, rodada no laboratorio certo, havia dado codigo 0 --
# e esta registrada no commit do par.
#
# O criterio e tempo: se o conteiner nasceu DEPOIS da ultima escrita da execucao,
# o laboratorio de hoje nao e o que produziu aquele grafo.
def laboratorio_mais_novo(pasta: pathlib.Path) -> float | None:
    """Quantos segundos o conteiner mais novo nasceu DEPOIS da execucao.

    `None` quando nao se sabe -- sem Docker, sem data legivel. Nao afirmar e o
    lado seguro: dizer "o laboratorio e o mesmo" sem prova seria pior que nao
    dizer nada, porque e exatamente isso que valida o veredito.
    """
    passos = pasta / "passos.jsonl"
    if not passos.is_file():
        return None
    fim = passos.stat().st_mtime
    nascimentos = []
    for nome in ("tcc-atacante", "tcc-srv-deploy", "tcc-host-db"):
        try:
            r = subprocess.run(["docker", "inspect", "-f", "{{.State.StartedAt}}", nome],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        bruto = (r.stdout or "").strip()
        try:
            # O Docker devolve RFC3339 com nanossegundos; o Python aceita seis.
            limpo = re.sub(r"\.(\d{6})\d*", r".\1", bruto).replace("Z", "+00:00")
            nascimentos.append(datetime.datetime.fromisoformat(limpo).timestamp())
        except ValueError:
            return None
    if not nascimentos:
        return None
    return max(nascimentos) - fim


def main(argv: list[str]) -> int:
    cad = carregar_cadeia(RAIZ / "lab" / "cadeia.json")
    mapa = Oraculo().mapa()
    if not mapa:
        print("nenhum conteiner do laboratorio no ar: a conferencia so vale "
              "com o lab que produziu a execucao ainda de pe", file=sys.stderr)
        return 2

    alvos = sorted((RAIZ / "execucoes").glob("*/grafo.json"))
    if argv:
        alvos = [p for p in alvos if p.parent.name in argv]
        if not alvos:
            print(f"nenhuma execucao casa com {argv}", file=sys.stderr)
            return 2

    total = {OK: 0, ATRIBUICAO: 0, AUSENTE: 0, INDETERMINADO: 0}
    # D237. Quais execucoes foram conferidas contra um laboratorio que JA NAO E
    # o delas, e tinham achado. Guardadas por nome porque o aviso precisa dizer
    # QUAL -- um lote com uma execucao antiga e outra recente nao e um caso so.
    tarde: list[tuple[str, float, int]] = []
    for p in alvos:
        c = conferir(p, cad, mapa)
        for k, v in c.items():
            total[k] += v
        atraso = laboratorio_mais_novo(p.parent)
        achados = c[ATRIBUICAO] + c[AUSENTE]
        if atraso is not None and atraso > 0 and achados:
            tarde.append((p.parent.name, atraso, achados))

    print()
    if tarde:
        # ⚠️ **O VEREDITO NAO VALE, e dizer que vale foi o que quase me fez
        # descartar um par bom** (D237). Com o laboratorio recriado depois da
        # execucao, todo arquivo que o agente criou durante ela desapareceu --
        # e um caminho que era VERDADEIRO passa a parecer `ausente` ou, se o
        # pivo ainda o tiver, a assinatura exata de D171 sem o mecanismo de D171.
        #
        # ⚠️ **Achado ZERO continua valendo, e e por isso que a guarda olha
        # `achados`:** se nada foi acusado num laboratorio recriado, todo caminho
        # do grafo e nativo do laboratorio -- conclusao mais forte, nao mais
        # fraca. O que a recriacao estraga e o achado, nao a ausencia dele.
        print("NAO VERIFICAVEL: o laboratorio foi RECRIADO depois destas "
              "execucoes, entao os achados abaixo nao se separam de artefato "
              "de recriacao:", file=sys.stderr)
        for nome, atraso, achados in tarde:
            print(f"  {nome}: conteiner nasceu {atraso/3600:.1f} h depois do fim "
                  f"da execucao, e ha {achados} achado(s)", file=sys.stderr)
        print("  Esta conferencia so produz veredito ANTES da proxima recriacao "
              "(regra do CLAUDE.md: ao fim de cada execucao, com o laboratorio "
              "no ar). O veredito da epoca, se houve, esta no commit do par.",
              file=sys.stderr)
        return 4
    if total[AUSENTE]:
        # ⚠️ D184. ISTO REPROVA, e antes de 29 de setembro nao reprovava.
        #
        # A ferramenta imprimia este aviso e devolvia ZERO, entao a execucao
        # seguia com os caminhos falsos dentro e eu li "nenhum caminho do pivo
        # gravado em outro host" como verde. Foi assim que a execucao que eu
        # chamei de "a mais limpa do projeto" fechou as nove verificacoes com
        # DEZ caminhos inexistentes no grafo.
        #
        # Caminho gravado que nao existe em lugar nenhum e fato falso -- a classe
        # que §E53 nomeia como a pior deste projeto --, e fato falso nao passa
        # calado. Aceitar uma execucao com `ausente` maior que zero exige
        # explicar cada caminho por escrito no §E do par, um por um.
        print(f"AUSENTE: {total[AUSENTE]} caminho(s) gravado(s) que nao "
              "existem nem no host nem no pivo. E FATO FALSO no grafo. Nao e o "
              "mecanismo de D171; explicar cada um por escrito antes de usar "
              "esta execucao como dado.", file=sys.stderr)
    if total[INDETERMINADO]:
        print(f"{total[INDETERMINADO]} caminho(s) sem veredito: a sonda nao "
              "respondeu (D170). Nao conte como limpo.")
    if total[ATRIBUICAO]:
        print(f"FALSO FATO: {total[ATRIBUICAO]} caminho(s) do pivo gravado(s) "
              "em outro host. E o mecanismo de D171 acontecendo.",
              file=sys.stderr)
    elif not total[AUSENTE]:
        print("nenhum caminho do pivo gravado em outro host, e nenhum caminho "
              "inexistente")
    return veredito(total[ATRIBUICAO], total[AUSENTE])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
