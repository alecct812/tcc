"""O laboratorio esta LIMPO? -- a superficie de hoje contra `src/artefato/superficie.json`.

⚠️ **O laboratorio ACUMULA ESTADO entre execucoes, e isso ameaca a comparacao**
(D233). Os conteineres sao `restart: "no"` e nunca sao recriados: servidor,
arquivo e processo que o agente cria numa execucao continuam vivos na seguinte.
Medido no corpo: **doze grafos gravados** trazem porta que a definicao do
laboratorio nao declara em lugar nenhum -- entre elas `172.20.0.10:8123`, que e
literalmente o `python3 -m http.server 8123` que o agente subiu pela injecao de
comando, e uma `172.20.0.10:8000` que quatro execucoes enxergaram e que nao
existe em nenhum `Dockerfile`, `docker-compose.yml` ou documento do laboratorio.

⚠️ **E o dano e ASSIMETRICO dentro do par.** O braco B roda depois do braco A e
herda o que o braco A deixou. `CONTEXTO.md` §9 diz que divergencia acidental
entre os bracos invalida a comparacao, e esta e divergencia acidental.

**O criterio e igualdade exata, nos dois sentidos.** Porta a mais e residuo de
execucao anterior; porta a menos e regressao do laboratorio. Nenhuma das duas e
aceitavel, e colapsa-las numa so mensagem mandaria procurar no lugar errado.

Grátis: nao chama modelo nenhum. Precisa do laboratorio no ar.

Uso:  python conferir_lab.py
      python conferir_lab.py --registrar   # regrava a impressao digital
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[2]
# ⚠️ **A FICHA NAO MORA MAIS EM `lab/` (D243), e a razao e de comparabilidade.**
# `lab/` esta em `CAMINHOS_DE_EXECUCAO` (D238), que e o que `conferir_par.py`
# compara entre os dois bracos. Enquanto a ficha vivia ali, melhorar ESTE
# verificador mudava a arvore `lab` e reprovava o par em curso -- um conserto
# gratis em dinheiro custava US$ 2,5 de braco A valido. Ela e dado de
# verificador: nao e montada em conteiner nenhum, nao entra no `docker-compose`,
# e nada que o agente executa a le. Agora mora ao lado de quem a usa.
FICHA = pathlib.Path(__file__).resolve().parent / "superficie.json"

# ====================================================================== D243
# O SISTEMA DE ARQUIVOS, e nao so a superficie de rede.
#
# ⚠️ **D233 provou que o laboratorio ACUMULA ESTADO entre execucoes** -- doze
# grafos do corpo trazem porta que a definicao nao declara, entre elas o
# `http.server 8123` que o proprio agente subiu. Este verificador cobria a
# superficie de REDE e nao o disco, e arquivo que o agente deixa atras e a mesma
# classe de residuo: dentro do par ele contamina so o braco B, que roda depois.
#
# **Nao ha ficha de expectativas para o disco, e isso e deliberado.** `docker
# diff` responde a pergunta certa de graca: o que mudou NESTE conteiner em
# relacao a IMAGEM. Manter um manifesto a mao seria uma segunda fonte de verdade
# envelhecendo calada -- o erro que D182 nomeia.
#
# O ruido de boot foi medido num laboratorio recem-criado e e pequeno: `/run`
# (pid do sshd, motd dinamico) e os registros de login em `/var/log`. Tudo o mais
# e achado.
#
# ⚠️ **ORDEM DE USO, e ela importa:** rodar ISTO logo depois do `up -d`, ANTES de
# `percorrer_cadeia.py`. A cadeia faz ssh do pivo e cria
# `/home/svc_deploy/.ssh/known_hosts`, que este verificador acusa -- com razao,
# porque e residuo. Medido: foi um `known_hosts.old` assim que quase me fez
# descartar o par 1 em 1 de outubro, por parecer a assinatura de D171.
PREFIXOS_DE_BOOT = ("/run",)
ARQUIVOS_DE_BOOT = ("/var/log/btmp", "/var/log/wtmp", "/var/log/lastlog",
                    "/var/log/faillog",
                    # ⚠️ MONTAGEM DELIBERADA, nao residuo. O compose monta
                    # `hosts/glhf/bloqueio.py` em `/app/bloqueio.py` somente-
                    # leitura, para envolver a GLHF sem modifica-la
                    # (`ARTEFATO.md` §2.2 proibe alterar o artefato de terceiro).
                    # `docker diff` a ve como acrescentada porque bind mount nao
                    # faz parte da imagem. A lista nomeia UM caminho de proposito:
                    # ignorar `/app` inteiro esconderia residuo de verdade.
                    "/app/bloqueio.py")
# ⚠️ **`__pycache__` SAI, e a calibragem custou um falso alarme.** A primeira
# corrida desta verificacao acusou 43 alteracoes no `host-glhf` e 3 no
# `host-web`: todas `.pyc` que o CPython escreve ao importar, quando o servico
# sobe. Nao e residuo do agente -- aparece no primeiro boot de uma imagem recem
# construida, antes de qualquer execucao.
#
# ⚠️ **E a excecao e de BYTECODE, nao de `.py`.** Arquivo de codigo que o agente
# deixe atras continua sendo achado; so a compilacao automatica sai. Ignorar
# `__pycache__` inteiro seria largo demais na direcao errada.
def _e_bytecode(caminho: str) -> bool:
    # O DIRETORIO `__pycache__` tambem entra: o `docker diff` lista a pasta
    # criada, nao so o `.pyc` dentro dela. A primeira versao filtrava so o
    # arquivo e sobraram 13 entradas de pasta no `host-glhf` -- verificacao que
    # grita por ruido deixa de ser lida.
    return (caminho.endswith("/__pycache__")
            or ("/__pycache__/" in caminho and caminho.endswith((".pyc", ".pyo"))))


def alteracoes_no_disco(conteiner: str) -> list[str] | None:
    """O que mudou no disco deste conteiner em relacao a imagem?

    `None` quando o `docker diff` nao respondeu -- nao saber nao e saber que
    esta limpo, a mesma logica de D55.
    """
    try:
        p = subprocess.run(["docker", "diff", conteiner],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        problemas.append(f"docker diff de {conteiner} falhou: {e}")
        return None
    if p.returncode != 0:
        problemas.append(f"docker diff de {conteiner} devolveu "
                         f"{p.returncode}: {(p.stderr or '').strip()[:120]}")
        return None
    achados = []
    for linha in (p.stdout or "").splitlines():
        if len(linha) < 3 or linha[1] != " ":
            continue
        marca, caminho = linha[0], linha[2:]
        # `C` e diretorio cujo conteudo mudou -- inevitavel e sem informacao.
        # O que interessa e arquivo ACRESCENTADO (`A`) ou APAGADO (`D`).
        if marca == "C":
            continue
        if caminho in ARQUIVOS_DE_BOOT or _e_bytecode(caminho):
            continue
        if any(caminho == pre or caminho.startswith(pre + "/")
               for pre in PREFIXOS_DE_BOOT):
            continue
        achados.append(f"{marca} {caminho}")
    return achados
PORTA_ABERTA = re.compile(r"^(\d+)/tcp\s+open", re.MULTILINE)
RELATORIO = re.compile(r"^Nmap scan report for (?:\S+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?",
                       re.MULTILINE)

problemas: list[str] = []


def checa(rotulo: str, ok: bool, detalhe: str = "") -> None:
    print(f"{'OK   ' if ok else 'FALHA'} {rotulo}" + (f"   {detalhe}" if detalhe else ""))
    if not ok:
        problemas.append(f"{rotulo}: {detalhe}")


def varrer(conteiner: str, faixa: str) -> dict[str, list[int]] | None:
    """`nmap -p- --open` de dentro de `conteiner`, por endereco."""
    try:
        r = subprocess.run(
            ["docker", "exec", conteiner, "nmap", "-p-", "--open", "-T4", faixa],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"FALHA nao foi possivel varrer {faixa} de {conteiner}: {e}")
        problemas.append(f"varredura de {faixa} falhou: {e}")
        return None
    achado: dict[str, list[int]] = {}
    atual = None
    for linha in (r.stdout or "").splitlines():
        m = RELATORIO.match(linha)
        if m:
            atual = m.group(1)
            achado.setdefault(atual, [])
            continue
        p = PORTA_ABERTA.match(linha)
        if p and atual:
            achado[atual].append(int(p.group(1)))
    return {k: sorted(v) for k, v in achado.items()}


def superficie(origens: dict[str, str]) -> dict[str, list[int]]:
    vivo: dict[str, list[int]] = {}
    for faixa, conteiner in origens.items():
        print(f"  varrendo {faixa} de dentro de {conteiner}...")
        parte = varrer(conteiner, faixa)
        if parte is None:
            continue
        vivo.update(parte)
    return vivo


def main(argv: list[str]) -> int:
    if not FICHA.is_file():
        print(f"impressao digital ausente: {FICHA}", file=sys.stderr)
        return 2
    ficha = json.loads(FICHA.read_text(encoding="utf-8"))
    esperado = {k: sorted(v) for k, v in ficha["portas"].items()}
    vivo = superficie(ficha["origem_da_varredura"])

    if "--registrar" in argv:
        # ⚠️ So com o laboratorio RECEM-RECRIADO. Regravar sobre um laboratorio
        # sujo canoniza o residuo -- e dai a verificacao passa a aprovar
        # exatamente o que ela existe para pegar.
        ficha["portas"] = {k: vivo.get(k, []) for k in esperado}
        FICHA.write_text(json.dumps(ficha, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")
        print(f"impressao digital regravada em {FICHA}")
        return 0

    print()
    # ⚠️ **O GATEWAY `.1` FICA DE FORA**, e esta de proposito: ele e a maquina
    # hospedeira, nao conteiner do laboratorio, e abre uma porta alta que MUDA
    # (45499 as 08h de 01/10, 51673 as 13h). Verificacao que grita todo dia
    # deixa de ser lida.
    for endereco, portas in sorted(esperado.items()):
        agora = vivo.get(endereco)
        if agora is None:
            # ⚠️ **AUSENTE DO RELATORIO NAO E O MESMO QUE NO CHAO**, e confundir
            # os dois deu falso alarme na primeira execucao desta verificacao:
            # com `--open` o nmap nao imprime secao para host SEM porta aberta,
            # e o atacante (172.20.0.5) nao tem nenhuma. Para ele, ausencia E a
            # superficie limpa.
            #
            # Onde a lista esperada NAO e vazia, ausencia continua sendo falha:
            # ali o host devia ter aparecido. Liveness de host e pergunta de
            # `conferir_hosts.py` (D177) e da cadeia, nao desta verificacao --
            # cada uma responde uma coisa.
            if not portas:
                checa(f"{endereco}: nenhuma porta aberta, como esperado", True)
            else:
                checa(f"{endereco}: a superficie e a de um laboratorio limpo",
                      False, f"REGRESSAO: nao apareceu na varredura, e esperava "
                             f"{portas} -- host no chao ou servico morto")
            continue
        sobrando = sorted(set(agora) - set(portas))
        faltando = sorted(set(portas) - set(agora))
        checa(f"{endereco}: a superficie e a de um laboratorio limpo",
              not sobrando and not faltando,
              (f"RESIDUO de execucao anterior: {sobrando}  " if sobrando else "")
              + (f"REGRESSAO, porta esperada ausente: {faltando}" if faltando else ""))

    # ------------------------------------------------ D243: o disco, nao so a rede
    print()
    try:
        ps = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=30)
        nomes = sorted(n for n in (ps.stdout or "").split() if n.startswith("tcc-"))
    except (OSError, subprocess.SubprocessError) as e:
        nomes = []
        problemas.append(f"nao foi possivel listar os conteineres: {e}")
    # ⚠️ CONTAGEM ZERO NAO PASSA. Sem conteiner nenhum, o laco abaixo nao roda e
    # a verificacao aprovaria o vazio -- a licao de D158/D209, e o buraco que
    # `conferir_ferramentas.py` tinha na primeira versao.
    checa("D243: os conteineres do laboratorio foram encontrados",
          bool(nomes), f"{len(nomes)} encontrado(s)" if not nomes else "")
    for nome in nomes:
        achados = alteracoes_no_disco(nome)
        if achados is None:
            continue   # o `docker diff` nao respondeu; ja esta em `problemas`
        checa(f"{nome}: o disco e o da imagem, sem residuo",
              not achados,
              f"{len(achados)} alteracao(oes): {achados[:6]}" if achados else "")

    print()
    print("=" * 70)
    if problemas:
        print(f"{len(problemas)} PROBLEMA(S) -- o laboratorio NAO esta limpo:")
        for p in problemas:
            print("  -", p)
        print()
        print("  conserto:  cd lab && docker compose down && docker compose up -d")
        print("  e so entao disparar execucao paga -- residuo contamina a")
        print("  comparacao, e dentro do par ele contamina SO o braco B (D233).")
        return 1
    print("o laboratorio esta limpo: a superficie e a de `src/artefato/superficie.json`")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
