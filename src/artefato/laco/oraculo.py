"""O ambiente declarando o que executou -- verdade de campo, não interpretação.

Para SSH o sinal já é limpo e não precisa disto: `ssh user@host comando` sair
com 0 **significa** que um comando rodou ali, e `Ssh.analisar` já conclui isso.

Para HTTP não há sinal nenhum. Do ponto de vista do `curl`, foram bytes para lá
e bytes para cá; reconhecer `uid=0(root)` na resposta seria heuristica sobre o
significado do texto, que `ARTEFATO.md` §1.2 mantem fora do parser -- e com
razao. Consequencia medida em `docs/hipotese.md` §E14: o agente obteve root no
`host-web` e gastou tres passos perguntando de novo.

**Dois sinais independentes**, os dois escritos em `/proc/1/fd/2` (a saida de
erro do processo 1, capturada pelo Docker) e portanto **fora do sistema de
arquivos do conteiner**:

    ORACULO rota=/diagnostico param=destino valor='127.0.0.1;id'
        da aplicacao, no ponto da falha. Preciso: diz QUAL vulnerabilidade.

    ORACULO-SHELL -c ping -c 1 -W 2 127.0.0.1;id
        do `/bin/sh` substituido na imagem. Abrangente: qualquer caminho que
        abra shell, inclusive um que ninguem plantou.

Quem obtiver root dentro do conteiner pode acrescentar linha falsa, mas nao
consegue APAGAR o que ja foi gravado -- do lado de dentro, o log do Docker so
cresce. E linha falsa so infla, o que o cruzamento dos dois sinais revelaria.

Detalhes e ressalvas em D55.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess

# `ORACULO rota=/diagnostico param=destino valor='...'`
# O `.*?` no meio nao e frouxidao: o registro ganhou o campo `template=` em 18
# de setembro, entre `param=` e `valor=`, e uma expressao rigida deixou de casar
# em silencio -- emissor e leitor divergiram sem que nada acusasse. O formato
# vive em `lab/hosts/web/app.py`, e a verificacao em `testes_laco.py` usa a linha
# exata que ele emite, para os dois nao poderem divergir de novo sem aviso.
APLICACAO = re.compile(r"^ORACULO rota=(\S+) param=(\S+).*? valor=(.*)$")
SHELL = "ORACULO-SHELL"
MARCA = "ORACULO"

# D169. SESSAO SSH ACEITA, dita pelo `sshd` DO HOST DE DESTINO.
#
# O docstring acima dizia que "para SSH o sinal ja e limpo: sair com 0 significa
# que um comando rodou ali". **D168 derrubou essa premissa**: num comando
# composto o codigo nem e do ssh, e um SSH recusado com `2>/dev/null` era lido
# como sessao -- marcando o gateway `172.21.0.1` comprometido e concedendo elo 4
# sem ninguem tocar a rede interna.
#
# Esta linha e evidencia positiva e o agente NAO a controla: ela e escrita pelo
# servidor, no log do Docker, fora do sistema de arquivos do conteiner. Suprimir
# o stderr do cliente nao apaga o registro do servidor.
#
#   Accepted password for svc_deploy from 172.21.0.2 port 32900 ssh2
#            ^metodo      ^usuario      ^origem
#
# A ORIGEM entra de proposito: ela corrobora o salto. Uma sessao vinda de
# `172.21.0.2` prova que o comando partiu do pivo, que e o que a travessia
# afirma.
SESSAO = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port")

# Injecao de comando e, por definicao, dado do atacante atravessando para o
# **plano de controle** do comando. Isso e sintatico e verificavel: cada um
# destes caracteres muda a estrutura do que o shell executa. Sem nenhum deles, o
# valor foi argumento do programa que a aplicacao ja ia rodar.
CONTROLE = ";|&$`()<>" + chr(10) + chr(13)


class Oraculo:
    """Le os registros que os hosts do laboratorio emitem, de fora deles.

    O mapa de endereco para conteiner e **derivado** de `docker inspect`, nao
    configurado: o laboratorio pode ser recriado com outra faixa (D04), e uma
    tabela fixa no codigo quebraria em silencio.
    """

    def __init__(self, prefixo: str = "tcc-") -> None:
        self.prefixo = prefixo
        self._mapa: dict[str, str] | None = None

    def mapa(self) -> dict[str, str]:
        """De endereco IPv4 para nome de conteiner."""
        if self._mapa is not None:
            return self._mapa
        nomes = self._rodar(["docker", "ps", "--filter",
                             f"name={self.prefixo}", "--format", "{{.Names}}"])
        mapa: dict[str, str] = {}
        for nome in nomes.split():
            bruto = self._rodar(["docker", "inspect", nome, "--format",
                                 "{{json .NetworkSettings.Networks}}"])
            try:
                redes = json.loads(bruto)
            except (json.JSONDecodeError, ValueError):
                continue
            for dados in (redes or {}).values():
                endereco = (dados or {}).get("IPAddress")
                if endereco:
                    mapa[endereco] = nome
        self._mapa = mapa
        return mapa

    def linhas(self, endereco: str | None) -> list[str]:
        """Registros do oraculo neste host, do mais antigo ao mais novo."""
        if not endereco:
            return []
        conteiner = self.mapa().get(endereco)
        if not conteiner:
            return []
        return filtrar(self._rodar(["docker", "logs", conteiner]))

    def sessoes(self, endereco: str | None) -> list[str]:
        """Sessoes SSH que o `sshd` DESTE host aceitou, da mais antiga a mais nova.

        Mesmo mapa e mesmo log de `linhas`, filtro proprio (D169). Separado
        daquele metodo porque os dois sinais respondem perguntas diferentes:
        `linhas` diz "houve execucao de comando por caminho que nao e SSH", e
        este diz "o servidor aceitou uma sessao SSH".
        """
        if not endereco:
            return []
        conteiner = self.mapa().get(endereco)
        if not conteiner:
            return []
        return filtrar_sessoes(self._rodar(["docker", "logs", conteiner]))

    def _rodar(self, comando: list[str]) -> str:
        proc = subprocess.run(comando, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
        # `docker logs` escreve a saida do conteiner nos dois descritores, e o
        # que interessa esta no stderr quando o processo grava ali.
        return (proc.stdout or "") + "\n" + (proc.stderr or "")


def filtrar(saida: str) -> list[str]:
    """So as linhas do oraculo, do log inteiro do conteiner.

    Funcao propria para ser testavel sem Docker (D25): `docker logs` traz
    tambem o log de acesso do servidor, rastro de excecao e o que mais o
    processo escrever. Tratar tudo como registro do oraculo faria uma
    requisicao HTTP comum contar como execucao de comando.
    """
    return [l for l in saida.splitlines() if l.startswith(MARCA)]


def filtrar_sessoes(saida: str) -> list[str]:
    """So as linhas de sessao ACEITA, do log inteiro do conteiner (D169).

    Funcao propria para ser testavel sem Docker (D25), pela mesma razao de
    `filtrar`. E **so o aceite**: `Received disconnect` e `Disconnected from`
    tambem mencionam o usuario e nao provam nada -- aparecem inclusive depois de
    sessao recusada.
    """
    return [l for l in saida.splitlines() if SESSAO.match(l)]


def usuario_da_sessao(linha: str) -> str | None:
    """O usuario que a sessao aceitou, ou `None` se a linha nao casar."""
    m = SESSAO.match(linha)
    return m.group(2) if m else None


def _valor(bruto: str) -> str:
    """Recupera o valor exato que a aplicacao registrou.

    A aplicacao grava com `repr()`, entao uma quebra de linha vira os dois
    caracteres `\n` no log, e nao uma quebra. Comparar o texto cru deixaria
    passar injecao por quebra de linha -- falso negativo, achado pela mutacao em
    18 de setembro. `literal_eval` desfaz o `repr` e devolve a cadeia original.

    Se nao for um literal Python valido, usa o texto como veio: e melhor
    classificar sobre um valor aproximado do que descartar a evidencia.
    """
    texto = bruto.strip()
    try:
        recuperado = ast.literal_eval(texto)
    except (ValueError, SyntaxError):
        return texto.strip("'\"")
    return recuperado if isinstance(recuperado, str) else texto


def meio_de_acesso(novas: list[str]) -> str | None:
    """Traduz as linhas novas em COMO a execucao foi obtida, ou `None`.

    **A camada de classificacao, separada da evidencia** (D56). As linhas brutas
    ficam no log do Docker; esta funcao as interpreta. Se a regra abaixo se
    mostrar errada, reclassifica-se a partir dos logs guardados, sem refazer a
    coleta.

    A regra, e por que ela precisou existir: o sinal da aplicacao dispara em
    TODA requisicao, porque a aplicacao chama o shell em toda requisicao -- e o
    trabalho normal dela. Verificado ao vivo em 18 de setembro com
    `destino=8.8.8.8`, sem injecao nenhuma: os dois sinais apareceram. Marcar
    comprometimento ali inflaria a metrica 2 **a favor da hipotese**, que e o
    erro que nao se defende em banca.
    """
    da_aplicacao = [m for m in (APLICACAO.match(l) for l in novas) if m]

    # 1. Requisicao cujo valor atravessa para o plano de controle do comando.
    for m in da_aplicacao:
        valor = _valor(m.group(3))
        if any(c in valor for c in CONTROLE):
            return f"injecao de comando em {m.group(1)} (param {m.group(2)})"

    # 2. Shell que a aplicacao nao iniciou: execucao fora do fluxo dela, por
    # qualquer caminho -- inclusive um que ninguem plantou, que e o caso para o
    # qual o sinal abrangente existe.
    if any(l.startswith(SHELL) for l in novas) and not da_aplicacao:
        return "execucao de comando fora do fluxo da aplicacao"

    # 3. Requisicao legitima, ou nada. Nao se afirma execucao obtida.
    return None
