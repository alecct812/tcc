"""A acao que o modelo propos, lida da resposta dele.

Fronteira entre o que o modelo escreveu e o que a camada de ferramentas
executa. Duas traducoes acontecem aqui, e as duas tem armadilha:

1. **`alvo` vem como `hNN`** -- identificador que nasce na serializacao. O mapa
   de volta vem da MESMA funcao que os gera; duplicar a ordenacao aqui faria os
   dois discordarem no dia em que um host novo entrasse, sem dar sinal.
2. **`comando` vem como texto** e o executor precisa de lista. `shlex.split`
   resolve, e nenhum shell entra no caminho.

**O que aqui NAO invalida uma proposta: alvo que nao existe.** O comando roda,
falha, e a falha e o dado que a metrica 6 e `docs/hipotese.md` §E1 contam.
Recusar aqui apagaria o fenomeno que o experimento existe para medir.
"""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field, fields

from .prompt import FERRAMENTAS

# O primeiro objeto JSON equilibrado do texto. O `claude -p` nao tem saida
# estruturada (D52), entao cerca de markdown e prosa em volta acontecem.
ABRE = re.compile(r"\{")


# `ls` e TODOS os seus argumentos, flags e caminhos em qualquer ordem. As
# ancoras de palavra impedem que `lsof`, `lsblk` ou `lsattr` sejam confundidos
# com `ls`. A lista para no primeiro pedaco que nao e flag nem caminho -- e
# assim `2>&1`, `;` e `|` ficam de fora sem precisar serem nomeados.
ARGUMENTO = r"-\S+|/[^\s'\";&|]*"
LISTAGEM = re.compile(rf"\bls\b((?:\s+(?:{ARGUMENTO}))+)")
CAMINHO_ARGUMENTO = re.compile(r"(?<=\s)/[^\s'\";&|]*")


def diretorio_listado(comando: str | None) -> str | None:
    """Qual diretorio o comando mandou listar, se mandou exatamente um.

    Os nomes de uma listagem sao RELATIVOS. A base tem de vir do comando que
    NOS enviamos -- e nao de adivinhacao sobre a saida --, e por isso mora aqui,
    do lado de quem monta a acao.

    **Decodifica a URL antes de procurar**: a injecao chega com `ls%20-la%20/opt`
    dentro da URL, e sem decodificar o comando fica escondido atras dos `%20`.

    Devolve `None` em dois casos, e os dois sao o mesmo problema:

    - **mais de um `ls`** no comando;
    - **um `ls` com mais de um diretorio**, como `ls -la /root /home /opt`.

    Nos dois, varias listagens se misturam na mesma saida, e resolver tudo pela
    primeira base gravaria `/root/diagnostico` no lugar de `/opt/diagnostico` --
    um arquivo que nao existe. Fato falso no grafo e exatamente o que este
    parser existe para nao produzir.

    **`None` aqui nao quer dizer listagem perdida.** O `ls` com varios
    diretorios imprime um cabecalho por bloco (`/opt:`), e `analisar_saida` usa
    ESSE cabecalho como base (D59) -- ali a base nao e adivinhada, e declarada
    pela propria saida. A divisao e de responsabilidade: esta funcao so afirma
    base quando o COMANDO a determina sem ambiguidade; o resto quem resolve e
    quem le a saida.
    """
    if not comando:
        return None
    texto = urllib.parse.unquote(comando)
    achados = LISTAGEM.findall(texto)
    if len(achados) != 1:
        return None
    caminhos = CAMINHO_ARGUMENTO.findall(achados[0])
    if len(caminhos) != 1:
        return None
    return caminhos[0]


@dataclass
class Proposta:
    """Uma acao proposta, valida ou nao. Proposta invalida tambem e registro."""

    alvo: str | None = None
    endereco: str | None = None
    ferramenta: str | None = None
    comando: str | None = None
    pivo: str | None = None
    endereco_pivo: str | None = None
    justificativa: str | None = None
    # O texto cru da resposta, guardado para o registro do passo. Nao vai para
    # o grafo nem volta ao modelo.
    bruta: str = ""
    valida: bool = False
    motivo: str | None = None

    def como_dicionario(self) -> dict:
        return {"alvo": self.alvo, "endereco": self.endereco,
                "ferramenta": self.ferramenta, "comando": self.comando,
                "pivo": self.pivo, "endereco_pivo": self.endereco_pivo,
                "justificativa": self.justificativa, "valida": self.valida,
                "motivo": self.motivo, "bruta": self.bruta}

    @classmethod
    def de_dicionario(cls, d: dict) -> "Proposta":
        """Le de volta do disco, ignorando o que nao e campo da proposta.

        O arquivo em disco guarda tambem os contadores da chamada ao modelo,
        sob `_resultado`, para que o registro do passo sobreviva a morte do
        processo entre propor e executar. Filtrar aqui e o que permite juntar as
        duas coisas num arquivo so sem que a leitura quebre.
        """
        campos = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in campos})


def _primeiro_objeto(texto: str) -> dict | None:
    """Extrai o primeiro objeto JSON equilibrado do texto.

    Conta chaves em vez de casar expressao regular: o `comando` pode conter
    chaves (uma carga de injecao, por exemplo), e uma expressao gulosa ou
    preguicosa erraria o fechamento nos dois sentidos.
    """
    for inicio in (m.start() for m in ABRE.finditer(texto)):
        profundidade, dentro_de_aspas, escapado = 0, False, False
        for i in range(inicio, len(texto)):
            c = texto[i]
            if escapado:
                escapado = False
                continue
            if c == "\\":
                escapado = True
                continue
            if c == '"':
                dentro_de_aspas = not dentro_de_aspas
                continue
            if dentro_de_aspas:
                continue
            if c == "{":
                profundidade += 1
            elif c == "}":
                profundidade -= 1
                if profundidade == 0:
                    try:
                        d = json.loads(texto[inicio:i + 1])
                    except (json.JSONDecodeError, ValueError):
                        break
                    if isinstance(d, dict):
                        return d
                    break
    return None


def ler_proposta(texto: str, mapa: dict[str, str]) -> Proposta:
    """Le a resposta do modelo. `mapa` leva `hNN` a endereco."""
    p = Proposta(bruta=texto)
    d = _primeiro_objeto(texto or "")
    if d is None:
        # Sem JSON nao ha acao. Nada e inventado: `None` continua `None`, e o
        # passo sera contado como malformado (D52).
        p.motivo = "resposta sem json"
        return p

    for campo in ("alvo", "ferramenta", "comando", "justificativa"):
        valor = d.get(campo)
        if not isinstance(valor, str) or not valor.strip():
            p.motivo = f"falta o campo {campo}"
            return p

    ferramenta = str(d["ferramenta"]).strip().lower()
    if ferramenta not in FERRAMENTAS:
        p.motivo = f"ferramenta desconhecida: {ferramenta}"
        return p

    comando = str(d["comando"]).strip()
    # O comando tem de se separar em argumentos. Nenhum shell entra no caminho
    # (ver o cabecalho deste modulo), entao `shlex.split` e o unico tradutor, e
    # uma aspa sem fechamento faz ele levantar.
    #
    # Isto aconteceu de verdade: no passo 23 da `dmz-04` o modelo escreveu
    # `curl "http://...%22` -- codificou a propria aspa de FECHAMENTO como
    # `%22` -- e o `ValueError` subiu do `executar` e MATOU o processo. Em modo
    # assistido da para retomar do disco; em modo autonomo, na segunda 21, uma
    # execucao inteira morreria por causa de um passo.
    #
    # Vira proposta invalida, e nao excecao: o passo foi gasto e nao produziu
    # acao, que e o mesmo tratamento da recusa (`ARTEFATO.md` §4.3) e o que a
    # metrica 6 existe para contar.
    try:
        shlex.split(comando)
    except ValueError as e:
        p.motivo = f"comando nao se separa em argumentos: {e}"
        return p

    p.alvo = str(d["alvo"]).strip()
    # Alvo fora do mapa deixa o endereco em `None` -- nao inventa. Quem executa
    # decide o que fazer com isso; a proposta segue valida de proposito.
    p.endereco = mapa.get(p.alvo)
    p.ferramenta = ferramenta
    p.comando = comando
    p.justificativa = str(d["justificativa"]).strip()
    pivo = d.get("pivo")
    if isinstance(pivo, str) and pivo.strip():
        p.pivo = pivo.strip()
        p.endereco_pivo = mapa.get(p.pivo)
    p.valida = True
    return p
