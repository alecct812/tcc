"""`claude -p`: o caminho de desenvolvimento, pela assinatura.

`ARTEFATO.md` §1.4 reserva este caminho para "as milhares de chamadas de
tentativa e erro", com custo marginal zero. Em troca: nao da identificador de
modelo versionado com data, paga spawn de processo Node a cada chamada, e esta
sujeito a limite de sessao no meio de uma execucao longa -- por isso a coleta
final vai pela API (D01).
"""

from __future__ import annotations

import json
import subprocess
import time

from .base import Motor
from .resultado import Resultado, classificar

# O agente executa ferramentas pela propria camada de ferramentas, com parser
# dedicado. O CLI nao pode rodar as dele: saida bruta de ferramenta nunca chega
# ao modelo (`ARTEFATO.md` §1.2), e um `claude -p` com ferramentas habilitadas
# furaria isso pelas costas do grafo.
FERRAMENTAS_PROIBIDAS = "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"


class MotorCLI(Motor):
    nome = "claude-cli"

    # O `claude -p` nao tem saida estruturada: e parametro so da API. Declarar
    # isso e o que faz o registro de cada passo distinguir os dois caminhos em
    # vez de os confundir (D52).
    estrutura_saida = False

    def __init__(self, modelo: str | None, regime: str,
                 formato: dict | None = None):
        super().__init__(modelo, regime, formato)
        # O CLI nao expoe "raciocinio desligado". `--effort low` foi o mais
        # perto disso na medicao de 9 de setembro: 0 tokens de pensamento em
        # 8 de 8 chamadas. Fica registrado como aproximacao, nao equivalencia.
        self.esforco = "low" if regime == "sem-raciocinio" else "high"

    def identificacao(self) -> dict:
        d = super().identificacao()
        d["esforco"] = self.esforco
        return d

    def chamar(self, prompt: str) -> Resultado:
        cmd = ["claude", "-p", "--output-format", "json",
               "--strict-mcp-config",
               "--disallowed-tools", FERRAMENTAS_PROIBIDAS,
               "--effort", self.esforco]
        if self.modelo:
            cmd += ["--model", self.modelo]

        inicio = time.perf_counter()
        proc = subprocess.run(cmd, input=prompt, capture_output=True,
                              text=True, encoding="utf-8")
        decorrido = time.perf_counter() - inicio

        try:
            d = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            texto = (proc.stderr or proc.stdout or "")[:600]
            return Resultado(motor=self.nome, modelo=self.modelo,
                             regime=self.regime, wall_s=round(decorrido, 3),
                             texto=texto,
                             categoria=classificar(texto, marcado_erro=True),
                             erro="sem json no stdout")
        return self._normalizar(d, decorrido)

    def _modelo_que_respondeu(self, d: dict) -> str | None:
        """Qual dos modelos do `modelUsage` de fato respondeu ao prompt.

        O `claude -p` nao traz campo `model` no topo, e o `modelUsage` lista
        **mais de um** modelo: o que respondeu e o auxiliar interno que o
        Claude Code usa para tarefas proprias. Medido em 14 de setembro de
        2026: numa chamada com `--model claude-sonnet-5`, o dicionario trazia
        `claude-haiku-4-5-20251001` (898 tokens de entrada) e `claude-sonnet-5`
        (2 tokens de entrada, 25982 de cache) -- e o `usage` do topo trazia
        exatamente 2 e 25982.

        Dai o criterio: o `usage` do topo descreve a chamada que respondeu,
        entao o modelo e aquele cuja entrada casa com ele. Pegar a primeira
        chave, como a versao anterior fazia, depende da ordem do dicionario e
        registrava o auxiliar -- num experimento cujo requisito e "mesmo
        modelo nos dois bracos", isso invalidaria a comparacao sem dar sinal.
        """
        por_modelo = d.get("modelUsage") or {}
        if d.get("model"):
            return d["model"]
        if not por_modelo:
            return self.modelo
        if len(por_modelo) == 1:
            return next(iter(por_modelo))

        uso = d.get("usage") or {}
        alvo = (uso.get("input_tokens"), uso.get("cache_read_input_tokens"))
        for nome, u in por_modelo.items():
            if (u.get("inputTokens"), u.get("cacheReadInputTokens")) == alvo:
                return nome

        # Nenhum casou. Nao inventa: deixa a ambiguidade visivel no log, que e
        # melhor do que um identificador errado com cara de certo.
        return "indeterminado:" + "|".join(sorted(por_modelo))

    def _normalizar(self, d: dict, decorrido: float) -> Resultado:
        uso = d.get("usage") or {}
        det = uso.get("output_tokens_details") or {}
        texto = str(d.get("result") or "")

        return Resultado(
            motor=self.nome,
            # O identificador vem da resposta, nao do que foi pedido.
            modelo=self._modelo_que_respondeu(d),
            regime=self.regime,
            wall_s=round(decorrido, 3),
            cli_ms=d.get("duration_ms"),
            api_ms=d.get("duration_api_ms"),
            entrada_tokens=uso.get("input_tokens"),
            cache_criado=uso.get("cache_creation_input_tokens"),
            cache_lido=uso.get("cache_read_input_tokens"),
            saida_tokens=uso.get("output_tokens"),
            pensamento_tokens=det.get("thinking_tokens"),
            texto=texto,
            motivo_de_parada=d.get("stop_reason"),
            # D180, pela mesma razao da API: uso reportado prova que um modelo
            # gerou o texto. **E aqui o parametro tem consequencia maior**, pois
            # o limite de sessao do `claude -p` chega como TEXTO, e nao como
            # codigo HTTP -- entao a resposta sem uso continua sendo o caso que
            # `PADRAO_LIMITE` existe para pegar, e ele segue pego.
            categoria=classificar(texto, marcado_erro=bool(d.get("is_error")),
                                  motivo_de_parada=d.get("stop_reason"),
                                  com_uso=bool(uso.get("input_tokens")
                                               or uso.get("output_tokens"))),
            custo_usd=d.get("total_cost_usd"),
        )
