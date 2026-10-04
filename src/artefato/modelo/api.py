"""API da Anthropic: o caminho da coleta.

Ao contrario do CLI, da identificador de modelo versionado com data -- que vai
para o relatorio -- e nao esta sujeito a limite de sessao. Em troca, custa
credito: cerca de US$ 6 para as 600 chamadas do piso teorico de `ARTEFATO.md`
§4.3/§4.4.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from .base import Motor
from .resultado import Resultado, classificar

VERSAO_API = "2023-06-01"

# Teto por resposta, nao alvo: so se paga o que for gerado, entao um teto folgado
# nao custa nada e um teto apertado corta a resposta no meio e obriga a repetir.
# 2048 era o valor inicial e e arriscado no regime `raciocinio`, onde os tokens
# de pensamento contam para o mesmo teto. 16000 e o padrao recomendado pela
# referencia da API para requisicao sem streaming.
TETO_SAIDA = 16000


class MotorHTTP(Motor):
    """Base dos provedores que falam HTTP.

    A politica de retentativa vive aqui, e ela e a razao de este projeto nao
    usar uma biblioteca generica de provedores (D16 em
    `docs/decisoes-tecnicas.md`).
    """

    # Recuos em segundos. Se todos se esgotarem, para: throttle que nao cede
    # depois de ~10 min de espera nao e rajada, e cota acabada.
    RECUOS = (5, 15, 45, 120, 300)

    def montar(self, prompt: str) -> tuple[str, dict, dict]:
        raise NotImplementedError

    def _normalizar(self, d: dict, decorrido: float) -> Resultado:
        raise NotImplementedError

    def chamar(self, prompt: str) -> Resultado:
        """Uma chamada, com nova tentativa APENAS em throttle de transporte.

        A distincao precisa ficar explicita porque as duas coisas parecem a
        mesma e nao sao. Repetir uma **recusa** mascara o que se quer contar:
        a recusa e decisao do modelo sobre este prompt, e retentar apaga o
        dado -- que e metrica reportada do trabalho (`docs/hipotese.md` §E2,
        §E7, §E8). Repetir um **429** nao mascara nada: a requisicao foi
        barrada no transporte e nunca chegou ao modelo, entao nao ha decisao
        para apagar.

        Contar 429 como recusa mediria a cota da conta e chamaria isso de
        salvaguarda -- erro ja cometido em 9 de setembro de 2026, quando 13
        limites de sessao teriam inflado a taxa de 23,5% para 56,7%.
        """
        espera_total = 0.0
        for tentativa, recuo in enumerate((*self.RECUOS, None)):
            r = self._uma_chamada(prompt)
            r.throttles = tentativa
            r.espera_throttle_s = round(espera_total, 1)

            if r.categoria != "throttle":
                return r
            if recuo is None:
                # D174. QUAL DOS DOIS nao cedeu decide o que se afirma.
                #
                # Para 429, "nao cede depois de ~10 min" e mesmo cota da conta.
                # **Para 503 nao e**: 503 e o provedor indisponivel, e chamar
                # isso de `limite_de_uso` grava no registro que a cota do autor
                # acabou quando a API e que estava fora -- fato falso, e que
                # aponta para a acao errada (comprar credito em vez de
                # esperar). Flagrado ao vivo em 29 de setembro: tres passos
                # seguidos assim, e a sonda devolveu 503 de corpo vazio, com
                # `server: cloudflare` e SEM `request-id` -- a requisicao nem
                # chegou a API.
                r.categoria = ("limite_de_uso" if r.http_status == 429
                               else f"erro_http_{r.http_status or 503}")
                r.erro = (f"{r.erro or 'throttle'} persistente apos {tentativa} "
                          f"novas tentativas e {espera_total:.0f}s de espera")
                return r

            # Avisa: o recuo pode segurar a execucao por minutos antes de
            # qualquer coisa ser gravada, e silencio nesse intervalo e
            # indistinguivel de processo travado.
            print(f"    {r.erro or 'throttle'} — aguardando {recuo}s "
                  f"(espera acumulada {espera_total:.0f}s)",
                  file=sys.stderr, flush=True)
            if recuo:
                time.sleep(recuo)
            espera_total += recuo
        raise AssertionError("inalcancavel")

    def _uma_chamada(self, prompt: str) -> Resultado:
        url, corpo, cabecalhos = self.montar(prompt)
        req = urllib.request.Request(
            url, data=json.dumps(corpo).encode("utf-8"), headers=cabecalhos)

        inicio = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                d = json.loads(r.read())
        except urllib.error.HTTPError as e:
            decorrido = time.perf_counter() - inicio
            texto = e.read().decode("utf-8", "replace")[:600]
            # Nenhum erro HTTP e recusa do modelo: um 404 de modelo aposentado
            # ou um 400 de corpo malformado nao chegou a ser julgado por
            # ninguem. 429 e barreira de ritmo e 503 e sobrecarga passageira;
            # os dois barram a requisicao antes do modelo e cedem com espera.
            if e.code in (429, 503):
                cat = "throttle"
            else:
                cat = classificar(texto)
                if cat == "aceita":
                    cat = f"erro_http_{e.code}"
            return Resultado(motor=self.nome, modelo=self.modelo,
                             regime=self.regime, wall_s=round(decorrido, 3),
                             texto=texto, categoria=cat, erro=f"HTTP {e.code}",
                             http_status=e.code)
        except (urllib.error.URLError, TimeoutError) as e:
            decorrido = time.perf_counter() - inicio
            return Resultado(motor=self.nome, modelo=self.modelo,
                             regime=self.regime, wall_s=round(decorrido, 3),
                             texto=str(e)[:600], categoria="erro_de_rede",
                             erro=str(e)[:200])
        return self._normalizar(d, time.perf_counter() - inicio)


class MotorAnthropic(MotorHTTP):
    nome = "anthropic"
    estrutura_saida = True

    def __init__(self, modelo: str | None, regime: str,
                 chave: str | None = None, formato: dict | None = None):
        super().__init__(modelo, regime, formato)
        # A chave vem do ambiente por padrao. Nunca de argumento de linha de
        # comando nem de arquivo versionado (regra em `CLAUDE.md`). O
        # parametro existe para o teste poder injetar uma chave falsa sem
        # tocar no ambiente da maquina.
        self.chave = chave or os.environ.get("ANTHROPIC_API_KEY")

    def identificacao(self) -> dict:
        d = super().identificacao()
        d["versao_api"] = VERSAO_API
        return d

    def montar(self, prompt: str) -> tuple[str, dict, dict]:
        if not self.chave:
            raise RuntimeError(
                "ANTHROPIC_API_KEY ausente no ambiente. Defina a variavel; "
                "nao passe a chave por argumento.")
        corpo = {
            "model": self.modelo,
            "max_tokens": TETO_SAIDA,
            "messages": [{"role": "user", "content": prompt}],
            # O regime vai SEMPRE explicito, nos dois valores. Omitir `thinking`
            # em `claude-sonnet-5` nao desliga nada: roda adaptativo. Um
            # `sem-raciocinio` implementado por omissao estaria pensando calado,
            # e o controle que D02 existe para garantir sumiria sem sinal.
            "thinking": ({"type": "adaptive"} if self.regime == "raciocinio"
                         else {"type": "disabled"}),
            # Mesmo esforco que o `MotorCLI` traduz em `--effort`. Sem isto a
            # API cairia no padrao `high` e os dois provedores mediriam coisas
            # diferentes sob o mesmo rotulo de regime, estragando a comparacao
            # CLI contra API que `docs/motor.md` §10 planeja fazer.
            "output_config": {
                "effort": "high" if self.regime == "raciocinio" else "low"},
        }
        if self.formato:
            # Saida estruturada (D52). Nao ajuda o modelo a decidir: garante o
            # TRANSPORTE da decisao. Qual alvo, qual ferramenta e qual comando
            # continuam dele, e §E1 -- que conta endereco inventado -- fica
            # intacto, porque um JSON de forma garantida ainda pode nomear um
            # host que nao existe.
            corpo["output_config"]["format"] = self.formato
        # Sem parametro de amostragem: os modelos Claude atuais removeram
        # `temperature`, `top_p` e `top_k` da API e envia-los devolve 400 (D02).
        # O determinismo e controlado pelo regime de raciocinio, acima.

        cabecalhos = {
            "content-type": "application/json",
            "x-api-key": self.chave,
            "anthropic-version": VERSAO_API,
        }
        return "https://api.anthropic.com/v1/messages", corpo, cabecalhos

    def _normalizar(self, d: dict, decorrido: float) -> Resultado:
        uso = d.get("usage") or {}
        blocos = d.get("content") or []
        texto = "".join(b.get("text", "") for b in blocos
                        if b.get("type") == "text")
        parada = d.get("stop_reason")
        # O numero de tokens de pensamento vem do `usage`, nunca do conteudo.
        # No Sonnet 5 o padrao de `thinking.display` e "omitted", entao os blocos
        # de raciocinio chegam com texto VAZIO mesmo quando houve raciocinio --
        # medir pelo conteudo devolveria None ("nao informado") numa chamada em
        # que a API informou. O campo tem o mesmo nome no CLI, o que torna os
        # dois provedores diretamente comparaveis.
        det = (d.get("usage") or {}).get("output_tokens_details") or {}

        # A API sinaliza recusa de forma estruturada, e o sinal manda sobre o
        # regex: `stop_reason == "refusal"` com `stop_details.category`. Inferir
        # recusa pela redacao do texto e aproximacao que ja errou neste projeto
        # (uma recusa acentuada do gemini caiu em `formato_invalido` em 10 de
        # setembro). O campo `stop_details` so vem preenchido nesse caso, entao
        # e preciso conferir antes de ler.
        if parada == "refusal":
            detalhes = d.get("stop_details") or {}
            return Resultado(
                motor=self.nome, modelo=d.get("model") or self.modelo,
                regime=self.regime, wall_s=round(decorrido, 3),
                entrada_tokens=uso.get("input_tokens"),
                saida_tokens=uso.get("output_tokens"),
                texto=texto, motivo_de_parada=parada, categoria="recusa",
                categoria_recusa=detalhes.get("category"),
                explicacao_recusa=detalhes.get("explanation"))

        return Resultado(
            motor=self.nome,
            # Do que respondeu, nao do que foi pedido.
            modelo=d.get("model") or self.modelo,
            regime=self.regime,
            wall_s=round(decorrido, 3),
            entrada_tokens=uso.get("input_tokens"),
            cache_criado=uso.get("cache_creation_input_tokens"),
            cache_lido=uso.get("cache_read_input_tokens"),
            saida_tokens=uso.get("output_tokens"),
            pensamento_tokens=det.get("thinking_tokens"),
            texto=texto,
            motivo_de_parada=parada,
            # D180. O uso reportado prova que um modelo gerou este texto, entao
            # `PADRAO_LIMITE` nao se aplica a ele. Sem isso, o agente falando
            # do rate limit do ALVO virava limite de conta do PROVEDOR -- e o
            # passo saia do denominador das metricas 6 e 10.
            categoria=classificar(texto, motivo_de_parada=parada,
                                  com_uso=bool(uso.get("input_tokens")
                                               or uso.get("output_tokens"))),
        )
