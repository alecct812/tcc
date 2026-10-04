"""Fecha o aceite da sprint com chamadas REAIS, uma por provedor.

`testes.py` não chama nada e roda de graça; este arquivo chama de verdade e
existe por causa da lição de `docs/motor.md` §10: os três defeitos do adaptador
do Gemini — modelo aposentado com 404, `thinkingBudget: 0` rejeitado com 400,
resposta cortada no teto — **só apareceram na primeira chamada real**, e nenhum
teste sintético os pegaria.

Custo: uma chamada por provedor, prompt de poucos tokens. O `claude -p` sai pela
assinatura, custo marginal zero. A da API custa frações de centavo.

Uso:  python verificar.py
"""

from __future__ import annotations

import os
import sys

from modelo import criar_motor

PROMPT = "Responda apenas com a palavra: pronto"
MODELO = "claude-sonnet-5"

falhas: list[str] = []


def relatar(rotulo: str, r) -> None:
    print(f"\n--- {rotulo}")
    print(f"  categoria ....... {r.categoria}")
    if r.categoria_recusa:
        print(f"  categoria_recusa  {r.categoria_recusa}")
    print(f"  modelo .......... {r.modelo}")
    print(f"  regime .......... {r.regime}")
    print(f"  motivo_de_parada  {r.motivo_de_parada}")
    print(f"  texto ........... {r.texto[:60]!r}")
    print(f"  wall_s .......... {r.wall_s}   api_ms: {r.api_ms}")
    print(f"  entrada_tokens .. {r.entrada_tokens}   saida: {r.saida_tokens}")
    print(f"  pensamento ...... {r.pensamento_tokens}")
    if r.erro:
        print(f"  erro ............ {r.erro}")

    if r.categoria != "aceita":
        falhas.append(f"{rotulo}: categoria {r.categoria} ({r.erro or 'sem erro'})")
    # O modelo que responde tem de ser o pedido. Se divergir, o log do
    # experimento nomearia o modelo errado e `ARTEFATO.md` §4.1 ("mesmo modelo
    # nos dois braços") ficaria impossível de conferir.
    if r.modelo != MODELO:
        falhas.append(f"{rotulo}: respondeu {r.modelo}, esperado {MODELO}")


print("=" * 66)
print("ACEITE DA SPRINT: uma chamada de teste passa pelos dois provedores")
print("=" * 66)

# --- provedor 1: assinatura, custo zero
relatar("claude -p (assinatura)",
        criar_motor("cli", MODELO, "sem-raciocinio").chamar(PROMPT))

# --- provedor 2: API, precisa de crédito
if not os.environ.get("ANTHROPIC_API_KEY"):
    print("\n--- API da Anthropic")
    print("  PENDENTE: ANTHROPIC_API_KEY ausente no ambiente.")
    print("  Defina a variável e rode de novo. Não passe a chave por argumento.")
    falhas.append("API da Anthropic: não verificada (sem chave)")
else:
    relatar("API da Anthropic (sem-raciocinio)",
            criar_motor("anthropic", MODELO, "sem-raciocinio").chamar(PROMPT))
    # O segundo regime vai junto porque é onde moravam os dois defeitos de
    # formato achados em 14 de setembro (D19): o `budget_tokens` rejeitado com
    # 400 e o raciocínio que não desligava por omissão. Verificar só um regime
    # deixaria metade do adaptador sem prova.
    relatar("API da Anthropic (raciocinio)",
            criar_motor("anthropic", MODELO, "raciocinio").chamar(PROMPT))

print()
print("=" * 66)
if falhas:
    print(f"{len(falhas)} PENDÊNCIA(S) OU FALHA(S):")
    for f in falhas:
        print("  -", f)
    sys.exit(1)
print("ACEITE FECHADO: os dois provedores responderam, com o modelo pedido.")
