#!/usr/bin/env bash
# Roda um grupo de faixas de mutacao dentro de um worktree isolado.
# Uso: rodar_grupo.sh <dir-do-worktree> <rodada> <INICIO FIM INICIO FIM ...>
#
# ⚠️ **SILENCIO NAO E SUCESSO** (D209). Ate 30 de setembro este script canalizava
# a saida do arnes por `grep -E "^(morreu|SOBREVIVEU)"` e mais nada. Grupo que
# morria -- por arvore suja, por erro de importacao, por qualquer coisa --
# produzia arquivo VAZIO, indistinguivel de "nada a relatar". Aconteceu: na
# bateria de 15:02 os grupos 2 e 3 devolveram zero resultado e o arnes somou
# 140 de 481 sem ninguem notar, enquanto o resumo final comparava as duas
# rodadas como se estivessem completas.
#
# Agora cada faixa confere se o numero de resultados casa com o numero de
# mutacoes pedidas, e grita a saida crua quando nao casa.
set -u
WT="$1"; shift
RODADA="$1"; shift
cd "$WT/src/artefato" || { echo "ERRO nao entrei em $WT"; exit 2; }
find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null

BRUTO="$(mktemp)"
trap 'rm -f "$BRUTO"' EXIT

while [ "$#" -ge 2 ]; do
  A="$1"; B="$2"; shift 2
  PYTHONDONTWRITEBYTECODE=1 python -B mutacoes.py "$A" "$B" > "$BRUTO" 2>&1
  CODIGO=$?
  grep -E "^(morreu|SOBREVIVEU)" "$BRUTO"
  VISTOS=$(grep -cE "^(morreu|SOBREVIVEU)" "$BRUTO")
  PEDIDAS=$((B - A))
  if [ "$VISTOS" -ne "$PEDIDAS" ]; then
    echo "ERRO faixa $A..$B em $WT: $VISTOS de $PEDIDAS resultados (codigo $CODIGO)"
    tail -20 "$BRUTO" | sed 's/^/ERRO   /'
  fi
done
echo "FIM rodada $RODADA em $WT"
