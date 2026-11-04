# Medição de motores e da taxa de recusa

Estes são os arquivos que sustentam o Apêndice B do relatório, mais o necessário para reproduzi-los
(`medir.py`, `motores.py` e o prompt canônico `prompt-teste.txt`). As demais medições do
desenvolvimento ficam no histórico local, disponível aos avaliadores mediante pedido. O texto que
interpreta os números é [`../motor.md`](../motor.md).

Cada número da tabela foi **recalculado a partir dos arquivos**, somando as células ou os registros,
e não copiado do campo de resumo que o arquivo traz. Os links são relativos a esta pasta, exceto os de
`execucoes/`, que está na raiz do repositório.

## A coluna "suporte"

| valor | significado |
|---|---|
| **dados** | o número sai de um arquivo publicado e foi reproduzido |
| **parcial** | parte do número sai de um arquivo publicado; o resto está só em descrição no `docs/motor.md` |
| **só descrição no `docs/motor.md`** | o número existe apenas em prosa em [`../motor.md`](../motor.md); não há dado bruto no repositório |

## A tabela do Apêndice B

| Data | Modelo | Caminho | Número | Suporte | Arquivo(s) |
|---|---|---|---|---|---|
| 8 e 9 set | Claude Opus 5 | Claude Code | 42 e 16 chamadas, 11 e 1 recusas | **dados** | [`historico/taxa-recusa.json`](historico/taxa-recusa.json) e [`historico/taxa-recusa-2.json`](historico/taxa-recusa-2.json) (42 e 11); [`historico/decomposicao-latencia.json`](historico/decomposicao-latencia.json), variante `completa` (16 e 1). Ver a ressalva 1 |
| 9 set | Claude Sonnet 5 | Claude Code | 30 chamadas, 0 recusas | **dados** | [`resultados/claude-cli-matriz.json`](resultados/claude-cli-matriz.json) |
| 9 set | Claude Haiku 4.5 | Claude Code | 4 chamadas, 6 a 11 vezes mais lento | **só descrição no `docs/motor.md`** | Seção "Nota: o modelo mais barato não foi o mais rápido" de [`../motor.md`](../motor.md). Os tempos do Sonnet 5 usados na razão (5,64, 10,30, 4,70 e 11,93 s) saem de [`resultados/claude-cli-matriz.json`](resultados/claude-cli-matriz.json); os do Haiku (62,19, 62,02, 30,99 e 94,24 s) não têm arquivo |
| 9 set | Kimi K3 | NVIDIA, gratuita | 4 chamadas, 0 recusas, cota esgotada (~35) | **parcial** | [`resultados/nvidia-sondas-iniciais.json`](resultados/nvidia-sondas-iniciais.json) cobre 2 das 4 chamadas (3,864 s e 4,093 s), 0 recusas, e o aborto por limite na chamada 3. As outras 2 ("sondas isoladas", 5,22 s e 7,91 s) e o "~35" estão só em [`../motor.md`](../motor.md) |
| 10 set | Gemini 3.6 Flash | Google, gratuita | 12 chamadas, 6 recusas (4 de 4 com inventário completo) | **dados** | [`resultados/gemini-matriz.json`](resultados/gemini-matriz.json): 13 chamadas, 1 de limite de uso fora do denominador, 12 julgadas, 6 recusas; as duas células `completa` somam 4 de 4 |
| 22 set | Claude Sonnet 5 | Claude Code | 15 chamadas, 11 recusas | **dados** | [`resultados/2026-09-22-claude-cli-prompt-velho.json`](resultados/2026-09-22-claude-cli-prompt-velho.json). Ver a ressalva 2 |
| 22 set | Claude Sonnet 5 | API Anthropic | 30 chamadas, 0 recusas | **dados** | [`resultados/2026-09-22-anthropic-prompt-velho.json`](resultados/2026-09-22-anthropic-prompt-velho.json) |
| 24 set | Claude Sonnet 5 | API, antes do CVP | diag-05: 68 de 90 passos recusados | **dados** | [`../../execucoes/diag-05/passos.jsonl`](../../execucoes/diag-05/passos.jsonl) (90 registros, 68 com `recusa: cyber`) e [`../../execucoes/diag-05/estado.json`](../../execucoes/diag-05/estado.json) (`recusas: 68`). O campo `proposito` de [`resultados/2026-09-24-ab-recusa-diag05.json`](resultados/2026-09-24-ab-recusa-diag05.json) cita a mesma taxa como 76% (68/90 = 75,6%) |
| 24 set | Claude Sonnet 5 | API, antes/depois | 5/5 contra 0/5 recusas, Fisher bicaudal p = 0,0079 | **dados** | [`resultados/2026-09-24-ab-recusa-diag05.json`](resultados/2026-09-24-ab-recusa-diag05.json) (braço `B-diag05`: 5 recusas em 5) e [`resultados/2026-09-24-ab-recusa-diag05-depois-do-cvp.json`](resultados/2026-09-24-ab-recusa-diag05-depois-do-cvp.json) (mesmo braço: 0 em 5). O p é a probabilidade exata 2/252, recalculada |
| 2 e 3 out | Claude Sonnet 5 | API Anthropic | coleta: 1.600 chamadas de decisão, 0 recusas | **dados** | `execucoes/coleta-A-01` a `coleta-B-10`, `passos.jsonl`: 20 pastas de 80 registros, todos com categoria `aceita`; o `estado.json` de cada uma traz `recusas: 0`. A tabela gerada está em [`../resultados/coleta.md`](../resultados/coleta.md) |

**CVP** é o Cyber Verification Program. A organização do Console da API foi aprovada nele antes do
reteste de 24 de setembro, e o segundo arquivo da penúltima linha repete o teste depois da aprovação,
com o mesmo grafo, o mesmo prompt byte a byte, o mesmo modelo e o mesmo regime.

## Duas ressalvas de contagem

**1. Opus 5: as 13 respostas de limite de sessão ficam fora do 42 e do 11.**
O arquivo `historico/taxa-recusa.json` tem 30 registros, e o resumo dele diz `recusadas: 17` e
`taxa_observada: 0.5667`. Esse resumo conta como recusa 13 respostas com o texto *"You've hit your
session limit"*, que são o limite de uso do plano e não a salvaguarda. Dos 30 registros, 13 têm
categoria `sem_categoria` (o limite de sessão) e 17 são chamadas válidas, das quais 4 foram recusadas
com categoria `cyber`. Somadas as 25 chamadas válidas de `taxa-recusa-2.json` (7 recusadas), saem
**42 chamadas e 11 recusas**. O arquivo não foi alterado, e quem ler só o campo de resumo obtém
56,7%, que não é a taxa de recusa.

**2. 22 de setembro, Claude Code: as 15 chamadas são só as do regime com raciocínio, de um total de 30.**
O arquivo `2026-09-22-claude-cli-prompt-velho.json` tem 30 chamadas em seis células de 5. As 15 da
tabela são as três células `/raciocinio` (`completa`, `minima` e `sem-comando`), que somam
**11 recusas** (4, 4 e 3). As três células `/sem-raciocinio` têm 0 recusas em 15, e todas as 11
recusas do arquivo estão no subconjunto com raciocínio. É o mesmo regime em que a coleta roda.
