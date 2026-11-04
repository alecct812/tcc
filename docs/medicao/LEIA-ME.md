# Medição de motores e da taxa de recusa

Estes são os arquivos que sustentam o Apêndice B do relatório, mais o necessário para reproduzi-los
(`medir.py`, `motores.py` e os dois arquivos de prompt). As demais medições do desenvolvimento ficam
no histórico local, disponível aos avaliadores mediante pedido. O texto que interpreta os números é
[`../motor.md`](../motor.md).

Cada número da tabela foi **recalculado a partir dos arquivos**, somando as células ou os registros,
e não copiado do campo de resumo que o arquivo traz. Os links são relativos a esta pasta, exceto os de
`execucoes/`, que está na raiz do repositório.

## Os dois prompts, e qual deles mediu o quê

| Arquivo | Caracteres | SHA-256 com fim de linha CRLF | SHA-256 com fim de linha LF |
|---|---|---|---|
| [`prompt-teste-2026-09-10.txt`](prompt-teste-2026-09-10.txt) | 5.743 | `e1cfcbda5ebf4e22d4d28fb1d4707a23eca3f85f4fe0ea49f850e7b86dce8121` | `278ee2f9d01518c0a42154def0dd2f8cb13ea0d7b9a87fd65c967786ab597e5b` |
| [`prompt-teste.txt`](prompt-teste.txt) | 6.698 | `f8ba6b1304d2875cba3a8e914496fd9155c024bc49e464b9547b71a74850417a` | `5362da9b037380a36653bd00c0533bbf2cfb80d29c871c02e1626854115e8fbb` |

**O `prompt-teste.txt` atual (6.698 caracteres) não foi usado em nenhuma das medições do Apêndice B**:
é uma revisão de 27 de setembro de 2026, posterior a todas elas, e os hashes e tamanhos que os
arquivos de resultado registram a excluem. O prompt que as mediu é o de 10 de setembro.

**Sobre o fim de linha.** As medições registraram o SHA-256 do arquivo como estava no disco, que era
CRLF (Windows). Este repositório trava LF (`.gitattributes`), então quem o clonar terá os arquivos
com LF, e o hash do mesmo texto passa a ser o da última coluna. Para conferir o registrado contra o
arquivo publicado, normalize antes de calcular:

```python
import hashlib, pathlib
b = pathlib.Path("prompt-teste-2026-09-10.txt").read_bytes().replace(b"\r\n", b"\n")
print(hashlib.sha256(b.replace(b"\n", b"\r\n")).hexdigest())   # e1cfcbda5ebf...
```

## As colunas "suporte" e "prompt"

| suporte | significado |
|---|---|
| **dados** | o número sai de um arquivo publicado e foi reproduzido |
| **parcial** | parte do número sai de um arquivo publicado; o resto está só em descrição no `docs/motor.md` |
| **só descrição no `docs/motor.md`** | o número existe apenas em prosa em [`../motor.md`](../motor.md); não há dado bruto no repositório |

| prompt | significado |
|---|---|
| **hash registrado e confere** | o arquivo de resultado registra o SHA-256 do prompt, e ele bate com um dos dois arquivos desta pasta (com CRLF, ver acima) |
| **tamanho registrado confere, sem hash** | o arquivo registra só o número de caracteres, que é o do prompt de 10 de setembro e exclui o atual; não registra hash nem o nome do arquivo |
| **nada registrado** | o arquivo não registra nada sobre o prompt |
| **prompt do agente, não é nenhum dos dois** | a medição usa o prompt real do agente com o grafo da execução, e não um dos dois arquivos de prompt |

## A tabela do Apêndice B

| Data | Modelo | Caminho | Número | Suporte | Prompt | Arquivo(s) |
|---|---|---|---|---|---|---|
| 8 e 9 set | Claude Opus 5 | Claude Code | 42 e 16 chamadas, 11 e 1 recusas | **dados** | **42 e 11: nada registrado.** O texto pode ser o de 5.741 caracteres (registrado em 8 de setembro, no histórico local) ou o de 5.743. **16 e 1: tamanho registrado confere, sem hash.** O registrado (5.742, 1.554 e 5.788 nas três variantes) é 1 caractere menor que o que `motores.derivar()` dá sobre o prompt de 10 de setembro (5.743, 1.555 e 5.789) em cada variante; a causa não foi determinada | [`historico/taxa-recusa.json`](historico/taxa-recusa.json) e [`historico/taxa-recusa-2.json`](historico/taxa-recusa-2.json) (42 e 11); [`historico/decomposicao-latencia.json`](historico/decomposicao-latencia.json), variante `completa` (16 e 1). Ver a ressalva 1 |
| 9 set | Claude Sonnet 5 | Claude Code | 30 chamadas, 0 recusas | **dados** | **tamanho registrado confere, sem hash** (`prompt_canonico_caracteres` = 5.743) | [`resultados/claude-cli-matriz.json`](resultados/claude-cli-matriz.json) |
| 9 set | Claude Haiku 4.5 | Claude Code | 4 chamadas, 6 a 11 vezes mais lento | **só descrição no `docs/motor.md`** | **nada registrado** (não há arquivo de dados) | Seção "Nota: o modelo mais barato não foi o mais rápido" de [`../motor.md`](../motor.md). Os tempos do Sonnet 5 usados na razão (5,64, 10,30, 4,70 e 11,93 s) saem de [`resultados/claude-cli-matriz.json`](resultados/claude-cli-matriz.json); os do Haiku (62,19, 62,02, 30,99 e 94,24 s) não têm arquivo |
| 9 set | Kimi K3 | NVIDIA, gratuita | 4 chamadas, 0 recusas, cota esgotada (~35) | **parcial** | **tamanho registrado confere, sem hash** (5.743), para as 2 chamadas do arquivo; as 2 sondas isoladas não têm arquivo | [`resultados/nvidia-sondas-iniciais.json`](resultados/nvidia-sondas-iniciais.json) cobre 2 das 4 chamadas (3,864 s e 4,093 s), 0 recusas, e o aborto por limite na chamada 3. As outras 2 ("sondas isoladas", 5,22 s e 7,91 s) e o "~35" estão só em [`../motor.md`](../motor.md) |
| 10 set | Gemini 3.6 Flash | Google, gratuita | 12 chamadas, 6 recusas (4 de 4 com inventário completo) | **dados** | **tamanho registrado confere, sem hash** (5.743) | [`resultados/gemini-matriz.json`](resultados/gemini-matriz.json): 13 chamadas, 1 de limite de uso fora do denominador, 12 julgadas, 6 recusas; as duas células `completa` somam 4 de 4 |
| 22 set | Claude Sonnet 5 | Claude Code | 15 chamadas, 11 recusas | **dados** | **hash registrado e confere:** `e1cfcbda…` é o de `prompt-teste-2026-09-10.txt` (com CRLF) | [`resultados/2026-09-22-claude-cli-prompt-velho.json`](resultados/2026-09-22-claude-cli-prompt-velho.json). Ver a ressalva 2 |
| 22 set | Claude Sonnet 5 | API Anthropic | 30 chamadas, 0 recusas | **dados** | **hash registrado e confere:** `e1cfcbda…` é o de `prompt-teste-2026-09-10.txt` (com CRLF) | [`resultados/2026-09-22-anthropic-prompt-velho.json`](resultados/2026-09-22-anthropic-prompt-velho.json) |
| 24 set | Claude Sonnet 5 | API, antes do CVP | diag-05: 68 de 90 passos recusados | **dados** | **prompt do agente, não é nenhum dos dois** | [`../../execucoes/diag-05/passos.jsonl`](../../execucoes/diag-05/passos.jsonl) (90 registros, 68 com `recusa: cyber`) e [`../../execucoes/diag-05/estado.json`](../../execucoes/diag-05/estado.json) (`recusas: 68`). O campo `proposito` de [`resultados/2026-09-24-ab-recusa-diag05.json`](resultados/2026-09-24-ab-recusa-diag05.json) cita a mesma taxa como 76% (68/90 = 75,6%) |
| 24 set | Claude Sonnet 5 | API, antes/depois | 5/5 contra 0/5 recusas, Fisher bicaudal p = 0,0079 | **dados** | **prompt do agente, não é nenhum dos dois** | [`resultados/2026-09-24-ab-recusa-diag05.json`](resultados/2026-09-24-ab-recusa-diag05.json) (braço `B-diag05`: 5 recusas em 5) e [`resultados/2026-09-24-ab-recusa-diag05-depois-do-cvp.json`](resultados/2026-09-24-ab-recusa-diag05-depois-do-cvp.json) (mesmo braço: 0 em 5). O p é a probabilidade exata 2/252, recalculada |
| 2 e 3 out | Claude Sonnet 5 | API Anthropic | coleta: 1.600 chamadas de decisão, 0 recusas | **dados** | **prompt do agente, não é nenhum dos dois** | `execucoes/coleta-A-01` a `coleta-B-10`, `passos.jsonl`: 20 pastas de 80 registros, todos com categoria `aceita`; o `estado.json` de cada uma traz `recusas: 0`. A tabela gerada está em [`../resultados/coleta.md`](../resultados/coleta.md) |

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

## Como rodar o `medir.py` com o prompt de 10 de setembro

O `medir.py` lê por padrão o `prompt-teste.txt`, a revisão posterior, e esse padrão **não foi
alterado**. Para medir com o texto das medições do Apêndice B, passe `--prompt` com o nome do arquivo
(relativo a esta pasta) ou com o caminho absoluto:

```sh
cd docs/medicao
python medir.py --motor claude-cli --modelo claude-sonnet-5 --matriz --repeticoes 5 --prompt prompt-teste-2026-09-10.txt --saida resultados/minha-rodada.json
```

- **Confira o que foi usado.** O resultado registra `prompt_canonico`, `prompt_canonico_sha256` e
  `prompt_canonico_caracteres`. Devem ser o nome do arquivo, o hash e 5.743. Num checkout com LF o
  hash será o da coluna LF da primeira tabela, e não o `e1cfcbda…` das medições de 22 de setembro
  (ver "Sobre o fim de linha").
- **Use sempre `--saida` com um nome novo.** Sem ela, o padrão grava em
  `resultados/<motor>-<rótulo>.json`, e o script **não recusa nem avisa** se o arquivo já existe: uma
  matriz do `claude-cli` ou do `gemini` sobrescreveria `claude-cli-matriz.json` ou
  `gemini-matriz.json`, que são dados publicados.
- **Rodar com `--motor` chama o modelo.** O `claude-cli` usa a assinatura do Claude Code. O `gemini` e o
  `nvidia` leem `GEMINI_API_KEY` e `NVIDIA_API_KEY` do ambiente. O `anthropic` lê `ANTHROPIC_API_KEY` e
  **consome crédito de API**. Nenhuma chave vai por argumento nem por URL.
- **O script grava `variantes/`** a partir do prompt escolhido, e não do padrão.
- **Sem chamar o modelo:** `python medir.py --reanalisar resultados/gemini-matriz.json` rejulga um
  resultado já gravado. Ele **regrava o arquivo no lugar**; copie antes.
