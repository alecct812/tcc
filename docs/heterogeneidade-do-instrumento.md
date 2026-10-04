### Heterogeneidade do instrumento entre os pares

O artefato foi desenvolvido e medido na mesma janela, e a coleta definitiva não
rodou sob uma única árvore de código. A unidade de comparabilidade é o **par**:
§4.1 exige modelo, prompt, ferramentas, limite de passos e regime idênticos entre
os dois braços, e é isso que `conferir_par.py` verifica, comparando as árvores
`git` dos caminhos de que o agente depende (D238) — não a string de commit.

Comparadas dessa forma, a coleta tem **duas** árvores de instrumento, não cinco:

| par | árvore dos caminhos de execução | diferença |
|-----|--------------------------------|-----------|
| 1   | `1631d9625192`                 | — |
| 2-5 | `bed368f2af6b`                 | +115 linhas em `laco/__main__.py` (trava de D246) |
| 6-10| `bed368f2af6b` + D247          | `Hydra.resumir` devolve o comando inteiro |

Dentro de cada par os dois braços são byte-idênticos, e `conferir_par.py` aprova
os cinco pares fechados sem nenhuma falha. A diferença entre o par 1 e os pares
2-5 é a trava de concorrência de D246: ela age uma vez, antes do primeiro passo,
decide apenas se a execução começa, e não entra no prompt nem no grafo — o agente
não a observa.

A fronteira entre o par 5 e o par 6 é D247, que corrigiu um rótulo que escondia
`-P <lista>` do braço A e não do braço B (§E111). Sua manifestação nos pares já
colhidos foi medida lendo as treze justificativas de `hydra` do braço A: quatro
ocorrências, **todas posteriores ao desfecho primário do braço em que ocorreram**.
Três delas (`coleta-A-02`) são posteriores ao elo 4, que é o próprio critério de
sucesso de §4.4. Resta uma — o passo 67 da `coleta-A-05`, um de 61 passos ainda
disponíveis depois do elo 3 daquele braço —, e ela fica **declarada como não
resolvida**. A direção do viés penaliza o braço A, de modo que mantê-la aperta o
critério de D162 em vez de afrouxá-lo.

Duas condições não controladas por congelamento de código são declaradas: o
modelo é referenciado pelo alias `claude-sonnet-5`, não por um *snapshot* datado,
e as imagens do laboratório instalam pacotes sem fixação de versão. Ambas são
mitigadas pela janela de coleta: os cinco pares fechados foram colhidos em cerca
de dez horas de um único dia, contra um único conjunto de imagens, recriando-se os
contêineres entre todos os braços — o que se verifica no registro, já que em todos
os braços que usaram as listas de palavras o download precede o uso.

Para que a fronteira do par 5 / par 6 seja verificável pelo leitor e não apenas
declarada, **o critério de D162 é relatado desagregado por bloco** — pares 1-5
(pré-D247) e pares 6-10 (pós-D247), além do total sobre os dez. A desagregação é
divulgação, não inferência: com cinco pares em cada bloco e a variância medida
entre pares de instrumento idêntico, uma diferença entre blocos não estabelece
efeito do conserto, mas sua ausência torna a objeção verificável no próprio dado.
O regime em que o defeito de D247 podia alterar um desfecho — repetição de `hydra`
com `-P` anterior ao elo máximo do braço — ocorreu em **1 de 6** execuções do braço
A, e em nenhuma das cinco que compõem os pares fechados.

Esta é também a razão pela qual os pares 1-5 **não** foram recolhidos sob a árvore
corrigida: eles são o único grupo de comparação disponível para medir o efeito de
D247, e refazê-los eliminaria a informação em nome da uniformidade.

O tratamento de um defeito encontrado com a coleta em curso é pré-registrado em
D248, e a coleta encerra-se no par 10 por esse critério, não pela ausência de
defeitos — condição inalcançável num artefato cuja validação exige executá-lo.
