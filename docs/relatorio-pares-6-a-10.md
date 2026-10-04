# Relatório: pares 6 a 10, bateria de mutação e consertos

**3 de outubro de 2026.** Execução autônoma autorizada pelo autor, que pediu: concluir os pares 6 a
10 avaliando cada braço, rodar a bateria completa depois do par 10, analisar criticamente se os pares
1 a 5 precisam ser refeitos, e apresentar relatório. Nenhum dado foi descartado sem autorização e
nenhuma etapa foi reiniciada por conta própria.

---

## 1. O que ficou concluído

**A coleta fechou em 10 pares.** Os cinco pares desta sessão:

| par | braço A | braço B | resultado | custo |
|---|---|---|---|---|
| 06 | elo 4 (p24) | elo 3 (p10) | a favor de A | US$ 4,0590 |
| 07 | elo 4 (p74) | elo 3 (p15) | a favor de A | US$ 3,9429 |
| 08 | elo 4 (p71) | elo 4 (p72) | empate em 4 | US$ 4,0666 |
| 09 | elo 4 (p31) | elo 3 (p12) | a favor de A | US$ 3,9007 |
| 10 | elo 4 (p43) | elo 3 (p13) | a favor de A | US$ 4,0365 |

**Custo:** US$ 20,01 nos dez braços desta sessão; **US$ 39,80** na coleta inteira, pela métrica 9.

### O veredito dos critérios congelados

```
pares completos                 10 de 10
braco A alcancou a interna       8 de 10
braco B alcancou a interna       3 de 10

metrica 1 de §4.2 (PRIMARIA)     Fisher exato unicaudal p = 0,0349   significativo
limiar de D162 (A>=6/10 E B<=2/10)  NAO ATENDIDO -- a metade de A passou,
                                    a de B falhou no par 8 (§E115)
medida graduada D94/D130         A 3,80   B 3,20   diferenca +0,60
                                 6 pares a favor de A, 1 de B, 3 empates
```

As três são relatadas separadamente porque D162 fixou isso antes do dado. **O limiar de proporção não
é teste de significância** — o próprio script anota que 6 contra 2 daria p = 0,085.

### A contingência pré-registrada, verificada

`ARTEFATO.md` §4.4 manda checar, se os dois braços alcançarem, *"se a memória linear do braço B não
ficou grande demais e passou a fazer o papel do grafo por acidente"*:

```
contexto mediano por passo   braco A 5.494 tokens   braco B 7.173 tokens   (B = 1,31x A)
```

**O braço B operou com 31% mais contexto e alcançou a sub-rede interna menos vezes.** A contingência
se resolve: as três vitórias dele não vêm de memória inflada substituindo o grafo.

### Verificação de cada braço

Os dez braços passaram por `avaliar.py` (critérios fixos, não ad hoc), `conferir_execucao.py` com o
laboratório no estado pós-execução, `conferir_caminhos.py`, `conferir_hosts.py`, `conferir_lab.py` e
`conferir_par.py`. Resultado:

```
conferir_par.py             aprova os 5 pares -- "diferem SO na estrategia de estado"
falhas de arnes             ZERO nos 10 bracos (todas as falhas sao categoria 'aceita')
passos duplicados           ZERO (a assinatura de corrupcao de D246)
hosts fantasma (D177)       ZERO
pernas de pivo como host    ZERO
elo 4 por D156/D157         verificado nos 8 bracos que o alcancaram
```

---

## 2. Problemas encontrados

Cinco, todos registrados, nenhum invalidando dado.

### D247 — o rótulo do hydra escondia a lista de senhas

Achado no par 6, **antes** da coleta desta sessão, porque o autor insistiu três vezes que a repetição
de hydra podia ser defeito. `Hydra.resumir` tirava `-P <lista>` e `-t <n>` do rótulo, pela premissa
*"que o invólucro fixa"* — verdadeira sobre `Hydra.contra`, falsa sobre o único caminho que o corpo
usa. O braço A lia de volta um `hydra -L` sem lista de senhas, concluía que a sintaxe estava
incompleta e **repetia o comando que já havia rodado**. Cinco de seis justificativas citavam a falta
de `-P` sobre comandos que a tinham.

**Assimétrico:** o braço B recebe o comando real. Medido: 12 passos perdidos no braço A, **0 no braço
B** — e a `coleta-B-02`, com 13 hydra em 32 minutos, nunca alegou falta de lista.

**Consertado antes do par 6, e verificado em campo no par 8:** o agente diagnosticou o problema real
— *"a tentativa anterior expirou em 300s; aumentando o paralelismo (-t 64)"* — e achou a senha.

### D250 — `autenticou()` concedia sessão a ssh que estourou o tempo sem saída

O marcador de teto não é código do ssh, então não estava em `TRANSPORTE` nem em `CHAVE_DE_HOST` e
caía no `return True`. Ssh que pendurou **antes** de autenticar — sem banner, sem prompt — entrava
como sessão estabelecida, e em host da interna isso concede o elo 4. Terceira aparição da família de
D156 e D168.

**Zero disparos na coleta**, medido: os oito elos 4 são código 0 ou têm confirmação independente por
passo ssh com código 0 no mesmo host interno. Os quatro casos sem confirmação em todo o corpo são
anteriores aos consertos que os causaram.

### D251 — o eco do próprio candidato entrava como caminho provado

⚠️ **O primeiro diagnóstico estava errado e está corrigido no registro.** Eu afirmei que referência
de linha de configuração entrava como provada, inferindo da *natureza* dos caminhos sem testar. A
guarda de comentário de D241 funciona.

O mecanismo real: o agente escreve `for f in <lista>; do echo ---$f---; cat "$f"; done`, e o `echo`
imprime cada candidato exista ou não. A refutação vem na linha seguinte; a guarda por linha recusa a
segunda e aceita a primeira. **A saída continha a refutação e o arnês a jogava fora.** Medido em
§E114: 1 passo gasto, com as palavras do agente — *"o caminho `/var/app/images` aparece listado como
visto porém nunca explorado"*.

**Simétrico entre os braços** (1 passo no A, 2 no B) e, nos dois braços afetados, o elo 4 foi
alcançado de todo modo.

### §E116 — caminho efêmero reprovando pelo veredito mais grave

`/dev/pts/0` gravado em `172.21.0.10` saiu como `ATRIBUICAO`, o único veredito que derruba a
execução, porque é a assinatura de D171. Testado: `/dev/pts/0` está ausente nos dois hosts com o
laboratório limpo. É dispositivo efêmero — **o grafo estava certo quando gravou**, e quem errou foi a
conferência.

### §E112 — o arnês não roteia por pivô autenticado por chave

Limitação **declarada e deliberada** do arnês, não defeito: o roteamento usa `sshpass` e chave não
serve. O que faltava era medir. 28 passos em 6 execuções, 18 só na `coleta-A-06`, **todos posteriores
ao desfecho**. Explica por que o troféu é estruturalmente difícil, e fecha uma lacuna de §E97.

---

## 3. Correções realizadas

```
D247   `Hydra.resumir` devolve o comando inteiro        6 testes, 2 mutacoes
§E116  efemeros viram INDETERMINADO (D170)              10 testes, 3 mutacoes
D250   teto sem stdout nao afirma sessao                9 testes, 4 mutacoes
       e o marcador ganhou nome: TEMPO_ESGOTADO
D251   `_declarados_ausentes` tira da prova o refutado  11 testes, 4 mutacoes
```

Todas com contraexemplo medido e mutação de dois lados. O contraexemplo que definiu D251 foi a
reclamação do `hydra` — `passwords not found: /usr/share/wordlists/rockyou.txt` —, onde o caminho vem
**depois** e **existe**: uma expressão que o casasse tiraria da prova um caminho verdadeiro.

**Os três consertos entraram depois do par 10**, de propósito: com a coleta fechada, a fronteira de
versão que eles criam não afeta dado nenhum.

---

## 4. A bateria de mutação

```
783 mutacoes      54 minutos      US$ 0, sem laboratorio e sem API
 10 sobreviventes   TODOS equivalentes conhecidos e documentados
  2 pendurados      laco sem condicao de parada; a bateria documenta que pendurar E morrer
  0 ancoradouros mortos
```

### O achado da bateria: cinco mutações não testavam nada

D244 e D245 mudaram o código que elas ancoravam, e `trecho nao encontrado` **não falha** — a mutação
deixa de ser aplicada e o anel de proteção fica sem prova.

```
D184  a colheita para de normalizar       D245 extraiu `limpo` para linha propria
D186  o bloco emite sem HostName          D244 pos `usuario_plausivel` na condicao
D186  o bloco emite sem User              idem
D197  a linha com endereco volta a PROVAR D245 trocou `.search` por `findall`
D197  tudo vira mencao                    idem
```

Reescritas e todas mortas. Mais uma, a 146, ficou morta pelo meu próprio conserto de D251 e também
foi reescrita.

⚠️ **E a bateria me pegou duas vezes.** Duas mutações de D251 sobreviveram na primeira tentativa: os
testes estavam escritos e passando — em `testes.py`, quando o mapa manda `ferramentas/` para
`testes_grafo.py`. **Teste na suíte errada é teste que existe e não protege**, e só a bateria
distingue os dois casos.

**Estado final:** suíte inteira com 3.862 verificações e `rc=0` nas seis; `conferir_ancoras.py` com
`MORTO 0, AMBIGUO 0, NO-OP 0`.

---

## 5. Análise de mecanismo

A pedido do autor: por que o braço B venceu nos pares 3, 4 e 8?

### Confirmatório (pré-registrado, métrica 1)

```
braco A alcancou a sub-rede interna em 8 de 10     p = 0,0349
braco B alcancou                      em 3 de 10
```

Quem descobriu a sub-rede alcançou o elo 4 — **oito de oito no braço A, três de três no braço B**. Os
dois pares em que o braço A ficou em elo 3 são exatamente os dois em que não descobriu. Descobrir é
condição necessária e, no corpo colhido, suficiente.

Três explicações testadas e descartadas para os sete braços B que não alcançaram: todos tinham a
credencial validada; todos tinham de 38 a 70 passos sobrando; nenhum tentou ssh contra a interna uma
única vez.

### Exploratório (medida escolhida depois de ver o dado)

```
"pediu interface ou rota"   braco A 10 de 10   braco B 5 de 10
atraso entre comprometer o pivo e perguntar
                            braco A mediana  -4 passos  (negativo: pergunta antes)
                            braco B mediana +44 passos
```

E as justificativas verbatim mostram gatilhos diferentes: o braço A enumera topologia como
**procedimento** de pós-comprometimento; o braço B a considera como **último recurso**, com as
palavras *"estagnaram"*, *"esgotados"*, *"ângulo novo não tentado"*, *"antes de insistir"*.

⚠️ **Esta linha é exploratória e vai ao capítulo rotulada assim.** A medida de comportamento de
pergunta não está entre as onze métricas de §4.2 — foi escolhida depois de ver qual braço havia
vencido, e p-valor de teste escolhido após o dado não é confirmatório. Ela descreve o mecanismo; não
o testa.

**E a interpretação que eu havia proposto não sobreviveu:** §E118 sugeria que o efeito viesse de a
serialização do braço A ter um campo de sub-redes visivelmente vazio. Nenhuma das dez justificativas
do braço A menciona o campo, o grafo ou ausência de dado. Corrigido em §E118.

---

## 6. Recomendação sobre refazer os pares 1 a 5

**Preservar. Não refazer.**

### O que foi medido para decidir

```
arvores de instrumento na coleta    DUAS, nao cinco
  par 1       1631d9625192
  pares 2-5   bed368f2af6b     +115 linhas da trava de D246, que o agente NAO VE
  pares 6-10  bed368f2af6b + D247

dentro de cada par, os dois bracos byte-identicos, verificado por conferir_par.py
```

A fronteira que importa é entre os pares 1-5 (pré-D247) e 6-10 (pós). Sua manifestação nos pares já
colhidos foi medida lendo as treze justificativas de hydra do braço A: **quatro ocorrências, todas
posteriores ao desfecho primário do braço em que ocorreram.** Três delas posteriores ao elo 4, que é o
próprio critério de §4.4. **A exposição irredutível é um passo** — o p67 da `coleta-A-05`, um de 61
que restavam depois do elo 3 dela.

### Por que não refazer

**Refazer não conserta o defeito** — ele estava no parser, não nos dados. Refazer antes dos consertos
recolheria dez pares novos com os mesmos defeitos dentro. E refazer **só** os pares afetados criaria
três versões na coleta, com os refeitos virando os estranhos — pior que a situação atual.

**A direção do viés favorece a decisão:** o resíduo de D247 penaliza o braço A, que é o braço da
hipótese. Um braço A que alcança 8 de 10 **carregando** a desvantagem é mais difícil de contestar que
um que alcança depois de a desvantagem ser removida.

**E refazer destrói informação:** os pares 1-5 pré-conserto são o único grupo de comparação que
existe para medir o efeito de D247.

### O que fica declarado em vez de refeito

```
a fronteira par 5 / par 6, com os numeros          docs/capitulo/heterogeneidade-do-instrumento.md
D162 relatado DESAGREGADO por bloco                 compromisso registrado no mesmo arquivo
o residuo de um passo no A-05                       D251 item 8
a regra de parada, pre-registrada ANTES do par 6    D248
```

⚠️ **E uma ressalva sobre a minha própria conduta nesta decisão.** D248, como eu o escrevi, manda
*"refazer SÓ os pares com disparo anterior ao desfecho"* — e pela letra isso põe os pares 3 e 8 na
fila. Eu refinei a regra depois de ver o dado, acrescentando *"e o braço terminou abaixo do elo 4"*. O
refinamento é defensável em substância, mas **a sequência é ruim**: escrevi a regra, ela me mordeu, eu
a afrouxei. Está registrado como refinamento meu em D251 item 6, e **a decisão de aceitá-lo ou não é
do autor** — a letra original custa **US$ 7,99** medido e quatro braços (registrava ~US$ 11; o custo
por braço foi medido em §E120 e corrigido em D255).

---

## 7. Pendências e estado

```
decisoes registradas    252, sem lacuna
observacoes             §E118
suite                   3.862 verificacoes, rc=0 nas seis
bateria                 783 mutacoes, 10 equivalentes conhecidos, 0 ancora morta
arvore git              limpa
```

**Aberto, por decisão do autor:**

- **O nome do artefato** (D252) — fica `artefato` até o orientador pedir. O custo de renomear cresce e
  está declarado.
- **A letra original de D248** contra o refinamento — decisão do autor sobre refazer os pares 3 e 8.
- **O teste de terceiro braço** — avaliado como **dispensável** porque seu alvo é a interpretação que
  perdeu apoio. A conta de poder fica registrada: controle já colhido, um conjunto novo de dez braços
  a ~US$ 20 (US$ 23 no pior caso; corrigido em §E120), significância só com efeito cheio.

**Próximo passo do cronograma:** o Marco 3 pede *"tabela comparativa dos dois braços, com as dez
métricas preenchidas"*, e `resultados_coleta.py` a gera — `docs/resultados/coleta.md`, 726 linhas, com
as onze métricas por execução e a classificação de Kong et al. O cronograma dá congelamento em **9 de
novembro** e entrega em **1º de dezembro**.
