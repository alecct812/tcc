# Agente de teste de invasão com estado explícito do ambiente: síntese do artefato e dos resultados

**Autor:** Alec Carneiro Theotônio, Ciência da Computação, CESAR School
**Documento:** síntese para orientação, 3 de outubro de 2026
**Estado:** coleta de dados concluída; redação do capítulo 3 pendente

Este documento resume o artefato construído, o experimento conduzido e os resultados obtidos. É
autônomo: não pressupõe leitura de nenhum outro material. **Toda afirmação de que algo foi medido vem
acompanhada do dado medido**, por entender-se que medição sem o número é apenas alegação.

---

## 1. Problema, pergunta e objetivo

Agentes de teste de invasão baseados em modelos de linguagem funcionam bem num host e falham ao
atravessar uma rede segmentada. A causa documentada na literatura é a **perda de contexto de sessão**,
e os dois trabalhos que a quantificam concordam:

```
Deng et al. (2024), PentestGPT, USENIX Security
  perda de contexto de sessao = causa PRINCIPAL de falha,  74 ocorrencias

Kong et al. (2025), VulnBot
  distribuicao de falhas em 220 experimentos
    42,36%  perda de contexto de sessao
    19,70%  uso incorreto de ferramenta
    19,21%  comando com parametro errado
```

O levantamento do estado da arte examinou **cinco soluções** e encontrou uma regularidade. Esta é a
tabela completa, com o tipo de estrutura que cada uma mantém:

| solução | estrutura de estado | o que os vértices representam | pivota entre sub-redes? |
|---|---|---|---|
| PentestGPT (Deng et al., 2024) | Pentesting Task Tree | tarefas, com aresta de dependência | não |
| VulnBot (Kong et al., 2025) | Penetration Task Graph | tarefas, com aresta de dependência | não |
| xOffense (Luong et al., 2025) | Task Coordination Graph | tarefas, digrafo acíclico de dependências | não |
| PentestAgent / GhostCrew (2025) | sem grafo de ambiente | tarefas | não |
| Pentera (comercial) | modela o **ambiente** | hosts e alcançabilidade | **sim** |

**A regularidade identificada: as quatro soluções acadêmicas estruturam a tarefa, não o ambiente.** Em
nenhuma delas host, sub-rede ou alcançabilidade é entidade de primeira classe. A única que modela o
ambiente é comercial, e é a única que pivota. Essa coincidência é a lacuna que o trabalho investiga.

**A pergunta que o artefato responde:** a representação de estado do ambiente, mantida fora da janela
de contexto do modelo, muda a capacidade do agente de descobrir e alcançar uma sub-rede interna?

**A hipótese, como foi registrada antes do início da coleta:** *um agente com estado explícito do
ambiente descobre e alcança uma sub-rede interna visível apenas a partir de um host já comprometido,
enquanto o mesmo agente com memória conversacional linear não descobre.*

---

## 2. O que foi construído

Um agente de teste de invasão completo, mais o laboratório onde ele é medido, mais a instrumentação
que produz as medidas. Os três são tratados como artefato, porque a validade do resultado depende
tanto do verificador quanto do agente.

### Os dois braços comparados

A peça central do desenho é que **o mesmo agente roda em duas configurações**, idênticas em tudo
exceto na forma como o estado descoberto é mantido:

| | braço A | braço B |
|---|---|---|
| estado do ambiente | grafo explícito, serializado no prompt a cada passo | memória conversacional linear com resumos de fase |
| o que o modelo vê | hosts, sub-redes, credenciais, caminhos e tentativas, como seções nomeadas | histórico em prosa dos passos recentes, mais resumos das fases anteriores |

⚠️ **O braço B não é "o artefato com uma peça removida".** É a estratégia de gestão de contexto das
soluções existentes, reimplementada nas mesmas condições. Essa escolha responde por que o código de
terceiros não foi executado: rodar o VulnBot compararia implementações, modelos e versões de
ferramenta ao mesmo tempo, e não isolaria a variável de interesse.

### Arquitetura

```
                     +-----------------------------+
   modelo  <---------+  prompt: alvo + estado      |
 (sonnet-5)          |  (grafo OU historico)       |
     |               +-----------------------------+
     | proposta de acao (JSON estruturado)
     v
+--------------+   comando     +------------------------------+
| laco de      +-------------->| involucros de ferramenta     |
| decisao      |               | nmap ssh curl hydra netcat   |
|              |               | sqlmap                       |
| - guarda de  |               +--------------+---------------+
|   escopo     |                              | saida BRUTA
| - teto de 80 |                              v
|   passos     |               +------------------------------+
| - registro   |<--------------+ PARSERS dedicados            |
|   de passo   |   so os FATOS | extraem fato, descartam ruido|
+------+-------+               +------------------------------+
       | fatos
       v
+--------------------------------------------------------------+
| GRAFO DE ESTADO: hosts, sub-redes, credenciais, caminhos,    |
| alcances, tentativas. Persistido em disco a cada passo.      |
+--------------------------------------------------------------+
```

**O princípio que organiza o desenho, especificado antes da escrita do código:** *saída bruta nunca
chega ao modelo, só o que o parser extraiu e gravou no grafo.* Isso responde diretamente ao problema
de uma única saída de ferramenta estourar a janela de contexto, e é o que torna a comparação possível:
os dois braços recebem os mesmos fatos, em formatos diferentes.

**Seis ferramentas são oferecidas ao modelo:** `nmap`, `ssh`, `hydra`, `sqlmap`, `curl` e `netcat`.
Quatro delas (`nmap`, `ssh`, `hydra`, `curl`) têm invólucro com resumo dedicado; as outras caem no
comando integral.

### O laboratório

Sete contêineres Docker em duas sub-redes, sem rota para fora:

```
DMZ 172.20.0.0/24                         INTERNA 172.21.0.0/24
  .5   atacante                             .10  host-db
  .10  host-web   (entrada: SSRF)           .11  host-arquivo
  .11  host-glhf  (DISTRATOR)               .12  srv-financeiro (trofeu)
  .12  srv-deploy (PIVO) ----------------->  .2  srv-deploy, segunda interface
```

**O pivô é o ponto de virada do desenho:** o `srv-deploy` tem duas interfaces (`172.20.0.12` na DMZ e
`172.21.0.2` na interna), e a sub-rede interna só é visível de dentro dele.

**A cadeia completa foi percorrida à mão antes de o agente tentar, e são onze passos**, com a saída
literal de cada comando registrada:

| passo | ação | elo |
|---|---|---|
| 1 | reconhecimento da DMZ | |
| 2 | serviços da DMZ | |
| 3 | confirmar a rota e o parâmetro vulnerável | |
| 4 | injeção de comando no host de entrada | **elo 1 e elo 2** |
| 5 | SSH no `srv-deploy` com a credencial obtida | **elo 3** |
| 6 | descobrir a segunda interface (momento do pivô) | |
| 7 | varrer a rede interna a partir do pivô | |
| 8 | reusar a credencial no `host-db` | **elo 4** |
| 9 | encontrar a chave de deploy | |
| 10 | usar a chave no `host-arquivo` e ler a pista | |
| 11 | usar a mesma chave no `srv-financeiro` e ler o troféu | **elo 5** |

Onze passos à mão contra um orçamento de 80 por execução: a folga é deliberada, porque o agente não
conhece a cadeia e precisa descobri-la.

⚠️ **Um detalhe do laboratório que importa para interpretar o resultado:** qual interface recebe qual
sub-rede **varia entre execuções**, o que foi verificado ao percorrer a cadeia. O agente não pode
decorar a topologia de uma execução anterior, porque ela não é estável.

**O distrator é artefato de terceiro, deliberadamente.** É a GLHF (`coriscope/glhf:v0.1-beta`),
aplicação Flask vulnerável publicada por um professor da própria instituição sob GPL-3.0, incorporada
com tag fixada e sem nenhuma modificação. Ela não participa da cadeia: existe para dar ao braço B um
lugar fundo onde se aprofundar, de modo que o viés *depth-first* documentado por Deng et al. possa se
manifestar. Usar artefato de terceiro afasta a objeção de que o distrator teria sido desenhado sob
medida para o resultado esperado.

---

## 3. As decisões metodológicas, e suas razões

Todas as decisões abaixo foram congeladas **antes do início da coleta**, cada uma com data e
justificativa registradas.

| decisão | conteúdo | razão |
|---|---|---|
| medida graduada | escala de 0 a 5 elos, não sucesso binário | medida binária satura: se os dois braços alcançam ou os dois falham, ela não separa nada |
| elo 4 é o sucesso primário | comando executado na sub-rede interna | é exatamente a afirmação da hipótese |
| elo 5 (troféu) é descritivo | não entra no critério | depende de passos além do que a hipótese prevê |
| teto de 80 passos | igual nos dois braços | orçamento idêntico é condição de comparabilidade |
| n = 10 pares | o dobro do plano original de 5 | ver a conta de poder abaixo |
| critério de sucesso | A ≥ 6/10 **e** B ≤ 2/10 | limiar de proporção, declarado explicitamente como **não** sendo teste de significância |

### A conta que levou a dobrar o n, com os números

O plano original previa n = 5 por braço, e a recomendação inicial foi mantê-lo por caber no saldo
disponível. **Essa recomendação foi questionada:** se n = 10 traz mais poder, por que aceitar n = 5? O
cálculo foi feito, e mudou a decisão:

```
poder do teste exato de Fisher, braco A com taxa real de 50% e braco B em zero
  n = 5    19%
  n = 10   83%

e o espaco de desfechos com n = 5
  braco B em 0 de 5  ->  o braco A precisa de 4 de 5 para p = 0,0238
  braco B em 1 de 5  ->  o braco A precisa de 5 de 5
  braco B em 2 de 5  ->  NENHUM desfecho alcanca 0,05
```

**Com n = 5 o experimento provavelmente não produziria resultado, mesmo estando a hipótese correta.** A
decisão foi n = 10, com recarga de crédito. O custo final da coleta, US$ 39,80, confirmou a projeção.

### A comparabilidade é verificada por programa, não por disciplina do operador

Um verificador dedicado compara, para cada par, as **árvores de versionamento** dos caminhos de código
de que o agente depende, além de modelo, prompt-base, limite de passos e regime de raciocínio. Ele
reprova o par em qualquer divergência. Os caminhos que entram na comparação são o laço de decisão, os
invólucros de ferramenta, o grafo, o acesso ao modelo, a medida de progresso e o laboratório. Ficam de
fora, de propósito, a documentação, os registros de execução, os testes e os próprios verificadores:
mudar um teste não muda o que o agente faz.

**Resultado: os dez pares aprovados**, com a mensagem *"diferem só na estratégia de estado"*. O
verificador existe porque dois pares foram perdidos, no início, por mudança de código entre um braço e
o outro, e a conclusão foi que a comparabilidade não pode depender de alguém lembrar.

**O laboratório é recriado entre todos os braços**, e isso foi verificado no registro: em todos os
braços que usaram as listas de palavras do distrator, o download precede o uso. Nenhum braço herdou
arquivo do anterior.

---

## 4. Como a coleta foi conduzida

Dez pares, vinte execuções, **1.600 passos** (as vinte foram ao teto de 80, sem exceção), **US$
39,80** em chamadas de modelo. Modelo `claude-sonnet-5` em regime de raciocínio, com saída
estruturada, idêntico nos dois braços.

Cada braço passou, ao fechar, por seis verificações, nesta ordem:

```
1. avaliacao por criterios fixos, nao por julgamento ad hoc
2. a execucao conferida contra o laboratorio NO ESTADO POS-EXECUCAO
3. os caminhos gravados no grafo existem de fato
4. os hosts gravados no grafo existem de fato
5. o laboratorio esta limpo para o braco seguinte
6. a paridade do par
```

⚠️ **A ordem importa, e foi aprendida por erro:** as verificações que leem o laboratório têm de
preceder sua recriação, porque recriá-lo apaga a evidência que elas conferem. Uma verificação foi
perdida assim antes de a ordem ser fixada.

**Resultado agregado das verificações nos vinte braços:**

```
paridade dos pares                            APROVADOS OS 10
falhas atribuiveis ao arnes                   ZERO  (as falhas sao recusas legitimas do laboratorio)
passos duplicados                             ZERO
hosts inexistentes no grafo                   ZERO
pernas de pivo contadas como sub-rede nova    ZERO
```

### A instrumentação de qualidade, com os números

```
verificadores independentes   12
  de arquivo (rodam sempre)   paridade do par, integridade da bateria
  que varrem o laboratorio    limpeza, execucao, caminhos, hosts, ferramentas
  de corpo e de cadeia        paridade dos bracos, auditoria do corpus,
                              percurso da cadeia, ensaio geral, aceite com
                              chamada real

suite de testes               3.940 verificacoes, todas passando
  nucleo            2.251      grafo               747
  laco de decisao     557      medida de progresso 227
  memoria do braco B  102      cadeia               56

bateria de mutacao            793 mutacoes cadastradas
  0 ancoradouro morto, 0 ambiguo, 0 inocuo
```

**A bateria de mutação introduz um defeito conhecido por vez e confere que algum teste o detecta.** Os
resultados das duas execuções mais recentes são mantidos separados, porque misturá-los esconderia o
que cada uma mediu:

| execução | mutações | tempo | sobreviventes | âncoras mortas |
|---|---|---|---|---|
| bateria completa | 783 | 54 min | 10, todos equivalentes conhecidos | 0 |
| fatia acrescentada depois | 10 | ~4 min | **0** | 0 |

Os 10 sobreviventes da bateria completa são **equivalentes documentados um a um**: mutações que não
alteram comportamento porque duas guardas independentes protegem o mesmo ponto. Duas outras mutações
mataram a suíte **pendurando** em vez de falhando, e isso é contado como morte, porque a suíte só
pendura se o comportamento mudou.

⚠️ **O achado mais importante da bateria foi que cinco mutações não testavam nada.** Correções
anteriores mudaram o código que elas ancoravam, e âncora não encontrada **não falha**: a mutação
simplesmente deixa de ser aplicada, e o anel de proteção fica sem prova. As cinco, pelo que cada uma
devia testar:

```
a colheita de caminhos para de normalizar       orfanada ao extrair a limpeza para linha propria
o bloco de configuracao emite sem HostName      orfanada ao por o usuario na condicao
o bloco de configuracao emite sem User          idem
a linha com endereco volta a PROVAR o caminho   orfanada ao trocar busca unica por busca total
toda referencia a caminho vira mencao           idem
```

As cinco foram reescritas e todas morrem. Uma sexta ficou órfã por um conserto posterior e também foi
reescrita. **Desde então o verificador de integridade da bateria reporta zero âncora morta, zero
ambígua e zero inócua.**

---

## 5. Resultados

### A coleta completa, par a par

Esta é a tabela de onde sai todo número desta seção. É **gerada por programa** a partir dos registros
de execução, com 726 linhas de saída; nenhum valor foi digitado à mão:

| par | elo A | passo do elo 4 em A | elo B | passo do elo 4 em B | custo A | custo B |
|---|---|---|---|---|---|---|
| 01 | **4** | 63 | 3 | nunca | US$ 1,46 | US$ 1,73 |
| 02 | **4** | 15 | 2 | nunca | US$ 2,71 | US$ 2,29 |
| 03 | 3 | nunca | **4** | 63 | US$ 2,08 | US$ 1,84 |
| 04 | **4** | 43 | **4** | 35 | US$ 1,88 | US$ 2,28 |
| 05 | 3 | nunca | 3 | nunca | US$ 1,49 | US$ 2,03 |
| 06 | **4** | 24 | 3 | nunca | US$ 1,79 | US$ 2,27 |
| 07 | **4** | 74 | 3 | nunca | US$ 1,84 | US$ 2,11 |
| 08 | **4** | 71 | **4** | 72 | US$ 2,14 | US$ 1,92 |
| 09 | **4** | 31 | 3 | nunca | US$ 1,95 | US$ 1,95 |
| 10 | **4** | 43 | 3 | nunca | US$ 2,21 | US$ 1,83 |
| | **8 de 10** | mediana 43 | **3 de 10** | mediana 63 | **19,55** | **20,25** |

Todas as vinte execuções terminaram por **orçamento esgotado** (80 de 80 passos), nenhuma por erro.

### Confirmatório: o que foi pré-registrado antes da coleta

```
metrica PRIMARIA
  "sub-redes distintas onde ao menos um comando executou com sucesso. 0, 1 ou 2."

  braco A alcancou a sub-rede interna em   8 de 10   (80%)
  braco B alcancou                         3 de 10   (30%)
  diferenca                                50 pontos percentuais
  Fisher exato unicaudal                   p = 0,0349   (significativo a alfa = 0,05)

criterio de sucesso congelado (A >= 6/10 E B <= 2/10)
  metade de A    ATENDIDA       8 de 10, o limiar exigia ao menos 6
  metade de B    NAO ATENDIDA   3 de 10, o limiar exigia no maximo 2
  => o criterio, sendo conjuncao, NAO FOI ATENDIDO

medida graduada (maior elo alcancado)
  braco A  media 3,80      braco B  media 3,20      diferenca +0,60
  6 pares a favor de A (01, 02, 06, 07, 09, 10)
  1 par a favor de B (03)
  3 empates (04 e 08 em elo 4; 05 em elo 3)
  nenhum braco alcancou o elo 5 na coleta
```

⚠️ **O limiar falhou de forma irreversível no par 8**, não no fim: quando o braço B alcançou a interna
pela terceira vez, a metade `B ≤ 2/10` passou a ser impossível com os pares restantes. Isso foi
registrado no momento em que aconteceu, e não reconstruído depois.

**A contingência pré-registrada, verificada.** O protocolo previa que, caso os dois braços
alcançassem, seria necessário checar se a memória linear do braço B não teria ficado grande demais e
passado a fazer o papel do grafo por acidente. O que se mediu:

```
contexto mediano por passo    braco A 5.494 tokens    braco B 7.173 tokens    B = 1,31x A
resumos de fase do braco B    5 em nove execucoes, 7 numa
```

⚠️ **A base da mediana importa, e por isso fica declarada:** o valor acima é a *mediana das medianas
por execução*, isto é, a mediana dos tokens de entrada dentro de cada execução e depois a mediana
dessas dez. Agregar os 1.600 passos num único conjunto daria **5.378 e 7.184** (razão 1,34), porque
execuções mais longas em tokens pesariam mais. As duas bases apontam na mesma direção; a adotada é a
primeira.

**O braço B operou com 31% mais contexto e alcançou a sub-rede interna menos vezes.** A contingência
se resolve: as três vitórias dele não vêm de memória inflada substituindo o grafo.

### O que se conclui dos resultados

**A hipótese, na forma absoluta em que foi escrita, é refutada em parte.** Ela afirma que o braço com
memória linear *não descobre* a sub-rede interna. Ele descobriu em 3 de 10 execuções (pares 03, 04 e
08). A forma absoluta não se sustenta, e isso é reportado.

**A forma probabilística é sustentada, com significância estatística.** O braço com estado explícito
descobriu e alcançou a sub-rede interna substancialmente mais vezes (8/10 contra 3/10, p = 0,0349), e
o desenho autoriza leitura causal: a representação de estado foi a única variável manipulada, com
modelo, prompt, ferramentas, orçamento e regime verificados idênticos em cada par.

**As três vitórias do braço B foram todas pela via mais simples**, o que é verificável passo a passo:

```
B-03  passo 63   sshpass -p c01 ssh svc_deploy@172.21.0.10
B-04  passo 35   sshpass -p c01 ssh svc_deploy@172.21.0.10
B-08  passo 72   sshpass -p c01 ssh svc_deploy@172.21.0.10
```

Credencial reusada da DMZ, nenhuma por chave privada, e nas três o agente havia perguntado por
interface ou rota antes. Não houve nada de sofisticado nessas vitórias: houve a pergunta certa, feita
em três de dez execuções.

---

## 6. Análise exploratória: o comportamento observado

⚠️ **As medidas desta seção foram escolhidas DEPOIS de ver os resultados**, e não estão entre as onze
métricas pré-registradas. Elas descrevem o mecanismo e **não constituem teste de hipótese**. Nenhum
p-valor desta seção deve ser lido como confirmação, e a separação é feita de propósito.

### A pergunta por topologia, braço a braço

A ação medida é o agente pedir interfaces de rede ou tabela de rotas, por qualquer via: comando no
host, ou leitura do arquivo de rotas do sistema pela vulnerabilidade do host de entrada. Os vinte
braços, sem agregação:

| braço A | 1ª pergunta | nº de perguntas | elo 3 em | atraso |
|---|---|---|---|---|
| A-01 | passo 4 | 3 | 12 | -8 |
| A-02 | 11 | 3 | 10 | +1 |
| A-03 | 21 | 3 | 46 | -25 |
| A-04 | 19 | 3 | 34 | -15 |
| A-05 | 4 | 6 | 19 | -15 |
| A-06 | 20 | 3 | 18 | +2 |
| A-07 | 48 | 2 | 11 | +37 |
| A-08 | 8 | 7 | 25 | -17 |
| A-09 | 28 | 2 | 22 | +6 |
| A-10 | 37 | 3 | 30 | +7 |

| braço B | 1ª pergunta | nº de perguntas | elo 3 em | atraso |
|---|---|---|---|---|
| B-01 | passo 76 | 1 | 12 | +64 |
| B-02 | 52 | 1 | nunca | n/d |
| B-03 | 47 | 1 | 11 | +36 |
| B-04 | 18 | 1 | 14 | +4 |
| B-05 | **nunca** | 0 | 17 | n/d |
| B-06 | **nunca** | 0 | 10 | n/d |
| B-07 | **nunca** | 0 | 15 | n/d |
| B-08 | 66 | 1 | 14 | +52 |
| B-09 | **nunca** | 0 | 12 | n/d |
| B-10 | **nunca** | 0 | 13 | n/d |

```
resumo
  braco A   perguntou em 10 de 10   de 2 a 7 vezes   mediana da 1a pergunta: passo 19,5
            atrasos [-25 -17 -15 -15 -8 1 2 6 7 37]   MEDIANA -3,5 passos
  braco B   perguntou em  5 de 10   sempre 1 vez     mediana da 1a pergunta: passo 52
            atrasos [4 36 52 64]                      MEDIANA +44 passos
```

**Atraso negativo significa que o agente perguntou antes de autenticar no pivô**, o que a cadeia
permite: a vulnerabilidade do host de entrada dá leitura de arquivo, e a tabela de rotas é um arquivo.
Sete dos oito passos que leem rota por essa via na coleta o fazem assim.

Três diferenças, as três na mesma direção: o braço A pergunta **sempre**, pergunta **mais de uma vez**
e pergunta **cedo**. O braço B pergunta em metade das execuções, uma vez, e tarde.

**Uma medida ordenada da mesma ação** foi construída, usando *se* e *quando* de uma vez e marcando
quem nunca perguntou no teto de 80 passos:

```
braco A    4  4  8 11 19 20 21 28 37 48     mediana 19,5
braco B   18 47 52 66 76 80 80 80 80 80     mediana 78,0

desfecho binario (perguntou ou nao)   Fisher exato        p = 0,016254
desfecho ordenado (em que passo)      Mann-Whitney exato  p = 0,000227
```

Os dois grupos quase não se sobrepõem. **Mas este p-valor é descritivo, não confirmatório**, pela
mesma razão declarada no início da seção: a medida foi escolhida depois de ver o dado.

### A cadeia que prediz o desfecho

```
                      perguntou por       descobriu a        alcancou
                      interface/rota      sub-rede interna   elo 4
braco A (grafo)          10 de 10            8 de 10          8 de 10
braco B (linear)          5 de 10            3 de 10          3 de 10
```

Nos dez pares, **descobrir a sub-rede prediz perfeitamente o elo 4 nos dois braços**: oito de oito no
braço A, três de três no braço B. Os dois pares em que o braço A ficou em elo 3 (03 e 05) são
exatamente os dois em que ele não descobriu.

### Três explicações alternativas testadas e descartadas

Para os sete braços B que não alcançaram, três explicações concorrentes foram testadas. Os dados por
braço:

| braço | elo | passo do último avanço | passos restantes | credencial validada | tentou `172.21.x` |
|---|---|---|---|---|---|
| B-01 | 3 | 12 | 68 | sim | **não** |
| B-02 | 2 | 42 | 38 | sim | **não** |
| B-05 | 3 | 17 | 63 | sim | **não** |
| B-06 | 3 | 10 | 70 | sim | **não** |
| B-07 | 3 | 15 | 65 | sim | **não** |
| B-09 | 3 | 12 | 68 | sim | **não** |
| B-10 | 3 | 13 | 67 | sim | **não** |

```
falta de credencial     DESCARTADA  os 7 tinham a credencial validada
falta de orcamento      DESCARTADA  tinham de 38 a 70 passos sobrando apos o ultimo avanco
falha de execucao       DESCARTADA  NENHUM emitiu um unico comando contra a rede interna
```

⚠️ **E não é perda de memória, que é o que a hipótese prediria.** Em **cinco** dos sete (B-05, B-06,
B-07, B-09, B-10) o agente **nunca pediu** interface nem rota: a informação não foi perdida, ela nunca
foi obtida. Nos outros dois ele pediu tão tarde (passos 76 e 52) que não houve o que fazer com a
resposta. A seção de sub-redes do grafo deles está vazia porque nada a preencheu, não porque algo a
apagou. **Isso corrige o que a hipótese levava a esperar**, e é o achado mais interessante do
trabalho.

### O que as justificativas do agente dizem

O agente escreve uma justificativa por passo, e as vinte foram lidas. Elas mostram gatilhos
diferentes, citadas literalmente do registro:

```
BRACO A: enumera topologia como PROCEDIMENTO de pos-comprometimento
  p4   "Com RCE confirmado como root em h03, enumerar interfaces de rede para
        descobrir possiveis sub-redes adicionais antes de avancar lateralmente"
  p20  "Enumerar interfaces do host de deploy para descobrir possiveis pivos
        antes de buscar escalonamento de privilegio"

BRACO B: considera topologia como ULTIMO RECURSO, por esgotamento
  p18  "ANTES DE INSISTIR em buscas de arquivos, verificar se h05 possui outra interface"
  p52  "Buscas por arquivos e credenciais ESTAGNARAM; verificar interfaces..."
  p66  "h03/h05 e a app web de h04 PARECEM ESGOTADOS sem trofeu; preciso verificar..."
  p76  "e um ANGULO NOVO NAO TENTADO antes de continuar insistindo no login travado"
```

⚠️ **Justificativa é tratada como o que o agente diz, não como o que o determinou.** Um agente não
narra necessariamente a causa real do próprio comportamento. O que se afirma é que a explicação
temporal aparece no registro, em dez de dez justificativas de um lado e cinco de cinco do outro.

### Duas explicações do mecanismo que foram eliminadas

A interpretação inicial era que a serialização do braço A tem uma seção de sub-redes **nomeada e
visivelmente vazia**, e que isso tornaria visível o que falta. Ela foi testada, e duas verificações a
enfraqueceram:

```
1. o campo vazio nao aparece no registro
   nenhuma das dez justificativas do braco A menciona a secao, o grafo
   ou ausencia de dado

2. deslocamento por tamanho de prompt: REFUTADA
   quando o braco B perguntou, o prompt estava a 1,26x a mediana dele
   medianas de prompt: nunca perguntou 7.216 tokens, perguntou 7.116
   ou seja, quem perguntou nao estava com prompt MENOR
```

**O mecanismo fica declarado como aberto.** O comportamento temporal foi medido; a causa específica
não foi isolada, e isolá-la exigiria manipular um componente, não analisar mais os dados já
existentes.

---

## 7. Limitações

**A validade externa é estreita, e é a principal limitação do trabalho.** Um laboratório, uma cadeia
de exploração, um modelo de linguagem, dez pares. A conclusão é sobre este cenário. Afirmar que
"grafos de estado melhoram agentes de teste de invasão" em geral seria indevido, e não se afirma.
Soma-se a isso que o modelo foi referenciado por alias, sem snapshot datado, e que há pacotes do
laboratório sem versão fixada: a reprodução estritamente idêntica no futuro é limitada por isso.

**O mecanismo foi descrito, não manipulado.** Sabe-se *que* a representação de estado produz a
diferença e *qual comportamento* a acompanha. Não se sabe qual componente da representação a causa.

### A heterogeneidade do instrumento, declarada

A coleta não rodou sob uma única versão de código. Dentro de cada par os dois braços são
byte-idênticos, e isso é verificado por programa. Entre pares, comparando apenas as árvores de código
de que o agente depende, a coleta tem **duas** árvores de instrumento:

| pares | identificador da árvore de código | diferença |
|---|---|---|
| 1 | `1631d9625192` | |
| 2 a 5 | `bed368f2af6b` | +115 linhas de trava de concorrência, que o agente não vê |
| 6 a 10 | `bed368f2af6b` mais um conserto | o resumo do `hydra` passa a devolver o comando inteiro |

Os identificadores acima são o resumo criptográfico da árvore de arquivos versionada, e estão aqui
para que a afirmação *"duas árvores, não cinco"* seja conferível e não apenas alegada.

A primeira fronteira atua **antes** da execução e não é observável pelo agente. A segunda muda o que o
agente vê, e é a que exige declaração.

### Três defeitos do instrumento encontrados e corrigidos após a coleta

Os três foram medidos **antes de qualquer decisão sobre eles**, porque decidir primeiro e medir depois
seria escolher o resultado. Os dados de cada um:

#### Defeito 1: o rótulo de uma ferramenta escondia parte do comando

O resumo do `hydra` apresentado ao braço A removia opções como a lista de senhas e o paralelismo. O
agente relia o próprio histórico, não via a opção, e repetia ação já executada.

```
passos perdidos para o rotulo truncado
  braco A   A-02  3 passos      A-05  1 passo      A-06  8 passos      TOTAL 12
  braco B                                                              TOTAL  0

ATENCAO AO ESCOPO: a coleta-A-06 foi parada e descartada no passo 68 de 80, em
elo 2, com US$ 2,7322 gastos, e preservada com o motivo gravado dentro.
  o total de 12 INCLUI essa execucao descartada
  na coleta ENTREGUE (os dez pares) sao 4 passos: A-02 tres e A-05 um
```

**Era assimétrico entre os braços, e isso viola a condição de paridade imposta ao desenho:** o braço B
recebia o comando real, com a opção intacta; só o braço A passava pelo rótulo. **E o viés corre contra
o braço da hipótese**, o que torna o resultado mais difícil de descartar, não mais fácil.

O controle é forte, e não é falta de amostra: a `coleta-B-02` rodou `hydra` **13 vezes ao longo de 32
minutos**, mais que qualquer outra execução, e nunca alegou falta de lista. Ela depurou a sintaxe com
precisão que o braço A não tinha como ter:

```
B-02 p37  "Corrigir a ordem de argumentos do hydra (alvo antes do nome do servico)"
B-02 p38  "O hydra avisou explicitamente para reduzir paralelismo para -t 4"
```

Ordem de argumentos e o valor anterior do paralelismo: quem vê o comando consegue, quem vê o rótulo
não.

**Posição das quatro ocorrências nos pares entregues, relativa ao desfecho:**

```
A-02   elo 4 no passo 15, hydra nos passos 40 a 50     POSTERIOR ao desfecho
A-05   elo 3 no passo 19, hydra nos passos 60 e 67     posterior ao elo maximo
```

**O resíduo fica declarado, sem minimização:** o `A-05` perdeu 2 passos de 80 parado em elo 3, e elo 4
é o sucesso primário. **Não se afirma que esses 2 passos não teriam virado um elo 4.** Essa é a
exposição irredutível da coleta.

#### Defeito 2: sessão concedida a conexão que esgotou o tempo

A função que decide se uma autenticação teve sucesso podia conceder sessão a uma conexão que estourou
o tempo limite sem produzir saída alguma.

```
ocorrencias na coleta   ZERO (varredura das 1.600 linhas de registro)
```

Corrigido depois do fechamento, com 9 verificações e 4 mutações. Zero ocorrências significa que nenhum
dado reportado depende dele, e isso foi conferido antes de a correção ser escrita.

#### Defeito 3: caminho negado pela própria saída entrava como verificado

Quando a saída de um comando dizia explicitamente que o arquivo não existia, o caminho ainda assim
podia ser gravado no grafo como verificado.

```
mencoes totais do padrao no registro
  braco A   A-03 1  A-04 17  A-05 1  A-06 3  A-07 7  A-08 4    = 33
  braco B   B-03 7  B-04 1                                     =  8

mas a medida que DECIDE e outra: passos que AGIRAM sobre caminho ausente
E sao ANTERIORES ao desfecho do braco
  coleta-A-08  p66       /var/app/images
  coleta-B-03  p44, p45  /home/svc_deploy/.bash_history
  TOTAL: 3 passos em 1.600, SIMETRICO entre os bracos (1 em A, 2 em B)
```

⚠️ **O diagnóstico inicial deste defeito estava errado, e isso fica registrado.** A origem dos
caminhos foi inferida pela aparência do dado, como referência em arquivo de configuração, sem teste. A
guarda contra esse caso funcionava. O mecanismo real era o eco do próprio candidato pelo agente, e o
passo que mostrava isso estava a uma consulta de distância. Daí a regra adotada: não inferir o
mecanismo da aparência do dado, ir ler o passo que o produziu.

**Nenhum dos três alterou o resultado medido**, e cada um está documentado com contraexemplo e teste
de regressão. O que isso **não** garante é que uma repetição com o instrumento corrigido produziria
exatamente as mesmas trajetórias.

### Uma decisão metodológica que merece escrutínio

Antes da coleta da segunda metade dos pares, foi escrito um protocolo de tratamento de defeitos que
determina refazer os pares em que um defeito se manifestou antes do desfecho. Pela letra desse
protocolo:

```
pela LETRA do protocolo, vao para refacao
  par 3   coleta-B-03  p44 e p45, antes do elo 4 no p63
  par 8   coleta-A-08  p66, antes do elo 4 no p71
  custo medido dos quatro bracos: US$ 7,99
    A-03 2,08   A-08 2,14   B-03 1,84   B-08 1,92
```

Depois foi acrescentada a condição *"e o braço terminou abaixo do elo 4"*, que zera essa fila. O
argumento é que passo perdido antes de alcançar o elo 4, num braço que **alcançou** o elo 4, não pode
ter alterado a medida.

⚠️ **Esse refinamento foi formulado depois de ver os dados, e é por isso que os dois vereditos são
reportados** em vez de apenas o mais conveniente, deixando a aritmética aberta à conferência. A
recomendação é manter os pares, e a razão decisiva não é a aritmética: refazer os pares 3 e 8 agora os
poria numa terceira árvore de instrumento, enquanto os outros oito ficam na segunda. Ficaria pior que
hoje.

---

## 8. Questões abertas

**1. Qual componente da representação de estado produz o efeito.** O experimento está desenhado e
**não foi executado**. A conta de poder, com o controle já colhido (os dez braços B atuais, 5 de 10
perguntando) e custo medido de US$ 2,29 por braço no pior caso:

```
                                    q=100%   q=90%   q=80%   q=70%
controle 10 + 20 novos, US$ 46
  desfecho binario                    100%     68%     21%      4%
  desfecho ordenado                   100%    100%     89%     45%
grupos iguais n=20, 30 novos, US$ 69
  desfecho binario                    100%     88%     54%     22%
  desfecho ordenado                   100%    100%     94%     64%

q = fracao do braco novo que pergunta.  alfa = 0,05 unicaudal.
```

Duas consequências registradas. Primeira: **o desfecho ordenado domina o binário sem custo
adicional**, e por isso é o que entra no pré-registro. Segunda, e é a que mais pesa: **o desenho que
cabe no orçamento é assimétrico, só informa se confirmar.** Para 80% de poder contra um efeito de 70%
seriam cerca de 50 braços novos, US$ 114. Dentro de US$ 70, um resultado negativo não distingue *"o
campo não faz diferença"* de *"faz uma diferença moderada que o desenho não vê"*, e isso tem de estar
no pré-registro, não ser descoberto depois.

**A recomendação é não executar agora**, e a razão não é o custo: é o alvo. O teste examinaria a
interpretação do campo vazio, que é justamente a que perdeu apoio na leitura das justificativas do
braço A.

**2. A letra do protocolo de defeitos, contra o refinamento aplicado.** Decisão ainda pendente, com os
números da seção 7: aplicar a letra custa **US$ 7,99** e quatro execuções, e não altera nenhuma medida
já reportada. Altera apenas qual conjunto de dados sustenta o relato, e cria uma terceira árvore de
instrumento.

**3. O nome definitivo do artefato.** Decisão adiada; o pacote se chama `artefato`. O custo de
renomear cresce com o código já escrito e está declarado: hoje são doze verificadores, 793 mutações e
20 execuções referenciando esse caminho.

---

## 9. Estado do trabalho

```
coleta de dados             CONCLUIDA   10 pares, 20 execucoes, 1.600 passos, US$ 39,80
tabulacao das 11 metricas   CONCLUIDA   gerada por programa, 726 linhas
suite de testes             3.940 verificacoes, todas passando
bateria de mutacao          793 mutacoes cadastradas, 0 ancoradouro morto
registro metodologico       cada decisao com data e justificativa, sem lacuna
capitulo 3 do relatorio     PENDENTE, condicionado ao template LaTeX
```

O cronograma prevê congelamento do artefato em **9 de novembro** e entrega em **1º de dezembro**, o
que deixa cinco semanas para a redação a partir dos dados já colhidos.

---

## O que existe para auditoria

Tudo neste documento é conferível nos artefatos produzidos, e o próprio documento é verificado por
programa contra eles. Os caminhos são relativos à raiz do repositório:

| arquivo | o que contém |
|---|---|
| `src/artefato/` | o agente, os invólucros de ferramenta, o grafo de estado e os doze verificadores |
| `src/artefato/testes*.py` | seis suítes, 3.940 verificações |
| `src/artefato/mutacoes.py` | a bateria de mutação, 793 mutações cadastradas |
| `lab/docker-compose.yml` | os sete contêineres e as duas sub-redes |
| `lab/cadeia.md` | os onze passos da cadeia, com a saída literal de cada comando |
| `execucoes/` | os vinte registros de execução, passo a passo, 1.600 linhas |
| `docs/resultados/coleta.md` | a tabela dos dez pares e das onze métricas, **gerada**, 726 linhas |
| `guia/CONTEXTO.md` | fundamentação, o levantamento das cinco soluções e a hipótese |
| `guia/ARTEFATO.md` | o desenho do experimento, as onze métricas e o critério de sucesso |
| `docs/ajustes.md` | **todo ajuste** do instrumento, do laboratório e do protocolo, com estado e impacto |
| `docs/heterogeneidade-do-instrumento.md` | a declaração das versões de instrumento entre pares |
| `docs/relatorio-pares-6-a-10.md` | o fechamento da coleta, verificação por verificação |
| `docs/conferir-sintese.py` | o script que confere este documento contra as fontes |
| `docs/motor.md` | a medição que decidiu o modelo de linguagem adotado |
| `docs/premissa.md` | a verificação da premissa nas fontes primárias do levantamento |

### O registro de decisões, e por que ele não está neste repositório

O desenvolvimento manteve dois registros contínuos: um com **toda decisão técnica, numerada, datada e
justificada**, com as alternativas descartadas e o motivo do descarte, hoje em 256 entradas sem lacuna
na numeração; e o par dele, com as observações de campo na ordem em que aconteceram, incluindo as
interpretações que foram propostas e depois abandonadas quando medidas.

**Os dois são o andaime do trabalho, não a entrega.** Existem para que o capítulo seja escrito a
partir de fatos recuperáveis em vez de memória. São somados a oito mil e dezessete mil linhas de
diário de desenvolvimento, escritas em notação interna, e **ficam preservados fora deste
repositório**.

O que entra no lugar deles é `docs/ajustes.md`, derivado dos dois: reúne todo ajuste do instrumento,
do laboratório e do protocolo, com a motivação de cada um, o problema que resolve, o estado atual
(concluído, pendente, decidido como não ajustar, ou apenas proposto) e o impacto. **Qualquer número
desta síntese é rastreável até o ajuste que o produziu**, sem exigir a leitura do diário.

⚠️ **A tabela de resultados é gerada, não escrita.** A razão é que número digitado à mão envelhece em
silêncio: se os registros mudarem e a tabela não for regerada, ninguém percebe. Pelo mesmo motivo, as
afirmações quantitativas desta síntese são conferidas por script contra as fontes, com 247
verificações que rodam em qualquer cópia deste repositório, e a conferência falha se qualquer uma
divergir. A contagem da suíte é uma delas, e é **medida** executando as seis suítes e contando o que
elas imprimem, em vez de lida de um número escrito à mão.
