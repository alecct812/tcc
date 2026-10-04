# Ajustes do instrumento, do laboratório e do protocolo

**Documento complementar à síntese dos resultados.** Reúne todo ajuste feito, decidido ou proposto
sobre o instrumento de medida, o laboratório e o protocolo de coleta, com a motivação de cada um, o
problema que resolve, o estado atual e o impacto.

---

## Como ler este documento

Cada ajuste aparece com um **estado explícito**, e os três estados não se misturam:

```
CONCLUIDO    aplicado, com teste de regressao, e a data situa o ajuste em
             relacao a coleta: antes do primeiro par valido, entre pares,
             ou depois do fechamento
PENDENTE     a decisao esta tomada ou identificada, e a execucao nao
NAO AJUSTAR  o defeito foi medido e a decisao foi deliberadamente nao
             consertar, com a razao registrada
PROPOSTO     desenhado e nao executado. Nenhum dado foi produzido
```

**A regra que organiza todos eles: nada se ajusta com uma coleta em curso.** Mudar o instrumento no
meio de um par torna as duas execuções incomparáveis, o que destrói a única garantia que o desenho
oferece. Por isso os ajustes se concentram em dois momentos: antes do primeiro par válido e depois do
fechamento do último.

**A linha do tempo da coleta válida**, para situar cada ajuste:

```
1 e 2 de outubro      ajustes no extrator de fatos e no laboratorio
                      as tentativas anteriores de par 1 foram DESCARTADAS e
                      estao preservadas, com o motivo no nome da pasta
2 de outubro, 13h20   par 1 (inicio da coleta valida)
entre o par 5 e o 6   um unico ajuste no meio da coleta, declarado na sintese
3 de outubro, 11h49   par 10 (fechamento)
depois do fechamento  tres defeitos corrigidos de proposito nessa ordem,
                      para que nao pudessem afetar dado nenhum
```

---

## Parte 1. O laboratório como instrumento de medida

### 1.1. O limitador de conexões SSH punia mais o braço que tentava mais

**Estado: CONCLUÍDO, antes do primeiro par válido.**

**O problema.** Os servidores SSH do laboratório usavam o padrão do OpenSSH para conexões
simultâneas pendentes. Autenticação que falha segura o lugar na fila por até dois minutos, e acima de
dez pendentes o servidor recusa cerca de 30% das conexões com um erro de transporte. Medido no corpo
inteiro de execuções anteriores:

```
braco A    1 passo de recusa em 2.957    (0,0%)
braco B   21 passos de recusa em 1.781   (1,2%)   trinta vezes mais, por passo
pior caso: uma execucao perdeu 13 passos de 80, 16% do orcamento
```

**Por que era grave, e a direção importa.** O braço B tenta mais e falha mais, portanto era mais
punido. Isso fazia o braço B parecer pior por uma razão que **não tem nenhuma relação com a
estratégia de representação de estado**. O efeito empurrava o resultado na direção que **favorece a
hipótese do trabalho**, e um defeito cujo sintoma é o resultado desejado é o mais difícil de
encontrar, porque nada no resultado chama atenção.

**O ajuste.** O teto de conexões pendentes foi elevado nos quatro hosts que rodam SSH, e não apenas
no pivô onde o efeito foi medido, porque o agente tenta autenticar em todos e assimetria em um host
continua sendo assimetria.

**Desvio declarado.** O laboratório fica menos parecido com uma instalação padrão. Isso é deliberado:
o laboratório é instrumento de medida, e instrumento que reage ao quanto o sujeito se debate não mede
o sujeito. A especificação do experimento exige condições **idênticas** entre os braços, não
fidelidade a um padrão de distribuição.

**Impacto nos resultados.** Devolve ao braço B os passos que o limitador tomava dele, e portanto
**tende a reduzir a diferença entre os braços**. O resultado publicado foi obtido já com o ajuste
aplicado, isto é, sob a condição menos favorável à hipótese.

### 1.2. O verificador do laboratório passou a conferir o disco

**Estado: CONCLUÍDO, antes do primeiro par válido.**

**O problema.** A verificação de limpeza do laboratório entre braços conferia o estado dos
contêineres, mas não o conteúdo em disco. Um arquivo deixado por uma execução anterior podia
sobreviver à verificação e ser encontrado pela execução seguinte, que o acharia sem o ter produzido.

**O ajuste.** A verificação passou a conferir o disco. A ficha do que precisa estar presente saiu do
diretório do laboratório, para que o verificador não validasse o laboratório contra um arquivo que o
próprio laboratório fornece.

**Impacto.** Fecha uma via pela qual uma execução poderia herdar informação da anterior. A
verificação correspondente está entre as seis aplicadas ao fechamento de cada braço, e o resultado
registrado é que em todos os braços que usaram listas de palavras o download precede o uso.

---

## Parte 2. O extrator de fatos

O princípio do desenho é que a saída bruta das ferramentas nunca chega ao modelo: apenas os fatos que
o extrator reconheceu e gravou. Isso torna o extrator parte do instrumento de medida, e um erro nele
grava fato falso com aparência de fato medido. Os quatro ajustes abaixo são todos da mesma classe.

### 2.1. Quatro sintaxes de comentário entravam como fato provado

**Estado: CONCLUÍDO, antes do primeiro par válido.**

**O problema.** Linhas de comentário em arquivos de configuração mencionam caminhos que não existem,
ou que existem em outro host. O extrator não distinguia comentário de conteúdo efetivo, e **oito de
cada dez dessas menções entravam no grafo como caminho provado**.

**O ajuste.** O reconhecimento das quatro sintaxes de comentário alcançáveis no laboratório, com os
contraexemplos como teste.

**Impacto.** Remove uma fonte de caminho falso que o agente poderia tentar usar, gastando passos do
orçamento com base em informação que o instrumento inventou.

### 2.2. Texto sem forma de nome virava credencial

**Estado: CONCLUÍDO, antes do primeiro par válido.**

**O problema.** O extrator reconhecia atribuições de usuário em arquivos de configuração, mas não
verificava se o valor extraído tinha forma de nome. Uma referência a variável de shell foi gravada
como nome de usuário válido.

**Impacto.** Esse defeito **custou uma execução do braço A**, que foi descartada e está preservada.
O ajuste exige que o valor tenha forma plausível de nome antes de virar credencial.

### 2.3. A associação entre endereço e caminho era descartada

**Estado: CONCLUÍDO, antes do primeiro par válido.**

**O problema.** Quando a saída de um comando trazia na mesma linha um endereço e um caminho, o
extrator tinha a associação entre os dois e a descartava, gravando apenas o caminho sem o host a que
pertence. Um caminho sem host é menos útil e mais perigoso: o agente pode tentá-lo no host errado.

**O ajuste.** A associação passou a ser preservada.

### 2.4. Fragmentos de dados codificados viravam caminho

**Estado: CONCLUÍDO, durante o desenvolvimento, antes da coleta válida.**

**O problema.** Fragmentos de base64 e de hashes contêm barras, e barras pareciam caminho. O extrator
gravava caminhos curtos inexistentes a partir de dados binários codificados. O caso foi observado numa
execução piloto do braço B.

**O ajuste.** Reconhecimento desses fragmentos, com os contraexemplos como teste. Na mesma frente
foram corrigidos dois casos vizinhos: a truncagem de caminho por dois-pontos e a entrada como provado
de caminho apenas mencionado no conteúdo de um arquivo, sem endereço na mesma linha.

---

## Parte 3. O arnês de execução

### 3.1. Uma execução por pasta

**Estado: CONCLUÍDO, aplicado entre o par 1 e o par 2.**

**O problema.** Nada impedia que duas execuções escrevessem na mesma pasta de registro. Isso
aconteceu: duas rodaram simultaneamente e **corromperam a terceira tentativa de um par**, que foi
descartada.

**O ajuste.** Uma trava de concorrência que recusa a segunda execução sobre a mesma pasta.

**Impacto na comparabilidade, e é o que exige declaração.** Este ajuste é a razão pela qual o par 1
está sob uma árvore de código e os pares 2 a 5 estão sob outra. A trava atua **antes** da execução
começar e não é observável pelo agente: ela não altera prompt, ferramenta, orçamento nem o que o
modelo vê. Por isso a heterogeneidade que ela cria é declarada, mas não afeta o que foi medido.

### 3.2. O marcador de árvore suja

**Estado: CONCLUÍDO, depois do fechamento.**

**O problema.** O registro de cada execução anota o identificador da versão de código, com um
marcador quando a árvore tem modificação não versionada. Esse marcador aparecia em todas as
execuções, e a investigação mostrou que **ele nunca poderia estar ausente**: a própria execução suja a
árvore ao criar seus arquivos de registro.

**O ajuste.** A documentação do campo passou a dizer isso, em vez de deixar um marcador permanente
parecer um aviso.

**Impacto.** Nenhum nos dados. O ajuste remove um falso sinal de alarme que levaria quem auditasse a
desconfiar das vinte execuções por um motivo inexistente.

---

## Parte 4. Ajustes concluídos depois do fechamento da coleta

Os três defeitos abaixo foram encontrados depois de o último par fechar. **A ordem foi deliberada:**
corrigi-los antes teria criado mais uma fronteira de versão no meio da coleta; corrigi-los depois
garante que não podem ter afetado dado nenhum. Os três foram **medidos antes de qualquer decisão**
sobre eles, porque decidir primeiro e medir depois é escolher o resultado.

### 4.1. O resumo de uma ferramenta escondia parte do comando

**Estado: CONCLUÍDO, e é o único ajuste aplicado no meio da coleta.**

**O problema.** O resumo da ferramenta de força bruta apresentado ao braço A removia opções, entre
elas a lista de senhas e o grau de paralelismo. O agente relia o próprio histórico, não via a opção, e
repetia uma ação já executada acreditando que faltava um argumento.

```
passos perdidos para o resumo truncado
  braco A   3 passos numa execucao, 1 noutra, 8 numa terceira    total 12
  braco B                                                        total  0

ESCOPO: a terceira execucao foi parada e descartada no passo 68 de 80.
  o total de 12 INCLUI essa execucao descartada
  na coleta entregue, de dez pares, sao 4 passos
```

**Por que era grave.** Era **assimétrico entre os braços**, e assimetria viola a condição de paridade
que o desenho impõe: o braço B recebia o comando real, com a opção intacta, e apenas o braço A passava
pelo resumo. O controle é forte e não é falta de amostra: uma execução do braço B rodou a mesma
ferramenta treze vezes ao longo de trinta e dois minutos, mais que qualquer outra, e nunca alegou
falta de lista; ela depurou a sintaxe com precisão que o braço A não tinha como ter, porque via o
comando.

**A direção do viés.** Corre **contra o braço da hipótese**, o que torna o resultado mais difícil de
descartar, não mais fácil.

**O ajuste.** O resumo passou a devolver o comando integral. Para essa ferramenta nada é invariante,
e portanto não há ruído fixo a economizar.

**Impacto nos resultados, com o resíduo declarado.** As quatro ocorrências nos pares entregues são
posteriores ao desfecho do braço em que ocorreram. A exposição irredutível é de **dois passos de
oitenta** numa execução que terminou um elo abaixo do sucesso primário. **Não se afirma que esses dois
passos não teriam virado um sucesso.** Essa é a exposição residual da coleta, e ela fica declarada.

### 4.2. Sessão concedida a conexão que esgotou o tempo

**Estado: CONCLUÍDO, depois do fechamento.**

**O problema.** A função que decide se uma autenticação teve sucesso podia conceder sessão a uma
conexão que estourou o tempo limite sem produzir saída alguma. O julgamento usava a ausência de certa
mensagem de erro, e tempo esgotado sem saída não produz essa mensagem.

```
ocorrencias na coleta   ZERO, em varredura das 1.600 linhas de registro
```

**O ajuste.** O julgamento passou a exigir saída efetiva, e não a ausência de erro. A guarda exige
saída no canal padrão e não a ausência de mensagem no canal de erro, porque o aviso de chave de host
desconhecida chega pelo canal de erro antes de qualquer autenticação.

**Impacto.** Nenhum nos dados reportados, e isso foi conferido **antes** de a correção ser escrita.
Zero ocorrências significa que nenhum número publicado depende dele.

### 4.3. Caminho negado pela própria saída entrava como verificado

**Estado: CONCLUÍDO, depois do fechamento.**

**O problema.** Quando a saída de um comando dizia explicitamente que o arquivo não existia, o
caminho ainda assim podia ser gravado como verificado. O agente então agia sobre um caminho que a
mesma saída havia negado.

```
mencoes do padrao no registro             33 no braco A, 8 no braco B
a medida que DECIDE: passos que AGIRAM sobre caminho ausente
  E sao anteriores ao desfecho do braco    3 passos em 1.600
  simetrico entre os bracos                1 no braco A, 2 no braco B
```

**O ajuste.** Caminho que a saída do comando declara ausente é **descartado**, e não rebaixado a
menção. Rebaixar convidaria o mesmo caminho a voltar por outra via.

**Um erro de diagnóstico que fica registrado.** A origem desses caminhos foi inicialmente inferida
pela aparência do dado, como referência em arquivo de configuração, sem teste. A guarda contra esse
caso funcionava. O mecanismo real era o eco do próprio candidato pelo agente, e o passo que mostrava
isso estava a uma consulta de distância. A regra que isso gerou: não inferir o mecanismo a partir da
aparência do dado, ir ler o passo que o produziu.

### 4.4. Caminhos efêmeros reprovavam uma execução correta

**Estado: CONCLUÍDO, depois do fechamento.**

**O problema.** O verificador de caminhos reprovou um braço porque o grafo registrava um terminal
virtual, que existe durante a sessão e desaparece quando ela fecha. **O defeito era do verificador, e
não do grafo:** o caminho existia quando foi observado.

**O ajuste.** Caminhos sob as árvores efêmeras do sistema passaram a ser classificados como
indeterminados, e não como inexistentes. Não saber não autoriza afirmar que não existe.

**Impacto.** Nenhum nos dados. O ajuste evita que uma execução correta seja descartada por um
veredito falso do próprio instrumento de verificação.

### 4.5. Cinco mutações da bateria não testavam nada

**Estado: CONCLUÍDO, depois do fechamento.**

**O problema.** A bateria de mutação introduz um defeito conhecido por vez e confere que algum teste o
detecta. Correções anteriores mudaram o código que cinco mutações ancoravam, e **âncora não encontrada
não falha**: a mutação simplesmente deixa de ser aplicada, e o anel de proteção fica sem prova. As
cinco apareciam como aplicadas e mortas.

**O ajuste.** As cinco foram reescritas contra o código atual, e uma sexta, órfã por um ajuste
posterior, também. Um verificador dedicado passou a afirmar, a cada execução da bateria, que nenhuma
âncora está morta, ambígua ou inócua.

**Impacto.** Nenhum nos dados, e tudo na confiança que se pode depositar na bateria. O estado atual é
zero âncora morta em 793 mutações cadastradas.

### 4.6. Uma medida ordenada do comportamento de busca

**Estado: CONCLUÍDO, depois do fechamento. Não é correção de defeito.**

**O que é.** Uma medida da ação de pedir interfaces de rede ou tabela de rotas que usa, de uma vez,
**se** o agente pediu e **em que passo**, marcando quem nunca pediu no teto de oitenta passos. A medida
anterior era binária e descartava o momento, que é a maior parte do sinal.

```
sobre os mesmos vinte bracos ja colhidos
  desfecho binario    p = 0,016254
  desfecho ordenado   p = 0,000227
```

**Dois pontos que limitam o uso dessa medida.** Primeiro: ela é **exploratória**, escolhida depois de
ver os resultados, e não está entre as métricas pré-registradas; nenhum p-valor dela confirma
hipótese. Segundo: a implementação revelou um defeito próprio, descrito abaixo, e o número acima é o
posterior ao conserto.

**Um defeito encontrado no próprio ajuste.** A primeira versão do reconhecimento de comandos não
casava a leitura da tabela de rotas pela via do arquivo de sistema, porque a construção do padrão
impedia o casamento. Sete dos oito passos que leem rota por essa via o fazem assim. Uma execução
aparecia perguntando trinta e um passos mais tarde do que de fato perguntou, **e a mediana do braço
não mudava**, o que torna o erro invisível no agregado. O conserto está coberto por teste de
regressão com a forma real que o laboratório entrega.

---

## Parte 5. Defeitos medidos com decisão de NÃO ajustar

Esta parte existe porque decisão de não consertar também é decisão, e esconder as duas que foram
tomadas tornaria a lista de ajustes enganosa.

### 5.1. O resumo de duas ferramentas descarta a saída

**Estado: NÃO AJUSTAR, com a perda medida.**

Duas das seis ferramentas oferecidas ao modelo não têm invólucro com extração dedicada, e sua saída é
descartada em vez de virar fato. A perda foi medida, as quatro opções de conserto foram avaliadas, e
cada uma foi descartada por um motivo registrado. **O que fica declarado é a perda**, e não a
impressão de que todas as ferramentas recebem o mesmo tratamento.

### 5.2. A frase de escopo é mais estrita que a guarda de escopo

**Estado: NÃO AJUSTAR, com a divergência declarada.**

O texto do prompt descreve o escopo permitido de forma mais restritiva do que a guarda que o
verifica em código. A divergência foi medida e a decisão foi mantê-la, porque alinhar as duas exigiria
mudar o prompt, o que inviabiliza a comparação com as execuções já colhidas. O efeito é que o agente
é informado de um limite mais estreito do que o que o arnês aplicaria.

---

## Parte 6. Ajustes pendentes

### 6.1. A letra do protocolo de defeitos contra o refinamento aplicado

**Estado: PENDENTE, decisão do autor.**

O protocolo de tratamento de defeitos, escrito antes da coleta da segunda metade dos pares, determina
refazer os pares em que um defeito se manifestou antes do desfecho. Pela letra desse protocolo, dois
pares iriam para refação:

```
pela LETRA do protocolo
  um par   o defeito disparou nos passos 44 e 45, antes do sucesso no passo 63
  outro    o defeito disparou no passo 66, antes do sucesso no passo 71
  custo medido dos quatro bracos: US$ 7,99
```

Depois foi acrescentada a condição *"e o braço terminou abaixo do sucesso primário"*, que zera essa
fila, com o argumento de que passo perdido antes de alcançar o sucesso, num braço que **alcançou** o
sucesso, não pode ter alterado a medida.

⚠️ **Esse refinamento foi formulado depois de ver os dados.** É por isso que os dois vereditos são
reportados, em vez de apenas o mais conveniente, deixando a aritmética aberta à conferência.

**A recomendação registrada é manter os pares**, e a razão decisiva não é a aritmética: refazer os
dois pares agora os poria numa terceira árvore de instrumento, enquanto os outros oito ficam na
segunda. O resultado seria pior que o estado atual.

### 6.2. A emissão das tabelas de resultado em formato de publicação

**Estado: PENDENTE, condicionado a um insumo externo.**

A tabela de resultados é gerada por programa, e nenhum número dela é digitado. A redação do capítulo
será feita em LaTeX, e redigitar aquelas tabelas à mão quebraria essa garantia **no momento em que os
números entram no documento final**, que é o pior lugar para quebrá-la. O ajuste registrado é ensinar o
gerador a emitir as tabelas também em LaTeX, reusando a mesma implementação da métrica, sem uma
segunda. Depende do template a ser adotado, para que o formato saia compatível.

### 6.3. O nome definitivo do artefato

**Estado: PENDENTE, decisão adiada pelo autor.**

O pacote se chama `artefato`. O custo de renomear cresce com o código já escrito e está declarado:
doze verificadores, 793 mutações e vinte execuções referenciam esse caminho.

---

## Parte 7. Ajustes apenas propostos

### 7.1. O teste de terceiro braço, para isolar o mecanismo

**Estado: PROPOSTO. Desenhado, não executado. Nenhum dado produzido.**

O resultado publicado sustenta que a representação de estado produz a diferença, porque foi a única
variável manipulada. **Não** identifica qual componente da representação a causa. Isolar isso exige um
terceiro braço com um componente alterado, e o desenho está registrado com a conta de poder:

```
                                    q=100%   q=90%   q=80%   q=70%
controle 10 + 20 novos, US$ 46
  desfecho binario                    100%     68%     21%      4%
  desfecho ordenado                   100%    100%     89%     45%
grupos iguais n=20, 30 novos, US$ 69
  desfecho binario                    100%     88%     54%     22%
  desfecho ordenado                   100%    100%     94%     64%

q = fracao do braco novo que exibe o comportamento.  alfa = 0,05 unicaudal.
```

**Duas consequências do desenho, registradas antes de qualquer execução.** Primeira: o desfecho
ordenado domina o binário sem custo adicional, e por isso é o que entra no pré-registro. Segunda, e é
a que mais pesa: **o desenho que cabe no orçamento é assimétrico, só informa se confirmar.** Para 80%
de poder contra um efeito de 70% seriam cerca de cinquenta braços novos, US$ 114. Dentro de US$ 70, um
resultado negativo não distingue *"o componente não faz diferença"* de *"faz uma diferença moderada
que o desenho não vê"*.

**A recomendação é não executar**, e a razão não é o custo: é o alvo. O teste examinaria a
interpretação de que um campo nomeado e vazio na serialização induz a busca, e essa é justamente a
interpretação que perdeu apoio na leitura das justificativas do agente.

### 7.2. Reconhecer a assinatura do limitador de conexões no arnês

**Estado: PROPOSTO, registrado como melhoria futura.**

O ajuste de 1.1 removeu a causa elevando o teto do laboratório. A solução mais principiada seria
ensinar o arnês a reconhecer a assinatura daquela recusa e não gravá-la como resposta do alvo, porque
valor gravado por arnês defeituoso não é dado. Ela mora na camada compartilhada entre os braços e é
mais código; foi preterida em favor da que remove a causa com uma linha, e fica registrada.

---

## Onde cada ajuste é verificável

| evidência | onde |
|---|---|
| o código de cada conserto, com teste de regressão | `src/artefato/` |
| a bateria que confere se os testes detectam o defeito | `src/artefato/mutacoes.py` |
| os vinte registros de execução, passo a passo | `execucoes/` |
| as execuções descartadas, com o motivo no nome da pasta | mantidas localmente, fora deste repositório |
| o desenho do experimento e o critério pré-registrado | `guia/ARTEFATO.md` |
| os resultados por par, gerados por programa | `docs/resultados/coleta.md` |
| a declaração das versões de instrumento entre pares | `docs/heterogeneidade-do-instrumento.md` |

⚠️ **Sobre as execuções descartadas.** Elas não entram neste repositório por serem registro de
desenvolvimento, e não dado do experimento. Cada uma está preservada localmente com o motivo do
descarte no nome da pasta, e as que importam para avaliar o trabalho estão descritas aqui: a execução
perdida para o reconhecimento de nome em 2.2, a corrompida por concorrência em 3.1 e a interrompida
pelo resumo truncado em 4.1.
