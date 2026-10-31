# Agente de teste de invasão com estado explícito do ambiente

Artefato de Trabalho de Conclusão de Curso em Ciência da Computação, CESAR School.
Autor: **Alec Carneiro Theotônio**. Orientador: **Prof. Ronierison Maciel**.

**A pergunta:** manter o estado do ambiente fora da janela de contexto do modelo, numa estrutura
persistente, muda a capacidade de um agente de teste de invasão de descobrir e alcançar uma sub-rede
interna visível apenas de dentro de um host já comprometido?

**O resultado, em dez pares de execuções pareadas:**

```
metrica primaria, pre-registrada: sub-redes distintas com comando executado

  braco A, estado em grafo explicito    8 de 10
  braco B, memoria conversacional       3 de 10
  Fisher exato unicaudal                p = 0,0349

o criterio binario congelado antes da coleta (A >= 6/10 E B <= 2/10)
NAO FOI ATENDIDO: a metade de A passou, a de B falhou
```

A leitura completa, com as limitações e o que o desenho **não** autoriza concluir, está em
[`docs/sintese-para-orientacao.md`](docs/sintese-para-orientacao.md). **Comece por lá.**

---

## Aviso de uso restrito

Este repositório contém código e configuração destinados **exclusivamente** a um laboratório
isolado, local, em contêiner, sob controle do autor. As duas sub-redes são declaradas `internal` no
Docker, não têm rota para fora e não publicam porta no host.

Não há alvo de terceiros e não há exposição de rede externa. **Nada aqui deve ser executado contra
sistema que você não esteja autorizado a testar.** O uso fora desse enquadramento pode configurar
crime nos termos da Lei 12.737/2012.

A documentação de cada falha registra a **classe** da vulnerabilidade e onde ela está, com
identificador CWE, categoria OWASP, rota e parâmetro, e não ensina a explorá-la.

**Uma exceção, deliberada e delimitada:** `lab/cadeia.md` contém a sequência exata de comandos da
exploração, incluindo os payloads. Ela existe porque o método exige que a cadeia seja percorrida à
mão e documentada **antes** de o agente ser escrito: é a verdade de referência contra a qual o
comportamento do agente é conferido, e sem os comandos exatos ela não serviria para isso. Os alvos
são sete contêineres construídos pelo próprio autor, e os payloads não têm alvo fora dali.

### Credenciais e chaves neste repositório são ficção de laboratório

Para que o laboratório funcione, ele precisa conter o material que o agente deve encontrar. Está
tudo aqui, e nada disso tem valor fora dos contêineres:

```
lab/hosts/web/config.ini                       credencial de servico, sintetica
lab/hosts/db/deploy_ed25519                    chave SSH PRIVADA, gerada para este laboratorio
lab/hosts/atacante/senhas.txt                  lista de senhas, sintetica
lab/saidas-exemplo/senhas-das-capturas-*.txt   as mesmas senhas, nas capturas
lab/hosts/financeiro/trofeu.txt                o arquivo-alvo da cadeia
```

**A chave privada e as senhas foram criadas para este laboratório e nunca foram usadas em outro
lugar.** Elas são parte do instrumento de medida: sem elas o agente não tem o que descobrir. Chaves
de API de modelos de linguagem, essas sim reais, **nunca entram no repositório** e são lidas apenas
de variável de ambiente.

---

## Como reproduzir

**Requisitos:** Docker com Compose, **Python 3.13.6 ou posterior**, e uma chave de API da Anthropic
em variável de ambiente. A coleta publicada usou `claude-sonnet-5` em regime de raciocínio, com saída
estruturada, e rodou em Python 3.13.15.

⚠️ **O que decide é a versão de correção do Python, e não "3.12 contra 3.13".** Em versões anteriores
à correção, **duas verificações de `testes.py` falham**, as duas no parser de resposta HTTP
(`ferramentas/curl.py`). Medido nesta máquina (Windows), rodando `python testes.py` inteiro com
`PYTHONUNBUFFERED=1`, uma versão por linha:

```
versao      python testes.py    linhas OK    linhas FALHA
3.12.5      falha (codigo 1)    2.250        2
3.12.11     falha (codigo 1)    2.250        2
3.12.12     passa (codigo 0)    2.252        0
3.13.2      falha (codigo 1)    2.250        2
3.13.5      falha (codigo 1)    2.250        2
3.13.6      passa (codigo 0)    2.252        0
3.13.15     passa (codigo 0)    2.252        0     <- a da coleta
```

O limite está medido aqui nos dois ramos, e não inferido: **3.12.11 falha e 3.12.12 passa; 3.13.5
falha e 3.13.6 passa.** Por isso um 3.13 não basta (o 3.13.2 falha) e um 3.12 pode bastar (o 3.12.12
passa); o requisito é a versão da correção, e a menor 3.13 que a traz é a 3.13.6. As duas
verificações que falham são `curl: titulo nao fechado engole o documento, como manda o HTML` e `e o
que sobrou vira o titulo, sem inventar rota`.

A causa é a biblioteca padrão, não o projeto: o `html.parser` corrigiu o tratamento de `<title>`
**não fechado** (o modo de texto bruto escapável de `textarea` e `title`, registrado no
[changelog da 3.11](https://docs.python.org/pt-br/3.11/whatsnew/changelog.html) como gh-118350, na
3.11.14). Com `<title>abre e nao fecha</head><body><a href="/some?x=1">`, a versão corrigida deixa o
título engolir o resto do documento e nenhuma rota é extraída, enquanto a anterior ainda emite a tag
`<a>` e uma rota aparece. As duas verificações fixam o comportamento corrigido, que é o do HTML.

Medido em **outro ambiente (Linux), não nesta máquina**: 3.11.9 falha e 3.11.17 passa. Esse resultado
não foi reproduzido aqui, e fica registrado só para dizer de onde vem.

### 1. Subir o laboratório

```sh
cd lab && docker compose up -d
```

Sete contêineres em duas sub-redes. A verificação de que o isolamento vale está em
`lab/verificacao-rede.md`, e `src/artefato/conferir_lab.py` confere os endereços.

### 2. Rodar a suíte, que não gasta nada

```sh
cd src/artefato && python testes.py
```

**2.252 verificações**, sem chamar modelo e sem precisar do laboratório. `testes.py` é a única porta de
entrada: ele executa por subprocesso as outras sete suítes, então o total é o que ele imprime, e a
quebra soma esse mesmo total, sem contar nada duas vezes:

```
nucleo proprio de testes.py     509
grafo                           747   (testes_grafo.py)
laco de decisao                 557   (testes_laco.py)
medida de progresso             227   (testes_metricas.py)
memoria do braco B              102   (testes_memoria.py)
cadeia                           56   (testes_cadeia.py)
ensaio geral                     18   (ensaio.py)
paridade                         36   (paridade.py)
total                         2.252
```

A contagem é o número de linhas que começam com `OK`, e não depende de a saída ir para o terminal,
para um arquivo ou para um pipe: `testes.py` esvazia o buffer antes de cada suíte filha.

### 3. Conferir a cadeia à mão, antes de confiar no agente

`lab/cadeia.md` traz os onze passos com a saída literal de cada comando.
`src/artefato/percorrer_cadeia.py` percorre a cadeia pelo laço real, contra o laboratório no ar.

### 4. Executar um braço

```sh
cd src/artefato
export ANTHROPIC_API_KEY=...        # nunca em argumento de linha de comando

python -m laco autonomo --execucao minha-execucao --braco A     --origem 172.20.0.5 --limite 80 --ate-elo 5
```

`--braco A` serializa o grafo de estado no prompt; `--braco B` usa memória conversacional com
resumos de fase. Todo o resto é idêntico entre os dois, e é isso que o verificador de paridade
confere par a par.

⚠️ **Isso gasta crédito de API.** A coleta publicada custou **US$ 39,80** em vinte execuções, com
mediana de cerca de US$ 2 por execução de oitenta passos.

### 5. Reconferir os números publicados, de graça

```sh
cd src/artefato && python resultados_coleta.py --conferir   # a tabela de resultados
cd ../.. && python docs/conferir-sintese.py                 # a sintese contra as fontes
```

O primeiro regenera `docs/resultados/coleta.md` a partir dos registros de execução; **nenhum número
daquela tabela é digitado à mão**. O segundo confere 225 afirmações quantitativas da síntese contra
as fontes e falha se qualquer uma divergir.

---

## Estrutura

```
docs/sintese-para-orientacao.md   O PONTO DE ENTRADA: artefato, experimento e resultados
docs/ajustes.md                   todo ajuste do instrumento, do laboratorio e do protocolo,
                                  com estado (concluido / pendente / nao ajustar / proposto)
docs/resultados/coleta.md         os dez pares e as onze metricas, GERADO por programa
docs/relatorio-pares-6-a-10.md    o fechamento da coleta, verificacao por verificacao
docs/heterogeneidade-do-instrumento.md   as versoes de instrumento entre pares
docs/premissa.md                  verificacao da premissa nas fontes primarias
docs/motor.md                     a medicao que decidiu o modelo adotado
docs/conferir-sintese.py          confere a sintese contra as fontes

guia/CONTEXTO.md                  fundamentacao, levantamento das cinco solucoes, hipotese
guia/ARTEFATO.md                  O DESENHO DO EXPERIMENTO: as onze metricas e o criterio,
                                  escritos ANTES da coleta. E o pre-registro

src/artefato/                     o agente: laco de decisao, grafo de estado, involucros de
                                  ferramenta com parser dedicado, acesso ao modelo
src/artefato/testes.py            a suite: ela e as sete que chama, 2.252 verificacoes
src/artefato/mutacoes.py          bateria de mutacao, 793 mutacoes cadastradas
src/artefato/conferir_*.py        verificadores de laboratorio, execucao, caminhos, hosts,
                                  paridade do par e integridade da bateria

lab/docker-compose.yml            os sete conteineres e as duas sub-redes
lab/cadeia.md                     os onze passos da cadeia, saida literal de cada comando
lab/verificacao-rede.md           a evidencia de que o isolamento vale
lab/saidas-exemplo/               saida bruta de ferramenta, usada como fixture de teste

execucoes/coleta-A-01..10         os vinte registros de execucao da coleta, passo a passo
execucoes/coleta-B-01..10
```

### O que não está aqui, e por quê

O desenvolvimento manteve registros contínuos que **são andaime do trabalho, não a entrega**, e eles
ficam preservados fora deste repositório:

```
o diario de decisoes tecnicas          256 entradas, 17.000 linhas, notacao interna
o diario de observacoes de campo       120 observacoes, 8.100 linhas
o cronograma e as notas de sessao      gestao de projeto, nao metodologia
o harness de medicao de modelos        70 arquivos de instrumentacao de desenvolvimento
85 execucoes de piloto e descartadas   historia de desenvolvimento, nao dado do experimento
```

**O que substitui o diário de decisões é [`docs/ajustes.md`](docs/ajustes.md)**, derivado dele:
reúne todo ajuste com motivação, problema resolvido, estado e impacto, e distingue o que foi
concluído do que está pendente e do que é apenas proposta. Qualquer número da síntese é rastreável
até o ajuste que o produziu sem exigir a leitura do diário.

**As execuções descartadas** ficam de fora por serem registro de desenvolvimento, não dado do
experimento. As três que importam para avaliar o trabalho estão descritas em `docs/ajustes.md`: uma
perdida para um defeito de reconhecimento de nome, uma corrompida por concorrência e uma
interrompida pelo resumo de ferramenta truncado.

**Sobre o histórico de versões.** O desenvolvimento foi feito num repositório local, com histórico
completo de commits, e este repositório público foi criado a partir dele em 4 de outubro de 2026,
depois do fechamento da coleta. Por isso ele começa com um único commit. O histórico de
desenvolvimento fica preservado e pode ser disponibilizado aos avaliadores do trabalho mediante
pedido.

---

## Terceiros

O distrator do laboratório é a **GLHF**, aplicação Flask deliberadamente vulnerável publicada por um
professor da própria instituição sob **GPL-3.0**. Ela **não** é redistribuída aqui: o
`docker-compose.yml` a referencia pela imagem `coriscope/glhf:v0.1-beta`, com tag fixada e sem
modificação. O único arquivo local relacionado a ela, `lab/hosts/glhf/bloqueio.py`, é do autor e
serve para confirmar o isolamento dela em relação à cadeia.
