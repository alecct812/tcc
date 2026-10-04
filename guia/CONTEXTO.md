# CONTEXTO

Contexto da pesquisa, da decisão de mudança de rota e do artefato. Leitura obrigatória antes de qualquer tarefa.

Documentos irmãos: `ARTEFATO.md` (o que construir) e `CRONOGRAMA.md` (quando construir).

---

## 1. O trabalho

Trabalho de Conclusão de Curso em Ciência da Computação, CESAR School. Autor: Alec Carneiro Theotônio. Orientador: Prof. Ronierison Maciel.

O documento final segue o **template de Relatório Técnico da CESAR School**, em LaTeX, norma ABNT. Estrutura fixa:

```
1 INTRODUÇÃO (justificativa, problema, contribuições, objetivos)
2 FUNDAMENTAÇÃO TEÓRICA
3 DESENVOLVIMENTO TÉCNICO   ← o artefato mora aqui
4 CONSIDERAÇÕES FINAIS
```

O capítulo 3 exige: visão geral do artefato, processo de desenvolvimento, tecnologias utilizadas, testes e validação (com cenário, métricas e procedimento) e dificuldades encontradas.

**Prazo final: 1º de dezembro de 2026.** O artefato deve estar congelado por volta de 9 de novembro para dar espaço à redação.

---

## 2. A pesquisa do período anterior

No 7º período o trabalho era um **estudo do estado da arte** sobre abordagens baseadas em agentes de IA para automação de testes de invasão, organizado em três eixos:

- **Escalabilidade:** manter desempenho conforme crescem hosts, serviços e caminhos de ataque.
- **Adaptabilidade:** revisar estratégia diante de mudanças, erros e evidências novas durante o teste.
- **Aplicação em redes reais de grande porte:** operar fora de benchmark, em topologia segmentada.

Cinco soluções foram analisadas em profundidade.

### PentestGPT (Deng et al., 2024, USENIX Security)

Três módulos (Reasoning, Generation, Parsing). Introduz a **Pentesting Task Tree (PTT)**, árvore atribuída inspirada em árvore de ataque, cujos nós são tarefas. Opera em modo *human-in-the-loop*.

- Perda de contexto de sessão é a principal causa de falha: 74 ocorrências.
- Geração de comando inexistente é a segunda: 55 ocorrências.
- Força bruta priorizada antes de checar falha lógica é a operação desnecessária mais frequente: 235 ocorrências.
- Raciocínio exclusivamente *depth-first*: aprofunda em um serviço e esquece descobertas anteriores.
- A saída de uma única ferramenta pode ter milhares de tokens e estourar a janela.

### VulnBot (Kong et al., 2025)

Multiagente em três fases. Usa o **Penetration Task Graph (PTG)**, grafo acíclico dirigido cujos vértices são tarefas e cujas arestas são dependências. Tem RAG, Summarizer entre fases e mecanismo de checagem e reflexão.

- AutoPenBench: 30,30% de conclusão geral, 69,05% de subtarefas.
- A taxa de subtarefas cai para 49,90% exigindo consistência em cinco execuções.
- Distribuição de falhas em 220 experimentos: **42,36% perda de contexto de sessão, 19,70% uso incorreto de ferramenta, 19,21% comando com parâmetro errado.**
- Ablação: remover papéis, PTG ou Summarizer zera a conclusão geral.
- Não processa informação não textual. Validado só sobre máquinas isoladas.

### xOffense (Luong et al., 2025)

Evolução do VulnBot. Qwen3-32B ajustado por LoRA em GPU A100 de 80 GB. Usa o **Task Coordination Graph (TCG)**, digrafo acíclico cujos vértices são tarefas e cujas arestas são dependências. Tem grey-box prompting e MemAgent.

- AutoPenBench: 72,72% de conclusão geral, 79,17% de subtarefas.
- Cai para 60,94% exigindo consistência em cinco execuções.
- O mesmo modelo sem ajuste fino faz 52,36%. A especialização vale cerca de 27 pontos.
- Os autores admitem por escrito que os benchmarks não capturam heterogeneidade de produção.
- Validado só sobre máquinas isoladas.

### PentestAgent, também chamado GhostCrew (2025)

Framework prático de código aberto, licença MIT. Integra mais de 18 ferramentas via Model Context Protocol. Quatro modos, RAG opcional, modelo trocável via LiteLLM.

- **Nenhuma validação empírica publicada.** Sem taxa de conclusão, sem baseline, sem benchmark.

### Pentera

Plataforma comercial proprietária. Motor determinístico, *agentless*, catálogo de técnicas codificadas. Mais de 1.200 organizações.

- **É a única das cinco que faz movimentação lateral real entre sub-redes.**
- Métricas autorreportadas, sem metodologia verificável.
- Adapta recalculando caminhos dentro do catálogo conhecido. Não raciocina sobre cenário inédito.

---

## 3. A lacuna e a síntese que origina o artefato

Nenhuma solução contempla os três eixos ao mesmo tempo. As acadêmicas oferecem raciocínio flexível sem escala comprovada. A comercial oferece escala sem raciocínio aberto.

A síntese que sustenta o artefato: **as quatro soluções acadêmicas estruturam a tarefa, não o ambiente.** PTT, PTG e TCG são, os três, grafos de tarefa com aresta de dependência de execução. Em nenhum deles host, sub-rede ou alcançabilidade é entidade de primeira classe. O Pentera é o único que modela o ambiente, e não por acaso é o único que pivota.

**Esta síntese ainda não foi verificada nas fontes primárias.** É a primeira tarefa do cronograma. Se for refutada, o artefato precisa ser redesenhado antes de qualquer código.

---

## 4. A mudança de rota

O trabalho deixou de ser estudo do estado da arte e passou a **produzir um artefato**, com o documento no formato de relatório técnico.

Motivo: o pré-TCC tinha contradição frontal entre a natureza declarada da pesquisa, classificada como básica, e o objetivo geral, que prometia propor e avaliar um artefato de prova de conceito. O orientador apontou duas rotas possíveis, e esta foi a escolhida.

Consequências práticas:

- **Não se adota Design Science Research.** O formato de relatório técnico já carrega o encadeamento e não tem capítulo de metodologia.
- O capítulo de soluções existentes e o de fundamentação teórica **colapsam em um só** (capítulo 2), e a análise comparativa passa a existir para justificar o artefato, não como fim em si.
- O rigor de avaliação continua cobrado, na forma de cenário, métricas e procedimento na seção de testes e validação.

---

## 5. O artefato, e por que cada peça existe

Agente de teste de invasão que mantém um **modelo persistente e explícito da rede alvo**, em vez de carregar o que descobriu na janela de contexto do modelo de linguagem. É isso que permite transitar entre sub-redes.

Cada peça deriva de um achado da pesquisa:

| Peça | Origem |
|---|---|
| Grafo de estado do ambiente | Nenhuma solução acadêmica opera multi-host; só o Pentera modela ambiente |
| Alvo escolhido a partir do grafo | Viés *depth-first* do PentestGPT |
| Parser dedicado, saída bruta nunca vai ao modelo | Saída de ferramenta com milhares de tokens estoura a janela |
| Registro de tentativas já feitas | 235 operações desnecessárias registradas por Deng et al. |
| Execução por pivô | É o mecanismo concreto da lacuna |
| Cinco execuções por braço | Quedas de 79,17% para 60,94% e de 69,05% para 49,90% |
| Distribuição de falhas por categoria | Permite comparar com os 42,36% de Kong et al. sem rodar código de terceiro |
| Ablação como método | O próprio estudo de ablação do VulnBot |

**Hipótese testável:** um agente com estado explícito do ambiente descobre e alcança uma sub-rede interna visível apenas a partir de um host já comprometido, enquanto o mesmo agente com memória conversacional linear não descobre.

**O braço B não é "o artefato com uma peça removida".** É a estratégia de gestão de contexto das soluções existentes, reimplementada em condições idênticas. Essa formulação responde por que o código de terceiros não foi executado: rodar o VulnBot compararia modelos, prompts e implementações ao mesmo tempo, enquanto o braço B isola a única variável de interesse.

---

## 6. Restrições

**Hardware.** Dell G15 5530: 16 GB de RAM, RTX 3050 com 6 GB de VRAM, i5-13450HX. Põe fora de escopo qualquer ajuste fino e impede rodar modelo local grande junto com o laboratório.

**Motor de linguagem.** Desenvolvimento por `claude -p` na assinatura Pro, em turno único, com ferramentas desabilitadas. Avaliação final em modelo Claude econômico com versão fixada, via crédito de API. Desenvolver e avaliar na mesma família evita que o ajuste de prompt não transfira. Detalhes e escada de contingência em `ARTEFATO.md`.

> **Medido em 9 de setembro de 2026** (`docs/motor.md`). O princípio desta seção — mesma família nos dois papéis — sobreviveu à medição e saiu reforçado: a recomendação é ir além dele e usar **o mesmo modelo** nos dois papéis, `claude-sonnet-5`, o que elimina de vez o risco de transferência. O que a medição contradiz é o *caminho* pressuposto aqui, "via crédito de API": o `claude -p` cobre os dois papéis a custo marginal zero, ao preço de não expor identificador com data. Decisão do autor ainda pendente.

**Tempo.** Três semanas para o núcleo, cerca de 58 horas úteis, sem folga.

---

## 7. Fora de escopo, e por quê

Decisões fechadas. Não reabrir sem conversa.

- **Ajuste fino com LoRA:** hardware insuficiente. O xOffense usou A100 de 80 GB.
- **Rodar as soluções existentes no laboratório multi-host:** foram projetadas para alvo único e marcariam zero por construção. O braço B cumpre o papel de forma mais limpa.
- **Furtividade e evasão:** exigiria instrumentar IDS e definir detecção operacionalmente.
- **Active Directory:** exige Windows Server e memória indisponíveis.
- **Orquestração distribuída:** só faz sentido acima de dezenas de hosts.
- **Model Context Protocol:** melhora extensibilidade, não altera métrica medida.

Portas abertas, **só depois da coleta de dados**, cada uma como braço próprio: leitura multimodal, RAG, e ancoragem externa em máquinas do VulnHub com número publicado.

---

## 8. Ética e escopo autorizado

O laboratório é inteiramente local, em contêiner, sob controle do autor. As vulnerabilidades e credenciais da cadeia são plantadas pelo próprio autor. O distrator é a aplicação GLHF, artefato público de terceiro sob licença GPL-3.0, usado sem modificação e com tag de imagem fixada. Não há alvo de terceiros e não há exposição de rede externa. A sub-rede interna é declarada como `internal` no Docker justamente para não ter rota para fora.

Todo código produzido fica restrito a este laboratório. O repositório leva aviso de uso restrito a ambiente autorizado.

No relatório, prever seção de considerações éticas com enquadramento na Lei 12.737/2012 e na LGPD.

---

## 9. Instruções permanentes para o agente de desenvolvimento

**Respeite a semana do cronograma.** A semana 1 não tem código de agente. Se o laboratório não funcionar antes de o agente existir, depura-se duas coisas ao mesmo tempo e não se sai do lugar.

**Nada de saída bruta para o modelo.** Toda ferramenta tem parser. O que vai ao modelo é o que o parser extraiu.

**O adaptador de modelo vem antes de qualquer outra peça do agente.** Interface mínima: recebe prompt, devolve texto. É o que torna a troca de motor barata se o degrau escolhido falhar.

**Os dois braços compartilham tudo menos o grafo.** Mesmo modelo, mesmas ferramentas, mesmos prompts, mesmo limite de passos. Qualquer divergência acidental invalida o experimento.

**Registre em português.** Código, comentários, log e documentação. O relatório é em português.

**Não gere payload de exploração** no código ou na documentação. O repositório documenta a classe da falha e onde ela está, não como explorá-la.

**Pendência aberta:** o nome do artefato. Até ser definido, use `artefato` como nome de pacote e evite espalhar o nome pelo código.
