# Verificação da premissa nas fontes primárias

Documento de portão da Terça 8 (`CRONOGRAMA.md`). Responde, para PentestGPT, VulnBot
e xOffense, a uma única pergunta:

> **A topologia da rede — host, sub-rede, alcançabilidade — é entidade de primeira
> classe na estrutura de estado da solução, ou é parâmetro dentro de uma tarefa?**

A premissa do artefato (`CONTEXTO.md` §3) afirma que as quatro soluções acadêmicas
estruturam a *tarefa*, não o *ambiente*. Deste documento constam as três que publicam
definição formal — PentestGPT, VulnBot e xOffense. A quarta, PentestAgent/GhostCrew,
não publica definição formal e por isso não entra na mesma verificação; ver nota ao
final da Conclusão do portão. Se qualquer uma das três verificadas modelar topologia
como entidade própria, a premissa cai e o artefato precisa ser redesenhado.

Data da verificação: 8 de setembro de 2026.
Método: leitura das definições formais nas fontes primárias, em inglês, com conferência
da paginação impressa nos PDFs.

---

## 1. PentestGPT — Pentesting Task Tree (PTT)

**Fonte:** DENG, Gelei et al. *PentestGPT: Evaluating and Harnessing Large Language
Models for Automated Penetration Testing*. In: PROCEEDINGS OF THE 33RD USENIX SECURITY
SYMPOSIUM, 2024, Philadelphia, PA. Philadelphia, PA: USENIX Association, 2024. p. 847-864.
ISBN 978-1-939133-44-1. Definition 2, p. 854 (p. 9 do PDF).

Título e imprint conferidos na capa do artigo (`artefato/artigos/pentest-gpt.pdf`,
p. 1 do PDF): "PentestGPT: Evaluating and Harnessing Large Language Models for
Automated Penetration Testing" — não "PentestGPT: An LLM-empowered Automatic
Penetration Testing Tool", que é o título do preprint no arXiv e não aparece nas três
primeiras páginas deste PDF. Faixa de páginas (847-864) conferida pelos rodapés
impressos de cada página do PDF, do início do artigo até o rodapé "USENIX Association"
que fecha o texto.

**Citação literal:**

> "**Definition 2 (Pentesting Task Tree)** A PTT T is a pair (N, A), where: (1) N is a
> set of nodes organized in a tree structure. Each node has a unique identifier, and
> there is a special node called the root that has no parent. Each node, other than the
> root, has exactly one parent and zero or more children. (2) A is a function that
> assigns to each node n ∈ N a set of attributes A(n). Each attribute is a pair (a, v),
> where a is the attribute name and v is the attribute value. The set of attributes can
> be different for each node."

**Contexto da definição** (mesma página): a PTT é apresentada como especialização de
*attributed tree*, e a Figura 3 mostra a PTT em "a) visualized tree format, and b)
natural language format encoded in LLM".

**Veredito: NÃO.** O nó é tarefa. Os atributos são pares nome-valor genéricos, sem tipo
declarado — não existe tipo `host`, `sub-rede` ou `alcançabilidade`. A aresta é
parentesco de decomposição de tarefa, não alcançabilidade de rede. A Figura 3 mostra a
PTT em "a) visualized tree format, and b) natural language format encoded in LLM": o
formato b) confirma que a árvore pode ser codificada como texto em linguagem natural
dentro do modelo, mas isso não é evidência de ausência de estrutura consultável — o
próprio formato a) da mesma figura é uma árvore visualizada e estruturada. O veredito
não depende dessa observação sobre a Figura 3: o argumento decisivo é a própria
Definition 2, examinada acima.

---

## 2. VulnBot — Penetration Task Graph (PTG)

**Fonte:** KONG, He et al. *VulnBot: Autonomous Penetration Testing for A Multi-Agent
Collaborative Framework*. arXiv:2501.13411v1 [cs.SE], 23 jan. 2025. Disponível em:
https://arxiv.org/abs/2501.13411. Acesso em: 8 set. 2026. Definition 1, p. 6.

Identificador conferido na p. 1 do PDF (`artefato/artigos2/vulnbot.pdf`):
"arXiv:2501.13411v1 [cs.SE] 23 Jan 2025". Preprint sem veículo de publicação formal —
por isso a citação carrega o identificador do arXiv e o par "Disponível em / Acesso em"
exigido pela ABNT para material eletrônico sem edição definitiva.

**Citação literal:**

> "**Definition 1 (Penetration Task Graph)** A Penetration Task Graph (PTG) is a directed
> acyclic graph G = (V, E) where: **V** is the set of nodes, each representing an
> individual task in the penetration testing process. [...] **E** is the set of directed
> edges, representing dependencies between tasks. If task T1 must be executed before task
> T2, then there exists a directed edge from T1 to T2."

**Atributos do nó**, listados na mesma definição: `Instruction`, `Action`, `Dependencies`,
`Command`, `Result`, `Finished Status`, `Success Status`.

**O IP como parâmetro dentro da tarefa.** O exemplo dado pelos próprios autores para o
atributo `Instruction` é:

> "Describes the primary task directive (e.g., *'enumerate open ports on the target
> machine'*)."

O alvo não é vértice nem atributo tipado: é substantivo dentro de uma cadeia de caracteres
em linguagem natural.

**Veredito: NÃO.** V é conjunto de tarefas, E é dependência de execução. Nenhum dos sete
atributos do nó guarda host, interface, sub-rede ou rota.

---

## 3. xOffense — Task Coordination Graph (TCG)

**Fonte:** Phung Duc Luong et al. *xOffense: An AI-driven autonomous penetration testing
framework with offensive knowledge-enhanced LLMs and multi agent systems*. arXiv
preprint arXiv:2509.13021v1, 2025. Seção 4.3.1, p. 6.

<!-- conferir: forma de entrada do primeiro autor na referência ABNT. A capa do PDF
(`artefato/artigos2/2509.13021v1.pdf`, p. 1) traz o nome como "Phung Duc Luong",
sem vírgula que indique onde termina o sobrenome. O autor está afiliado à University
of Information Technology (Vietnã), o que sugere ordem vietnamita — sobrenome
"Phung", nome do meio "Duc", nome "Luong" — mas o PDF não confirma isso
explicitamente, e o e-mail do autor (`21522312@gm.uit.edu.vn`) também não resolve a
dúvida. A entrada anterior deste documento ("LUONG, Phung et al.") assumia ordem
ocidental e descartava o nome do meio "Duc" sem justificativa. Até confirmação (ex.:
lista de autores do departamento, outra publicação do mesmo autor com sobrenome
inequívoco), registre o nome como aparece na fonte, por extenso, e não inverta para
formato SOBRENOME, Nome na referência final sem resolver este ponto. -->

Título conferido na capa do PDF: "multi agent systems", sem hífen — a transcrição
anterior deste documento trazia "multi-agent systems".

**Citação literal:**

> "The TCG is a structured acyclic digraph, defined as G = (V, E), where V represents
> individual tasks and E denotes dependencies, ensuring logical and conflict-free
> execution."

**Atributos do nó**, listados logo em seguida: `Directive`, `Operation Type`,
`Prerequisites`, `Command`, `Outcome`, `Completion Status`, `Success Status`.

**A evidência mais forte das três.** O exemplo de `Directive` dado pelos autores é:

> "Directive: A clear instruction, e.g., *'enumerate services on port 80 of 192.168.X.X.'*"

O endereço IP aparece **literalmente embutido numa cadeia de caracteres em linguagem
natural**, dentro do atributo textual de uma tarefa. É a confirmação direta do que a
premissa afirma. Some-se a isso o enunciado do fluxo em §4.1, na página anterior, em que
o objetivo submetido pelo usuário é "Identify vulnerabilities on IP 192.168.X.X [...]" —
citação truncada aqui porque a frase completa da fonte é "Identify vulnerabilities on IP
192.168.X.X and retrieve root-level flags", cujo trecho final não muda o ponto: um único
alvo, informado de fora, nunca descoberto e mantido como entidade.

**Veredito: NÃO.** Estrutura idêntica à do VulnBot, do qual é evolução declarada.

---

## Conclusão do portão

| Solução | Estrutura | O que é o vértice | O que é a aresta | Topologia de primeira classe? |
|---|---|---|---|---|
| PentestGPT | PTT, árvore atribuída | Tarefa | Decomposição de tarefa | **Não** |
| VulnBot | PTG, DAG | Tarefa | Dependência de execução | **Não** |
| xOffense | TCG, digrafo acíclico | Tarefa | Dependência de execução | **Não** |

**A premissa se sustenta nas três fontes.** Nenhuma modela host, sub-rede ou
alcançabilidade como entidade própria; nas três, o alvo é parâmetro textual dentro do
atributo de uma tarefa. O portão está **aberto**: o artefato segue como especificado e a
Semana 1 continua.

### Observação metodológica, para o relatório

A verificação incide sobre a **estrutura de estado declarada formalmente** por cada
trabalho, não sobre o que a implementação eventualmente guarda em memória. É o recorte
correto para o argumento do artefato: a contribuição aqui é justamente promover o
ambiente a estrutura explícita e persistente, e a comparação honesta é contra o que as
fontes assumem como seu modelo de estado.

Fica registrado que Pentera, quinta solução analisada em `CONTEXTO.md` §2, não entra
nesta verificação por não publicar definição formal — é plataforma comercial
proprietária. O que se sabe dela vem de material de divulgação, e é tratado com essa
ressalva.

Fica registrado também que PentestAgent/GhostCrew, a quarta solução **acadêmica**
(`CONTEXTO.md` §2 e §3), tampouco entra nesta verificação, por um motivo diferente do da
Pentera: é framework de código aberto sob licença MIT, mas não publica definição formal
de estrutura de estado em artigo — não há uma "Definition N" equivalente à PTT, à PTG ou
à TCG para ler e citar com página. O que se saberia do seu modelo de estado teria de ser
lido diretamente do código-fonte do projeto, método diferente do aplicado neste
documento (leitura de definição formal publicada em fonte primária). Por isso a síntese
de `CONTEXTO.md` §3 — "as quatro soluções acadêmicas estruturam a tarefa, não o
ambiente" — permanece verificada apenas nas três que publicam definição formal; a
quarta permanece fora do escopo desta verificação específica, não fora do artefato.

### Nota sobre a paginação

Verificada com PyMuPDF (`fitz`), abrindo cada PDF diretamente (`pdftoppm` não está
disponível nesta máquina).

- **PentestGPT** (USENIX Security Symposium 2024, proceedings paginados de forma
  contínua no volume): a página do PDF que contém a Definition 2 é a página 9 do
  arquivo, mas o rodapé impresso naquela página traz "854 · 33rd USENIX Security
  Symposium". Conferido também nas páginas vizinhas do mesmo PDF — página 8 do PDF
  traz rodapé "853", página 10 traz "855" — confirmando a sequência contínua e a
  correção de p. 854. Citação registrada como **p. 854 (p. 9 do PDF)**.
- **VulnBot** (preprint, sem veículo de publicação formal identificado no PDF): o
  rodapé da página do PDF que contém a Definition 1 traz apenas o número "6", idêntico
  ao número de página do PDF (marcador de conversão `page_number=6`). Não há
  paginação de periódico ou de anais sobreposta. Citação registrada como **p. 6**.
- **xOffense** (arXiv 2509.13021v1): mesma situação — o rodapé da página do PDF que
  contém a Seção 4.3.1 traz apenas o número "6", idêntico à página do PDF. Citação
  registrada como **p. 6**.
