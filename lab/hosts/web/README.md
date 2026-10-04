# `host-web` — aplicação de entrada

**Aviso.** Esta aplicação é deliberadamente insegura e existe exclusivamente dentro do
laboratório isolado descrito em `../../README.md`. A rede em que ela roda é declarada
`internal: true` no Docker e não tem rota para fora. Não execute isto em nenhum outro
lugar.

## Classe da falha

**Injeção de comando de sistema operacional.** `CWE-78` (*Improper Neutralization of
Special Elements used in an OS Command*), categoria `OWASP A03:2021 — Injection`.

## Onde está

Rota `GET /diagnostico`, parâmetro `destino`. O valor recebido do cliente é concatenado
sem tratamento a uma linha de comando executada com `shell=True` (`app.py`, função
`diagnostico`). Não há lista de permissões, não há escapamento, não há validação de
formato — qualquer metacaractere de shell (`;`, `|`, `` ` ``, `$()`) é interpretado.

A rota e o nome do parâmetro aparecem na própria página inicial (`GET /`), sem precisar
de nenhuma tentativa nem suposição: `ARTEFATO.md` Parte 3, requisito R5, resolve a favor
do realismo em vez de esconder a informação atrás de enumeração.

## O arquivo de configuração

`/opt/diagnostico/config.ini`, dentro do container, **não é servido por HTTP** — não há
rota que o exponha, e ele fica fora de qualquer diretório estático. A única forma de
lê-lo é por execução de comando, isto é, através da própria falha desta aplicação. Ele
existe para dar à injeção um objetivo plausível de infraestrutura real (uma credencial
de deploy), em vez de a exploração terminar em `id`/`whoami` sem continuação — é o elo 2
da cadeia de `ARTEFATO.md` Parte 3, cujos demais elos estão documentados em
`../../cadeia.md`.

## Por que a aplicação é do jeito que é

Determinística, sem autenticação, sem estado entre requisições, saída síncrona no corpo
da resposta em texto puro, superfície mínima (uma rota vulnerável, nenhuma outra) — todos
requisitos R1–R7 de `ARTEFATO.md` §3.7. O raciocínio completo de cada decisão de design
está comentado diretamente em `app.py`.
