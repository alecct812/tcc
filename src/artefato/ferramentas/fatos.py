"""O que os parsers extraem: fatos, nao texto.

`ARTEFATO.md` §1.2 exige que a saida bruta nunca chegue ao modelo -- so o que o
parser extraiu. Estas tres classes sao essa fronteira. Elas ficam de proposito
**proximas do que a ferramenta diz**, nao do modelo do grafo, que nasce so na
quarta 16: inventar hoje a forma do grafo daria retrabalho amanha, e o grafo
mapeia isto sem dificuldade.

O criterio de cada campo e o mesmo do `Resultado` do adaptador: `None` significa
"a ferramenta nao informou", nunca zero nem string vazia, porque afirmar medida
onde nao houve foi o erro que produziu os 14 s falsos de latencia em 8 de
setembro de 2026.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

# ====================================================================== D244
# NOME QUE NAO TEM FORMA DE NOME NAO E NOME.
#
# ⚠️ **Existe porque custou um braco A inteiro** (§E100, 2 de outubro). O agente
# rodou, pela injecao no `.10`, um laco que fazia `cat` de tudo o que casasse com
# `grep -ril pass /opt /app /etc` mais `*.pem`, `*id_rsa*` e `*.env` --
# **814.983 bytes** de corpo, e dentro vinha CODIGO DE SCRIPT. Uma linha como
# `user="$4"` casa com o par chave-valor do `curl.py`, e o grafo gravou:
#
#     usuario='"$4"'  tipo=senha  tem_segredo=True
#
# O agente ficou com o segredo certo e sem saber de quem ele e. Chutou `root` e
# queimou **72 dos 80 passos** em `ssh root@172.20.0.12`, 64 deles redundantes.
# Fechou em elo 2, quando o braco A alcanca o elo 4 em 27 de 57 execucoes.
#
# ⚠️ **E o defeito era ANTIGO, so nao tinha custado nada.** Varredura dos grafos
# do corpo: `piloto-B-01-preD164` tem SEIS usuarios que sao fragmentos de codigo
# Python -- `getpass.getuser()`, `os.environ.get(name)`, `lexer.get_token()`,
# `input("Enter username for %s at %s: " % (realm, host))`. Era piloto.
#
# **E o principio de D212 nunca aplicado a credenciais:** D212 estabeleceu que
# conteudo de script e mencao e nao prova, e isso valia para CAMINHOS. Para
# usuario nunca houve guarda.
#
# **A direcao do erro e a certa por D04.** Recusar nome malformado perde um
# achado que nao existia -- onde o nome e lixo, nao havia credencial. Aceita-lo
# INVENTA um fato, que e a classe pior (§E53).
#
# Medido antes de entrar no codigo: passam 9 de 9 legitimos (`svc_deploy`,
# `svc_backup`, `svc_app`, `root`, `admin`, `www-data`, `user1`, `postgres`,
# `mysql.sys`); recusados 10 de 10 lixos, inclusive `$USER`, `${SSH_USER}` e
# `$(whoami)`.
#
# ⚠️ **O SEGREDO NAO TEM GUARDA EQUIVALENTE, e isso e declarado, nao esquecido.**
# Nenhum teste de forma separa senha legitima de referencia de shell: `$up3rS3cret`
# e senha valida e tem a mesma forma de `$SENHA`. Guardar o segredo recusaria
# achado de verdade, e D04 so autoriza perder achado quando o que se evita e
# inventar fato -- aqui as duas pontas custam. Fica declarado: valor de segredo
# que seja referencia de variavel ainda entra, e so o par morre se o USUARIO for
# lixo (o que mata o caso medido, porque era o usuario).
FORMA_DE_USUARIO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")


def usuario_plausivel(usuario: str | None) -> bool:
    """O nome extraido tem forma de nome de conta POSIX? Fonte unica da regra."""
    return bool(usuario) and bool(FORMA_DE_USUARIO.match(usuario))


# ====================================================================== D245
@dataclass
class Associacao:
    """Uma linha de arquivo PAREIA um endereco com um caminho.

    ⚠️ **Existe porque o parser tinha o dado na mao e o jogava fora.** D197
    detecta "esta linha fala de OUTRA maquina" assim:

        prova = not ENDERECO_NA_LINHA.search(linha)

    O `.search()` devolve o objeto com `172.21.0.12` dentro, e o `not` reduz tudo
    a **um bit**. O caminho ia para `mencionados` do host que LEU o arquivo, e o
    endereco -- a metade que diz de QUEM o caminho e -- era descartado.

    **O custo medido disso.** §E96: na `coleta-A-01` de 1 de outubro o agente leu
    o inventario, escreveu de proprio punho *"podem conter o trofeu ou credenciais
    para h09 (financeiro) ou outro usuario"*, e entao procurou `/home/svc_app`
    **no host errado** por tres passos, porque o grafo dizia que aquele caminho
    era mencionado no `host-arquivo`. §E97 mediu o efeito de ancorar certo:
    proposta do passo do elo 5 vai de **0/20 a 11/20**, Fisher p = 7,3e-05.

    ⚠️ **E ASSOCIACAO NAO AFIRMA EXISTENCIA, que e o que destrava o conserto.**
    §E99 havia rejeitado a correcao com o argumento de que dois dos cinco caminhos
    do inventario (`/srv/backup/fin`, `/srv/backup/db`) **nao existem em host
    nenhum** -- entao reancora-los como caminho do `.12` seria fato falso. Esta
    afirmacao e outra: *"uma linha de arquivo lido no h08 associa o endereco
    172.21.0.12 ao caminho /home/svc_app"*. Isso e **verdade sobre o texto lido**,
    e permanece verdade quer o caminho exista ou nao. A objecao de §E99 nao se
    aplica a esta forma, e §E99 esta corrigida nesse ponto.

    **O que ela NAO resolve, e fica declarado:** a outra metade da perda e a
    **prosa**. O inventario diz, em duas frases das Observacoes, que *"o acesso
    dos jobs e pela chave de deploy do pipeline, a mesma usada nos demais"* e que
    o chamado para segregar as chaves esta aberto. `FatosDeShell` nao tem campo de
    texto livre, e nenhum dos oito campos carrega prosa -- entao essa frase nao
    chega a braco nenhum. Isso explica o outro lado de §E97 (das 11 propostas
    certas, **6 usaram senha** e so 4 a chave: nada lhes disse que a chave e
    reusada). **Nao se conserta aqui**: canal de texto livre muda o que "grafo de
    estado explicito" significa e desfoca o contraste com a memoria linear do
    braco B. E experimento seguinte, nao conserto de bug.
    """

    endereco: str
    caminho: str


def juntar(partes: list[str]) -> str:
    """Os argumentos numa linha so, **preservando o aspeamento**.

    Existe porque `" ".join` nao o preserva, e o rotulo da tentativa e lido por
    um agente que o REPRODUZ. Terceiro nivel do mesmo defeito:

        D64  a URL sumia do rotulo
        D76  `-G` e `--data-urlencode` sumiam
        aqui as ASPAS sumiam, e um argumento virava varios

    Concretamente, com `" ".join`:

        argv:    ['curl', '--data-urlencode', 'destino=x;find / -iname "*a*"']
        rotulo:  curl --data-urlencode destino=x;find / -iname "*a*"
        lido:    5 argumentos em vez de 3 -- o curl le `-iname` como opcao

    Na `auto-02`, com as duas correcoes anteriores ja aplicadas, **12 de 31
    passos** falharam so por isto.

    `shlex.quote` so poe aspas em quem precisa, entao `curl` e `-sV` saem
    limpos e o rotulo nao fica mais pesado do que precisa (D45).
    """
    return " ".join(shlex.quote(p) for p in partes)


@dataclass
class Servico:
    """Uma porta de um host, do jeito que o nmap a reporta."""

    porta: int
    protocolo: str
    estado: str
    servico: str | None = None
    versao: str | None = None
    # O nmap marca com `?` o servico que ele achou mas nao identificou com
    # firmeza. Engolir a interrogacao transformaria palpite em fato -- e o
    # agente decidiria em cima de uma identificacao que o proprio nmap nao
    # assina.
    incerto: bool = False

    @property
    def aberta(self) -> bool:
        return self.estado == "open"


@dataclass
class Host:
    endereco: str
    # Nome do DNS reverso do Docker, quando existe. O gateway da bridge vem sem
    # nome; exigir nome perderia um host, e a diferenca entre hosts projetados e
    # hosts vistos ja e assunto explicado em `lab/README.md`.
    nome: str | None = None
    ativo: bool = True
    servicos: list[Servico] = field(default_factory=list)


@dataclass
class Autenticacao:
    """Desfecho de uma tentativa de autenticacao por SSH."""

    endereco: str | None
    usuario: str | None
    sucesso: bool
    codigo: int | None = None
    # Endereco do host por onde o comando passou, quando houve salto. `None`
    # numa execucao direta. Sem este campo, a autenticacao feita no host interno
    # atraves do pivo seria atribuida ao pivo -- e o grafo registraria o host
    # errado como comprometido, contaminando a metrica 2 ("hosts comprometidos
    # sobre 5") e a metrica 1 ("sub-redes distintas onde ao menos um comando
    # executou"), que sao a medicao primaria do trabalho.
    via: str | None = None
    # Metodo que o servidor recusou, quando ele diz. O ssh informa isso em
    # "Permission denied (publickey,password)".
    metodo: str | None = None
    # Motivo textual normalizado. `None` no sucesso.
    motivo: str | None = None
    # O endereco respondeu? Sondado em 15 de setembro: o ssh distingue "No
    # route to host" (endereco morto) de "Connection refused" (endereco vivo,
    # servico ausente), e colapsar os dois em "falhou" descarta o sinal de
    # alcancabilidade -- que `ARTEFATO.md` §1.2 poe como aresta do grafo. Sem
    # ele o agente reinsiste num endereco morto e a metrica de acao redundante
    # nao distingue a reinsistencia de uma tentativa nova.
    # `None` quando nao da para afirmar.
    alcancavel: bool | None = None


@dataclass
class Credencial:
    """Uma credencial que uma ferramenta reportou ter encontrado.

    Proxima do que a ferramenta diz, como todo fato deste modulo: o hydra
    reporta host, porta e servico junto com o par; o curl le o par de dentro de
    um arquivo e so sabe de que host veio. O grafo funde as duas formas.
    """

    usuario: str
    # "senha" ou "chave". Forca bruta so produz senha; leitura de arquivo pode
    # produzir as duas.
    tipo: str
    segredo: str | None = None
    endereco: str | None = None
    porta: int | None = None
    servico: str | None = None


@dataclass
class ForcaBruta:
    """Desfecho de uma corrida de hydra.

    `credenciais` vazia com `concluida` verdadeira e **fato**: a lista acabou e
    nada passou. E o dado que impede o agente de repetir a mesma forca bruta --
    e `ARTEFATO.md` §2.3 exige que seja esse o desfecho dentro da cadeia.

    `concluida` falsa significa que a corrida parou antes do fim, por tempo ou
    por erro; ai a lista vazia nao autoriza conclusao nenhuma.
    """

    endereco: str | None = None
    porta: int | None = None
    servico: str | None = None
    credenciais: list[Credencial] = field(default_factory=list)
    concluida: bool = False
    tentativas: int | None = None


@dataclass
class Rota:
    """Um caminho que o documento revelou, e os parametros que ele declara.

    Vem de leitura direta da marcacao -- `action`, `method`, `name` --, nunca de
    juizo sobre o que a rota faz. O parser nao decide que uma rota e vulneravel,
    nao sugere carga e nao classifica: so registra que ela existe e o que ela
    aceita, que e o que o documento diz.
    """

    caminho: str
    metodo: str = "GET"
    parametros: list[str] = field(default_factory=list)
    # ⚠️ **A PORTA EM QUE A ROTA MORA (D225), e sem ela o grafo mente por
    # omissao quando o host tem mais de um servidor HTTP.** O `host-web` do
    # laboratorio tem dois: `8000` com um `SimpleHTTPServer` e `8080` com o
    # Werkzeug que serve o `/diagnostico`. O prompt dizia
    #
    #     [h03] 172.20.0.10 tcc-host-web ... enumerado nao comprometido
    #      rotas: /diagnostico (GET, param destino)
    #      servicos: 8000/tcp http ...; 8080/tcp http-proxy ...
    #
    # e o agente nao tinha como saber em qual das duas a rota estava. Na
    # execucao de 1 de outubro ele escolheu a porta rotulada `http` em vez da
    # `http-proxy` e gastou **6 dos 8 primeiros passos** batendo em 8000.
    #
    # **Mesma classe de D197**: la o caminho era atribuido ao host errado, aqui
    # a rota fica sem porta no host certo. Fato pela metade se completa
    # adivinhando, e adivinhar custa passo.
    #
    # `None` quando nao se sabe -- carregar `grafo.json` antigo cai aqui, e
    # `None` nunca vira um numero inventado.
    porta: int | None = None


@dataclass
class RespostaHttp:
    """O que uma requisicao curl devolveu.

    `corpo` existe para o laco de decisao e para os testes, nunca para o
    prompt: `ARTEFATO.md` §1.2 mantem a saida bruta fora do modelo, e o grafo
    guarda o que foi extraido daqui, nao isto.
    """

    status: int | None = None
    tipo: str | None = None
    tamanho: int | None = None
    endereco: str | None = None
    porta: int | None = None
    corpo: str = ""
    credenciais: list[Credencial] = field(default_factory=list)
    # O que a PAGINA revela. Faltavam os dois ate 18 de setembro, e sem eles o
    # agente perdia, no passo seguinte, a rota e o parametro que a requisicao
    # tinha acabado de descobrir -- porque o historico e descartado (§E13, D54).
    titulo: str | None = None
    rotas: list[Rota] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """`None` nao vira falso por omissao -- vira falso por nao ser 2xx."""
        return self.status is not None and 200 <= self.status < 300
