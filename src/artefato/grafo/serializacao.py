"""O texto que vai ao modelo.

Esta e a peca que o experimento mede. O braco A envia isto; o braco B envia
memoria conversacional linear. Tudo o mais nos dois bracos e identico
(`ARTEFATO.md` §4.1), entao a diferenca medida e a diferenca entre este texto e
um historico de conversa.

**O formato copia o de `docs/medicao/prompt-teste.txt`, de proposito.** Foi
sobre aquele texto que `docs/motor.md` mediu invencao de parametro (§E1, 0 de 22
com grafo completo contra 3 de 14 com grafo reduzido) e taxa de recusa (§E2,
que varia de 0% a 100% conforme a densidade). Emitir um formato diferente faria
aquelas medicoes descreverem um texto que o agente nunca envia -- perderiam
valor como evidencia justamente no capitulo de validacao.

**O que NAO se copia daquele arquivo:** as linhas `nota:`, que trazem analise
humana ("onze acoes gastas aqui sem dado util em outro host"). O grafo nao tem
como derivar isso de um parser, e sintetizar seria inventar.

`CRONOGRAMA.md` para hoje: "caber em poucas centenas de tokens importa mais do
que ser bonito". Dai as abreviacoes e a ausencia de campo vazio -- campo que
nao tem valor nao gasta linha.
"""

from __future__ import annotations

from .modelo import Alcance, Credencial, Host, Tentativa


# A RESTRICAO DO ARNES, e ela NAO E ESTADO DO AMBIENTE (D218).
#
# ⚠️ **Constante porque chegava a UM braco so, por nove dias e quinze execucoes.**
# Esta frase saia na linha do host de origem, dentro da serializacao -- entao o
# braco A a lia em todo passo e o braco B **nunca** a recebia. Conferido nas 15
# execucoes do braco B com memoria em disco: ausente em `partida`, nos fatos,
# nos resumos de passo e nos resumos de fase, em 15 de 15.
#
# E o comentario que a justifica afirmava o contrario: *"sem isto ele queima
# passos descobrindo a restricao, em toda execucao e NOS DOIS BRACOS"*. Rotulo
# falso na nossa propria documentacao, que §E53 nomeia como a pior classe de
# defeito deste projeto. Medido na `coleta-B-01`: o braco B gastou os passos 30
# e 32 montando `nc -lvnp 4444 &`, shell reverso, contra 0 passos do braco A.
#
# **Por que uma constante e nao duas copias da frase:** em 21 de setembro duas
# copias de `juntar` e `autenticou` divergiram em menos de uma hora. Aqui as
# duas copias divergiriam em silencio e a assimetria voltaria sem nenhum teste
# vermelho -- por isso ha tambem a checagem de `paridade.py` sobre o PROMPTO
# MONTADO, que e a segunda camada de D65/D68.
#
# **Mora aqui, e nao em `laco/prompt.py`, por camada:** `laco` importa `grafo`,
# nunca o contrario. Fica ao lado de onde a frase e emitida para o braco A.
NOTA_DO_ARNES = ("um comando por passo, sincrono; sem processo em segundo plano")


def _id_host(indice: int) -> str:
    return f"h{indice + 1:02d}"


def _id_credencial(indice: int) -> str:
    return f"c{indice + 1:02d}"


def identificadores_de_credenciais(credenciais) -> dict[str, str]:
    """Mapa segredo -> `c01`, na MESMA numeracao que a secao CREDENCIAIS imprime.

    Vive aqui, ao lado de `_id_credencial`, porque o numero que o agente le no
    prompt e o numero que o laco tem de resolver (D159). Duas numeracoes
    independentes concordariam hoje e divergiriam no dia em que uma das duas
    mudasse, e a divergencia resolveria a credencial ERRADA -- fato falso, que
    o projeto trata como pior que achado perdido (D04).

    **`enumerate` corre a lista INTEIRA e o filtro vem depois.** Filtrar antes
    desalinharia: com uma credencial sem segredo na frente -- uma chave achada
    num diretorio --, a primeira COM segredo e a `c02` para o prompt e viraria
    `c01` aqui.
    """
    return {c.segredo: _id_credencial(i)
            for i, c in enumerate(credenciais) if c.segredo}


def credencial_utilizavel(c) -> bool:
    """O agente tem COM QUE usar esta credencial? Unica fonte da regra (D221).

    ⚠️ **Existe porque D161 consertou metade do problema e declarou a outra
    metade impossivel.** A nota de D161 dizia: *"uma credencial `chave` tambem
    tem `segredo` vazio, mas e usada por `ssh -i`, nao por `-p` -- nao e
    irresolvivel, e uma via diferente"*, e fechava com *"o corpo inteiro
    confirma: as 6 credenciais sem segredo do corpus sao TODAS `senha`, nenhuma
    `chave`"*. **O corpo cresceu e a confirmacao envelheceu.** Na `coleta-A-01`:

        [c03] svc_deploy chave; recusada h09; nao testada h01,h03,...,h08
        [c04] svc_app    chave; recusada h09; nao testada h01,h03,...,h08

    As duas sao `chave` com `identidade` VAZIA -- a conta existe e o arquivo da
    chave nao se sabe. "Usada por `ssh -i`" exige saber o que vai DEPOIS do
    `-i`, e sem isso nao ha via nenhuma. O prompt convidava (`nao testada` em
    oito hosts), o agente aceitou o convite nos passos 73 e 75, e o grafo gravou
    `recusada h09` de uma chave que nunca saiu da maquina.

    **O que decide e o MATERIAL, por tipo, nao a presenca de `segredo`:** uma
    `senha` se usa pelo segredo, uma `chave` pelo arquivo. Tipo desconhecido
    conta como utilizavel, para um tipo novo nao desaparecer do prompt em
    silencio -- esconder achado e o erro oposto e tambem e erro.

    Uma fonte, tres consumidores: a marca `(...)` na linha da credencial, a
    lista `nao testada`, e a guarda do laco que recusa o identificador
    irresolvivel. Em 21 de setembro a mesma regra em duas copias divergiu em
    menos de uma hora.
    """
    if c.tipo == "chave":
        return bool(c.identidade)
    if c.tipo == "senha":
        return bool(c.segredo)
    return True


def identificadores_irresolviveis(credenciais) -> set[str]:
    """Os `cNN` que o agente nao tem como usar, e que o laco deve recusar.

    **Era `identificadores_sem_segredo`, e o nome virou falso** (D221): ele
    descrevia a regra de D161 -- `senha` sem segredo --, e a regra passou a ser
    "sem material utilizavel", que inclui `chave` sem arquivo. Nome que descreve
    menos do que a funcao faz e rotulo falso, a classe que §E53 nomeia como a
    pior deste projeto, e por isso o nome mudou junto com o corpo.

    Mesma numeracao posicional de `identificadores_de_credenciais` -- a lista
    inteira corre e o filtro vem depois, pela mesma razao (o numero aqui e o
    numero no prompt). O laco usa este conjunto para RECUSAR um comando que
    referencia uma dessas: D159 mandou referenciar credencial por identificador,
    e uma sem material nao resolve; sem esta guarda o identificador ia literal
    -- como senha depois de `-p`, como NOME DE ARQUIVO depois de `-i` -- e o
    grafo gravava `recusada` de uma credencial nunca apresentada.
    """
    return {_id_credencial(i) for i, c in enumerate(credenciais)
            if not credencial_utilizavel(c)}


def _id_tentativa(indice: int) -> str:
    return f"t{indice + 1:02d}"


def mapa_de_identificadores(hosts: list[Host]) -> dict[str, str]:
    """De endereco para `hNN`, na ordem que a serializacao usa.

    Existe como funcao propria porque o laco precisa do caminho inverso, e
    duplicar a ordenacao la faria os dois discordarem no dia em que um host novo
    entrasse -- silenciosamente, que e o pior jeito.
    """
    ordenados = sorted(hosts, key=lambda h: _chave(h.endereco))
    return {h.endereco: _id_host(i) for i, h in enumerate(ordenados)}


def serializar_ambiente(hosts: list[Host], credenciais: list[Credencial],
                        alcances: list[Alcance],
                        subredes: dict[str, str | None],
                        credenciais_omitidas: int = 0,
                        derivados: bool = True) -> str:
    """As quatro secoes que descrevem o AMBIENTE: sub-redes, hosts, alcance, contas.

    ⚠️ **`derivados=False` e o braco B, e a bandeira nomeia a variavel do
    experimento dentro do codigo** (D215). §4.1 diz que no braco B a
    serializacao *"nao e enviada a lugar nenhum"*, e que o braco B *"grava em
    disco um grafo que nunca foi mostrado ao modelo"*. D125 diz o mesmo pela
    terceira e decisiva das suas razoes: *"a consolidacao e justamente o que nao
    se repassa."* Mas a implementacao de D125 entrega ao braco B a diferenca de
    `serializar_ambiente()` INTEIRA -- e ali dentro vao as consolidacoes. As
    duas coisas nao podem valer juntas, e quem cede e a implementacao.

    **O criterio, e ele e verificavel linha por linha: derivacao e a afirmacao
    que NENHUMA saida de ferramenta sozinha poderia ter produzido.** Nao e "tudo
    que o grafo calcula" -- a linha `[h03] 172.20.0.10 host-web ...` tambem e
    montada por nos, e continua indo, porque cada campo dela saiu de uma saida
    so. Lista de observacoes tambem continua indo (`validada h05,h07` sao dois
    eventos vistos, enfileirados). O que sai e o que exige o grafo TODO ao mesmo
    tempo:

      `172.21.0.0/24 so via h05`    a rota, derivada da topologia inteira
      `h05 -> h07 via ssh em h05`   a aresta, que e a estrutura do grafo
      `; nao testada h03,h04`       o COMPLEMENTO -- nao esta em saida nenhuma
      ` interfaces: nao enumeradas` afirmacao sobre a AUSENCIA de dado (D167)
      `(+N nao listados)`           contabilidade dos tetos do grafo

    **Medido nos dois braco B gravados, antes de implementar:** 217 de 4.691 e
    302 de 3.669 caracteres, **5% e 8%** do ambiente. As credenciais com segredo
    -- o que D125 existe para proteger, e o defeito cujo sintoma seria o
    resultado desejado -- ficam INTEIRAS nos dois.

    **Padrao `True`, e isso e proposital:** o braco A passa por `serializar()`,
    que nao menciona a bandeira, e fica byte a byte o que era. A mudanca e so do
    braco B, e ha teste que exige a igualdade.

    ⚠️ **ISTO ENFRAQUECE O BRACO B, e o enfraquecimento nao e a justificativa
    nem o efeito colateral aceito de um ganho: e a consequencia de ele passar a
    ser o que a especificacao diz que e.** O autor formulou a regra assim, em 30
    de setembro: *"nao tem problema enfraquecer o braco B quando a questao e que
    o braco B nao ta sendo o que foi definido que ele seria; se ele ta se
    aproveitando de algo que e naturalmente de A, entao naturalmente isso
    deveria ser tirado dele. E, consequentemente, ele e realmente mais fraco."*
    Nenhum numero de resultado entrou nesta decisao, e nenhum pode entrar: ela
    se justifica por §4.1 e pela propria terceira razao de D125, dois textos
    anteriores a qualquer dado.

    As secoes `=== OBJETIVO ===` e `=== INSTRUCAO ===` do prompt medido NAO
    saem daqui: sao texto fixo do laco de decisao, iguais em todo passo e nos
    dois bracos. Misturar as duas coisas faria o grafo carregar instrucao, e a
    instrucao mudar quando o estado mudasse.

    **Separada de `serializar_tentativas` em 30 de setembro (D201).** Ate aqui
    as duas saiam da mesma funcao, e o braco B recortava a segunda procurando o
    texto `"=== TENTATIVAS"` DENTRO do resultado. Dois modulos acoplados pela
    string renderizada: no dia em que o cabecalho mudasse, o braco B passaria a
    repetir cada acao duas vezes no proprio prompt -- em silencio, e contra o
    teto que D125 existe para manter.

    A divisao tambem e a que o conteudo pede. Esta funcao emite ESTADO DO
    AMBIENTE, limitado pelo ambiente: nove hosts, duas sub-redes, um punhado de
    contas. A outra emite HISTORICO DA ACAO, limitado pela execucao. Uma funcao
    com as duas coisas tem duas razoes para mudar.
    """
    ordenados = sorted(hosts, key=lambda h: _chave(h.endereco))
    por_endereco = mapa_de_identificadores(hosts)
    linhas: list[str] = []

    # Esta secao informa COMO CHEGAR, nao o que ja foi conquistado -- como o
    # prompt medido faz ("alcancavel do atacante" contra "so via host-pivo").
    # Conquista e outra coisa, e esta na linha de cada host. Saber que uma
    # sub-rede so se alcanca por salto e o que faz o agente escolher o pivo em
    # vez de insistir no caminho direto.
    #
    # ⚠️ **E e ROTA, que e derivacao: as TRES redacoes saem no braco B** (D215).
    # Nenhuma saida de ferramenta diz "so via h05" -- a frase sai de cruzar a
    # origem, a varredura de cada host e as travessias. `alcancavel direto` e
    # `rota desconhecida` respondem a mesma pergunta pelo mesmo cruzamento, e
    # manter duas e tirar uma seria escolher qual derivacao ajuda.
    #
    # **A EXISTENCIA da sub-rede nao se perde com isso**, e essa era a objecao a
    # conferir antes de decidir: a faixa continua na linha de cada host
    # (`[h05] 172.20.0.12 srv-deploy 172.20.0.0/24 ...`) e na linha de interface
    # (` interfaces: eth1 172.21.0.2/24`), que sao observacao -- a saida do
    # comando trouxe o endereco, e o /24 dele e conta local de um dado so, nao
    # consolidacao do grafo. Foi por ai que o braco B da `piloto-B-01` achou a
    # segunda perna do pivo: `ip -o addr show` no passo 51, varredura da faixa
    # no 52, **pelo comando dele**.
    if derivados:
        linhas.append("=== SUB-REDES ===")
        for faixa in sorted(subredes):
            rota = subredes[faixa]
            if rota is None:
                linhas.append(f"{faixa} rota desconhecida")
            elif rota == "direto":
                linhas.append(f"{faixa} alcancavel direto")
            else:
                linhas.append(f"{faixa} so via {por_endereco.get(rota, rota)}")
        linhas.append("")

    linhas.append("=== HOSTS ===")
    # D245: endereco -> rotulo `hNN`, para a linha de associados dizer DE ONDE
    # a afirmacao veio no vocabulario que o agente ja usa. Mesma ordenacao do
    # laco, pela mesma razao que `_id_host` existe como funcao propria.
    ids = {x.endereco: _id_host(k) for k, x in enumerate(ordenados)}
    for i, h in enumerate(ordenados):
        enum = "enumerado" if h.enumerado else "nao enumerado"
        comp = "comprometido" if h.comprometido else "nao comprometido"
        nome = h.nome or "sem nome"
        # A palavra `origem` e a do prompt medido: `[h01] 172.20.0.5 atacante
        # dmz origem comprometido`. Ela diz ao agente qual host e a maquina
        # dele, o que muda a leitura de "comprometido" ali (D53).
        marca = " origem" if h.origem else ""
        linhas.append(f"[{_id_host(i)}] {h.endereco} {nome} "
                      f"{h.subrede or 'sub-rede desconhecida'}{marca} {enum} {comp}")
        if h.meio_de_acesso:
            # So aparece quando a execucao veio por caminho que nao e SSH. No
            # caso comum a credencial ja descreve como se entrou, e repetir
            # gastaria token sem acrescentar fato.
            linhas.append(f" acesso por: {h.meio_de_acesso}")
        if h.origem:
            # A caixa de ferramentas do agente, descrita na linha da maquina
            # dele -- como o prompt medido faz com `ferramentas:` e `nota:`.
            #
            # Existe porque em 18 de setembro o agente propos `nc -lvnp 4444`
            # para montar shell reverso: acao sensata para quem esta cego, e
            # impossivel aqui, onde o laco roda um comando por passo e espera
            # ele terminar. Sem isto ele queima passos descobrindo a restricao,
            # em toda execucao e nos dois bracos -- ruido dentro da metrica
            # primaria, pelo mesmo argumento de D52.
            linhas.append(f" nota: {NOTA_DO_ARNES}")
        if h.usuario:
            # Formato do prompt medido: `execucao: usuario app, sem root`. Aqui
            # sai tambem o uid, que e o dado de onde "sem root" foi deduzido --
            # e deduzir e do leitor, nao nosso.
            linhas.append(f" execucao: usuario {h.usuario} (uid {h.uid})")
        if h.interfaces:
            # Formato do prompt medido: `interfaces: eth0 172.21.0.2/24`. O
            # PREFIXO fica -- e dele que o agente deduz a faixa a varrer, e sem
            # ele a linha diria so que existe um endereco a mais.
            linhas.append(" interfaces: " + ", ".join(
                f"{i.nome} {i.endereco}/{i.subrede.split('/')[1]}"
                for i in h.interfaces))
        elif h.comprometido:
            # D167. A LACUNA TEM DE APARECER. Ate 28 de setembro esta linha
            # simplesmente nao saia quando as interfaces eram desconhecidas, e o
            # host aparecia como `[h05] ... enumerado comprometido` -- onde
            # `enumerado` significa so "tem servico descoberto" (`__init__.py`:
            # `enumerado=bool(o.servicos)`). O agente lia "enumerado" e nada
            # sobre interfaces, e concluia, com razao, que ali nao havia mais o
            # que descobrir. A incognita mais importante do laboratorio -- a
            # segunda perna do pivo -- ficava invisivel.
            #
            # §E63 mediu o preco: das execucoes do braco A que enumeraram dentro
            # do pivo, 2 de 2 alcancaram o elo 4; das que nunca enumeraram, 1 de
            # 4. O rotulo suprimia justamente a acao que decide o desfecho
            # primario -- e so o braco A o le, entao a omissao era assimetrica
            # contra o braco que a hipotese diz que vence.
            #
            # SO EM HOST COMPROMETIDO: nao se enumera interface de host sem
            # sessao, e em host nao comprometido a linha seria ruido. E para
            # TODOS os comprometidos, nao so o pivo: assim a linha diz "voce nao
            # olhou" e nunca "aqui tem algo" -- nao entrega a descoberta, que e o
            # que D155 e D164 preservam como tarefa do agente.
            #
            # ⚠️ **NAO VAI AO BRACO B** (D215), e e a derivacao mais pura das
            # cinco: a linha nao relata dado nenhum, relata a AUSENCIA de dado
            # no grafo -- "voce nunca olhou aqui". So se sabe isso tendo o
            # historico inteiro ao mesmo tempo, que e exatamente o que o braco B
            # nao tem.
            #
            # O paragrafo de §E63 acima diz que a omissao desta linha era
            # "assimetrica contra o braco que a hipotese diz que vence". O
            # argumento vale nos dois sentidos, e por isso ele decide os dois
            # casos: entrega-la ao braco B e assimetria A FAVOR dele, porque a
            # linha nasce da forma de estado que so o braco A deveria receber.
            if derivados:
                linhas.append(" interfaces: nao enumeradas")
        if h.caminhos:
            linha = " caminhos vistos: " + ", ".join(h.caminhos)
            if h.caminhos_omitidos and derivados:
                # A CONTAGEM do teto e contabilidade do grafo, nao do ambiente
                # (D215): quantos caminhos um limite NOSSO descartou e fato
                # sobre a estrutura, e o braco B nao recebe a estrutura. A lista
                # dos caminhos VISTOS fica -- ela e o que o `find` imprimiu.
                linha += f" (+{h.caminhos_omitidos} nao listados)"
            linhas.append(linha)
        elif h.caminhos_omitidos and derivados:
            # ⚠️ **CABECALHO COM LISTA VAZIA NAO E LINHA** (D214). Com o teto por
            # comando de pe, o host do trofeu da `piloto-A-01-preD211` recebia
            # literalmente ` caminhos vistos:  (+620 nao listados)` -- a linha
            # dizia "caminhos vistos" e nao listava nenhum. Confuso em vez de
            # instrutivo, e o agente tinha de estreitar as cegas.
            #
            # Com D214 este caso ficou raro, mas nao impossivel: um host cujo
            # unico lote foi despejado inteiro cai aqui. A frase agora diz o que
            # aconteceu.
            linhas.append(f" {h.caminhos_omitidos} caminhos achados aqui, "
                          "nenhum listado")
        if h.mencionados:
            # ⚠️ D197. A REDACAO E O CONSERTO, tanto quanto a lista separada. Se
            # isto dissesse "caminhos", o agente leria como descoberta e o
            # defeito voltaria pela palavra -- foi assim que ele gastou 6 passos
            # procurando `/home/svc_app` no host errado.
            linhas.append(" mencionados em arquivo daqui (nao verificados): "
                          + ", ".join(h.mencionados))
        # ⚠️ **D245. A REDACAO IMPORTA TANTO QUANTO A LISTA, e pela mesma razao
        # de D197.** Nao diz "caminhos": diz que um arquivo lido em OUTRO host
        # associa estes caminhos a este. O agente le de onde a afirmacao veio e
        # que ela nao foi verificada -- e as duas coisas sao verdade sobre o texto
        # lido, nao sobre o disco (§E99 corrigida: associacao nao afirma
        # existencia).
        #
        # Esta e a linha cujo efeito §E97 mediu: com ela, a proposta do passo do
        # elo 5 vai de 0/20 a 11/20, Fisher p = 7,3e-05.
        if getattr(h, "associados", None):
            porfonte: dict[str, list[str]] = {}
            for caminho, fonte in h.associados.items():
                porfonte.setdefault(fonte, []).append(caminho)
            for fonte, caminhos in sorted(porfonte.items()):
                rotulo = ids.get(fonte, fonte) if ids else fonte
                linhas.append(f" associados em arquivo de {rotulo} "
                              f"(nao verificados): " + ", ".join(sorted(caminhos)))
        if h.titulo:
            linhas.append(f' titulo http: "{h.titulo}"')
        if h.rotas:
            # Formato do prompt medido: `rotas: / (form), /diagnostico (POST,
            # param host)`. Rota sem parametro sai so com o metodo: campo sem
            # valor nao gasta linha.
            partes = []
            for r in h.rotas:
                # D225. A PORTA, quando se sabe. O host do laboratorio tem dois
                # servidores HTTP, e sem este campo o agente escolhe entre eles
                # pelo rotulo do nmap -- `http` contra `http-proxy` -- e erra.
                # Campo sem valor nao gasta texto, como no resto do formato.
                onde = f" em {r.porta}" if r.porta else ""
                if r.parametros:
                    partes.append(f"{r.caminho} ({r.metodo}, param "
                                  + ",".join(r.parametros) + f"){onde}")
                else:
                    partes.append(f"{r.caminho} ({r.metodo}){onde}")
            linhas.append(" rotas: " + ", ".join(partes))
        abertas = [s for s in h.servicos if s.aberta]
        if abertas:
            linhas.append(" servicos: " + "; ".join(_servico(s) for s in abertas))
        fechadas = [s for s in h.servicos if s.estado == "closed"]
        if fechadas:
            # Porta fechada nao merece uma linha cada: o que o agente precisa
            # saber e que ja foram testadas, para nao repetir.
            linhas.append(" ja testadas e fechadas: "
                          + ",".join(f"{s.porta}/{s.protocolo}" for s in fechadas))
        indecisas = [s for s in h.servicos
                     if not s.aberta and s.estado != "closed"]
        if indecisas:
            # `filtered` e os estados compostos do nmap nao sao "fechada": sao
            # ausencia de resposta. Junta-los a linha de fechadas afirmaria ao
            # agente que o servico nao existe, quando o que houve foi silencio
            # -- e ele descartaria um caminho que talvez esteja aberto. Mesmo
            # principio do `None` que nunca vira zero.
            linhas.append(" sem resposta conclusiva: "
                          + ",".join(f"{s.porta}/{s.protocolo}" for s in indecisas))
        if h.autenticacao_indiscriminada:
            # D199. O FATO QUE UMA ENXURRADA DE FORCA BRUTA REALMENTE PRODUZ.
            #
            # A redacao e o conserto tanto quanto a contagem -- a licao de D197.
            # Esta linha diz o que se OBSERVOU (tantos pares aceitos, inclusive
            # segredos diferentes para o mesmo usuario) e nao a conclusao ("e um
            # distrator", "nao vale insistir"). A deducao fica com o agente, que
            # e o que se mede.
            linhas.append(" autenticacao nao discrimina: " + ", ".join(
                f"porta {porta}, {n} pares aceitos, inclusive segredos "
                "diferentes para o mesmo usuario"
                for porta, n in sorted(h.autenticacao_indiscriminada.items())))

    # ⚠️ **A SECAO INTEIRA SAI NO BRACO B** (D215), e este e o caso mais claro
    # do criterio: `hNN -> hNN via ssh em hNN` e literalmente uma ARESTA, a
    # estrutura de dado que da nome ao braco A. O `nenhuma travessia registrada`
    # sai junto -- afirmar a ausencia de travessia e afirmar sobre o grafo todo.
    #
    # O braco B nao fica sem saber por onde entrou: ele leu a saida do `ssh` que
    # atravessou, e ela esta no historico verbatim dele.
    if derivados:
        linhas.append("")
        linhas.append("=== ALCANCABILIDADE ===")
        if not alcances:
            linhas.append("nenhuma travessia registrada")
        # Uma linha por salto, com os destinos agrupados -- como no prompt
        # medido:
        #   h04 -> h07,h08,h09 via ssh em h04
        # Numa execucao de 60 passos o mesmo pivo alcanca varios hosts, e uma
        # linha para cada gastaria orcamento de tokens repetindo a mesma rota.
        grupos: dict[tuple[str, str | None], list[str]] = {}
        for a in alcances:
            grupos.setdefault((a.origem, a.via), []).append(a.destino)
        for (origem, via), destinos in grupos.items():
            alvo = ",".join(por_endereco.get(d, d) for d in destinos)
            if via:
                linhas.append(f"{por_endereco.get(origem, origem)} -> {alvo} "
                              f"via ssh em {por_endereco.get(via, via)}")
            else:
                linhas.append(
                    f"{por_endereco.get(origem, origem)} -> {alvo} direta")

    linhas.append("")
    linhas.append("=== CREDENCIAIS ===")
    if not credenciais:
        linhas.append("nenhuma obtida")
    for i, c in enumerate(credenciais):
        cabeca = f"[{_id_credencial(i)}] {c.usuario} {c.tipo}"
        if c.segredo:
            # O valor em si. A instrucao do laco pede "a linha exata a
            # executar", e sem o segredo o modelo nao tem como escreve-la
            # (D40). Credencial sem segredo -- uma chave achada num diretorio,
            # por exemplo -- simplesmente nao emite o campo.
            cabeca += f" {c.segredo}"
        elif c.tipo == "chave" and not credencial_utilizavel(c):
            # D221. CHAVE SEM ARQUIVO, e o prompt diz isso EXPLICITAMENTE. Irma
            # da marca de D161 logo abaixo, e nasceu do mesmo defeito uma
            # posicao de argumento depois: a conta existe, o arquivo nao se
            # sabe, e `ssh -i c04` manda o identificador como NOME DE ARQUIVO.
            # Sem a marca o prompt mostrava `[c04] svc_app chave` -- indistinto
            # de uma chave utilizavel.
            cabeca += " (arquivo da chave desconhecido)"
        elif c.tipo == "senha":
            # SENHA SEM SEGREDO, e o prompt diz isso EXPLICITAMENTE (D161). O
            # agente descobriu que a conta existe -- achado legitimo, que fica no
            # grafo --, mas nao tem a senha, e D159 manda referenciar credencial
            # por identificador. Sem esta marca o prompt convidava a escrever
            # `c02` como senha, o laco nao tinha o que resolver, e o
            # identificador ia literal. A guarda em `executar` recusa esse
            # comando; esta linha tira o convite na origem (D65/D68: as duas
            # camadas). Uma `chave` sem segredo NAO ganha a marca: e usavel por
            # `-i`, e a ausencia de senha nela e esperada, nao lacuna.
            cabeca += " (segredo desconhecido)"
        if c.tipo == "chave" and c.identidade:
            # O ARQUIVO, e sem ele a chave e inutil (D186). O agente precisa do
            # que vai depois de `-i`; saber que a conta existe sem saber que
            # arquivo abrir e o mesmo beco de D181 -- fato pela metade, que se
            # completa adivinhando.
            cabeca += f" em {c.identidade}"
        partes = [cabeca]
        if c.origem:
            partes.append(f"origem {por_endereco.get(c.origem, c.origem)}")
        if c.validada_em:
            partes.append("validada "
                          + ",".join(por_endereco.get(e, e) for e in c.validada_em))
        if c.recusada_em:
            partes.append("recusada "
                          + ",".join(por_endereco.get(e, e) for e in c.recusada_em))
        # TENTADA E SEM VEREDITO: o agente levou a credencial ali e ninguem do
        # outro lado chegou a julga-la -- handshake quebrado, porta fechada,
        # tempo esgotado. Fato diferente de "recusada", e o agente precisa dos
        # dois: a recusa diz "a senha esta errada aqui", esta diz "ainda nao se
        # sabe, e o obstaculo foi a rede".
        #
        # Sem esta linha o host sumiria da secao: ele sai da lista "nao
        # testada" abaixo, que exclui tudo que ja foi tentado, e nao apareceria
        # em nenhuma das outras duas.
        sem_veredito = [e for e in c.tentada_em
                        if e not in c.validada_em and e not in c.recusada_em]
        if sem_veredito:
            partes.append("tentada sem veredito "
                          + ",".join(por_endereco.get(e, e) for e in sem_veredito))
        # Onde ela ainda NAO foi tentada e o que dirige a metrica 8, "vezes em
        # que credencial coletada em um host foi aplicada em outro". Sem esta
        # lista o agente nao tem de onde tirar a ideia de reusar. O host de
        # origem fica de fora: foi de la que ela saiu, e sugeri-lo seria
        # conselho circular.
        # `tentada_em` e o superconjunto: inclui o que foi julgado e o que a
        # rede derrubou antes do veredito. Usar a uniao dos dois vereditos aqui
        # faria o grafo sugerir de novo um host onde o agente acabou de tentar.
        testada = set(c.tentada_em) | {c.origem}
        # So entram hosts com servico ABERTO conhecido. Nao ha onde aplicar
        # credencial num host sem servico -- e sem este filtro a lista enchia de
        # ruido: no laboratorio ela sugeria o gateway da rede e a propria
        # maquina do atacante, que sao dois dos cinco enderecos da DMZ.
        # Derivado de observacao, nao de configuracao: nada aqui sabe qual host
        # e "o atacante", e nao pode saber sem plantar informacao.
        # NAO para `senha` SEM segredo (D161). "nao testada" e o campo que
        # dirige a metrica 8, "reusar credencial coletada num host em outro".
        # Uma `senha` sem segredo nao pode ser aplicada em lugar nenhum, e
        # sugerir hosts para ela e conselho impossivel -- foi esse convite que
        # fez o agente gastar 5 passos com `c02`/`c03`/`c04` na coleta-A-01. Uma
        # `chave` sem segredo mantem o campo: e usavel por outra via.
        #
        # ⚠️ **NAO VAI AO BRACO B** (D215). `nao testada h03,h04,h05` e o
        # COMPLEMENTO de um conjunto: cruza toda credencial com todo host e
        # subtrai o que ja se tentou. Nenhuma saida de ferramenta contem essa
        # frase nem poderia conte-la, e o proprio comentario acima diz o que ela
        # e -- "o campo que DIRIGE a metrica 8". Dirigir uma metrica e o que o
        # estado consolidado do braco A faz; no braco B a ideia de reusar a
        # credencial tem de vir dele. **O que fica e a credencial com o segredo**
        # (D125), e sem ela nao haveria o que reusar.
        utilizavel = credencial_utilizavel(c)
        faltando = [por_endereco[h.endereco] for h in ordenados
                    if h.endereco not in testada
                    and any(s.aberta for s in h.servicos)]
        if faltando and utilizavel and derivados:
            partes.append("nao testada " + ",".join(faltando))
        linhas.append("; ".join(partes))

    # Mesma razao de `caminhos_omitidos`: contabilidade de teto NOSSO (D215).
    if credenciais_omitidas and derivados:
        # D200, e o mesmo principio de `caminhos_omitidos`: o que SAIU do que o
        # agente via tem de aparecer como contagem. Esconder o despejo faria o
        # prompt perder informacao em silencio.
        linhas.append(f"(+{credenciais_omitidas} nao listadas: teto de "
                      "credenciais do grafo)")

    return "\n".join(linhas) + "\n"


# D201. TETO DA SECAO DE TENTATIVAS, em acoes distintas mostradas por extenso.
#
# **Medido no corpus, nao escolhido.** A secao existe para o agente nao repetir
# o que ja fez. Entao o numero certo e o alcance real das repeticoes: nas
# execucoes gravadas ha **418 repeticoes de assinatura**, e a distancia entre
# uma acao e a repeticao dela e p50=1, p75=3, p90=11, p95=17, p99=37. Uma janela
# de 25 cobre **96,9%** delas por extenso.
#
# **E os 3,1% restantes nao se perdem**, porque a cauda nao e cortada: ela
# colapsa em contagem por (alvo, ferramenta). O que se perde de uma acao antiga
# e o TEXTO EXATO do comando, nunca o fato de ela ter sido feita.
#
# **Por que existir teto.** Ate 30 de setembro esta secao era uma linha por acao
# distinta, sem limite nenhum: na `coleta-A-01` ela foi **75% da serializacao
# inteira** (11.967 de 15.924 caracteres). O braco A afirma manter *estado
# consolidado* em vez de historico (`ARTEFATO.md` §1), e tres quartos do que ele
# enviava era historico. O braco B ja tinha teto (`TETO_DE_TEXTO`, D125); o
# braco A nao tinha nenhum, e essa assimetria nunca foi declarada nem medida --
# §4.1 manda manter igual tudo que nao seja a forma do estado.
JANELA_DE_TENTATIVAS = 25


def serializar_tentativas(hosts: list[Host],
                          tentativas: list[Tentativa] | None = None) -> str:
    """A secao de historico da acao, com teto e cauda colapsada (D201)."""
    por_endereco = mapa_de_identificadores(hosts)
    linhas: list[str] = ["=== TENTATIVAS JA REALIZADAS ==="]

    # Uma linha por acao DISTINTA, com a contagem quando houve repeticao. Numa
    # execucao de 60 passos, uma linha por passo encheria o orcamento de tokens
    # repetindo o que ja esta dito -- e o cronograma e explicito em que caber em
    # poucas centenas de tokens importa mais do que ser bonito.
    #
    # O rotulo de cada linha e o COMANDO, nao uma descricao. O prompt medido
    # traz descricoes em prosa ("leitura de arquivo de configuracao") porque foi
    # escrito a mao; derivar prosa assim de um comando seria sintetizar, e o
    # comando diz mais ao modelo do que qualquer parafrase que o grafo pudesse
    # inventar.
    grupos: dict[str, list[Tentativa]] = {}
    ultima_posicao: dict[str, int] = {}
    for posicao, t in enumerate(tentativas or []):
        # Agrupa pela ASSINATURA, que distingue tudo; mostra o ROTULO, que
        # cabe. Agrupar pelo rotulo fundiria duas acoes diferentes numa linha
        # so, e o agente deixaria de tentar o que nunca tentou.
        grupos.setdefault(t.assinatura, []).append(t)
        # A posicao da ULTIMA ocorrencia, que e o que ordena a janela. Pela
        # PRIMEIRA, uma acao repetida agora ficaria na cauda por ter nascido
        # cedo -- e a janela deixaria de cobrir justamente a repeticao recente,
        # que e o caso mais comum (p50 = 1 acao de distancia).
        ultima_posicao[t.assinatura] = posicao
    if not grupos:
        linhas.append("nenhuma acao registrada")
        return "\n".join(linhas) + "\n"

    ordem = sorted(grupos, key=lambda a: ultima_posicao[a])
    antigas = ordem[:-JANELA_DE_TENTATIVAS]
    recentes = ordem[-JANELA_DE_TENTATIVAS:]

    if antigas:
        # A CAUDA COLAPSADA. Conta ACOES, nao assinaturas distintas: o agente
        # pergunta "quantas vezes eu ja fiz curl aqui", e a resposta honesta e o
        # numero de vezes. Ordenada para ser deterministica -- duas execucoes do
        # mesmo braco tem de ser comparaveis, mesmo motivo de `_chave`.
        colapso: dict[tuple[str, str], list[int]] = {}
        for chave in antigas:
            for t in grupos[chave]:
                onde = por_endereco.get(t.alvo or "") or t.alvo or "sem alvo"
                conta = colapso.setdefault((onde, t.ferramenta), [0, 0])
                conta[0] += 1
                conta[1] += 1 if t.sucesso else 0
        linhas.append("acoes mais antigas, so contadas: " + "; ".join(
            f"{onde} {ferramenta} {n}x, {ok} ok"
            for (onde, ferramenta), (n, ok) in sorted(colapso.items())))

    for i, chave in enumerate(recentes):
        lista = grupos[chave]
        ultima = lista[-1]
        # A SETA CARREGA O IDENTIFICADOR, e existe por causa dele: `hNN` e o que
        # o agente escreve no campo `alvo`, e e a ponte entre esta secao e a de
        # hosts. Quando o alvo NAO tem identificador -- uma sub-rede, ou um host
        # que o grafo ainda nao viu --, a seta so repetiria o que o rotulo ja
        # diz, agora que o rotulo traz o alvo (D64/D65). Sem identificador, sem
        # seta.
        identificador = por_endereco.get(ultima.alvo) if ultima.alvo else None
        seta = f" -> {identificador}" if identificador else ""
        if ultima.sucesso is None:
            # Tentativa que nunca fechou. Dizer "FALHA" afirmaria um desfecho
            # que nao houve.
            desfecho = "SEM DESFECHO"
        else:
            desfecho = "OK" if ultima.sucesso else "FALHA"
        linha = f"[{_id_tentativa(i)}] {ultima.rotulo or chave}{seta}: {desfecho}"
        if ultima.resumo:
            linha += f", {ultima.resumo}"
        if len(lista) > 1:
            linha += f" ({len(lista)}x)"
        linhas.append(linha)

    return "\n".join(linhas) + "\n"


def serializar(hosts: list[Host], credenciais: list[Credencial],
               alcances: list[Alcance], subredes: dict[str, str | None],
               tentativas: list[Tentativa] | None = None,
               credenciais_omitidas: int = 0) -> str:
    """As cinco secoes que saem do grafo: ambiente mais historico da acao.

    Composicao das duas funcoes acima, e so isso. Existe para que o braco A
    continue tendo UMA chamada, e para que a ordem das secoes e a linha em
    branco entre elas morem num lugar so.
    """
    return (serializar_ambiente(hosts, credenciais, alcances, subredes,
                                credenciais_omitidas)
            + "\n" + serializar_tentativas(hosts, tentativas))




def _servico(s) -> str:
    # D228. A INTERROGACAO DO NMAP, na notacao dele. O agente e um agente de
    # pentest: `waste?` ele le como "o nmap chutou pelo numero da porta e o
    # fingerprint nao confirmou", que e exatamente o que o campo diz. Inventar
    # uma redacao nossa ("(incerto)") seria traduzir o que nao precisa de
    # traducao -- e a lição de D197 e D199: a redacao e parte do conserto.
    nome = s.servico or "desconhecido"
    if s.servico and getattr(s, "incerto", False):
        nome += "?"
    fim = f"{s.porta}/{s.protocolo} {nome}"
    return f"{fim} {s.versao}" if s.versao else fim


def _chave(endereco: str):
    """Ordena endereco IPv4 por octeto, e o resto por texto.

    Sem isto, `172.20.0.5` viria depois de `172.20.0.10` na ordem alfabetica, e
    os identificadores `h01`, `h02` mudariam de dono conforme a ordem de
    descoberta -- o que tornaria duas execucoes do mesmo braco incomparaveis.
    """
    partes = endereco.split(".")
    if len(partes) == 4 and all(p.isdigit() for p in partes):
        return (0, tuple(int(p) for p in partes))
    return (1, endereco)
