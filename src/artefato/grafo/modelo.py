"""O que o grafo guarda.

`ARTEFATO.md` §1.2 chama o grafo de "a contribuicao" e lista o conteudo: hosts,
servicos, credenciais, sub-redes, alcancabilidade e tentativas ja feitas. As
tentativas ficam para a quinta 17, conforme o cronograma separa.

**Por que estas classes nao sao as de `ferramentas/fatos.py`.** La, `Host` e o
que UM comando observou. Aqui, e o que se sabe do host depois de varias
observacoes: o nome veio de uma varredura, os servicos de outra, o
comprometimento de uma autenticacao. Fundir as duas faria o grafo herdar a
forma de uma leitura isolada, e perder informacao a cada nova varredura --
que e exatamente o defeito que o teste "varrer a mesma faixa duas vezes nao
duplica host" existe para impedir.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ferramentas.fatos import Rota
from ferramentas.saida import Interface


@dataclass
class Servico:
    porta: int
    protocolo: str
    estado: str
    servico: str | None = None
    versao: str | None = None
    # ⚠️ **O PALPITE DO NMAP CHEGA AO GRAFO MARCADO COMO PALPITE** (D228).
    #
    # `ferramentas.fatos.Servico` carrega este campo desde sempre, com o
    # comentario que explica por que: *"o nmap marca com `?` o servico que ele
    # achou mas nao identificou com firmeza. Engolir a interrogacao
    # transformaria palpite em fato -- e o agente decidiria em cima de uma
    # identificacao que o proprio nmap nao assina."*
    #
    # **E o grafo nao tinha o campo, entao `absorver_hosts` o descartava.**
    # Conferido ao vivo em 1 de outubro, a cadeia inteira:
    #
    #     o nmap escreve:   1337/tcp open  waste?
    #     o parser extrai:  servico='waste'  incerto=True
    #     o grafo guardava: servico='waste'          <- o palpite virou fato
    #     o agente lia:     servicos: 1337/tcp waste
    #
    # E a porta 1337 e a do distrator -- onde o braco B queimou 16 de 80 passos.
    # O parser fazia o certo e o absorvedor jogava fora: **perder achado e menos
    # grave que inventar fato** (D04), e aqui se inventava.
    incerto: bool = False

    @property
    def aberta(self) -> bool:
        return self.estado == "open"


# ⚠️ **O VALOR DE `meio_de_acesso` QUE NAO E UMA ROTA DE ACESSO** (D219).
#
# O campo guarda duas coisas de naturezas diferentes: rota OBSERVADA pelo
# oraculo (`"injecao de comando em /diagnostico (param host)"`) e uma CONCLUSAO
# que o grafo tira sozinho -- "o comando rodou dentro deste host para alcancar o
# alvo, logo havia execucao aqui". A segunda e este valor.
#
# Precisou de nome em 30 de setembro porque um classificador novo leu o campo
# como se fosse sempre rota e produziu a frase `"o acesso nesse salto e por
# usado como pivo, nao por sessao ssh"` -- sem sentido, e fato falso sobre o
# ambiente. A suite pegou na hora, por um teste de D178 que exigia a razao
# CERTA. **Campo que guarda duas naturezas pede nome para a que nao e a obvia.**
ACESSO_POR_PIVO = "usado como pivo"


@dataclass
class Host:
    endereco: str
    nome: str | None = None
    subrede: str | None = None
    # Enumerado = alguma varredura ja olhou as portas dele. Comprometido =
    # houve autenticacao bem-sucedida. Sao coisas diferentes e a linha do host
    # na serializacao mostra as duas, como no prompt ja medido.
    enumerado: bool = False
    comprometido: bool = False
    # A maquina de onde o agente executa (D53). Ela e `comprometido` para que
    # `rota_para` responda "alcancavel direto" na sub-rede em que o agente
    # esta -- e ele esta mesmo. Mas a metrica 2 de `ARTEFATO.md` §4.2 conta
    # "hosts comprometidos SOBRE 5", e os cinco sao os da cadeia: contar a
    # propria maquina do atacante inflaria a metrica primaria de resultado em
    # um, de graca, nos dois bracos.
    origem: bool = False
    # COMO se obteve execucao aqui. `None` quando foi por autenticacao SSH, que
    # e o caso comum e ja fica descrito pela credencial. Existe porque o elo 1
    # da cadeia (`lab/cadeia.md`) e injecao de comando por HTTP: sem usuario,
    # sem credencial, sem ssh. Um dos cinco hosts da metrica 2 e desse tipo, e
    # sem este campo ele seria impossivel de registrar.
    meio_de_acesso: str | None = None
    servicos: list[Servico] = field(default_factory=list)
    # O que as paginas deste host revelaram. Sem os dois, o agente perde no
    # passo seguinte a rota e o parametro que a requisicao acabou de descobrir,
    # porque o historico e descartado (§E13, D54). O prompt medido ja os trazia:
    # `titulo http:` e `rotas:`.
    titulo: str | None = None
    rotas: list[Rota] = field(default_factory=list)
    # O que a saida de um comando executado aqui revelou (D57). Sem isto o
    # agente roda `find` e nao ve o resultado, porque o historico e descartado.
    usuario: str | None = None
    uid: int | None = None
    caminhos: list[str] = field(default_factory=list)
    # De que LOTE cada caminho veio -- quantos caminhos tinha o comando que o
    # revelou. E o criterio de despejo de D112, e e o mesmo de D58: saida
    # enorme tem pouca informacao por caminho, saida pequena tem muita. Sem
    # este campo o teto por host seria primeiro-a-chegar-fica, e uma varredura
    # ampla cedo cegaria o resto da execucao.
    #
    # Nao entra na serializacao que o agente le: ele ve `caminhos`, nao de onde
    # vieram. E contabilidade nossa, nao fato do ambiente.
    caminhos_lote: dict = field(default_factory=dict)
    # Quantos ficaram de fora do teto. `find /` devolve milhares, e enfia-los no
    # prompt destruiria o orcamento de tokens que D45 defende. Dizer quantos
    # ficaram de fora e fato util: ensina o agente a estreitar a busca.
    caminhos_omitidos: int = 0
    # D197. CAMINHOS QUE UM ARQUIVO DESTE HOST CITA, sem que se tenha observado
    # que existem aqui. Lista separada de proposito: `caminhos` afirma *este host
    # tem isto*, e `mencionados` afirma *um arquivo daqui fala disto* -- que e
    # mais fraco e e o que de fato se observou. O inventario do `host-arquivo` e
    # o caso: ele e uma tabela sobre OUTROS hosts.
    mencionados: list[str] = field(default_factory=list)

    # ⚠️ **D245. Caminho que uma linha de arquivo ASSOCIA a ESTE host, com o
    # endereco de onde o arquivo foi lido.** Terceira lista, e as tres afirmam
    # coisas diferentes:
    #
    #     caminhos     este host TEM isto           (prova)
    #     mencionados  um arquivo DAQUI fala disto   (mencao, D197)
    #     associados   um arquivo de OUTRO host diz que ESTE host tem isto
    #
    # A terceira existe porque o parser tinha o dado e o jogava fora: D197 fazia
    # `prova = not ENDERECO_NA_LINHA.search(linha)` e descartava o endereco. O
    # caminho ia para `mencionados` do host que LEU, e §E96 mediu o custo -- o
    # agente procurou `/home/svc_app` no `host-arquivo` por tres passos, quando a
    # linha do inventario o associava ao `srv-financeiro`.
    #
    # **Nao afirma existencia**, e por isso cabe aqui sem virar fato falso: o par
    # e verdade sobre o TEXTO lido, quer o caminho exista ou nao (§E99 corrigida).
    # Por isso tambem nao entra em `conferir_caminhos.py`, que audita `caminhos`.
    #
    # `caminho -> endereco de origem`. Dicionario, nao lista, porque o mesmo par
    # pode vir de duas linhas e a deduplicacao e de graca; a primeira origem
    # fica, que basta para o agente saber onde ler de novo.
    associados: dict = field(default_factory=dict)
    # As interfaces de rede deste host, lidas de `ip addr` (segunda 21). Sao o
    # que revela a segunda perna do pivo, e com ela a EXISTENCIA da sub-rede
    # interna -- o mecanismo central da hipotese deste trabalho.
    #
    # **O host continua sendo UM.** Cada interface nao vira host proprio: a
    # metrica 2 conta hosts comprometidos, e o pivo entrando duas vezes, uma por
    # perna, a inflaria em um -- no sentido que FAVORECE a hipotese, que e o
    # erro mais caro que este projeto pode cometer.
    #
    # E existir nao e alcancar: `Grafo.subredes_alcancadas` continua derivando
    # da `subrede` primaria, nunca daqui. Ver o comentario la, que e onde a
    # distincao morde.
    interfaces: list[Interface] = field(default_factory=list)
    # D199. PORTAS DESTE HOST ONDE A AUTENTICACAO NAO JULGA A SENHA. Chave: a
    # porta, em texto (JSON nao tem chave inteira, e o grafo persiste em JSON).
    # Valor: quantos pares a corrida reportou como aceitos.
    #
    # E fato sobre o AMBIENTE, e por isso mora aqui e nao numa lista de
    # credenciais: o que se observou foi uma propriedade do servico, nao a
    # existencia de contas. A leitura oposta -- cada par aceito virando uma
    # conta -- custou 57% do prompt do braco A na `coleta-A-02` e levou o agente
    # ao distrator pelo resto da execucao (§E81).
    autenticacao_indiscriminada: dict = field(default_factory=dict)

    def funde(self, outro: "Host") -> None:
        """Incorpora uma observacao nova sem perder a anterior.

        Campo ausente na observacao nova NAO apaga o que ja se sabia: uma
        varredura `-sn` nao traz servicos, e deixa-la sobrescrever a `-sV`
        apagaria tudo que a segunda descobriu.
        """
        self.nome = self.nome or outro.nome
        self.subrede = self.subrede or outro.subrede
        self.enumerado = self.enumerado or outro.enumerado
        self.origem = self.origem or outro.origem
        self.meio_de_acesso = self.meio_de_acesso or outro.meio_de_acesso
        self.titulo = self.titulo or outro.titulo
        self.usuario = self.usuario or outro.usuario
        self.uid = self.uid if self.uid is not None else outro.uid
        for r in outro.rotas:
            # D225. A PORTA ENTRA NA CHAVE, como em `absorver_resposta`: `/x` em
            # 8000 e `/x` em 8080 sao rotas diferentes. Duas chaves divergentes
            # para a mesma relacao e a divergencia de 21 de setembro esperando
            # acontecer, entao as duas tem a mesma regra.
            conhecida = next((x for x in self.rotas
                              if x.caminho == r.caminho and x.metodo == r.metodo
                              and (x.porta == r.porta or x.porta is None
                                   or r.porta is None)),
                             None)
            if conhecida is None:
                self.rotas.append(r)
                continue
            # Rota ja conhecida: a leitura nova so ACRESCENTA parametro. Uma
            # pagina pode revelar o formulario e outra so o link, e substituir
            # apagaria os parametros que a primeira trouxe.
            conhecida.porta = conhecida.porta or r.porta
            for nome in r.parametros:
                if nome not in conhecida.parametros:
                    conhecida.parametros.append(nome)
        self.comprometido = self.comprometido or outro.comprometido
        for s in outro.servicos:
            conhecida = next((x for x in self.servicos
                              if x.porta == s.porta and x.protocolo == s.protocolo),
                             None)
            if conhecida is None:
                self.servicos.append(s)
                continue
            # Porta ja conhecida: a leitura nova so acrescenta o que tem.
            conhecida.estado = s.estado or conhecida.estado
            conhecida.servico = s.servico or conhecida.servico
            conhecida.versao = s.versao or conhecida.versao
            # D228. A CERTEZA SO SOBE, nunca desce: uma leitura que identificou
            # o servico com firmeza (`incerto=False`) manda sobre um palpite
            # anterior, e um palpite novo NAO apaga uma identificacao firme.
            # `or` simples faria o palpite ganhar sempre que chegasse depois.
            if s.servico and not s.incerto:
                conhecida.incerto = False
            elif s.servico and conhecida.servico is None:
                conhecida.incerto = s.incerto
        # Interface ja conhecida nao duplica. A chave e o ENDERECO, nao o nome:
        # `eth0` de um host nao e `eth0` de outro, mas dentro do mesmo host o
        # endereco identifica a perna sem ambiguidade.
        for i in outro.interfaces:
            if not any(x.endereco == i.endereco for x in self.interfaces):
                self.interfaces.append(i)
        # D199. A observacao NOVA vence, porque uma corrida maior mede melhor o
        # quanto o servico aceita. Nao apagar o que ja havia: observacao antiga
        # de outra porta continua valendo.
        self.autenticacao_indiscriminada.update(outro.autenticacao_indiscriminada)


@dataclass
class Credencial:
    """Uma credencial e entidade propria, nao campo do host.

    A metrica 8 do trabalho e "reuso de credencial": a mesma credencial
    funcionando em mais de um host. Se ela fosse atributo do host, o reuso
    viraria duas credenciais parecidas e a metrica teria de compara-las por
    texto. Aqui e um objeto so, com a lista de onde funcionou.
    """

    usuario: str
    tipo: str
    # O valor em si. Existe porque a instrucao do laco pede ao modelo "a linha
    # exata a executar", e autenticar por senha passa por `sshpass -p <senha>`
    # (D10): sem o segredo no estado que o agente recebe, ele nao consegue
    # escrever a linha, e o aceite falharia por falta de dado em vez de por
    # falta de raciocinio -- que e o que o experimento mede (D40).
    segredo: str | None = None
    # O ARQUIVO DE IDENTIDADE, quando a credencial e uma chave (D186). Nao e
    # segredo e nao se mascara: e um CAMINHO, e sem ele o agente sabe que a conta
    # existe e nao sabe o que passar para `-i`. Mesma logica do `segredo` para a
    # senha -- o estado tem de conter o que a linha exata precisa (D40) --, com a
    # diferenca de que caminho pode aparecer em claro.
    identidade: str | None = None
    origem: str | None = None
    # ONDE O AGENTE A LEVOU, deu no que desse. Superconjunto das duas listas
    # abaixo, e o campo que a metrica 8 conta.
    #
    # Existe porque ate 22 de setembro `recusada_em` fazia os dois papeis, e as
    # duas perguntas nao sao a mesma: "eu tentei aqui?" e verdade mesmo quando
    # a rede caiu; "o host recusou?" so e verdade quando alguem do outro lado
    # olhou a credencial. Na `teto-03` o campo unico afirmou recusa em dois
    # enderecos que nunca julgaram nada -- um por falha de handshake, outro
    # porque o agente copiou a mascara do rotulo. O prompt dizia `recusada` de
    # uma senha que funcionava.
    tentada_em: list[str] = field(default_factory=list)
    validada_em: list[str] = field(default_factory=list)
    # So entra aqui quando o servico JULGOU a credencial e disse nao. A regra
    # mora em `ferramentas.julgou`, ao lado de `autenticou` (D79).
    recusada_em: list[str] = field(default_factory=list)

    @property
    def reusada(self) -> bool:
        return len(self.validada_em) > 1


@dataclass
class Alcance:
    """Uma aresta: de onde se alcanca o quê, e se precisou de salto."""

    origem: str
    destino: str
    via: str | None = None


# Argumentos que carregam segredo, por ferramenta. A tabela e pequena de
# proposito: as seis ferramentas do laboratorio estao fixadas em
# `ARTEFATO.md` §1.3, e uma regra generica do tipo "mascare o que vem depois de
# -p" apagaria as PORTAS do nmap, que sao o unico campo distinguindo duas
# varreduras diferentes do mesmo host -- as duas passariam a contar como a
# mesma acao na metrica 7.
# O que fica no lugar do segredo. **Marcador, nao tarja.**
#
# Ate 22 de setembro era `****`, e isso custava passos: `sshpass -p '****'` tem
# a forma exata de um comando pronto, e o agente o COPIOU -- 5 passos na
# `teto-03`, 4 deles terminando em codigo 5, com a senha certa disponivel a
# poucas linhas dali na secao CREDENCIAIS. Na `auto-01` foram 23 copias de
# rotulo quebrado (D64).
#
# D65 registrou o `ssh` como excecao deliberada a regra "o rotulo e um comando
# que roda", porque D40 manda o segredo morar so na credencial. A excecao
# continua; o que muda e o rotulo AVISAR que e excecao. `****` e um valor
# plausivel -- pode ser uma senha de quatro caracteres, pode ser um glob.
# `<SENHA>` e a convencao universal de "preencha aqui" e nao se confunde com
# conteudo, o que tambem torna segura a guarda que recusa o comando copiado:
# nenhuma linha legitima do laboratorio contem este texto.
MASCARA = "<SENHA>"


def mascarar(comando: list[str], segredos: tuple[str, ...] = (),
             identificadores: dict[str, str] | None = None) -> list[str]:
    """O comando com os segredos trocados pelo identificador da credencial.

    **`identificadores` mapeia segredo -> `c01`, e e o conserto de D159.** Sem
    ele o segredo vira `<SENHA>`, e o rotulo passa a ensinar uma forma de
    comando que NAO FUNCIONA: o agente copia o marcador, o `sshpass` recebe o
    texto literal como senha, e a guarda recusa o passo. Medido em 57 dos 1.669
    passos do corpo, em 8 execucoes, **todas do braco A** -- o braco B nao tem
    secao de tentativas e nunca ve o marcador. Com o identificador no lugar,
    copiar o rotulo passa a ser o comportamento CERTO, porque o laco o resolve.
    Medido: 20/20 escrevem `c01`, 0/20 copiam o marcador (Fisher p = 0,0083).

    O marcador continua sendo o que sai quando NAO se sabe de quem e o segredo
    -- valor que nenhuma credencial do grafo reclama. Mascarar e obrigatorio;
    nomear e so possivel quando ha nome.

    **Duas mascaras, e as duas sao necessarias.**

    A primeira e por POSICAO -- `sshpass -p <senha>` --, e cobre o caso comum
    sem precisar saber qual e a senha. A segunda e por VALOR, e cobre tudo o
    mais: em 22 de setembro, na `teto-02`, o agente escreveu
    `echo 7fQx2Lm9RtVzB4kd | sudo -S -l`, e a senha foi para a secao de
    tentativas em texto claro, repetida a cada passo seguinte. O segredo tem um
    lugar so no grafo, que e a credencial (D40).

    A mascara por valor troca a SUBSTRING, nao o argumento inteiro: o segredo
    costuma vir embutido numa linha de shell maior, e apagar a linha toda
    destruiria a acao que a tentativa descreve.

    `segredos` vem de quem chama -- o grafo, que os tem -- e nunca e deduzido
    aqui: adivinhar o que parece senha mascararia argumento legitimo e faria
    duas acoes diferentes virarem a mesma na assinatura da metrica 7.
    """
    nomes = identificadores or {}
    partes = list(comando)
    ferramenta = partes[0] if partes else ""
    for i in range(len(partes) - 1):
        if partes[i] != "-p":
            continue
        # `sshpass -p <senha>` e `hydra ... -p <senha>`. O `-p` do ssh e porta,
        # o `-P` do hydra e caminho de arquivo, e nenhum dos dois entra aqui.
        if (i > 0 and partes[i - 1] == "sshpass") or ferramenta == "hydra":
            partes[i + 1] = nomes.get(partes[i + 1], MASCARA)
    # Do mais longo para o mais curto: se um segredo for prefixo de outro,
    # trocar o curto primeiro deixaria o resto do longo exposto.
    for segredo in sorted((s for s in segredos if s), key=len, reverse=True):
        # O identificador tambem entra na mascara POR VALOR, e nao so na por
        # posicao: o segredo embutido numa linha de shell -- `echo <senha> |
        # sudo -S`, que e como a `teto-02` o vazou -- fica nomeado igual. Se o
        # rotulo dissesse `c01` num lugar e `<SENHA>` no outro, a mesma
        # credencial teria dois nomes no mesmo prompt.
        partes = [p.replace(segredo, nomes.get(segredo, MASCARA))
                  for p in partes]
    return partes


def assinatura(comando: list[str], segredos: tuple[str, ...] = (),
               identificadores: dict[str, str] | None = None) -> str:
    """Texto que identifica uma acao, sem o segredo dentro.

    E a chave de comparacao da metrica 7: duas acoes sao "a mesma" quando a
    assinatura coincide. Guardar o comando cru no lugar disto faria a senha
    entrar no grafo por uma porta lateral e sair na serializacao -- o segredo
    tem um lugar so, que e a credencial (D40).

    Compara o comando INTEIRO, inclusive as opcoes constantes. O rotulo curto
    que aparece na serializacao joga fora o que nunca varia (D45); a assinatura
    nao pode fazer isso, porque e ela que decide se duas acoes sao a mesma.

    **Recebe `identificadores` pelo mesmo motivo que o rotulo (D159):** se o
    rotulo dissesse `c01` e a assinatura `<SENHA>`, a mesma acao teria duas
    representacoes no arnes. E, com mais de uma credencial, nomear separa o que
    o marcador colapsava -- duas senhas diferentes davam a MESMA assinatura, e a
    metrica 7 contava como repeticao duas acoes distintas. Nos grafos reais de
    hoje ha uma credencial so, entao a diferenca e zero; a melhora e para quando
    houver duas. **Metrica 7 recalculada sobre o corpo antigo nao e comparavel
    com a de antes** -- declarado em D159 §5.
    """
    return " ".join(mascarar(comando, segredos, identificadores))


@dataclass
class Tentativa:
    """Uma acao que o agente decidiu executar, e o que ela rendeu.

    E a sexta entidade que `ARTEFATO.md` §1.2 lista como conteudo do grafo, e
    alimenta a metrica 7 de §4.2: "repeticao da mesma acao sobre o mesmo alvo
    sem informacao nova entre elas".

    `revisao` e `None` enquanto a tentativa nao fechou -- passo que morreu no
    meio nao autoriza conclusao nenhuma sobre o que se aprendeu nele, e `None`
    nunca vira zero neste projeto.
    """

    ferramenta: str
    # Comparada para decidir repeticao: o comando inteiro, mascarado.
    assinatura: str
    # Mostrada ao modelo: a forma curta que a propria ferramenta produz,
    # sem o que nunca varia (D45). Sao campos separados porque servem a dois
    # fins opostos -- um precisa distinguir tudo, o outro precisa caber.
    rotulo: str = ""
    alvo: str | None = None
    # Decidido na ABERTURA, contra o estado do grafo naquele instante. Calcular
    # depois seria calcular contra um grafo que ja incorporou o resultado desta
    # mesma acao, e ai toda repeticao pareceria informativa.
    redundante: bool = False
    sucesso: bool | None = None
    resumo: str | None = None
    revisao: int | None = None
    # A revisao do grafo NO MOMENTO DA ABERTURA. Com a de fechamento forma o par
    # que responde "esta acao ensinou alguma coisa?" -- metrica 11 (D87). Fica
    # aqui, e nao numa contagem a parte, porque a resposta e por ACAO: a ordem
    # das tentativas na lista nao basta, ja que uma pode morrer no meio e nunca
    # fechar. `None` em grafo gravado antes de 22 de setembro, e `None` nunca
    # vira zero neste projeto.
    revisao_ao_abrir: int | None = None

    @property
    def fechada(self) -> bool:
        return self.revisao is not None
