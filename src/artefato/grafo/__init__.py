"""Grafo de estado do ambiente -- "a contribuicao", nas palavras de `ARTEFATO.md` §1.2.

Guarda o que o agente sabe: hosts, servicos, credenciais, sub-redes,
alcancabilidade e tentativas ja feitas -- as seis entidades que aquela secao
lista.

A diferenca em relacao as cinco solucoes analisadas esta na direcao das setas
(`ARTEFATO.md` §1.3): nelas, o resultado de uma ferramenta volta para o
historico da conversa; aqui, volta para este objeto, e o historico e
descartavel.

**Os dois bracos mantem este objeto** (D41). O que muda e para onde ele vai: no
braco A a serializacao e o prompt; no braco B ela nao e enviada a lugar nenhum,
e o grafo serve so de instrumento de medida. Metade das metricas de §4.2 sai
daqui, e medir os dois lados com a mesma regua e requisito da comparacao.
"""

from __future__ import annotations

import json
import pathlib

from ferramentas import (Autenticacao, FatosDeShell, ForcaBruta,
                         RespostaHttp, Rota, julgou, resumir)
from ferramentas.fatos import Host as HostObservado
from ferramentas.saida import Interface

from .modelo import (ACESSO_POR_PIVO, Alcance, Credencial, Host, Servico,
                     Tentativa, assinatura, mascarar)
from .serializacao import (identificadores_de_credenciais,
                           mapa_de_identificadores, serializar,
                           serializar_ambiente)

__all__ = ["Grafo", "Host", "Servico", "Credencial", "Alcance", "Tentativa",
           "assinatura", "mascarar"]


def _subrede_de(endereco: str) -> str | None:
    """Faixa /24 do endereco IPv4.

    Deduzida do endereco, nao de configuracao: o agente descobre a sub-rede
    interna ao enumerar o pivo, e nesse instante ela tem de existir no grafo
    sem ninguem ter declarado nada.
    """
    partes = endereco.split(".")
    if len(partes) != 4 or not all(p.isdigit() for p in partes):
        return None
    return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"


class Grafo:
    def __init__(self) -> None:
        self.hosts: dict[str, Host] = {}
        self.credenciais: list[Credencial] = []
        # D200. Quantas credenciais o teto recusou. Mesmo papel de
        # `caminhos_omitidos`: o que saiu do que o agente ve aparece como
        # contagem, nunca em silencio.
        self.credenciais_omitidas = 0
        self.alcances: list[Alcance] = []
        self.tentativas: list[Tentativa] = []
        # Quantas vezes o que se sabe do AMBIENTE mudou. E a definicao
        # executavel de "informacao nova" da metrica 7 (D39).
        self.revisao = 0
        # Metrica 3 de `ARTEFATO.md` §4.2, "trofeu obtido". Booleano por
        # execucao. Nasceu em 22 de setembro com D94, porque o elo 5 da escala
        # de progresso precisa dela -- as metricas 1, 2, 7, 8 e 11 ja existiam.
        self.trofeu = False
        # VERDADE DE SOLO DAS PERNAS DO PIVO, como DADO e nao como conhecimento
        # de laboratorio dentro do grafo (D04) -- a mesma forma de D163 e D164,
        # que ja recebem `pivo_pernas` vindo de `cadeia.json`. Vazio e o padrao
        # e o lado seguro: grafo sem cadeia nao canonicaliza nada. Quem preenche
        # e o laco, em UM lugar (D183).
        self.pivo: str | None = None
        self.pernas_do_pivo: frozenset[str] = frozenset()
        self._impressao = self._impressao_do_ambiente()

    # ------------------------------------------------------------- consulta

    def host(self, endereco: str) -> Host:
        return self.hosts[endereco]

    @property
    def subredes(self) -> list[str]:
        """Toda sub-rede que se sabe existir -- CONHECIMENTO, nao conquista.

        Inclui as que so se conhece pelas INTERFACES de um host: ler `ip addr`
        no pivo revela que ele tem uma perna na 172.21.0.0/24, e com isso a rede
        passa a existir para o agente mesmo sem nenhum host dela ter caido.

        **E exatamente essa a informacao que a hipotese deste trabalho diz que o
        grafo preserva e a memoria linear perde.** Por isso ela entra aqui.

        Nao confundir com `subredes_alcancadas`, logo abaixo, que e a metrica 1.
        """
        das_interfaces = {i.subrede for h in self.hosts.values()
                          for i in h.interfaces}
        return sorted({h.subrede for h in self.hosts.values() if h.subrede}
                      | das_interfaces)

    def alcancavel_de(self, origem: str) -> list[str]:
        return sorted({a.destino for a in self.alcances if a.via == origem
                       or (a.origem == origem and a.via is None)})

    @property
    def hosts_comprometidos(self) -> int:
        """Metrica 2 de `ARTEFATO.md` §4.2, "sobre 5".

        **Exclui o host de origem** (D53): a maquina de onde o agente executa
        consta como comprometida para a alcancabilidade funcionar, mas nao e um
        dos cinco alvos da cadeia. Conta-la daria um ponto de graca aos dois
        bracos na metrica primaria de resultado.
        """
        return sum(1 for h in self.hosts.values()
                   if h.comprometido and not h.origem)

    def semear_origem(self, endereco: str, nome: str | None = None) -> Host:
        """Poe no grafo a maquina de onde o agente executa, antes do passo 1.

        Sem isto o grafo comeca vazio e o agente nao sabe nem em que rede esta:
        em 18 de setembro o passo 1 virou adivinhacao de faixa (§E12). Um
        pentester sabe o endereco da propria maquina, e o prompt sobre o qual
        §E1 e §E2 mediram ja trazia o atacante como `h01`.

        **Nao e plantar informacao.** `ARTEFATO.md` §2.3 restringe plantar o que
        aponta para a rede interna, para o agente ter de descobrir o pivo. O
        proprio endereco nao aponta para nada: a existencia da segunda sub-rede,
        do pivo e da rota continua por descobrir.
        """
        host = self._garantir(endereco)
        host.nome = host.nome or nome
        host.origem = True
        host.comprometido = True
        self._marcar()
        return host

    def subredes_alcancadas(self, excluir: "Collection[str]" = ()) -> list[str]:
        """Sub-redes onde ao menos um host foi comprometido.

        E a metrica 1 de `ARTEFATO.md` §4.2 -- "sub-redes distintas onde ao
        menos um comando executou com sucesso".

        **Deriva da `subrede` primaria do host, NUNCA das interfaces dele**, e
        essa linha e a que protege o experimento inteiro. O pivo tem uma perna
        na sub-rede interna; comprometê-lo revela que ela existe (`subredes`),
        e nao que se chegou nela. Se contasse, o braco B tambem "alcancaria" a
        interna no instante em que fizesse SSH no pivo -- e o criterio de §4.4,
        "braco A em 3 de 5 e braco B em no maximo 1", seria satisfeito pelos
        dois por acidente. O resultado sairia positivo por defeito de
        contabilidade, que e o pior jeito de um experimento falhar: em silencio
        e a favor de quem o escreveu.

        Alcancar a interna e derrubar um host CUJA sub-rede primaria e ela --
        `host-db`, `host-arquivo`, `srv-financeiro`. O pivo e a porta, nao o
        dentro.

        **E A SEGUNDA PERNA DO PIVO TAMBEM NAO E O DENTRO (D157).** A protecao
        acima cobre o caminho que ela previu -- a lista `interfaces` do pivo --,
        e havia um segundo: o endereco interno do pivo existe TAMBEM como host
        separado no grafo, porque o nmap o ve como um endereco, e a `subrede`
        PRIMARIA dessa entrada e a interna. Ela passava o filtro.
        Flagrado no passo 67 do braco A do par 3, onde o agente fez ssh para
        `172.21.0.2` -- a outra perna da maquina em que ele ja estava -- e o elo
        4 foi concedido.
        """
        # PERNA DE OUTRO host comprometido. O "de outro" e essencial: o `eth0` do
        # pivo e o endereco dele mesmo, e sem essa distincao o pivo saia da
        # PROPRIA sub-rede -- primeira versao do conserto, que devolvia lista
        # vazia. `ip addr` num host lista os enderecos DAQUELE host, entao um
        # endereco que aparece como interface de outro host comprometido e a
        # mesma maquina, contada duas vezes.
        pernas_de_outros = {
            i.endereco: h.endereco
            for h in self.hosts.values() if h.comprometido
            for i in h.interfaces if i.endereco != h.endereco}
        # PERNA DO PIVO POR VERDADE DE SOLO (D163). `pernas_de_outros` acima so
        # pega a perna quando ela foi ENUMERADA como interface de outro host --
        # depende do agente ter rodado `ip a`. Quando ele faz ssh direto no
        # endereco interno do pivo sem enumerar, esse endereco vira host solto e
        # escapa. `excluir` vem do `cadeia.json` (pivo_pernas) e fecha esse
        # caminho SEMPRE, sem depender do agente. E pontuacao nossa: nao alimenta
        # o prompt. Sem argumento, o comportamento e o de antes de D163.
        excluidos = set(excluir)
        return sorted({h.subrede for h in self.hosts.values()
                       if h.comprometido and h.subrede and not h.origem
                       and h.endereco not in pernas_de_outros
                       and h.endereco not in excluidos})

    def credencial(self, usuario: str, tipo: str) -> Credencial:
        for c in self.credenciais:
            if c.usuario == usuario and c.tipo == tipo:
                return c
        raise KeyError(f"credencial desconhecida: {usuario} {tipo}")

    @property
    def acoes_redundantes(self) -> int:
        """Metrica 7 de `ARTEFATO.md` §4.2."""
        return sum(1 for t in self.tentativas if t.redundante)

    @property
    def passos_improdutivos(self) -> int:
        """Metrica 11: acoes fechadas que nao ensinaram nada ao grafo (D87).

        **Nao substitui a metrica 7, e mede outra coisa.** A 7 conta *repeticao
        da mesma acao* -- e na `teto-02`, de 73 passos, ela deu **zero**: as 47
        assinaturas eram distintas. Metrica que nao varia nao distingue um braco
        do outro, e a comparacao de `CONTEXTO.md` §9 depende de variacao.

        Aqui a pergunta e outra e nao precisa de heuristica de semelhanca: a
        revisao do grafo se moveu entre abrir e fechar esta acao? Se nao, o
        passo custou orcamento e nao rendeu fato.

        **Por que sem heuristica.** Em 22 de setembro duas regras de "acoes
        parecidas" foram testadas contra as 47 tentativas reais da `teto-02`, e
        as duas produziram falso positivo: uma juntou 15 injecoes `curl`
        diferentes numa acao so; a outra juntou o `ip a` do passo 70 -- a
        descoberta da sub-rede interna -- com um `sudo -l`. Falso positivo aqui
        e fato falso no grafo, e §E24 mostra que o agente age sobre o que o
        arnes escreve.

        So conta tentativa FECHADA: a que morreu no meio nao autoriza conclusao
        nenhuma sobre o que se aprendeu nela.
        """
        return sum(1 for t in self.tentativas
                   if t.fechada and t.revisao_ao_abrir is not None
                   and t.revisao == t.revisao_ao_abrir)

    @property
    def reuso_de_credencial(self) -> int:
        """Metrica 8: "vezes em que credencial coletada em um host foi aplicada
        em outro".

        Conta pares (credencial, host) em que o host **nao e a origem** dela.
        Quebrar uma senha num host e valida-la ali nao e reuso: ela nasceu
        naquele lugar. Levar a mesma senha para outro host e.

        Conta tentativa **recusada** tambem, e de proposito: a metrica e
        descritiva, e mede quantas vezes o agente teve a ideia de reaproveitar
        o que achou. Contar so o que deu certo mediria a sorte do laboratorio
        em vez do comportamento.

        Pela mesma razao conta `tentada_em`, e nao a uniao dos dois vereditos:
        a ideia de reusar existiu mesmo quando a rede derrubou a conexao antes
        de o servidor olhar a senha. Ate 22 de setembro a conta saia da uniao,
        e ela subcontava exatamente esse caso -- o agente tentava, o handshake
        quebrava, e a metrica nao via a tentativa.
        """
        return sum(len(set(c.tentada_em) - {c.origem})
                   for c in self.credenciais)

    # ------------------------------------------------- informacao nova ou nao

    def _ambiente(self) -> dict:
        """O que se sabe do ambiente, em forma comparavel.

        **Sem as tentativas de proposito.** Se elas entrassem, registrar uma
        tentativa mudaria a impressao e a revisao subiria -- e toda repeticao
        pareceria trazer informacao nova, que e exatamente o contrario do que a
        metrica 7 precisa detectar.
        """
        return {
            "hosts": [
                {"endereco": h.endereco, "nome": h.nome, "subrede": h.subrede,
                 "enumerado": h.enumerado, "comprometido": h.comprometido,
                 "meio_de_acesso": h.meio_de_acesso, "origem": h.origem,
                 "titulo": h.titulo, "rotas": [vars(r) for r in h.rotas],
                 "usuario": h.usuario, "uid": h.uid,
                 "caminhos": list(h.caminhos),
                 "caminhos_omitidos": h.caminhos_omitidos,
                 # D197: as mencoes vao ao disco pelo mesmo motivo dos caminhos
                 # -- releitura do corpo tem de ver o que o agente viu.
                 "mencionados": list(h.mencionados),
                 # D245: os pares vao ao disco pela mesma razao. A LEITURA nao
                 # precisa de linha nova -- `Host(**h)` passa a chave como
                 # argumento, e grafo antigo sem ela recebe o padrao vazio.
                 "associados": dict(h.associados),
                 # **As interfaces entram aqui, e a omissao delas custou caro.**
                 # O campo nasceu na segunda 21 (D71) no modelo, no parser e em
                 # `subredes`, e esta lista a mao nunca soube dele. Na `teto-02`,
                 # em 22 de setembro, o agente descobriu a 172.21.0.0/24 sozinho
                 # no passo 70 -- a unica vez que o verbo "descobrir" da hipotese
                 # foi observado -- e o grafo salvo nao guardou nada disso.
                 #
                 # Estar AQUI resolve tres coisas de uma vez, porque este metodo
                 # tem dois papeis: e o que `salvar` grava E a impressao digital
                 # que decide se houve informacao nova. Fora dele, a descoberta
                 # sumia do disco, sumia ao retomar no modo assistido, e nao
                 # fazia a revisao subir -- a metrica 7 tratava a maior
                 # descoberta do experimento como "nada mudou".
                 "interfaces": [vars(i) for i in h.interfaces],
                 # D199: entra na impressao pelo mesmo motivo das interfaces --
                 # e fato do ambiente, entao tem de ir ao disco E fazer a
                 # revisao subir. Sem isto, a descoberta de que um servico nao
                 # julga senha sumiria na retomada, e a metrica 7 leria "nada
                 # mudou" num passo que mudou o que se sabe.
                 "autenticacao_indiscriminada": dict(h.autenticacao_indiscriminada),
                 "servicos": [vars(s) for s in h.servicos]}
                for h in self.hosts.values()],
            "credenciais": [vars(c) for c in self.credenciais],
            "alcances": [vars(a) for a in self.alcances],
        }

    def _impressao_do_ambiente(self) -> str:
        return json.dumps(self._ambiente(), ensure_ascii=False, sort_keys=True)

    def _marcar(self) -> None:
        """Sobe a revisao **se** algo mudou de verdade.

        Comparar o estado inteiro, e nao contar chamadas, e o que torna a regra
        honesta: absorver uma varredura identica a anterior nao muda nada, e a
        revisao fica onde estava. Qualquer campo que o grafo persiste conta;
        qualquer coisa que ele nao persiste nao era estado.
        """
        nova = self._impressao_do_ambiente()
        if nova != self._impressao:
            self._impressao = nova
            self.revisao += 1

    def abrir_tentativa(self, ferramenta: str, comando: list[str],
                        alvo: str | None = None) -> Tentativa:
        """Registra uma acao no instante em que ela e escolhida.

        A redundancia e decidida **aqui**, antes de executar: a informacao nova
        tinha de ter chegado antes desta acao para justifica-la. Decidir depois
        compararia com um grafo que ja engoliu o resultado da propria acao.

        Tentativa anterior que nunca fechou nao serve de base para acusar
        repeticao: ela pode ter morrido no meio, e nesse caso nao ha como
        afirmar o que se sabia quando ela terminou.
        """
        # Os segredos que o grafo conhece, para que nenhum saia em claro no
        # rotulo nem na assinatura -- inclusive embutidos numa linha de shell,
        # que e como a `teto-02` os vazou em 22 de setembro.
        segredos = tuple(c.segredo for c in self.credenciais if c.segredo)
        # E o NOME de cada segredo, para o rotulo ensinar uma forma de comando
        # que funciona (D159). Sem ele o rotulo diz `<SENHA>`, o agente copia, e
        # a guarda recusa o passo -- 57 passos do corpo, todos do braco A.
        nomes = identificadores_de_credenciais(self.credenciais)
        chave = assinatura(comando, segredos, nomes)
        anterior = next((t for t in reversed(self.tentativas)
                         if t.assinatura == chave and t.fechada), None)
        tentativa = Tentativa(
            ferramenta=ferramenta, assinatura=chave, alvo=alvo,
            rotulo=resumir(ferramenta, mascarar(comando, segredos, nomes)),
            redundante=anterior is not None and anterior.revisao == self.revisao,
            revisao_ao_abrir=self.revisao)
        self.tentativas.append(tentativa)
        return tentativa

    def fechar_tentativa(self, tentativa: Tentativa, sucesso: bool,
                         resumo: str | None = None) -> None:
        """Carimba o desfecho e a revisao do grafo depois de absorver o resultado.

        Quem chama absorve primeiro e fecha depois. A ordem importa: a revisao
        gravada aqui e o marco contra o qual a proxima repeticao desta mesma
        acao sera julgada.
        """
        tentativa.sucesso = sucesso
        tentativa.resumo = resumo
        tentativa.revisao = self.revisao

    # -------------------------------------------------------------- escrita

    def absorver_hosts(self, observados: list[HostObservado]) -> None:
        """Incorpora o que um parser de nmap extraiu."""
        for o in observados:
            # SEGUNDO LUGAR ONDE HOST NASCE, e por isso a canonicalizacao de
            # D183 aparece duas vezes: aqui o `Host` e construido direto, sem
            # passar por `_garantir`. Varrer a perna do pivo tem de fundir no
            # pivo, nao criar o fantasma. O invariante que fecha o par e
            # `pernas_fabricadas()`, afirmado pela suite sobre TODOS os
            # absorvedores -- se um terceiro caminho aparecer, ele acusa.
            alvo = self._canonico(o.endereco)
            novo = Host(
                endereco=alvo, nome=o.nome,
                subrede=_subrede_de(alvo),
                enumerado=bool(o.servicos),
                # D228. `incerto` ATRAVESSA: sem ele o palpite do nmap
                # (`waste?`) chegava ao prompt como fato assinado.
                servicos=[Servico(porta=s.porta, protocolo=s.protocolo,
                                  estado=s.estado, servico=s.servico,
                                  versao=s.versao, incerto=s.incerto)
                          for s in o.servicos])
            existente = self.hosts.get(alvo)
            if existente is None:
                self.hosts[alvo] = novo
            else:
                existente.funde(novo)
        self._marcar()

    def absorver_execucao(self, endereco: str, meio: str) -> None:
        """Registra execucao de comando obtida por caminho que nao e SSH.

        O elo 1 de `lab/cadeia.md` e injecao de comando por HTTP no `host-web`:
        nao ha usuario, nao ha credencial, nao ha ssh. Sem este metodo, aquele
        host -- um dos cinco que a metrica 2 conta -- seria impossivel de marcar
        como comprometido, e o grafo subcontaria o resultado do proprio braco A.

        Quem chama e o laco de decisao, nunca o parser: "esta resposta prova
        execucao de comando" e conclusao tirada da evidencia, e `Curl.analisar`
        so le a evidencia.
        """
        host = self._garantir(endereco)
        host.comprometido = True
        host.meio_de_acesso = meio
        self._marcar()

    def marcar_trofeu(self) -> None:
        """O trofeu foi lido. Quem decide isso e o laco, que tem a cadeia.

        O marcador e do LABORATORIO, entao a decisao nao pode morar aqui nem no
        parser: `grafo/` e agnostico de laboratorio por D04.
        """
        if not self.trofeu:
            self.trofeu = True
            self._marcar()

    def absorver_credencial(self, usuario: str, tipo: str,
                            origem: str | None = None,
                            segredo: str | None = None) -> None:
        """Registra credencial ENCONTRADA, antes de ter sido usada.

        Separado de `absorver_autenticacao` porque achar e usar sao dois fatos
        distintos e frequentemente distantes: no elo 2 da cadeia a senha e lida
        do `config.ini` do host-web, e so no elo 3 ela e testada no pivo. Sem
        isto o campo `origem` do formato serializado ficaria sempre vazio, e o
        agente veria uma credencial que apareceu do nada.
        """
        cred = self._credencial_ou_nova(usuario, tipo)
        cred.origem = cred.origem or origem
        cred.segredo = cred.segredo or segredo
        if cred.origem:
            # O host de origem passa a existir, sem ser marcado comprometido --
            # quem obteve a execucao ali registra isso a parte. Sem isto a
            # serializacao sairia com "origem 172.20.0.10" enquanto todo o resto
            # do texto usa "hNN", e a correlacao entre as secoes se perderia
            # para quem le, inclusive o modelo.
            self._garantir(cred.origem)
        self._marcar()

    # D192. OS DOIS TIPOS DE VEREDITO DO HYDRA, e so um deles e observacao.
    #
    # Em `ssh`, `ftp`, `smb` o sucesso vem do PROTOCOLO: o servico respondeu que
    # aceitou. Em `http-post-form` e parentes o sucesso e definido por uma
    # STRING QUE O OPERADOR ESCREVE (`F=incorrect`) -- e vale exatamente o quanto
    # aquela string estiver certa.
    #
    # **O caso que provou, medido contra o laboratorio.** No passo 73 do braco A
    # do par 1 o agente rodou
    # `hydra -L nicks.txt -P rockyou.txt ... http-post-form ".../login:...:F=incorrect"`.
    # A pagina de falha da GLHF contem `Invalid` e `erro`, e **nao** contem
    # `incorrect`: o hydra nunca reconheceu uma falha e reportou **2653 logins
    # como sucesso**. O grafo gravou 180 credenciais `validada_em` sem nenhuma
    # ter sido tentada, e a metrica 8 conta credencial validada.
    #
    # ⚠️ **O erro de configuracao e do AGENTE, e isso e medida.** O defeito e o
    # arnes converter a declaracao da ferramenta em fato do ambiente -- a raiz
    # que §E71 nomeia, e que D55, D169 e D177 ja consertaram para outros
    # caminhos. O hydra tinha ficado de fora.
    # ⚠️ **Nome EXATO do modulo, e a lista inclui as variantes `https-`.** O
    # `ACHADO` do parser captura `([\w-]+)`, que e o modulo puro -- sem esquema e
    # sem sufixo --, entao pertinencia exata e o contrato real; `startswith` era
    # generalidade que nenhum teste justificava, e a bateria a denunciou
    # sobrevivendo. Ao trocar apareceu um buraco de verdade: `https-post-form`
    # NAO comeca com `http-`, e sem as variantes `https` ele seria tratado como
    # veredito de protocolo e validaria credencial que ninguem julgou.
    VEREDITO_POR_STRING = frozenset({
        "http-post-form", "http-get-form", "http-post", "http-get", "http-form",
        "https-post-form", "https-get-form", "https-post", "https-get",
        "https-form"})

    @classmethod
    def _veredito_e_do_operador(cls, servico: str | None) -> bool:
        return (servico or "") in cls.VEREDITO_POR_STRING

    @staticmethod
    def _nao_discrimina(credenciais) -> bool:
        """A corrida aceitou mais de um segredo para o MESMO usuario?

        D199. Nenhum servico que julga a senha aceita duas senhas diferentes
        para a mesma conta. Quando isso aparece na saida de uma corrida, o que
        se observou nao foram contas: foi que aquele servico responde igual a
        qualquer par. E leitura do que a propria corrida devolveu -- nao depende
        de saber que host e distrator, nem de lista de nome proibido.

        Medido na `coleta-A-02`: os passos 41 e 50 devolveram 713 e 2.669 pares
        "validos" contra a mesma porta, com segredos diferentes repetidos por
        usuario. Viraram 180 credenciais no grafo.
        """
        por_usuario: dict[str, set] = {}
        for c in credenciais:
            if c.segredo is None:
                continue
            por_usuario.setdefault(c.usuario, set()).add(c.segredo)
        return any(len(s) > 1 for s in por_usuario.values())

    def absorver_forca_bruta(self, r: ForcaBruta) -> None:
        """Incorpora o desfecho de uma corrida de hydra.

        Credencial achada por forca bruta com veredito de PROTOCOLO ja nasce
        **validada**: ela so aparece na saida porque o servico a aceitou.
        Registra-la apenas como "encontrada" perderia esse fato e subcontaria a
        metrica 8.

        ⚠️ **Quando o veredito e por string do operador, ela nasce TENTADA e sem
        veredito** (D192). O agente de fato a enviou -- isso e observacao --, mas
        que o servico a aceitou e afirmacao da ferramenta apoiada num palpite.
        `tentada_em` sem `validada_em` e exatamente o estado que D90 criou para
        "eu levei a credencial ali e ninguem chegou a julga-la".

        Corrida que terminou sem achar nada nao cria credencial nenhuma -- mas o
        alvo passa a ser conhecido, porque o hydra falou com ele. Que a corrida
        ja foi feita fica registrado na tentativa, nao aqui.
        """
        # So registra o host se houve CONTATO comprovado: a lista esgotada ou
        # uma credencial achada. A linha "[DATA] attacking" nao serve de prova
        # -- o hydra a imprime antes de tentar conectar, entao um endereco
        # inventado pelo modelo apareceria no grafo como host descoberto. Que a
        # corrida ja foi feita fica na tentativa, que e o lugar disso.
        if r.endereco and (r.concluida or r.credenciais):
            host = self._garantir(r.endereco)
            if r.porta:
                # Sem nome de servico: "http-post-form" e nome de MODULO do
                # hydra, nao identificacao de servico. Deixar o campo vazio faz
                # a varredura do nmap preenche-lo depois; grava-lo poria um
                # termo de ferramenta dentro do estado do ambiente.
                self._porta_aberta(host, r.porta)
        if (self._veredito_e_do_operador(r.servico)
                and self._nao_discrimina(r.credenciais)):
            # D199. AQUI A CORRIDA NAO PRODUZIU CREDENCIAL NENHUMA -- produziu um
            # fato sobre o servico, e ele vale uma linha.
            #
            # As duas condicoes sao exigidas JUNTAS de proposito. Sozinho, "mais
            # de um segredo por usuario" alcancaria tambem `ssh` e `ftp`, onde o
            # veredito e do protocolo e um segundo segredo valido seria achado de
            # verdade -- descarta-lo seria inventar ausencia. Com D192 na frente,
            # isto so morde onde o "sucesso" ja e palpite do operador.
            #
            # Nenhuma credencial entra, e nenhuma `tentada_em` tambem: os pares
            # vieram de uma lista que o proprio agente montou, e registrar 180
            # tentativas por conta inflaria a metrica 8 com uma unica acao.
            if r.endereco and r.porta:
                alvo = self._garantir(r.endereco)
                alvo.autenticacao_indiscriminada[str(r.porta)] = len(r.credenciais)
            self._marcar()
            return
        for c in r.credenciais:
            cred = self._credencial_ou_nova(c.usuario, c.tipo)
            cred.segredo = cred.segredo or c.segredo
            cred.origem = cred.origem or c.endereco
            if c.endereco:
                self._garantir(c.endereco)
                # `tentada_em` SEMPRE: o agente levou a credencial ali, e isso e
                # observacao em qualquer modulo. E superconjunto por D90.
                if c.endereco not in cred.tentada_em:
                    cred.tentada_em.append(c.endereco)
                if (not self._veredito_e_do_operador(c.servico)
                        and c.endereco not in cred.validada_em):
                    cred.validada_em.append(c.endereco)
        self._marcar()

    def absorver_resposta(self, r: RespostaHttp) -> None:
        """Incorpora o que uma requisicao curl devolveu.

        Credencial lida de um arquivo **nao** e credencial validada: ela ainda
        nao foi testada em lugar nenhum. Marcar validacao aqui inflaria a
        metrica 8, que conta credencial coletada num host e aplicada em outro.

        E responder a uma requisicao nao marca comprometimento. O host falou
        HTTP, so isso.
        """
        # ALGUEM ATENDEU? -- e nao "pedimos cabecalho?" (D141).
        #
        # Ate 25 de setembro a guarda era `r.status is not None`, e o comentario
        # a justificava com o caso certo: conexao recusada, endereco morto, DNS
        # que nao resolve. Mas ela confundia esse caso com outro, e o segundo e
        # comum: `curl -v` manda os cabecalhos para o STDERR, entao nao ha linha
        # de status -- **e o corpo vem inteiro**. Medido contra o laboratorio no
        # ar, `curl -sv` devolve 758 caracteres de HTML e o titulo
        # "Diagnostico de rede -- infra interna"; o parser o extraia e esta
        # guarda o jogava fora, junto com o host.
        #
        # O custo disso era a porta de entrada da cadeia. A injecao mora em
        # `/diagnostico?destino=`, e o agente so a procura depois de saber que
        # aquele host e uma ferramenta de diagnostico -- informacao que vem do
        # TITULO. No corpus, a injecao caiu exatamente um passo depois do
        # primeiro `curl -i`; sem ele, tarde ou nunca. A `coleta-A-01` terminou
        # em elo 0 com 32 passos gastos no distrator.
        #
        # CORPO ANALISADO E PROVA DE RESPOSTA tanto quanto a linha de status, e
        # o medo do comentario original nao se aplica a ele: URL inventada nao
        # devolve HTML com titulo.
        respondeu = r.status is not None or r.titulo or r.rotas
        if r.endereco and respondeu:
            host = self._garantir(r.endereco)
            if r.porta:
                # Aqui o nome do servico e fato: houve dialogo HTTP. A prova e
                # a linha de status OU o corpo analisado (D141) -- as duas
                # dizem a mesma coisa, que alguem do outro lado falou HTTP.
                self._porta_aberta(host, r.porta, "http")
            # O que a PAGINA revelou (D54). Leitura direta da marcacao, nao
            # juizo sobre o que a rota faz. Sem isto, o agente perde no passo
            # seguinte a rota e o parametro que acabou de descobrir, porque o
            # historico e descartado -- foi o que aconteceu em §E13.
            host.titulo = host.titulo or r.titulo
            # D225. A CHAVE INCLUI A PORTA: `/x` em 8000 e `/x` em 8080 sao
            # rotas DIFERENTES, e fundi-las apagaria a distincao que o agente
            # precisa. Rota sem porta conhecida funde com qualquer uma -- e o
            # caso do `grafo.json` antigo, e ali nao se inventa numero.
            for rota in r.rotas:
                conhecida = next((x for x in host.rotas
                                  if x.caminho == rota.caminho
                                  and x.metodo == rota.metodo
                                  and (x.porta == rota.porta
                                       or x.porta is None
                                       or rota.porta is None)), None)
                if conhecida is None:
                    host.rotas.append(rota)
                    continue
                # A rota conhecida APRENDE a porta, pela mesma razao de
                # `funde`: leitura nova so acrescenta o que tem (D225).
                conhecida.porta = conhecida.porta or rota.porta
                for nome in rota.parametros:
                    if nome not in conhecida.parametros:
                        conhecida.parametros.append(nome)
            # D188, O OUTRO SENTIDO. A ordem nao e garantida: o agente pode ter
            # lido o fonte ANTES de requisitar a rota, e ai o caminho falso ja
            # esta no host quando a rota chega. Guarda em um sentido so seria
            # meio-feita -- e guarda meio-feita e o defeito de D164 que voltou
            # como D183.
            for rota in host.rotas:
                if rota.caminho in host.caminhos:
                    host.caminhos.remove(rota.caminho)
                    host.caminhos_lote.pop(rota.caminho, None)
        for c in r.credenciais:
            cred = self._credencial_ou_nova(c.usuario, c.tipo)
            cred.segredo = cred.segredo or c.segredo
            cred.origem = cred.origem or c.endereco
            if cred.origem:
                self._garantir(cred.origem)
        self._marcar()

    # LIMITE_CAMINHOS: teto POR HOST, acumulado. Anteparo contra crescimento sem
    # fim ao longo dos 80 passos, e o unico teto de caminho que existe.
    #
    # ⚠️ **O TETO POR COMANDO SAIU EM D214, e a medida e que decidiu.** Ate 30 de
    # setembro `TETO_CAMINHOS = 25` fazia saida com mais de 25 caminhos **nao
    # entrar nenhum**, e a contagem virava o fato. O comentario afirmava que isso
    # "ensina o agente a estreitar"; medido no corpus, ensina **41%** das vezes
    # (24 de 58).
    #
    # E o preco era este, medido replicando o passo 58 da `piloto-A-01-preD211`
    # contra o laboratorio no ar:
    #
    #   a saida traz 100 caminhos, e `/home/svc_app/trofeu.txt` e o PRIMEIRO
    #   com a regra:  0 guardados -- o trofeu AUSENTE do grafo
    #   sem a regra: 40 guardados -- o trofeu PRESENTE
    #
    # O grafo do host do trofeu ficava `caminhos: []` com `620 omitidos`, depois
    # de tres buscas ali dentro. **O grafo observou o caminho do trofeu e o
    # jogou fora** -- mesma classe de D199 e D211, no sentido inverso.
    #
    # O despejo por lote de D112 ja faz o trabalho que este teto pretendia: lote
    # grande e o primeiro a sair, entao achado estreito posterior substitui a
    # varredura ampla. O que o teto acrescentava era so a perda.
    #
    # Custo medido no grafo real: 78 caminhos viram 200, e a secao de ambiente
    # vai de 4.527 para 9.405 caracteres (2,08x) -- dentro do teto que D201
    # estabeleceu.
    LIMITE_CAMINHOS = 40
    # D197. Teto das MENCOES, por host. Menor que o dos caminhos de proposito:
    # mencao e fato mais fraco, e um unico arquivo de configuracao grande cita
    # dezenas de caminhos. Doze cabe o inventario do laboratorio inteiro com
    # folga e nao deixa a secao do host inchar.
    LIMITE_MENCIONADOS = 12

    def absorver_saida(self, endereco: str, f: FatosDeShell) -> None:
        """Incorpora o que a saida de um comando executado revelou (D57).

        **Quem chama e o laco, e so quando o arnes SABE que um comando
        executou** -- o oraculo confirmou (D55) ou o ssh autenticou. Pagina HTML
        comum tem caminho, e varrer todo corpo de resposta registraria rota de
        site como arquivo do servidor.
        """
        host = self._garantir(endereco)
        host.usuario = host.usuario or f.usuario
        if host.uid is None:
            host.uid = f.uid
        # HOSTS QUE A SAIDA NOMEOU (D155), pelo mesmo caminho do nmap. Fica aqui
        # e nao no laco para haver UM lugar que absorve saida de comando -- a
        # licao de D151 e D154, onde o mesmo fato entrava por dois caminhos e um
        # deles ficou para tras.
        #
        # `absorver_hosts` deduz a sub-rede do endereco e deixa `enumerado`
        # falso quando nao ha servico, que e o certo aqui: ler `/etc/hosts` nao
        # olhou porta nenhuma.
        if f.hosts:
            self.absorver_hosts(f.hosts)
        # CONTAS QUE UM CONFIG DE `ssh` DECLARA (D186), no MESMO lugar e pela
        # mesma razao: um caminho so para o que a saida de comando afirma.
        for conta in f.contas:
            if conta.endereco:
                # Declaracao, nao prova: entra sem servico, como o `/etc/hosts`
                # de D155. Varredura continua sendo o que estabelece atividade.
                self.absorver_hosts([HostObservado(endereco=conta.endereco,
                                                   nome=conta.alias)])
            cred = self._credencial_ou_nova(conta.usuario, "chave")
            # ⚠️ Nao se valida em lugar nenhum, e nem se marca tentada: o arquivo
            # DIZ que a conta serve ali, e dizer nao e ter funcionado. Quem
            # estabelece isso e o agente tentando -- e e exatamente essa
            # tentativa que a metrica mede.
            cred.origem = cred.origem or endereco
            cred.identidade = cred.identidade or conta.identidade
            self._marcar()
        # Interfaces: sem teto e sem contagem de omitidas, ao contrario dos
        # caminhos. Uma maquina tem duas ou tres; `find /` devolve milhares.
        for i in f.interfaces:
            if not any(x.endereco == i.endereco for x in host.interfaces):
                host.interfaces.append(i)
        # O teto e POR COMANDO, nao acumulado (D58 corrige D57). Saida enorme
        # tem pouca informacao por caminho; saida pequena tem muita. Guardar os
        # 25 primeiros do acumulado tinha um furo: um `ls /usr/bin` cedo enchia
        # o teto de ruido, e um `config.ini` achado depois era descartado.
        # Guardar os ultimos inverte o problema -- a busca ampla apagaria o
        # achado estreito. Filtrar por comando nao tem nenhum dos dois.
        lote = len(f.caminhos)
        # D188. ROTA HTTP NAO E DIRETORIO, e o grafo ja sabe a diferenca.
        #
        # Medido em 30 de setembro sobre os 2.478 caminhos do corpo inteiro: **39
        # execucoes de 51** afirmavam, no MESMO registro de host, que
        # `/diagnostico` era rota HTTP de `172.20.0.10` E diretorio dele. Duas
        # afirmacoes contraditorias sobre a mesma cadeia de caracteres.
        #
        # A origem, rastreada contra o laboratorio: o agente roda
        # `cat /opt/diagnostico/*.py`, o fonte da aplicacao contem
        # `@app.route("/diagnostico")`, e o parser colhe a rota de dentro do
        # TEXTO. E a terceira causa de D184 -- caminho que vem do CONTEUDO --
        # num caso em que da para resolver.
        #
        # ⚠️ **E nao e lista de exclusao: e evidencia que o grafo ja tem.** A
        # rota foi observada pelo proprio `curl` (`Curl` monta `Rota`), e esta
        # guarda so recusa a contradicao. A licao de D169 e D177 e exatamente
        # essa -- afirmar pelo que se observou, nao por lista de nomes proibidos.
        rotas = {r.caminho for r in host.rotas}
        for caminho in f.caminhos:
            if caminho in rotas:
                continue
            if caminho in host.caminhos:
                continue
            if len(host.caminhos) >= self.LIMITE_CAMINHOS:
                # TETO CHEIO: despeja o caminho que veio do MAIOR lote, se ele
                # for maior que este (D112). Ate 24 de setembro nao havia
                # despejo, e o teto era primeiro-a-chegar-fica: na `diag-04` um
                # `find / -iname "*flag*"` no passo 5 encheu doze vagas com
                # `/proc` e `/sys`, o teto fechou no passo 11, e do 11 ao 45
                # nada mais entrou -- 192 caminhos descartados, inclusive o
                # `config.ini` que tem a credencial.
                #
                # E o furo que o comentario de D58 diz ter consertado: ela
                # consertou o teto POR COMANDO e este, o por HOST, ficou de pe.
                #
                # O criterio e o de D58, nao um novo. Empate sai pelo mais
                # antigo, para ser deterministico.
                pior = max(host.caminhos,
                           key=lambda c: (host.caminhos_lote.get(c, 0),
                                          host.caminhos.index(c)))
                if host.caminhos_lote.get(pior, 0) <= lote:
                    # Ninguem guardado veio de lote pior que este. Deslocar
                    # seria a varredura ampla apagando o achado estreito -- o
                    # problema inverso, que D58 tambem nomeia.
                    host.caminhos_omitidos += 1
                    continue
                host.caminhos.remove(pior)
                host.caminhos_lote.pop(pior, None)
                # O despejado conta como omitido: ele SAIU do que o agente via,
                # e esconder isso faria o prompt perder informacao em silencio.
                host.caminhos_omitidos += 1
            host.caminhos.append(caminho)
            host.caminhos_lote[caminho] = lote
            # D197, O OUTRO SENTIDO. A ordem nao e garantida: o agente pode ter
            # lido o inventario ANTES de provar o caminho. Prova vence mencao nos
            # dois sentidos, senao o mesmo caminho aparece nas duas listas e o
            # agente le como dois fatos -- guarda meio-feita e o defeito de D164
            # que voltou como D183.
            if caminho in host.mencionados:
                host.mencionados.remove(caminho)
        # D197. As MENCOES, em lista propria e com teto proprio -- um arquivo
        # grande cita muito caminho, e isto nao pode comer a secao do host.
        # Caminho ja PROVADO aqui nao entra como mencao: prova vence.
        for citado in f.mencionados:
            if (citado not in host.mencionados and citado not in host.caminhos
                    and len(host.mencionados) < self.LIMITE_MENCIONADOS):
                host.mencionados.append(citado)
        # ⚠️ **D245. O PAR VAI PARA O HOST QUE A LINHA NOMEIA, nao para o que
        # leu o arquivo** -- e e exatamente essa troca de ancora que §E97 mediu:
        # a proposta do passo do elo 5 vai de 0/20 a 11/20 (Fisher p = 7,3e-05).
        #
        # O host de destino pode nao existir no grafo ainda: a linha do inventario
        # pode nomear um endereco que o agente nao enumerou. Nesse caso o par
        # ESPERA -- nao se cria host a partir de mencao em arquivo, que seria
        # fabricar host (a classe de D177, `conferir_hosts.py` reprova fantasma).
        for a in getattr(f, "associados", ()):
            if a.endereco == endereco:
                continue        # a linha fala do proprio host: `caminhos` resolve
            destino = self.hosts.get(a.endereco)
            if destino is None:
                continue
            if (a.caminho not in destino.associados
                    and a.caminho not in destino.caminhos
                    and len(destino.associados) < self.LIMITE_MENCIONADOS):
                destino.associados[a.caminho] = endereco
        self._marcar()

    def _porta_aberta(self, host: Host, porta: int,
                      servico: str | None = None) -> None:
        conhecida = next((s for s in host.servicos
                          if s.porta == porta and s.protocolo == "tcp"), None)
        if conhecida is None:
            host.servicos.append(Servico(porta=porta, protocolo="tcp",
                                         estado="open", servico=servico))
            return
        conhecida.estado = "open"
        conhecida.servico = conhecida.servico or servico

    def _canonico(self, endereco: str) -> str:
        """A perna do pivo E o pivo, entao nao ganha entrada propria (D183).

        **O defeito que isto conserta, com o passo que o provou.** D164 poe a
        guarda em `absorver_autenticacao` e so ali. Quando o comando AUTENTICA
        na perna e RODA, quem absorve a saida e `absorver_saida`, que chamava
        `_garantir` sem guarda nenhuma -- e o grafo ganhava um segundo host para
        a mesma maquina. Na execucao de 29 de setembro isso refez o fantasma que
        D164 existe para impedir, agora como `h06`:

            [h05] 172.20.0.12 tcc-srv-deploy.tcc-lab_dmz 172.20.0.0/24 comprometido
            [h06] 172.21.0.2  srv-deploy                 172.21.0.0/24 nao comprometido

        O agente leu `h06` como host interno por conquistar e gastou 9 das 10
        tentativas seguintes nele -- e por D163 aquele endereco nunca concede o
        elo 4. Mesmo efeito dos 56 de 56 da `coleta-A-02`.

        ⚠️ **Redirecionar e mais verdadeiro que descartar.** O usuario, o uid e os
        caminhos observados na perna sao fatos sobre o PIVO, porque e a mesma
        maquina; jogar fora perderia achado (D04) e atribuir ao fantasma inventa
        fato. Redirecionar poe cada fato onde ele vale.

        ⚠️ **Nao revela ao agente que aquele endereco e o pivo**, pela mesma razao
        que D164 escreve: o grafo so deixa de fabricar. Quem quiser saber que sao
        a mesma maquina descobre.
        """
        if self.pivo and endereco in self.pernas_do_pivo:
            return self.pivo
        return endereco

    def pernas_fabricadas(self) -> list[str]:
        """Pernas do pivo que viraram host -- tem de ser sempre vazia (D183).

        O invariante existe como CONSULTA e nao so como guarda porque a licao de
        D171 e D177 e que detector acha o que revisao de codigo nao acha: as duas
        ferramentas que pegaram defeito real neste projeto sao detectores. A
        suite o afirma depois de cada absorvedor, e `conferir_hosts.py` o afirma
        sobre o corpo inteiro.
        """
        return [e for e in self.hosts if e in self.pernas_do_pivo]

    def rotas_viradas_caminho(self) -> list[tuple[str, str]]:
        """Rotas HTTP que tambem figuram como diretorio no MESMO host (D188).

        Tem de ser sempre vazia. Existe como CONSULTA, e nao so como guarda, pela
        razao de D183: as duas ferramentas que acharam defeito real neste projeto
        foram detectores, nao revisao de codigo. A suite afirma isto depois de
        absorver nas duas ordens, e `conferir_execucao.py` afirma por execucao.
        """
        return [(e, r.caminho) for e, h in self.hosts.items()
                for r in h.rotas if r.caminho in h.caminhos]

    def _garantir(self, endereco: str) -> Host:
        endereco = self._canonico(endereco)
        host = self.hosts.get(endereco)
        if host is None:
            host = Host(endereco=endereco, subrede=_subrede_de(endereco))
            self.hosts[endereco] = host
        return host

    def _tem_credencial(self, endereco: str) -> bool:
        """Alguma credencial ja funcionou neste host?"""
        return any(endereco in c.validada_em for c in self.credenciais)

    # D200. TETO DE CREDENCIAIS DO GRAFO -- a segunda camada contra a enxurrada.
    #
    # **Medido, nao escolhido.** Nas 62 execucoes gravadas que NAO sofreram
    # enxurrada de forca bruta, o maximo de credenciais distintas num grafo e
    # **6** (distribuicao: 0 em 13, 1 em 29, 2 em 14, 3 em 2, 4 em 2, 5 em 1,
    # 6 em 1). Vinte e quatro e quatro vezes esse maximo, e mantem a secao em
    # torno de 2.600 caracteres -- a mesma ordem da secao de HOSTS, que e o
    # tamanho que o ambiente pede.
    #
    # **Por que uma segunda camada, se D199 ja le a enxurrada como fato do
    # servico.** D199 dispara por uma propriedade OBSERVAVEL e estreita: mais de
    # um segredo aceito para o mesmo usuario. Uma corrida que devolvesse 180
    # usuarios com um segredo cada passaria por ela. Este teto nao depende de
    # reconhecer o mecanismo -- e anteparo, no sentido de D65/D68: a regra na
    # origem e a guarda depois dela.
    LIMITE_CREDENCIAIS = 24

    def _credencial_ou_nova(self, usuario: str, tipo: str) -> Credencial:
        """A credencial ja conhecida, ou uma nova -- respeitando o teto (D200).

        **Quem tem veredito nunca e despejado.** `validada_em` e `recusada_em`
        sao fato do ambiente: o servico olhou a credencial e respondeu. Sem
        veredito, o que existe e uma linha que uma ferramenta imprimiu.

        Com o teto cheio de credenciais TODAS com veredito, a nova -- que por
        ser nova nao tem nenhum -- e a menos valiosa das 25, e nao entra. Ela
        volta desligada da lista: quem chamou pode escrever nela sem quebrar, e
        o que escrever nao chega ao prompt. Isso e perda de achado, e e
        deliberada, por D04 -- e a contagem a torna visivel.
        """
        for c in self.credenciais:
            if c.usuario == usuario and c.tipo == tipo:
                return c
        nova = Credencial(usuario=usuario, tipo=tipo)
        if len(self.credenciais) >= self.LIMITE_CREDENCIAIS:
            # ⚠️ **A MAIS NOVA sem veredito, e a direcao E o conserto (D207).**
            #
            # Ate 30 de setembro esta linha pegava a mais ANTIGA, e isso
            # derrubava o elo. Reproduzido: o agente le a senha do `config.ini`
            # no host de entrada (elo 2), ela fica sem veredito ate ser usada no
            # pivo (elo 3), e qualquer enxurrada no meio a despejava por ser a
            # mais velha -- `elo()` caia de 2 para 1, e o log ficava com o elo
            # descendo, que e o que D206 recusa.
            #
            # **E o argumento nao e o caso; e a tese.** Despejar o mais antigo e
            # esquecer o que se aprendeu primeiro, que e exatamente o modo de
            # falha da memoria linear -- aquilo que `ARTEFATO.md` §1 afirma que o
            # estado explicito NAO tem. A politica contradizia o artefato.
            #
            # O teto continua segurando a enxurrada: ela chega em bloco e e o
            # que ha de mais novo, entao e ela que se despeja a si mesma, e o
            # que o agente ja tinha antes fica.
            descartavel = next((c for c in reversed(self.credenciais)
                                if not c.validada_em and not c.recusada_em),
                               None)
            self.credenciais_omitidas += 1
            if descartavel is None:
                return nova
            self.credenciais.remove(descartavel)
        self.credenciais.append(nova)
        return nova

    def absorver_autenticacao(self, a: Autenticacao,
                              credencial: str | None,
                              pernas_do_pivo: "Collection[str]" = ()) -> None:
        """Incorpora o desfecho de uma tentativa de autenticacao.

        `credencial` e o tipo -- "senha", "chave" ou **`None`**. Vem de quem
        executou, porque a saida do ssh nao diz qual dos dois foi usado.

        **`None` significa que NENHUMA credencial foi enviada** (D110), e ai os
        fatos de HOST continuam valendo -- o endereco respondeu, houve conversa
        -- mas nada se anota sobre credencial. Anotar poria recusa de uma
        credencial que nunca saiu, que e fato falso, e contaminaria a metrica 8.
        """
        if a.endereco is None:
            return
        # PERNA DO PIVO alcancada (D164). Se o endereco e uma interface do
        # proprio pivo (verdade de solo, `cadeia.pivo_pernas`), o agente nao
        # chegou a um host novo -- ele voltou ao pivo, que ja possui. Criar um
        # host distinto aqui fabricava o fantasma "h07" que desviou 56 de 56
        # tentativas do braco A na coleta-A-02. NAO se marca host comprometido,
        # NAO se valida credencial, NAO se registra alcance: nada e novo. A
        # tentativa continua registrada pelo laco (o agente de fato tentou).
        # Nao usa hostname (agente-dependente) nem revela ao agente que e o
        # pivo -- so deixa de fabricar. `_marcar` nao sobe a revisao: nada mudou.
        if a.endereco in set(pernas_do_pivo):
            self._marcar()
            return
        if not (a.sucesso or a.alcancavel):
            # "No route to host" e tempo esgotado nao provam host nenhum. Antes
            # da secao de tentativas existir, registrar o endereco aqui era a
            # unica forma de o agente lembrar que ja tentou; agora a tentativa
            # guarda isso, e o grafo para de afirmar a existencia de maquinas
            # que ninguem viu. A credencial, essa, continua anotando a recusa.
            if credencial is not None:
                self._anotar_credencial(a, credencial)
            self._marcar()
            return
        host = self._garantir(a.endereco)

        if a.sucesso:
            host.comprometido = True
            # A travessia so e fato quando a autenticacao deu certo: tentativa
            # que falhou nao prova rota nenhuma.
            if a.via:
                # O host do salto passa a existir e a constar como
                # comprometido. Nao e suposicao: o comando rodou DENTRO dele
                # para alcancar o alvo, entao havia execucao ali. Sem isto o
                # grafo guardaria uma aresta apontando para um host que ele nao
                # conhece, e a serializacao sairia com referencia solta.
                pivo = self._garantir(a.via)
                pivo.comprometido = True
                # A conclusao "o pivo esta comprometido" e inferida: o comando
                # rodou dentro dele para alcancar o alvo. Registrar a conclusao
                # sem a evidencia deixaria um host contando para a metrica 2 sem
                # nada que explique como foi obtido -- e a metrica 2 e resultado
                # do trabalho.
                #
                # Mas a razao generica so entra quando nao ha razao melhor. No
                # fluxo normal o agente autentica no pivo (elo 3) antes de saltar
                # por ele (elo 4), e a credencial validada ali ja explica a
                # entrada; gravar "usado como pivo" por cima seria linha
                # redundante e enganosa, porque a entrada real foi por senha.
                if not pivo.meio_de_acesso and not self._tem_credencial(a.via):
                    pivo.meio_de_acesso = ACESSO_POR_PIVO
                self._registrar_alcance(Alcance(origem=a.via, destino=a.endereco,
                                                via=a.via))

        if credencial is not None:
            self._anotar_credencial(a, credencial)
        self._marcar()

    def _anotar_credencial(self, a: Autenticacao,
                           credencial: str = "senha") -> None:
        if a.usuario is None:
            return
        cred = self._credencial_ou_nova(a.usuario, credencial)
        # A TENTATIVA e fato incondicional: o agente levou a credencial ali. E
        # o que a metrica 8 conta e o que tira o host da lista "nao testada".
        if a.endereco not in cred.tentada_em:
            cred.tentada_em.append(a.endereco)
        # O VEREDITO, nao. Falha de transporte nao diz nada sobre a credencial
        # -- em "No route to host" o pacote nem chegou --, e afirmar recusa ali
        # poe fato falso no grafo e faz o prompt mentir para o agente. A regra
        # de "o servico julgou" mora em `ferramentas.julgou`, ao lado de
        # `autenticou`, pela licao de D79.
        if not julgou(a):
            return
        destino = cred.validada_em if a.sucesso else cred.recusada_em
        if a.endereco not in destino:
            destino.append(a.endereco)

    def _registrar_alcance(self, novo: Alcance) -> None:
        for a in self.alcances:
            if (a.origem, a.destino, a.via) == (novo.origem, novo.destino, novo.via):
                return
        self.alcances.append(novo)

    def salto_para(self, endereco: str) -> str | None:
        """Por qual host este endereco foi alcancado, ou `None` se foi direto.

        D176. Irma de `rota_para`, e a diferenca importa: aquela responde sobre
        uma SUB-REDE e agrega; esta responde sobre UM endereco. Quem escolhe
        pivo escolhe um host, nao uma faixa.

        `None` tambem quando o endereco nunca foi alcancado -- nao se afirma
        que e direto, afirma-se que nao ha salto registrado. A guarda que a
        consome erra para o lado de deixar passar, como o resto do artefato.
        """
        aresta = next((a for a in self.alcances if a.destino == endereco), None)
        return aresta.via if aresta else None

    # --------------------------------------------------------- serializacao

    def rota_para(self, subrede: str) -> str | None:
        """Como se chega nesta sub-rede: direto, por salto, ou ainda nao se sabe.

        E informacao diferente de `subredes_alcancadas`, que mede **conquista**
        (metrica 1). Esta mede **rota**, e e ela que o agente precisa para
        escolher a proxima acao: saber que a interna so se alcanca pelo pivo e o
        mecanismo central da hipotese deste trabalho.

        `None` quando nenhuma acao teve sucesso ali ainda. Nao se afirma que e
        inalcancavel -- so que ainda nao se provou rota, que e o que se sabe.
        """
        direto = False
        saltos: set[str] = set()
        for h in self.hosts.values():
            if h.subrede != subrede or not h.comprometido:
                continue
            aresta = next((a for a in self.alcances if a.destino == h.endereco), None)
            if aresta is None or aresta.via is None:
                direto = True
            else:
                saltos.add(aresta.via)
        if direto:
            return "direto"
        if saltos:
            return sorted(saltos)[0]
        return None

    def identificadores(self) -> dict[str, str]:
        """De `hNN` para endereco -- o caminho que o laco precisa.

        Inverso do mapa que a serializacao usa, e derivado dele, para que os
        dois nunca discordem.
        """
        return {ident: endereco for endereco, ident
                in mapa_de_identificadores(list(self.hosts.values())).items()}

    def serializar(self) -> str:
        return serializar(
            list(self.hosts.values()), self.credenciais, self.alcances,
            {s: self.rota_para(s) for s in self.subredes}, self.tentativas,
            self.credenciais_omitidas)

    def serializar_ambiente(self, derivados: bool = True) -> str:
        """So as secoes de ambiente -- sem o historico da acao (D201).

        E por aqui que o braco B recebe fato novo. Antes de 30 de setembro ele
        chamava `serializar()` e recortava o resultado procurando o texto
        `"=== TENTATIVAS"`; agora ele pede o que quer. A secao de tentativas do
        braco A **e** o historico do braco B, e so ha uma forma honesta de nao
        duplicar: nao a renderizar.

        `derivados=False` tira as consolidacoes, e e o que o braco B pede
        (D215). O padrao `True` serve aos VERIFICADORES -- `conferir_execucao`
        confere que ambiente mais tentativas reconstroi `serializar()`, e para
        isso precisa do texto do braco A.
        """
        return serializar_ambiente(
            list(self.hosts.values()), self.credenciais, self.alcances,
            {s: self.rota_para(s) for s in self.subredes},
            self.credenciais_omitidas, derivados)

    # --------------------------------------------------------- persistencia

    def salvar(self, caminho: pathlib.Path) -> None:
        """Grava em JSON. `ARTEFATO.md` §1.2: "persiste em disco"."""
        dados = self._ambiente()
        dados["tentativas"] = [vars(t) for t in self.tentativas]
        # D200. Fora de `_ambiente` de proposito: o teto e contabilidade nossa,
        # nao fato do laboratorio, e faze-lo mexer na impressao digital diria
        # que o ambiente mudou quando quem mudou foi o que coube no prompt.
        dados["credenciais_omitidas"] = self.credenciais_omitidas
        dados["revisao"] = self.revisao
        dados["trofeu"] = self.trofeu
        caminho.write_text(json.dumps(dados, ensure_ascii=False, indent=1),
                           encoding="utf-8")

    @classmethod
    def carregar(cls, caminho: pathlib.Path) -> "Grafo":
        d = json.loads(caminho.read_text(encoding="utf-8"))
        g = cls()
        for h in d["hosts"]:
            servicos = [Servico(**s) for s in h.pop("servicos")]
            rotas = [Rota(**r) for r in h.pop("rotas", [])]
            # `pop` com padrao: grafo gravado antes de 22 de setembro nao tem a
            # chave, e recusar de carregar apagaria as execucoes ja feitas.
            interfaces = [Interface(**i) for i in h.pop("interfaces", [])]
            g.hosts[h["endereco"]] = Host(servicos=servicos, rotas=rotas,
                                          interfaces=interfaces, **h)
        g.credenciais = [Credencial(**c) for c in d["credenciais"]]
        # `tentada_em` nasceu em 22 de setembro. Sem reconstrui-lo, os grafos
        # das sete execucoes ja pagas carregariam com a lista VAZIA e a metrica
        # 8 leria zero -- sem erro, sem aviso, so o numero errado. E a classe de
        # defeito que matou a `teto-02`, e ela e pior quando nao quebra.
        #
        # A uniao dos dois vereditos e exatamente o conjunto do que foi tentado
        # NAQUELE formato: antes do conserto, toda tentativa caia num deles.
        #
        # ⚠️ **PELA CHAVE AUSENTE, e nao pela lista vazia (D193).** Ate 30 de
        # setembro a condicao era `if not c.tentada_em`, que dispara em QUALQUER
        # grafo cuja lista esteja vazia -- inclusive os de hoje. A migracao
        # passou a consertar em silencio a incoerencia que D192 acabou de achar:
        # o grafo do par 1 tinha 180 credenciais `validada_em` e ZERO
        # `tentada_em`, e ao ser carregado ele saia coerente. Toda ferramenta que
        # le do disco via o defeito ja reparado, e a checagem de coerencia que eu
        # escrevi para pega-lo passou vazia.
        #
        # **Chave ausente e formato antigo; lista vazia e afirmacao do formato
        # atual** -- "nada foi tentado". Confundir as duas transforma
        # compatibilidade em encobrimento.
        for c, bruto in zip(g.credenciais, d["credenciais"]):
            if "tentada_em" not in bruto:
                c.tentada_em = list(dict.fromkeys(c.validada_em + c.recusada_em))
        g.alcances = [Alcance(**a) for a in d["alcances"]]
        g.tentativas = [Tentativa(**t) for t in d.get("tentativas", [])]
        g.revisao = d.get("revisao", 0)
        # `get` com padrao, mesmo motivo de `interfaces` e `tentada_em`: a chave
        # nasceu em 30 de setembro e todo grafo ja gravado veio sem ela.
        g.credenciais_omitidas = d.get("credenciais_omitidas", 0)
        # `get` com padrao, mesmo motivo de `interfaces` e `tentada_em` acima:
        # `trofeu` nasceu em 22 de setembro (D94), e todo `grafo.json` das dez
        # execucoes ja pagas foi gravado sem a chave. Recusar de carregar por
        # causa de um campo que nao existia apagaria essas execucoes.
        g.trofeu = d.get("trofeu", False)
        # A impressao tem de ser refeita sobre o que acabou de ser carregado.
        # Sem isto a primeira absorcao depois de um reinicio compararia com o
        # grafo vazio do construtor e subiria a revisao sem nada ter mudado --
        # e a metrica 7 perderia uma redundancia a cada retomada.
        g._impressao = g._impressao_do_ambiente()
        return g
