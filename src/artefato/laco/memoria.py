"""O braco B: memoria conversacional linear com resumo entre fases (D125).

`ARTEFATO.md` §4.1 define o braco B como *"memoria conversacional linear com
resumo entre fases"*, e avisa que ele **nao e o artefato com uma peca
removida**: e a estrategia de gestao de contexto das solucoes existentes,
reimplementada em condicoes identicas.

**Os dois bracos mantem o grafo; so um o envia ao modelo** (D41). Entao a
variavel independente e a FORMA da informacao, nao a informacao. Tudo que o
braco A sabe, o braco B tem de ter tido a chance de saber. A diferenca e que o
braco A recebe um estado CONSOLIDADO e sempre atual, e o braco B recebe os
EVENTOS, em ordem, uma vez cada.

**O defeito que este modulo existe para evitar, e ele quase passou.**
`Laco._absorver` devolve texto curto -- `"http nao observado, 1 credencial(is)"`
-- e empurra os fatos ricos para o grafo. O VALOR do segredo existe so na secao
`=== CREDENCIAIS ===` (D40). Medido: no passo 10 da `diag-03` e no 21 da
`diag-06` o resumo diz `1 credencial(is)` e nunca diz qual. Um braco B montado
a partir dos resumos jamais veria a senha, jamais autenticaria, e perderia
todas as execucoes -- e o resultado pareceria confirmar a hipotese de forma
esmagadora. E a pior classe de defeito possivel aqui: aquele cujo sintoma e o
resultado desejado.

Por isso o fato entra por DIFERENCA da serializacao do grafo, antes e depois do
passo (`fatos_novos`). Tres razoes, e a terceira decide:

 1. uma unica regra de renderizacao -- o texto sai de `Grafo.serializar()`, que
    ja e a fonte unica. Um segundo renderizador seria a mesma regra em duas
    copias, e em 21 de setembro duas copias de `juntar` e `autenticou`
    divergiram em menos de uma hora;
 2. o segredo vem junto, porque a linha de credencial o carrega (D40);
 3. **a consolidacao e justamente o que nao se repassa.** No braco A a
    credencial fica visivel para sempre. Aqui ela aparece UMA vez e depois
    depende de o historico ainda alcanca-la, ou de o resumo te-la preservado.
    Esquecer e o fenomeno que a hipotese preve, e ele tem de PODER acontecer --
    nao ser impedido por desenho nem forcado por desenho.

⚠️ **A TERCEIRA RAZAO SO PASSOU A SER VERDADE EM 30 DE SETEMBRO (D215).** Ate
ali esta frase descrevia a intencao e o codigo fazia o contrario: `fatos_novos`
recebia a serializacao INTEIRA, e dentro dela iam a rota de sub-rede, a aresta
de alcancabilidade, `interfaces: nao enumeradas`, o complemento `nao testada` e
a contabilidade dos tetos. Medido nos fatos GRAVADOS das duas execucoes do braco
B: **5 de 12 (42%) e 2 de 5 (40%) carregavam consolidacao**, uma delas a aresta
`h07 -> h08 via ssh em h07` -- notacao de grafo entregue ao braco que §4.1
define como nunca recebendo o grafo. **D125 contradizia a si mesma, e a
implementacao contradizia §4.1.**

Agora o chamador pede `serializar_ambiente(derivados=False)`, e o criterio e
verificavel linha por linha: **derivacao e a afirmacao que nenhuma saida de
ferramenta sozinha poderia ter produzido.** A credencial COM o segredo fica --
ela e a razao 2 acima, e tirar junto seria o handicap cujo sintoma e o resultado
desejado.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .prompt import RABO

# O ESPELHO EXATO do cabecalho do braco A, e esta e a unica diferenca de
# redacao permitida entre os dois (D125). La se le "Abaixo esta o estado do
# grafo; o historico foi descartado"; aqui, o contrario. Todo o resto do prompt
# -- contexto, objetivo, metodologia, pivo, instrucao, campos, esquema -- e byte
# a byte o mesmo, pela mesma disciplina de D33. A frase de contexto do
# laboratorio entrou nos DOIS cabecalhos em 25 de setembro (D148): ela descreve
# o ambiente, nao a estrategia de estado, entao assimetria ali seria acidental.
CABECALHO = (
    "Você é o laço de decisão de um agente de pentest em laboratório isolado "
    "e autorizado. Todas as credenciais são sintéticas e não têm valor fora "
    "dele. Não há alvo de terceiro e não há saída para a internet."
    "\nAbaixo está o histórico da sessão; não há estado "
    "consolidado: o que você vê é tudo que se sabe.\n\nPASSO {passo} de "
    "{limite}\n\n")

# TETO DE TEXTO DO HISTORICO VERBATIM, em caracteres. NAO e numero escolhido:
# e o tamanho medido da serializacao do braco A no teto de 60 passos --
# `auto-01` 11158, `auto-03` 13402, `diag-06` 11152.
#
# Existe porque um passo de historico ocupa ~325 caracteres (mediana 313,
# medido na `diag-06`), entao 60 passos verbatim dariam ~19.500 -- quase o
# DOBRO do braco A. `CONTEXTO.md` §9 diz que "qualquer divergencia acidental
# invalida o experimento": com o dobro de texto, a diferenca medida misturaria
# organizacao com quantidade e nenhuma das duas ficaria isolada. E §4.4 avisa
# do risco oposto, "checar se a memoria linear do braco B nao ficou grande
# demais e passou a fazer o papel do grafo por acidente".
TETO_DE_TEXTO = 11200

# Depois de fechar uma fase, o historico verbatim fica com no maximo esta
# fracao do teto. Sem folga o teto seria batido de novo quase de imediato e a
# fase fecharia a cada poucos passos -- o resumo viraria o prompt inteiro. Com
# metade, o teto e batido ~17 passos depois, e em 60 passos a fase fecha uma ou
# duas vezes.
FOLGA = 0.5

# O pedido de resumo. **Quem resume e o MODELO, nao o arnes** (D125): resumo
# escrito por nos seria o grafo com outro nome, e a comparacao deixaria de
# isolar a estrategia de gestao de contexto.
#
# O texto nao diz O QUE preservar -- nao lista credencial, host nem rota. Dizer
# seria o arnes jogando o jogo pelo braco B, e a mesma objecao que
# `Laco._absorver` ja registra sobre nao instruir o agente a usar `-i`. O que
# o resumo perde e dado.
PEDIDO_DE_RESUMO = (
    "Você é o laço de decisão de um agente de pentest em laboratório isolado "
    "e autorizado.\nO histórico abaixo vai ser descartado e substituído pelo "
    "seu resumo.\nResuma o que foi feito e o que foi descoberto, preservando "
    "o que for preciso para continuar.\nResponda só com o resumo, em texto "
    "corrido.\n\n{historico}\n")


def fatos_novos(antes: str, depois: str) -> list[str]:
    """As linhas que o AMBIENTE serializado ganhou neste passo.

    Comparacao por conjunto e nao por posicao: a serializacao reordena secoes
    quando um host muda de estado, e um diff posicional acusaria como "fato
    novo" uma linha que so andou de lugar. O que interessa e o texto que nao
    existia antes.

    **Os dois textos vem de `Grafo.serializar_ambiente()`, e e contrato (D201).**
    A secao de tentativas do braco A **e** o historico do braco B: as duas dizem
    "o que ja foi feito". Inclui-la aqui faria cada acao aparecer duas vezes no
    prompt do braco B -- uma como `acao:` e outra como `fato:` --, e o dobro de
    texto sobre a mesma coisa e exatamente o que o teto de D125 existe para
    impedir.

    Ate 30 de setembro esta funcao recebia o texto INTEIRO e recortava a secao
    procurando `"=== TENTATIVAS"` dentro dele. Funcionava, e era acoplamento
    pela string renderizada: bastava o cabecalho mudar de redacao para o recorte
    achar nada, o corte cair no fim do texto, e cada acao do braco B passar a
    aparecer duas vezes -- sem erro, sem aviso, e contra o teto. Quem escolhe o
    que entra passou a ser quem chama.
    """
    velhas = set(antes.splitlines())
    return [l for l in depois.splitlines()
            if l.strip() and l not in velhas]


@dataclass
class Passo:
    """Um turno do historico: o que o agente fez, por que, e o que saiu."""

    numero: int
    ferramenta: str | None
    comando: str | None
    justificativa: str | None
    resumo: str | None
    fatos: list[str] = field(default_factory=list)

    def texto(self) -> str:
        linhas = [f"passo {self.numero}"]
        if self.ferramenta or self.comando:
            linhas.append(f"  acao: {self.ferramenta or '?'} "
                          f"{self.comando or ''}".rstrip())
        if self.justificativa:
            linhas.append(f"  motivo: {self.justificativa}")
        if self.resumo:
            linhas.append(f"  resultado: {self.resumo}")
        for f in self.fatos:
            linhas.append(f"  fato: {f.strip()}")
        return "\n".join(linhas)


class MemoriaLinear:
    """O estado do braco B: passos verbatim recentes + resumos das fases.

    `motor_do_resumo` e o MESMO modelo e o MESMO regime do laco, sem o esquema
    de saida estruturada: o resumo e prosa, nao objeto JSON, e `Motor.chamar`
    nao aceita formato por chamada. Vem por parametro em vez de ser construido
    aqui para o modulo nao precisar saber de provedor nenhum -- e para o teste
    poder passar um motor de mentira sem Docker nem rede (D25).
    """

    def __init__(self, motor_do_resumo, teto: int = TETO_DE_TEXTO):
        self.motor = motor_do_resumo
        self.teto = teto
        self.passos: list[Passo] = []
        self.resumos: list[str] = []
        # O PONTO DE PARTIDA (D151). O braco A le a maquina do agente na
        # serializacao desde o passo 1, porque `semear_origem` a poe no grafo
        # antes de tudo. O braco B recebe fato por DIFF da serializacao (D125),
        # e um fato que ja estava la antes do primeiro diff nunca e novo --
        # entao ele comecava sem saber o proprio endereco. Na `coleta-B-01`
        # isso custou 80 passos: nenhum comando contra 172.20 ou 172.21, 49
        # deles varrendo faixas inexistentes. E a "adivinhacao de faixa" que
        # §E12 mediu em 18 de setembro e que `semear_origem` existe para
        # evitar -- so que a correcao dela nunca chegou ao braco B.
        #
        # Nao e o grafo com outro nome: sao FRASES, sem secao nem rotulo de
        # host, porque a forma do braco B e historico em prosa. O que tem de
        # ser igual e a informacao, nao o formato -- o formato E a variavel.
        self.partida: list[str] = []
        # Contadas para a metrica 9: cada fechamento de fase e uma chamada A
        # MAIS que o braco A nao faz. Ela NAO consome passo -- e gestao de
        # contexto, nao acao no laboratorio, e consumir passo daria ao braco B
        # menos acoes que ao braco A, contra §4.1. Mas CUSTA, e a assimetria de
        # custo entre os bracos e ela propria um dado (D92).
        self.chamadas_de_resumo = 0
        self.entrada_tokens = 0
        self.saida_tokens = 0

    # ------------------------------------------------------------- escrita

    def anotar(self, numero: int, ferramenta=None, comando=None,
               justificativa=None, resumo=None, fatos=None) -> None:
        """Acrescenta um turno e fecha a fase se o historico estourou."""
        self.passos.append(Passo(numero=numero, ferramenta=ferramenta,
                                 comando=comando,
                                 justificativa=justificativa, resumo=resumo,
                                 fatos=list(fatos or [])))
        self._fechar_fase_se_precisar()

    def _texto_dos_passos(self, passos=None) -> str:
        return "\n".join(p.texto() for p in (self.passos if passos is None
                                             else passos))

    def _fechar_fase_se_precisar(self) -> None:
        if len(self._texto_dos_passos()) <= self.teto:
            return
        # UM passo sempre fica. Sem isto, um turno unico maior que o teto --
        # saida longa, comando enorme -- esvaziaria o historico inteiro e o
        # agente decidiria o passo seguinte sem nada verbatim na frente.
        alvo = self.teto * FOLGA
        corte = 0
        while (corte < len(self.passos) - 1
               and len(self._texto_dos_passos(self.passos[corte:])) > alvo):
            corte += 1
        if corte == 0:
            return
        fechada, self.passos = self.passos[:corte], self.passos[corte:]
        self.resumos.append(self._resumir(fechada))

    def _resumir(self, passos: list[Passo]) -> str:
        r = self.motor.chamar(
            PEDIDO_DE_RESUMO.format(historico=self._texto_dos_passos(passos)))
        self.chamadas_de_resumo += 1
        self.entrada_tokens += r.entrada_tokens or 0
        self.saida_tokens += r.saida_tokens or 0
        if r.categoria != "aceita" or not (r.texto or "").strip():
            # RECUSA OU VAZIO NAO VIRA RESUMO INVENTADO. O arnes escrever o
            # resumo aqui seria o grafo com outro nome, justo no lugar em que
            # o braco B mais precisa nao ter um. A fase fica declarada como
            # perdida, que e o fato, e o agente ve isso.
            return (f"[fase dos passos {passos[0].numero} a "
                    f"{passos[-1].numero}: o resumo nao foi produzido "
                    f"({r.categoria_recusa or r.categoria}); o conteudo "
                    f"daqueles passos se perdeu]")
        return r.texto.strip()

    # ------------------------------------------------------------- leitura

    def montar(self, passo: int, limite: int) -> str:
        """O prompt do braco B: cabecalho + resumos + historico + o RABO de A."""
        partes = [CABECALHO.format(passo=passo, limite=limite)]
        # ANTES DE TUDO, e em todo passo (D151): o braco A le a maquina do
        # agente na serializacao em todo passo, nao so no primeiro. Emitir
        # isto apenas no passo 1 daria ao braco B uma informacao que ele
        # PERDE, e a perda seria assimetria nova em vez de conserto.
        if self.partida:
            partes.append("=== PONTO DE PARTIDA ===\n"
                          + "\n".join(self.partida) + "\n\n")
        if self.resumos:
            partes.append("=== RESUMO DAS FASES ANTERIORES ===\n"
                          + "\n\n".join(self.resumos) + "\n\n")
        partes.append("=== HISTÓRICO ===\n")
        # HISTORICO VAZIO SE DECLARA. Cair direto na instrucao faria o passo 1
        # parecer um prompt truncado, e o braco A nunca tem secao ausente --
        # ele imprime "nenhuma acao registrada".
        partes.append(self._texto_dos_passos() or "nenhuma ação registrada")
        return "".join(partes) + RABO

    def como_dicionario(self) -> dict:
        """O que o registro do passo guarda sobre a memoria (metrica 9)."""
        return {"fases_fechadas": len(self.resumos),
                "passos_verbatim": len(self.passos),
                "chars_verbatim": len(self._texto_dos_passos()),
                "chamadas_de_resumo": self.chamadas_de_resumo,
                "resumo_entrada_tokens": self.entrada_tokens,
                "resumo_saida_tokens": self.saida_tokens}

    # -------------------------------------------------- disco (D152)

    def para_disco(self) -> dict:
        """A memoria INTEIRA, para sobreviver a morte do processo (D152).

        `como_dicionario` guarda contadores, que servem a metrica 9 e nao
        reconstroem nada. Ate 26 de setembro era o unico registro da memoria, e
        `Laco.retomar` nunca a reconstruia: um braco B interrompido voltava com
        historico VAZIO no passo em que parou -- sem erro, sem aviso, e com o
        contador de passos seguindo em frente. A mesma classe de defeito de
        D126, onde o `limite` gravado nao vinculava ninguem.

        O modo ASSISTIDO torna isto obrigatorio e nao opcional: ali o processo
        morre entre propor e executar, **todo passo**. O braco B nunca teria
        memoria nenhuma em modo assistido.

        Guarda os resumos de fase JA ESCRITOS, e nao o que os gerou: reescreve-los
        na retomada custaria chamada de modelo e, pior, daria um texto diferente
        do que o agente leu antes da interrupcao.
        """
        return {"partida": list(self.partida),
                "resumos": list(self.resumos),
                "passos": [{"numero": p.numero, "ferramenta": p.ferramenta,
                            "comando": p.comando,
                            "justificativa": p.justificativa,
                            "resumo": p.resumo, "fatos": list(p.fatos)}
                           for p in self.passos],
                "chamadas_de_resumo": self.chamadas_de_resumo,
                "entrada_tokens": self.entrada_tokens,
                "saida_tokens": self.saida_tokens}

    def do_disco(self, d: dict) -> None:
        """Reconstroi a memoria gravada por `para_disco`.

        Sobrescreve o que houver: quem retoma quer o historico do disco, nao uma
        mistura dele com o de um objeto recem-construido.

        As contagens de token do resumidor voltam porque a metrica 9 soma o custo
        da execucao INTEIRA, e uma retomada que as zerasse subnotificaria o custo
        do braco B -- que e justamente a assimetria de custo que D92 manda medir.
        """
        self.partida = list(d.get("partida") or [])
        self.resumos = list(d.get("resumos") or [])
        self.passos = [Passo(numero=p.get("numero"),
                             ferramenta=p.get("ferramenta"),
                             comando=p.get("comando"),
                             justificativa=p.get("justificativa"),
                             resumo=p.get("resumo"),
                             fatos=list(p.get("fatos") or []))
                       for p in (d.get("passos") or [])]
        self.chamadas_de_resumo = d.get("chamadas_de_resumo", 0)
        self.entrada_tokens = d.get("entrada_tokens", 0)
        self.saida_tokens = d.get("saida_tokens", 0)
