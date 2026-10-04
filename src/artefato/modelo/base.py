"""A interface que o laco de decisao enxerga.

`ARTEFATO.md` §1.2 pede uma "camada fina que isola o laco do provedor", e
**primeira peca a ser construida**. Fina e literal: recebe prompt, devolve
`Resultado`. Extrair a acao proposta do texto e trabalho do laco, nao daqui --
se a extracao morasse no adaptador, trocar de provedor mudaria a interpretacao
da resposta, que e exatamente o que esta camada existe para impedir.
"""

from __future__ import annotations

from .resultado import Resultado

REGIMES = ("sem-raciocinio", "raciocinio")


class Motor:
    """Base de todo provedor.

    O `regime` e **obrigatorio e explicito**, nunca herdado de quem chama
    (D02 em `docs/decisoes-tecnicas.md`). Ele substituiu a temperatura como
    controle de determinismo, porque os modelos Claude atuais removeram os
    parametros de amostragem da API e enviar `temperature` devolve HTTP 400.
    Herda-lo implicitamente seria a divergencia acidental que `CONTEXTO.md` §9
    diz que invalida o experimento -- e ela seria silenciosa.
    """

    nome = "abstrato"

    # Provedor que sabe garantir a forma da resposta declara `True`. Serve para
    # a identificacao de cada chamada dizer, sem adivinhacao, se aquele passo
    # rodou com saida estruturada ou sem (D52).
    estrutura_saida = False

    def __init__(self, modelo: str | None, regime: str,
                 formato: dict | None = None):
        if regime not in REGIMES:
            raise ValueError(
                f"regime desconhecido: {regime!r}; esperado um de {REGIMES}")
        self.modelo = modelo
        self.regime = regime
        # Esquema da resposta, quando quem chama exige um. E parametro e nao
        # decisao do adaptador: o arnes de medicao usa a mesma classe e nao quer
        # esquema nenhum. Provedor que nao sabe cumpri-lo aceita e declara que
        # nao cumpriu, em vez de ignorar calado -- silencio aqui esconderia a
        # assimetria entre o caminho de desenvolvimento e o da coleta.
        self.formato = formato

    def identificacao(self) -> dict:
        """Vai para o log JSONL de cada passo (`ARTEFATO.md` §1.2).

        O regime aparece aqui porque o aceite da sprint exige que ele esteja
        no log de **cada chamada**: conferir paridade entre os dois bracos
        depois da coleta so e possivel se cada linha disser sob que regime
        rodou.
        """
        return {"motor": self.nome, "modelo": self.modelo,
                "regime": self.regime,
                "saida_estruturada": bool(self.formato) and self.estrutura_saida}

    def chamar(self, prompt: str) -> Resultado:
        raise NotImplementedError
