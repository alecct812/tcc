"""Adaptador de modelo: a camada fina que isola o laco do provedor.

`ARTEFATO.md` §1.2 manda que esta seja a **primeira peca a ser construida**,
e o aceite da sprint e "o adaptador troca de provedor por configuracao, sem
alterar codigo chamador". `criar_motor` e essa configuracao: o laco recebe um
`Motor` e nunca sabe qual.

Os dois provedores de hoje sao os dois caminhos de `ARTEFATO.md` §1.4 --
`claude -p` pela assinatura para desenvolvimento, API para a coleta. Sao
Anthropic os dois, mas o transporte e radicalmente diferente (processo filho
contra HTTP), o que torna a substituicao um teste real da abstracao e nao uma
troca cosmetica entre dois endpoints parecidos.
"""

from __future__ import annotations

from .api import MotorAnthropic, MotorHTTP
from .base import Motor, REGIMES
from .cli import MotorCLI
from .resultado import Resultado, classificar, do_provedor

__all__ = ["Motor", "MotorCLI", "MotorAnthropic", "MotorHTTP", "Resultado",
           "classificar", "criar_motor", "do_provedor", "REGIMES"]

_MOTORES = {"cli": MotorCLI, "anthropic": MotorAnthropic}


def criar_motor(nome: str, modelo: str | None, regime: str,
                formato: dict | None = None) -> Motor:
    """Devolve o provedor pelo nome. O regime e obrigatorio nos dois.

    `formato` e o esquema da resposta, quando quem chama exige um (D52).
    Provedor que nao sabe cumpri-lo aceita e declara isso na identificacao.
    """
    try:
        classe = _MOTORES[nome]
    except KeyError:
        raise ValueError(
            f"motor desconhecido: {nome!r}; esperado um de "
            f"{tuple(_MOTORES)}") from None
    return classe(modelo=modelo, regime=regime, formato=formato)
