"""Camada de ferramentas: invólucros com parser dedicado.

Hoje so os invólucros. O parser e a sprint da terca 15 -- e ate ele existir,
nada desta camada alimenta o prompt: `ARTEFATO.md` §1.2 exige que so o que o
parser extraiu e gravou no grafo chegue ao modelo.
"""

from __future__ import annotations

from .base import Execucao, Executor
from .curl import Curl
from .fatos import (Autenticacao, Credencial, ForcaBruta, Host, juntar,
                    RespostaHttp, Rota, Servico)
from .hydra import Hydra
from .netcat import Netcat
from .nmap import Nmap, enderecos_varridos, formato_nao_lido
from .saida import FatosDeShell, analisar_saida
from .ssh import Ssh, autenticou, julgou, mecanismo

# Despacho por nome, para quem so tem a string -- o grafo registra a tentativa
# pelo nome da ferramenta, nao pelo objeto. Sem rotulo conhecido, cai no
# comando inteiro, que e verdadeiro e so custa tokens.
FERRAMENTAS = {f.nome: f for f in (Nmap(), Ssh(), Hydra(), Curl())}


def resumir(ferramenta: str, comando: list[str]) -> str:
    alvo = FERRAMENTAS.get(ferramenta)
    return alvo.resumir(comando) if alvo else juntar(comando)


__all__ = ["Execucao", "Executor", "Nmap", "Ssh", "Hydra", "Curl", "Netcat",
           "Autenticacao", "Credencial", "ForcaBruta", "Host",
           "RespostaHttp", "Rota", "Servico", "resumir",
           "FatosDeShell", "analisar_saida", "enderecos_varridos", "formato_nao_lido", "autenticou", "julgou", "mecanismo"]
