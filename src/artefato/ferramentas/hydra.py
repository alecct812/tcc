"""Invólucro do hydra.

O hydra ocupa um lugar incomum neste projeto: ele e a ferramenta que **nao deve
funcionar** dentro da cadeia. `ARTEFATO.md` §2.3 proibe senha quebravel por forca
bruta nos elos, porque Deng et al. registraram 235 ocorrencias de forca bruta
desnecessaria como o comportamento indevido mais frequente, e premiar esse vicio
contaminaria a metrica 7 (acao redundante).

Dai a assimetria dos dois fixtures do domingo 13: o `05-hydra-glhf.txt` cede,
porque a GLHF traz senha fraca propria; o `06-hydra-srv-deploy.txt` nao cede, e
foi capturado justamente como verificacao daquele requisito.

**Por que "nao achou nada" e fato, e nao ausencia de fato.** Uma corrida que
terminou a lista sem sucesso diz ao agente que aquele caminho esta fechado. Se o
parser devolvesse `None` ali, o grafo nao teria como distinguir "ja tentei e nao
deu" de "nunca tentei", e o agente gastaria passo repetindo -- que e exatamente o
que a metrica 7 conta.
"""

from __future__ import annotations

import re

from .base import Execucao
from .fatos import juntar, Credencial, ForcaBruta

# "[DATA] attacking ssh://172.20.0.12:22/"
# "[DATA] attacking http-post-form://172.20.0.11:1337/login:username=^USER^&..."
ATAQUE = re.compile(r"^\[DATA\] attacking ([\w-]+)://([^:/\s]+):(\d+)")

# "[1337][http-post-form] host: 172.20.0.11   login: root   password: hashed"
ACHADO = re.compile(
    r"^\[(\d+)\]\[([\w-]+)\]\s+host:\s+(\S+)"
    r"(?:\s+login:\s+(\S+))?(?:\s+password:\s+(\S*))?")

# "1 of 1 target successfully completed, 1 valid password found"
# "1 of 1 target completed, 0 valid password found"
RESUMO = re.compile(
    r"^(\d+) of (\d+) targets? (?:successfully )?completed, "
    r"(\d+) valid passwords? found")

# "[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:1/p:8), ..."
TENTATIVAS = re.compile(r"(\d+) login tries")


class Hydra:
    nome = "hydra"

    LISTA = "/usr/share/wordlists/senhas.txt"

    def contra(self, alvo: str, usuario: str, lista: str = LISTA,
               tarefas: int = 16) -> Execucao:
        """Uma corrida contra um alvo, com um usuario e uma lista de senhas.

        **Dezesseis tarefas, medido e nao chutado** (D49). Contra o SSH deste
        laboratorio, em 17 de setembro:

            -t 4    120 senhas em 4m13s   2,1 s por senha
            -t 16   120 senhas em   59s   0,5 s por senha
            -t 32   erro: "6 targets did not resolve or could not be connected"

        Em `-t 32` o servidor comeca a derrubar conexao, e ai o hydra pode
        passar batido por uma senha que ESTAVA na lista -- falso negativo
        silencioso, o pior tipo. Controle com a senha certa na posicao 121:
        `-t 4`, `-t 16` e `-t 32` acharam as tres; so `-t 32` reportou erro.
        Dezesseis e o teto seguro.

        Por que a velocidade importa, se o orcamento e de passos e nao de
        segundos: a lista precisa CABER no teto de 300 s de `Executor.rodar`.
        Corrida que estoura devolve "nao concluida", o agente nao consegue
        descartar o alvo, e pode repetir -- contaminando a metrica 7 por motivo
        alheio ao que o experimento compara. Com `-t 16`, as 207 senhas levam
        ~105 s.

        A lista tem caminho padrao porque ela vive na imagem do atacante (D44).
        Sem isso, toda chamada morreria em "File for passwords not found" e uma
        acao legitima do agente contaria como comando invalido na metrica 6 --
        medindo uma falta do ambiente como se fosse erro de raciocinio.
        """
        return Execucao(comando=["hydra", "-l", usuario, "-P", lista,
                                 "-t", str(tarefas), alvo])

    def analisar(self, execucao: Execucao) -> ForcaBruta:
        if execucao.codigo is None:
            # Mesmo contrato de `Nmap.analisar` e `Ssh.analisar`. Devolver uma
            # corrida "sem credenciais" para algo que nunca rodou registraria
            # no grafo uma tentativa que nao houve, e inflaria a metrica 7.
            raise ValueError(
                "execucao ainda nao rodou: nao ha corrida para analisar")

        r = ForcaBruta()
        texto = f"{execucao.saida}\n{execucao.erro}"

        for linha in texto.splitlines():
            m = ATAQUE.match(linha)
            if m:
                # O alvo sai da SAIDA, nao do comando. No fixture 05 o host e a
                # porta vem em argumentos separados (`172.20.0.11 -s 1337`) e no
                # 06 vem colados num esquema (`ssh://172.20.0.12`); o hydra
                # normaliza os dois nesta linha, e ler dela evita um segundo
                # analisador so para a linha de comando.
                r.servico, r.endereco, r.porta = m.group(1), m.group(2), int(m.group(3))
                continue

            m = ACHADO.match(linha)
            if m and m.group(4):
                porta, servico, host, usuario, segredo = m.groups()
                r.credenciais.append(Credencial(
                    usuario=usuario,
                    # Forca bruta produz senha, nunca chave: o hydra testa
                    # strings de uma lista.
                    tipo="senha", segredo=segredo or None,
                    endereco=host, porta=int(porta), servico=servico))
                continue

            m = RESUMO.search(linha)
            if m:
                # "concluida" e o unico sinal de que a lista acabou. Sem ele,
                # uma corrida interrompida por tempo pareceria uma corrida que
                # esgotou a lista, e o agente concluiria que a senha nao esta
                # ali quando o que houve foi um timeout.
                r.concluida = True
                continue

            m = TENTATIVAS.search(linha)
            if m:
                r.tentativas = int(m.group(1))

        return r

    def resumir(self, comando: list[str]) -> str:
        """Forma curta para a secao de tentativas (D45): aqui, o comando inteiro.

        ⚠️ **Ate 2 de outubro esta funcao tirava `-P <lista>` e `-t <n>`**, com a
        justificativa "que o involucro fixa". A frase era verdadeira sobre
        `Hydra.contra`, que monta `["-l", usuario, "-P", LISTA, "-t", tarefas]` --
        e falsa sobre o unico caminho que o corpo usa. Depois de D202 o agente
        escreve a linha dele, escolhe a lista (`rockyou.txt`, que ele baixa da
        GLHF por conta propria) e escolhe o paralelismo. Nenhum dos dois e fixo.

        **O custo medido (§E111).** O rotulo voltava ao agente como
        `hydra -L nicks.txt -s 22 -f -I ssh://172.20.0.12` -- um hydra SEM lista
        de senhas, isto e, um ataque sintaticamente incompleto. O agente lia o
        proprio registro, concluia o que qualquer leitor concluiria, e consertava
        o que nao estava quebrado. Com as palavras dele, da `coleta-A-06`:

            p18  "A tentativa anterior (t17) nao especificou lista de senhas"
            p49  "falhou por sintaxe incompleta (sem lista de senhas)"
            p58  "Tentativas anteriores falharam por falta de lista de senhas (-P)"

        `t17` tinha `-P rockyou.txt`. **5 de 6 justificativas de hydra citam a
        falta de `-P` como motivo de repetir**, e o comando citado sempre a tinha.
        Custo: 9 passos nas coletas validas do braco A, 35 minutos de relogio so
        na `coleta-A-06`, e tres linhas da secao renderizadas com TEXTO IDENTICO
        sob ids diferentes -- a secao perdendo a unica coisa que ela faz.

        ⚠️ **E era assimetrico entre os bracos, o que viola §4.1.** O braco B
        recebe `proposta.comando` (`laco/__init__.py`, `anotar`): o comando real,
        com `-P` intacto. So o braco A passava pelo rotulo. Medido no corpus: 9
        passos perdidos no braco A, **0 no braco B** -- e a `coleta-B-02`, que
        rodou hydra 13 vezes por 32 minutos, nunca alegou falta de lista. O
        formato e a variavel do experimento; a informacao tem de ser igual
        (`laco/memoria.py`). Aqui a informacao diferia, contra o braco A.

        **Nada e tirado, e nao e desleixo.** Em hydra nada e invariante: `-s`
        varia (22, 1337), `-f` falta em algumas, `-I` e escolha, `-P` falta
        quando o agente usa `-p c01`. A economia de D45 vale onde ha ruido fixo
        -- as cinco opcoes `-o` do ssh, 30 de 45 tokens --, e aqui nao ha. O que
        fica e a regra que `curl.resumir` ja escrevia desde D64: **rotulo com
        forma de comando tem de ser comando que roda**, e tem de distinguir o
        que o agente escolheu, "senao o agente deixaria de tentar uma carga que
        nunca tentou". O caso de hydra e o inverso exato dessa frase: ele tentou
        de novo uma carga que ja tinha tentado, porque o rotulo escondia a parte
        que as tornava iguais.

        A assinatura nunca passou por aqui -- ela e o comando inteiro mascarado,
        e a contagem de redundancia (metrica 7) nao muda.
        """
        return juntar(comando)
