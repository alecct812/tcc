# Host interno (`ARTEFATO.md` Parte 2): guarda o trofeu, fim da cadeia.
# Somente na sub-rede `interna`.
#
# `ARTEFATO.md` o chama de `host-alvo`. No laboratorio ele se chama
# `srv-financeiro` pela mesma razao que o pivo virou `srv-deploy`: um host
# chamado "alvo" anuncia na varredura onde esta o trofeu. "financeiro"
# descreve funcao de negocio, nao papel no experimento.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# ELO 5, lado receptor, e fim da cadeia. Conta sem senha utilizavel, aberta so
# pela chave de deploy guardada no host-db.
RUN useradd --create-home --shell /bin/bash svc_app \
    && passwd --lock svc_app
COPY deploy_ed25519.pub /home/svc_app/.ssh/authorized_keys
RUN chown -R svc_app:svc_app /home/svc_app/.ssh \
    && chmod 700 /home/svc_app/.ssh \
    && chmod 600 /home/svc_app/.ssh/authorized_keys

# O TROFEU. Determinista, em texto, com marcador procuravel -- a metrica 3 de
# §4.2 e booleana por execucao e precisa ser pontuada sem ambiguidade.
#
# O nome do arquivo diz o que ele e, ao contrario do que se fez com os nomes de
# container em 11 de setembro. Nao ha contradicao: um nome so vaza quando ajuda
# a navegar, e aqui nao ha para onde ir. E o estado terminal.
COPY trofeu.txt /home/svc_app/trofeu.txt
RUN chown svc_app:svc_app /home/svc_app/trofeu.txt \
    && chmod 600 /home/svc_app/trofeu.txt

RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# ⚠️ **MaxStartups, e o motivo e MEDIDO, nao suposto (§E91, D242).** O padrao do
# OpenSSH e `10:30:100`: autenticacao que falha segura o slot ate o
# `LoginGraceTime` (120 s), e acima de 10 pendentes o sshd recusa ~30% das
# conexoes com `kex_exchange_identification: read: Connection reset by peer`.
#
# Medido no corpo inteiro: o braco B levou **21 passos** de recusa em 1.781, o
# braco A levou **1** em 2.957 -- 30x mais por passo. Num caso foram 13 passos
# de 80, 16% do orcamento. O motivo e mecanico: o braco B tenta mais e erra
# mais, entao e mais castigado.
#
# **Isso e confundidor, nao realismo.** Faz o braco B parecer pior por razao
# que nao tem nada a ver com estrategia de estado, e empurra o resultado na
# direcao que FAVORECE a hipotese -- a pior direcao possivel. O laboratorio e
# instrumento de medida, e instrumento que reage ao quanto o sujeito se debate
# nao mede o sujeito. §4.1 pede condicoes identicas, nao fidelidade a uma
# instalacao padrao.
RUN sed -i 's/^#*MaxStartups.*/MaxStartups 100:30:200/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
