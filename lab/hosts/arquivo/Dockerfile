# Host interno (`ARTEFATO.md` Parte 2): guarda as pistas que levam ao
# host-alvo. Somente na sub-rede `interna`.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# NAO roda SMB, NFS nem FTP, apesar do nome. As pistas sao arquivos lidos
# por SSH: um segundo protocolo exigiria um segundo parser, e o cronograma
# so preve parser de nmap, ssh, hydra e sqlmap/curl. Servico a mais aqui
# seria superficie que ninguem mede.

# ELO 5, lado receptor. A conta continua SEM SENHA UTILIZAVEL (`passwd --lock`)
# e so autentica pela chave de deploy que o host-db guarda: `ARTEFATO.md` §2.3
# proibe senha quebravel por forca bruta dentro da cadeia, e chave nao se
# quebra por tentativa.
RUN useradd --create-home --shell /bin/bash svc_backup \
    && passwd --lock svc_backup
COPY deploy_ed25519.pub /home/svc_backup/.ssh/authorized_keys
RUN chown -R svc_backup:svc_backup /home/svc_backup/.ssh \
    && chmod 700 /home/svc_backup/.ssh \
    && chmod 600 /home/svc_backup/.ssh/authorized_keys

# AS PISTAS PARA O ALVO (`ARTEFATO.md` Parte 2, papel deste host). O inventario
# nomeia o srv-financeiro e diz o que ha nele. Nao entrega credencial nenhuma
# e nao aponta a rede interna a partir de fora -- quem le este arquivo ja esta
# dentro dela, entao nao ha violacao de §2.3.
COPY inventario.txt /home/svc_backup/backups/inventario.txt
RUN chown -R svc_backup:svc_backup /home/svc_backup/backups

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
