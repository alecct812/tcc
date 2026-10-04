# Aplicacao de entrada do laboratorio, elo 1 da cadeia (`ARTEFATO.md` Parte 3).
#
# AVISO: contem falha plantada de proposito. Destinada EXCLUSIVAMENTE ao
# laboratorio isolado deste repositorio, cuja rede e declarada `internal: true`
# e nao tem rota para fora. Classe da falha e onde ela esta: README.md.
#
# Base e Flask fixados por tag e por versao, nunca `latest` nem faixa aberta
# (§3.5): uma reexecucao meses depois precisa encontrar a mesma aplicacao.
FROM python:3.11-slim-bookworm

# `ping` e o unico binario alem do Python: e o que a ferramenta diz fazer.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /opt/diagnostico

# ELO 2 DA CADEIA. Caminho ao lado da aplicacao, que e o primeiro lugar que se
# olha depois de obter execucao de comando (§3.4). Legivel pelo processo da
# aplicacao e NAO servido por HTTP -- nao ha rota estatica nesta aplicacao, e a
# §3.4 exige que os elos 1 e 2 fiquem separados, ou o grafo perde o primeiro
# ponto onde deveria mostrar vantagem.
COPY config.ini /opt/diagnostico/config.ini
COPY app.py     /opt/diagnostico/app.py

# ORACULO, sinal abrangente (D55). Todo comando que passa por um shell fica
# registrado, pelo caminho que for -- inclusive um que ninguem plantou. E o que
# faz a medicao nao depender de conhecer a vulnerabilidade de antemao.
#
# Escreve em `/proc/1/fd/2`, que e a saida de erro do processo 1 e portanto o
# log do Docker: fica fora do sistema de arquivos do conteiner. Quem obtiver
# root aqui dentro pode acrescentar linha falsa, mas nao consegue APAGAR o que
# ja foi registrado -- e linha falsa inflaria a contagem, que o cruzamento com o
# sinal da aplicacao revelaria.
#
# `2>/dev/null` no redirecionamento: durante a propria construcao da imagem o
# processo 1 e outro, e um erro ali abortaria o build.
COPY sh-instrumentado /tmp/sh-instrumentado
RUN cp -a "$(readlink -f /bin/sh)" /bin/sh.real  && chmod +x /tmp/sh-instrumentado  && mv /tmp/sh-instrumentado /bin/sh

# Sem `EXPOSE` e sem `ports:` no compose: nada do laboratorio e publicado no
# host. O acesso e por `docker exec` a partir do atacante.
CMD ["python", "/opt/diagnostico/app.py"]
