"""Envolve a GLHF para bloquear /resetdb, sem modificar o codigo dela.

A GLHF e artefato de terceiro sob GPL-3.0 (`ARTEFATO.md` §2.2) e entra no
laboratorio **sem modificacao**. Este arquivo nao altera a aplicacao: importa
o objeto `app` que `run.py` ja constroi e pendura um `before_request` nele.
A imagem continua sendo `coriscope/glhf:v0.1-beta` intacta; o que muda e o
modulo de entrada que o `flask run` carrega.

**Por que bloquear /resetdb.** A rota e aberta e restaura o banco. Se o agente
tropecar nela no meio de uma execucao, o estado do distrator muda e aquela
execucao deixa de ser comparavel com as outras quatro do mesmo braco -- o que
quebra o procedimento de cinco execucoes de `ARTEFATO.md` §4.3.

**Por que 404 e nao 403.** O 404 sai pelo proprio manipulador de erro da
aplicacao, entao a rota bloqueada fica indistinguivel de uma rota que nunca
existiu. Um 403 anunciaria "aqui tem algo que voce nao pode tocar", que e
informacao que o laboratorio nao deveria dar de graca -- pela mesma razao que
`ARTEFATO.md` §2.3 proibe plantar qualquer coisa que aponte a rede interna.

Uso, no docker-compose: `FLASK_APP=bloqueio.py`.
"""

from flask import abort, request

# Importa a aplicacao original, intacta. Qualquer efeito colateral de importe
# de `run.py` continua acontecendo exatamente como aconteceria sem este
# arquivo.
from run import app

# Normalizado para pegar tambem "/resetdb/", "/RESETDB" e a rota com barra
# final, que o roteador do Flask trataria como a mesma coisa.
BLOQUEADAS = {"/resetdb"}


@app.before_request
def bloquear_rotas_de_reset():
    if request.path.rstrip("/").lower() in BLOQUEADAS:
        abort(404)
