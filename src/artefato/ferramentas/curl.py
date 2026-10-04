"""Invólucro do curl.

E a ferramenta dos elos 1 e 2 de `lab/cadeia.md`: a injecao de comando no
`host-web` e a leitura do arquivo de configuracao que entrega a credencial do
elo 3. Escolhido no lugar do sqlmap pelo motivo registrado em D38 -- a unica
injecao de SQL do laboratorio esta no distrator, e parser bom para o distrator
o tornaria mais produtivo, enfraquecendo o vies que ele existe para revelar.

**O que este parser NAO faz: julgar se houve injecao de comando.** Ele le
codigo HTTP, tipo, tamanho e pares de credencial em formato ini. Dizer "esta
resposta prova execucao de comando" e conclusao, nao leitura, e quem conclui e
o laco de decisao -- que chama `Grafo.absorver_execucao`. Um parser que
adivinhasse isso estaria afirmando, a partir de texto, um fato que o texto nao
carrega; e o mesmo principio que faz `Ssh.analisar` nao distinguir senha errada
de conta inexistente, porque o ssh nao distingue.
"""

from __future__ import annotations

import html.parser
import re
import urllib.parse

from .base import Execucao
from .fatos import juntar, Credencial, RespostaHttp, Rota, usuario_plausivel

# "HTTP/1.1 200 OK", "HTTP/1.1 404 NOT FOUND"
STATUS = re.compile(r"^HTTP/[\d.]+\s+(\d{3})")
# "[secao]" de arquivo ini.
SECAO = re.compile(r"^\s*\[([^\]]+)\]\s*$")
# "usuario        = svc_deploy". A chave tem de comecar a linha: sem essa
# ancora, `value="127.0.0.1"` dentro de uma tag HTML viraria par chave-valor.
PAR = re.compile(r"^\s*([A-Za-z_][\w.-]*)\s*=\s*(.+?)\s*$")

USUARIO = {"usuario", "user", "username", "login", "conta"}
SEGREDO = {"senha", "password", "passwd", "pass", "secret"}


def _parece_html(corpo: str) -> bool:
    """O documento se identifica como HTML pelo proprio comeco?

    Serve para quando NAO ha `Content-Type` -- o caso do `curl` sem `-i`. E
    sniffing, como o de um navegador: olha o inicio do documento, nao o
    conteudo. Texto que apenas CONTEM marcacao no meio nao passa, e nao deve
    passar: o corpo de uma injecao pode trazer um arquivo `.html` lido do
    servidor, e registrar as rotas dele poria no grafo caminho que nenhum
    servidor anunciou.
    """
    inicio = corpo.lstrip()[:120].lower()
    return inicio.startswith("<!doctype html") or inicio.startswith("<html")


class _LeitorDeHtml(html.parser.HTMLParser):
    """Tira do documento o titulo, os formularios e os links.

    **Com `html.parser` da biblioteca padrao, nao com expressao regular.**
    Atributo fora de ordem, aspas simples, maiuscula, atributo sem valor e tag
    nao fechada quebram expressao regular de formas que so aparecem no caso
    raro -- e pagina de alvo vulneravel raramente e bem formada. Nenhuma
    dependencia nova entra: `html.parser` ja vem com o Python (mesmo criterio
    de D32, que manteve o NetworkX fora).
    """

    # Campos que declaram parametro. `button` fica de fora: ele quase sempre
    # nomeia a acao, nao o dado.
    CAMPOS = ("input", "select", "textarea")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titulo: str | None = None
        self.rotas: list[Rota] = []
        self._no_titulo = False
        self._forma: Rota | None = None

    def handle_starttag(self, tag: str, atributos) -> None:
        d = {k.lower(): (v or "") for k, v in atributos}
        if tag == "title":
            self._no_titulo = True
        elif tag == "form":
            # `method` ausente e GET: e o padrao do HTML, nao palpite nosso.
            self._forma = Rota(caminho=d.get("action") or "/",
                               metodo=(d.get("method") or "GET").upper())
            self.rotas.append(self._forma)
        elif tag in self.CAMPOS and self._forma is not None:
            nome = d.get("name")
            # Campo sem `name` nao e enviado pelo navegador; nao e parametro.
            if nome and nome not in self._forma.parametros:
                self._forma.parametros.append(nome)
        elif tag == "a":
            destino = d.get("href", "")
            if destino.startswith("/") and not destino.startswith("//"):
                if not any(r.caminho == destino for r in self.rotas):
                    self.rotas.append(Rota(caminho=destino))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._no_titulo = False
        elif tag == "form":
            self._forma = None

    def handle_data(self, dados: str) -> None:
        if self._no_titulo and dados.strip() and self.titulo is None:
            self.titulo = dados.strip()


class Curl:
    nome = "curl"

    def obter(self, url: str) -> Execucao:
        """GET simples. `-i` porque o cabecalho e metade do fato.

        O fixture `03-curl-injecao-config.txt`, capturado no domingo 13, usou
        `curl -s` puro e por isso nao tem linha de status -- um 200 e um 500
        ficavam indistinguiveis para quem so ve o corpo. Dai a recaptura em
        `09-curl-com-cabecalhos.txt`.
        """
        return Execucao(comando=["curl", "-s", "-i", url])

    def consultar(self, url: str, parametros: dict[str, str]) -> Execucao:
        """GET com parametros codificados pelo proprio curl.

        `--data-urlencode` e nao concatenacao na URL: o valor vem do modelo, e
        um `&` ou um espaco nele mudariam a requisicao em vez de virarem dado.
        A ferramenta nao filtra o conteudo do parametro -- e por ali que o elo 1
        da cadeia passa, e `docs/hipotese.md` §E1 mede invencao de parametro,
        que um guarda aqui mascararia.
        """
        cmd = ["curl", "-s", "-i", "-G", url]
        for chave, valor in parametros.items():
            cmd += ["--data-urlencode", f"{chave}={valor}"]
        return Execucao(comando=cmd)

    def analisar(self, execucao: Execucao) -> RespostaHttp:
        if execucao.codigo is None:
            raise ValueError(
                "execucao ainda nao rodou: nao ha resposta para analisar")

        cabecalho, corpo = self._partir(execucao.saida)
        r = RespostaHttp(corpo=corpo)
        r.endereco, r.porta = self._destino(execucao.comando)
        for i, linha in enumerate(cabecalho.splitlines()):
            if i == 0:
                m = STATUS.match(linha)
                if m:
                    r.status = int(m.group(1))
                continue
            nome, _, valor = linha.partition(":")
            nome, valor = nome.strip().lower(), valor.strip()
            if nome == "content-type":
                # "text/html; charset=utf-8" -> "text/html". O charset e
                # transporte, nao fato sobre o alvo.
                r.tipo = valor.split(";")[0].strip() or None
            elif nome == "content-length" and valor.isdigit():
                r.tamanho = int(valor)

        r.credenciais = self._credenciais(corpo, r.endereco)
        if r.tipo == "text/html" or (r.tipo is None and _parece_html(corpo)):
            # So documento HTML vira rota. A saida da injecao do elo 2 volta
            # como `text/plain`, e le-la como marcacao produziria rota inventada
            # a partir de texto que nao e marcacao.
            leitor = _LeitorDeHtml()
            leitor.feed(corpo)
            leitor.close()
            r.titulo, r.rotas = leitor.titulo, leitor.rotas
        # D225. A ROTA RECEBE A PORTA AQUI, e a POSICAO e o conserto.
        #
        # ⚠️ **A minha primeira versao punha este laco junto do `_destino`, logo
        # que `r.porta` fica conhecida -- e `r.rotas` so e atribuido no fim, na
        # linha acima.** O laco corria sobre lista vazia e nao selava nada. A
        # suite passava: ela exercita `absorver_resposta` com `Rota` montada a
        # mao, que ja vem com porta. **Quem pegou foi provar contra o
        # laboratorio** -- a linha do prompt saiu sem `em 8080`.
        #
        # Mesma licao de D109 e D211: o teste media a forma que eu montei, e o
        # caminho de verdade e outro.
        #
        # A rota nasce no parser de HTML, que le `action` e nao sabe de porta
        # nenhuma; a porta vem da URL que NOS enviamos. `or` e nao atribuicao
        # direta: se um dia o parser aprender a ler a porta de um `action`
        # absoluto (`http://host:9000/x`), aquele valor e mais especifico.
        for _rota in r.rotas:
            _rota.porta = _rota.porta or r.porta
        return r

    def _partir(self, saida: str) -> tuple[str, str]:
        """Separa cabecalho de corpo -- **se houver cabecalho**.

        So e cabecalho quando a primeira linha e uma linha de status HTTP. Sem
        essa condicao, cortar no primeiro branco duplo trata saida comum como se
        fosse cabecalho: a saida do `ping` tem branco duplo no meio, e metade do
        corpo desaparecia.

        Isso acontece de verdade. Os involucros sempre poem `-i`, mas a instrucao
        manda o modelo escrever "a linha exata a executar", e em 18 de setembro
        ele escreveu `curl` sem `-i` -- que e o comando natural para quem quer so
        o corpo.
        """
        normalizada = saida.replace("\r\n", "\n")
        if not STATUS.match(normalizada):
            return "", normalizada
        cabecalho, marca, corpo = normalizada.partition("\n\n")
        if not marca:
            # Resposta so de cabecalho, sem corpo.
            return normalizada, ""
        return cabecalho, corpo

    def _destino(self, comando: list[str]) -> tuple[str | None, int | None]:
        for arg in comando:
            if arg.startswith(("http://", "https://")):
                p = urllib.parse.urlparse(arg)
                porta = p.port
                if porta is None:
                    porta = 443 if p.scheme == "https" else 80
                return p.hostname, porta
        return None, None

    def _credenciais(self, corpo: str, endereco: str | None) -> list[Credencial]:
        """Pares usuario/senha em formato ini, por secao.

        **Por secao, nao pelo arquivo inteiro.** Um `usuario` numa secao e uma
        `senha` em outra descrevem duas coisas diferentes; junta-los produziria
        uma credencial que nao existe em lugar nenhum -- exatamente o tipo de
        fato inventado que `ARTEFATO.md` §1.2 mantem fora do grafo.
        """
        achadas: list[Credencial] = []
        atual: dict[str, str] = {}

        def fechar() -> None:
            usuario = next((atual[k] for k in atual if k in USUARIO), None)
            segredo = next((atual[k] for k in atual if k in SEGREDO), None)
            # ⚠️ D244: nome que nao tem forma de nome nao e nome. Uma linha de
            # SCRIPT -- `user="$4"` -- casava com `PAR` e forjava credencial com
            # o segredo certo e o usuario errado. Custou um braco A inteiro
            # (§E100): o agente chutou `root` e queimou 72 dos 80 passos.
            if usuario and segredo and usuario_plausivel(usuario):
                achadas.append(Credencial(usuario=usuario, tipo="senha",
                                          segredo=segredo, endereco=endereco))

        for linha in corpo.splitlines():
            if SECAO.match(linha):
                fechar()
                atual = {}
                continue
            m = PAR.match(linha)
            if m:
                atual[m.group(1).strip().lower()] = m.group(2).strip()
        fechar()
        return achadas

    def resumir(self, comando: list[str]) -> str:
        """Forma curta para a secao de tentativas (D45).

        Fora as flags do involucro. **A URL fica inteira**, e com ela o caminho
        e o valor do parametro, que e onde mora a acao: duas injecoes diferentes
        no mesmo endereco precisam continuar distinguiveis para quem le, senao o
        agente deixaria de tentar uma carga que nunca tentou.

        **Por que a URL voltou inteira** (D64, revendo D45). Ate 18 de setembro
        o esquema e o host saiam daqui, porque o host aparecia depois da seta.
        So que o rotulo continuava com FORMA de linha de comando -- e uma forma
        que nao roda. Na `dmz-04` o agente emitiu **seis comandos que nao rodam**
        (passos 16, 17, 25, 26, 27 e 32 de 36), e o do passo 27 era o rotulo
        letra por letra:

            rotulo lido:      curl /diagnostico?destino=%3Bid
            comando emitido:  curl '/diagnostico?destino=%3Bcat%20/proc/mounts'

        A regra que fica: **rotulo com forma de comando tem de ser comando que
        roda**; abreviar o que se parece com codigo convida a copia. D65 aplicou
        a mesma regra ao `nmap` e mudou a seta -- ela agora so aparece quando o
        alvo tem identificador `hNN`, entao o host no rotulo nao a repete.

        **`-G` e `--data-urlencode` FICAM, e D64 errou ao tira-los** (D76). Sem
        as duas, a URL e a carga viram dois argumentos soltos e o `curl` le a
        carga como opcao:

            rotulo antigo:  curl http://.../diagnostico destino=127.0.0.1;id
            ao rodar:       curl: option -iname: expected a proper numerical parameter

        Na execucao autonoma de 21 de setembro o agente copiou essa forma **23
        vezes** -- 38% do orcamento de 60 passos, todas falhando. A hipotese de
        copia de rotulo, que D64 registrou como "plausivel e nao testada", ficou
        provada.

        O argumento de D45 -- "flag do involucro nao distingue uma acao de
        outra" -- **nao vale para flag sem a qual o comando nao roda**. `-s` e
        `-i` continuam saindo: sao cosmeticas, e o comando roda sem elas.
        """
        partes = []
        for arg in comando:
            # `-s` e `-i` saem: mudam o que o curl IMPRIME, nao o que ele pede.
            # `-G` e `--data-urlencode` ficam: sem elas a carga nao chega ao
            # servidor, e o rotulo deixa de ser comando.
            if arg in ("curl", "-s", "-i"):
                continue
            partes.append(arg)
        return "curl " + juntar(partes)
