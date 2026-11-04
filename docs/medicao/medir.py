"""Mede um motor de linguagem sob o prompt de inventario do grafo.

Uma execucao roda uma ou mais CELULAS. Uma celula e um par
(variante de entrada, regime de raciocinio), repetido n vezes. As repeticoes
de celulas diferentes saem intercaladas em rodizio, nunca em blocos: se a
carga do servidor variar ao longo da execucao, ela se distribui por todas as
celulas em vez de entrar disfarcada de efeito de uma delas.

Uso tipico:

    # matriz de entrada x regime, o desenho completo
    python medir.py --motor claude-cli --modelo claude-sonnet-5 --matriz --repeticoes 5
    python medir.py --motor gemini --modelo gemini-3.6-flash --matriz --repeticoes 5 --pausa 5
    python medir.py --motor nvidia --modelo moonshotai/kimi-k3 --matriz --repeticoes 4 --pausa 25

    # uma celula so
    python medir.py --motor gemini --entrada completa --regime raciocinio --repeticoes 25

    # rejulga a ancoragem de um resultado ja gravado, sem chamar o motor
    python medir.py --reanalisar resultados/gemini-matriz.json

A chave de cada motor sai de uma variavel de ambiente -- `NVIDIA_API_KEY`,
`GEMINI_API_KEY` -- e o `claude-cli` usa a autenticacao da propria assinatura.
Nenhuma chave e passada por argumento nem entra na URL.

Sem retentativa, em nenhum modo. A retentativa e correta para medir latencia e
errada para medir taxa de recusa, porque mascara exatamente o que se quer
contar; como esta execucao mede as duas coisas ao mesmo tempo, a retentativa
sai e a recusa entra como dado.

Grava incrementalmente: um limite de uso no meio da execucao nao leva junto o
que ja foi coletado. Rodar `testes.py` antes de confiar em qualquer numero
daqui -- ele custa zero chamada e pega a classe de defeito que ja passou por
duas revisoes sem ser vista.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import secrets
import sys
import time
from datetime import datetime, timezone

import motores as M


def celulas_de(args) -> list[tuple[str, str]]:
    if args.matriz:
        return [(e, r) for e in ("completa", "minima", "sem-comando")
                for r in ("sem-raciocinio", "raciocinio")]
    return [(args.entrada, args.regime)]


def gravar(destino: pathlib.Path, cabecalho: dict,
           registros: list[M.Resultado], abortou: str | None) -> None:
    por_celula: dict[str, list[M.Resultado]] = {}
    for r in registros:
        por_celula.setdefault(f"{r.entrada}/{r.regime}", []).append(r)

    relatorio = dict(cabecalho)
    relatorio["abortou"] = abortou
    relatorio["total_de_chamadas"] = len(registros)
    relatorio["celulas"] = {k: M.resumir(v) for k, v in por_celula.items()}
    relatorio["geral"] = M.resumir(registros)
    # Todas as respostas, nao so a primeira aceita de cada celula. Guardar so
    # uma foi o que reduziu a observacao de 9 de setembro sobre parametro
    # inventado a indicio de sete respostas, quando podia ter sido taxa.
    relatorio["registros"] = [M.como_dicionario(r) for r in registros]

    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(relatorio, ensure_ascii=False, indent=2),
                       encoding="utf-8")


def reanalisar(caminho: pathlib.Path) -> None:
    """Recalcula a ancoragem de um resultado ja gravado, sem chamar o motor.

    A regra de ancoragem e uma decisao de analise, nao de coleta: quando ela
    muda -- e ela mudou uma vez, ao passar a aceitar `~/` como equivalente ao
    diretorio de lar informado no prompt -- os dados anteriores precisam ser
    julgados pela regra nova, ou o relatorio compara medicoes feitas com
    reguas diferentes. Como cada registro guarda a acao, a variante e o passo,
    o prompt exato daquela chamada e reconstruivel e nada precisa ser
    remedido.
    """
    d = json.loads(caminho.read_text(encoding="utf-8"))
    textos: dict[str, str] = {}
    mudou = recategorizadas = 0

    # Categorias decididas pelo TRANSPORTE, nao pelo modelo. Rejulga-las a
    # partir do texto seria errado: o corpo de um 404 nao e uma resposta.
    DO_TRANSPORTE = ("limite_de_uso", "throttle", "erro_de_rede")

    for reg in d["registros"]:
        entrada = reg.get("entrada")
        if entrada not in textos:
            textos[entrada] = M.derivar(entrada)
        prompt = M.montar_prompt(reg["passo"], textos[entrada])

        antes = (reg.get("ancoragem") or {}).get("ancorada")
        reg["ancoragem"] = M.conferir_ancoragem(reg.get("acao"), prompt)
        if antes != reg["ancoragem"].get("ancorada"):
            mudou += 1

        # A categoria tambem e decisao de analise, e a regra ja mudou uma vez:
        # os padroes de recusa nao casavam com portugues acentuado, e uma
        # recusa real do Gemini ("Desculpe, nao posso cumprir...") caiu em
        # `formato_invalido` em 10 de setembro de 2026. Sem rejulgar, o
        # relatorio compararia motores medidos com reguas diferentes.
        cat = reg.get("categoria", "")
        if cat not in DO_TRANSPORTE and not cat.startswith("erro_http"):
            nova = M.classificar(reg.get("texto", ""), reg.get("acao"), False)
            if nova != cat:
                reg["categoria"] = nova
                recategorizadas += 1

    # Refaz os resumos a partir dos registros julgados de novo.
    regs = [M.Resultado(**{k: v for k, v in r.items()
                           if k in M.Resultado.__dataclass_fields__})
            for r in d["registros"]]
    por_celula: dict[str, list[M.Resultado]] = {}
    for r in regs:
        por_celula.setdefault(f"{r.entrada}/{r.regime}", []).append(r)
    d["celulas"] = {k: M.resumir(v) for k, v in por_celula.items()}
    d["geral"] = M.resumir(regs)
    d["reanalisado_em"] = datetime.now(timezone.utc).astimezone().isoformat()

    caminho.write_text(json.dumps(d, ensure_ascii=False, indent=2),
                       encoding="utf-8")
    print(f"{caminho.name}: {len(regs)} registros, {mudou} veredito(s) de "
          f"ancoragem e {recategorizadas} categoria(s) mudaram",
          file=sys.stderr)
    print(json.dumps({"geral": d["geral"]}, ensure_ascii=False, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reanalisar", default=None, metavar="ARQUIVO",
                    help="rejulga a ancoragem de um resultado ja gravado, sem "
                         "chamar o motor. Dispensa --motor")
    ap.add_argument("--motor",
                    choices=["claude-cli", "anthropic", "gemini", "nvidia"])
    ap.add_argument("--modelo", default=None,
                    help="identificador do modelo; obrigatorio no motor 'api' "
                         "de terceiro para que o relatorio saiba o que mediu")
    ap.add_argument("--regime", choices=["sem-raciocinio", "raciocinio"],
                    default="sem-raciocinio",
                    help="regime de raciocinio, sempre explicito (CONTEXTO.md §9)")
    ap.add_argument("--entrada", choices=list(M.TRANSFORMACOES),
                    default="completa")
    ap.add_argument("--matriz", action="store_true",
                    help="roda as 6 celulas de entrada x regime")
    ap.add_argument("--repeticoes", type=int, default=10,
                    help="repeticoes POR CELULA")
    ap.add_argument("--pausa", type=float, default=0.0,
                    help="segundos de espera entre chamadas. Evita provocar o "
                         "throttle do provedor, que custa muito mais tempo "
                         "depois do que a pausa custa antes")
    ap.add_argument("--saida", default=None)
    # QUAL texto canonico medir. Existe desde 22 de setembro de 2026 (D84), para
    # que a revisao do prompt seja medida CONTRA a versao anterior na mesma
    # sessao, com o mesmo motor. Sem isso, um numero diferente teria duas
    # explicacoes possiveis -- a nossa mudanca ou deriva do provedor -- e nao
    # haveria como separa-las: o Gemini foi medido em 10 de setembro.
    ap.add_argument("--prompt", default=None, metavar="ARQUIVO",
                    help="texto canonico alternativo; o padrao e "
                         "prompt-teste.txt")
    args = ap.parse_args()

    if args.prompt:
        escolhido = pathlib.Path(args.prompt)
        if not escolhido.is_absolute():
            escolhido = M.AQUI / escolhido
        if not escolhido.exists():
            raise SystemExit(f"prompt nao encontrado: {escolhido}")
        M.PROMPT = escolhido

    if args.reanalisar:
        reanalisar(pathlib.Path(args.reanalisar))
        return
    if not args.motor:
        raise SystemExit("--motor e obrigatorio (ou use --reanalisar ARQUIVO)")

    if args.repeticoes < 1:
        raise SystemExit(f"--repeticoes precisa ser >= 1 (recebido {args.repeticoes})")

    M.gravar_variantes()
    celulas = celulas_de(args)
    textos = {e: M.derivar(e) for e, _ in celulas}
    instancias = {(e, r): M.criar_motor(args.motor, args.modelo, r)
                  for e, r in celulas}

    rotulo = "matriz" if args.matriz else f"{args.entrada}-{args.regime}"
    destino = pathlib.Path(args.saida or
                           M.RESULTADOS / f"{args.motor}-{rotulo}.json")

    base = secrets.randbelow(60)
    # Uma identificacao por celula, nao uma so: numa matriz as celulas diferem
    # justamente no regime de raciocinio, e um cabecalho com o regime da
    # primeira celula afirmaria da execucao inteira o que vale para um sexto
    # dela. O regime real de cada chamada tambem fica em cada registro.
    identificacao = {f"{e}/{r}": instancias[(e, r)].identificacao()
                     for e, r in celulas}
    cabecalho = {
        "data": datetime.now(timezone.utc).astimezone().isoformat(),
        "motor": args.motor,
        "modelo_solicitado": args.modelo,
        "identificacao": identificacao,
        "maquina": "Dell G15 5530, i5-13450HX, 16 GB RAM, RTX 3050 6 GB VRAM",
        # O ARQUIVO e o HASH, nao so o tamanho. Duas revisoes do prompt podem
        # ter o mesmo numero de caracteres, e ai o relatorio nao diria qual das
        # duas foi medida -- que e exatamente a pergunta que D84 precisa
        # responder ao comparar a revisao com a versao anterior.
        "prompt_canonico": M.PROMPT.name,
        "prompt_canonico_sha256": hashlib.sha256(
            M.PROMPT.read_bytes()).hexdigest(),
        "prompt_canonico_caracteres": len(M.texto_canonico()),
        "celulas_planejadas": [f"{e}/{r}" for e, r in celulas],
        "repeticoes_por_celula": args.repeticoes,
        "deslocamento_de_passo": base,
        "sem_retentativa": True,
        "limite_de_uso_excluido_do_denominador": True,
    }

    registros: list[M.Resultado] = []
    abortou = None
    total = len(celulas) * args.repeticoes
    feitas = 0

    # Rodizio: repeticao i de TODAS as celulas antes da repeticao i+1.
    for i in range(1, args.repeticoes + 1):
        for entrada, regime in celulas:
            feitas += 1
            passo = M.calcular_passo(feitas, base)
            prompt = M.montar_prompt(passo, textos[entrada])
            r = instancias[(entrada, regime)].chamar(prompt)
            r.entrada, r.regime, r.passo = entrada, regime, passo
            r.ancoragem = M.conferir_ancoragem(r.acao, prompt)
            registros.append(r)

            marca = "ok" if r.aceita else r.categoria.upper()
            anc = ""
            if r.ancoragem.get("aplicavel") and not r.ancoragem["ancorada"]:
                anc = f"  inventado={','.join(r.ancoragem['inventados'])[:60]}"
            thr = f"  ({r.throttles} throttle, +{r.espera_throttle_s:.0f}s)" \
                  if r.throttles else ""
            print(f"  {feitas:3d}/{total}  {entrada:11s} {regime:14s} "
                  f"{r.wall_s:6.2f}s  {marca}{thr}{anc}",
                  file=sys.stderr, flush=True)

            gravar(destino, cabecalho, registros, abortou)

            if r.categoria == "limite_de_uso":
                # Continuar depois do limite so gera registro que nao mede
                # nada. Aborta e mantem o que ja foi coletado.
                abortou = f"limite de uso na chamada {feitas}"
                print(f"  LIMITE DE USO -- abortando com {len(registros)} "
                      f"chamadas coletadas", file=sys.stderr)
                gravar(destino, cabecalho, registros, abortou)
                _fechar(destino, registros)
                return

            if args.pausa and feitas < total:
                time.sleep(args.pausa)

    gravar(destino, cabecalho, registros, abortou)
    _fechar(destino, registros)


def _fechar(destino: pathlib.Path, registros: list[M.Resultado]) -> None:
    dados = json.loads(destino.read_text(encoding="utf-8"))
    print(json.dumps({"geral": dados["geral"], "celulas": dados["celulas"]},
                     ensure_ascii=False, indent=2))
    print(f"\ngravado em {destino}", file=sys.stderr)


if __name__ == "__main__":
    main()
