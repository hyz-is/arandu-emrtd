<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu eMRTD

Examina no servidor os dados que um chip eMRTD (ICAO Doc 9303) entregou a um
dispositivo e responde com evidência. Não decide nada.

Foi feito para o KUAA: o passaporte brasileiro (modelo 2023) tem chip ICAO, e a
leitura do chip acontece num app nativo ou SDK no dispositivo, porque o
navegador não lê eMRTD (o Web NFC só fala NDEF). O dispositivo executa BAC ou
PACE, lê EF.COM, EF.SOD e os data groups, repassa a resposta da Active
Authentication e o que observou da Chip Authentication. Este pacote recebe
esses bytes e verifica o que um servidor consegue verificar. A CIN atual não
tem chip (o Decreto 10.977/2022 revogou a exigência do Decreto 9.278/2018);
se uma versão com chip ICAO aparecer, o mesmo caminho serve, e o layout TD1 da
MRZ já é lido.

O que ele tem:

- **Passive Authentication** — o hash de cada data group recebido contra o
  SOD; a assinatura CMS do SOD sobre os atributos assinados, com a chave do
  Document Signer; a cadeia Document Signer → CSCA contra o trust store que a
  aplicação configurou; a validade dos dois certificados; o signing time dentro
  da validade do Document Signer; a revogação pelas CRLs da CSCA cuja
  assinatura confere.
- **Parsers** limitados e tolerantes para EF.COM, EF.SOD, DG1 (MRZ TD1, TD2 e
  TD3, com todos os dígitos verificadores), DG2 (a imagem da face, JPEG ou
  JPEG 2000), DG14, DG15, EF.CardAccess (PACEInfo), certificados X.509 de
  qualquer curva e master lists de CSCA. Nenhum entra em pânico com entrada
  hostil: os testes de fuzz seguram isso.
- **Active Authentication** — `NewChallenge` gera o desafio de 8 bytes do
  servidor; `ExamineActiveAuthentication` confere a assinatura do chip com a
  chave do DG15: ISO/IEC 9796-2 (esquema 1, recuperação parcial) para RSA,
  ECDSA plain (BSI TR-03111) para EC.
- **Chip Authentication** — o protocolo roda no dispositivo; o servidor confere
  que o relato do dispositivo é coerente com um DG14 autenticado, e o
  resultado diz que é só isso (`device_asserted_only`).
- **MRZ** — os dígitos verificadores do DG1 e a comparação campo a campo com a
  MRZ da página impressa (`CompareMRZ`).
- **Module** — um `foundation.Module` sem rota, sem tabela, sem arquivo e sem
  rede. Só biblioteca padrão do Go e o framework; compila com
  `CGO_ENABLED=0`.

## O que ele não é

- **Não é uma decisão.** Cada check é um `Outcome` — `passed`, `failed`,
  `not_present` ou `unverifiable` — com `Reason` e `Detail`. O `Report` não tem
  campo que diga "documento autêntico", não tem booleano, e nenhum check vale
  pelos outros. Quem decide é o KUAA, com as regras dele.
  `tests/Unit/decision_test.go` recusa os nomes que decidem e procura
  booleanos no `Report`.
- **Não é leitor de chip.** BAC, PACE, Chip Authentication e secure messaging
  acontecem no dispositivo.
- **Não é Brainpool.** A biblioteca padrão do Go não implementa as curvas
  Brainpool, que muitas CSCAs e chips usam. Uma assinatura numa dessas curvas
  sai `unverifiable` com `unsupported_curve` — nunca `passed`. O certificado
  é lido, nomeado e posto na cadeia mesmo assim.
- **Não decodifica JPEG 2000.** A imagem do DG2 volta como bytes, com o
  formato informado (`jpeg2000_not_decoded`).
- **Não busca nada.** Nenhuma CSCA, master list ou CRL é baixada aqui; a
  aplicação entrega os bytes em que escolheu confiar.

## Requisitos

| | |
| --- | --- |
| Go | 1.26 ou posterior (`go.mod` declara o mínimo) |
| cgo | não usa; compila com `CGO_ENABLED=0` |
| Arandu | framework 0.56 ou posterior |
| Dependências | biblioteca padrão e `github.com/arandu-io/framework`. Nada mais: o `github.com/gmrtd/gmrtd` foi descartado porque a dependência dele `osanderson/brainpool` não tem arquivo de licença |

## Instalação

O nome público ainda não foi confirmado; o caminho `github.com/hyz-is/arandu-emrtd`
é provisório e o módulo não está publicado.

```bash
go get github.com/hyz-is/arandu-emrtd@v0.1.0
```

## Ligação, em `bootstrap/app.go`

Toda a ligação fica em `bootstrap/app.go`, à mão. Não há service provider,
container nem descoberta.

```go
import (
	emrtd "github.com/hyz-is/arandu-emrtd"
)
```

Em `Build`, antes de `k.Register`, com os bytes que a aplicação carregou de
onde guarda arquivos (no KUAA, um bucket privado do Cloudflare R2):

```go
	emrtdModule, err := emrtd.New(emrtd.Config{
		CSCACertificates:  cscaDERs,         // CSCAs fixadas pela aplicação
		MasterLists:       masterListDERs,   // arquivos .ml
		MasterListAnchors: anchorDERs,       // CSCAs que emitem os signers das listas
		CRLs:              crlDERs,
	})
	if err != nil {
		return App{}, err
	}
	k.Register(emrtdModule)
```

`New` recusa um certificado que não se lê, uma master list cuja assinatura
falha e, com âncoras, uma lista cujo signer nenhuma âncora emitiu. Uma lista
assinada em Brainpool não pode ser conferida aqui: só entra com o SHA-256
dela em `PinnedMasterListSHA256`.

## Uso, num controller da aplicação

```go
	// Ao abrir a sessão de leitura: o desafio fica guardado com a sessão.
	challenge, err := emrtd.NewChallenge()

	// Quando o dispositivo devolve a leitura:
	report := emrtdModule.Examine(emrtd.Input{
		COM:        files.COM,
		SOD:        files.SOD,
		DataGroups: map[int][]byte{1: files.DG1, 2: files.DG2, 14: files.DG14, 15: files.DG15},
		CardAccess: files.CardAccess,
		PrintedMRZ: ocrMRZ,
		ActiveAuthentication: &emrtd.ActiveAuthenticationResponse{
			Challenge: challengeDaSessao, // a cópia do servidor, nunca a ecoada pelo dispositivo
			Signature: files.AAResponse,
		},
	}, emrtd.Options{})

	if report.Outcome(emrtd.CheckSODSignature, emrtd.FileSOD) == emrtd.OutcomePassed { /* ... */ }
```

Os arquivos são os bytes de cada EF exatamente como lidos, com tag e tamanho:
o SOD guarda o hash do data group inteiro. O desafio vale para uma resposta,
uma vez; guardá-lo e expirá-lo é da aplicação.

## O que cada check prova, e o que não prova

| Check | `passed` prova | Não prova |
| --- | --- | --- |
| `data_group_hash` | o arquivo recebido tem o hash que o SOD traz para ele | nada sem `sod_signature` e `document_signer_chain` aprovados |
| `sod_signature` | o Document Signer do SOD assinou estes hashes | que o Document Signer é confiável |
| `document_signer_chain` | uma CSCA do trust store emitiu o Document Signer | que o trust store é o certo — isso é escolha da aplicação |
| `document_signer_validity`, `csca_validity`, `signing_time` | as datas batem com o momento da avaliação e da assinatura | que o relógio do emissor estava certo |
| `document_signer_revocation` | nenhuma CRL verificada da CSCA revoga o Document Signer | revogação publicada depois da CRL recebida (`crl_stale` avisa) |
| `com_consistency` | EF.COM e SOD listam os mesmos data groups | nada: EF.COM não é assinado |
| `mrz_check_digits` | os dígitos do DG1 conferem | que o DG1 é autêntico (veja o hash do DG1) |
| `mrz_printed_comparison` | a MRZ impressa lida é igual à do chip | que o OCR leu certo — um erro de leitura aparece como diferença |
| `active_authentication` | o chip tem a chave privada do DG15 autenticado, agora (desafio novo) | nada se o DG15 não passou no hash: aí sai `key_not_authenticated` |
| `chip_authentication_claim` | o relato do dispositivo bate com o DG14 autenticado | que o protocolo aconteceu: o servidor não o vê (`device_asserted_only`) |

Passive Authentication sozinha não impede clonagem: um chip copiado traz o
mesmo SOD. É a Active Authentication (ou a Chip Authentication, no
dispositivo) que liga a leitura ao chip físico.

## Dados pessoais

MRZ, foto do DG2 e chaves são dados pessoais, e a foto é biométrica. O
`Report` serializado em JSON deixa de fora os bytes da imagem e das chaves;
os `Detail` nunca repetem nome, número de documento ou data de nascimento.
Guardar, cifrar e auditar o resto é da aplicação. Os testes usam apenas dados
sintéticos gerados no próprio teste, do estado fictício Utopia.

## Testes

```bash
export GOWORK=off
go test -race -count=1 ./...
go test ./tests/Feature -run '^$' -fuzz '^FuzzExamine$' -fuzztime 30s
```

## Licença

MIT. Veja [LICENSE.md](LICENSE.md).
