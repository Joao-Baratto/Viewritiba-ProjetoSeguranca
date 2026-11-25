# Servidor de Autenticação do Viewritiba (Java + TLS)

Servidor Java que **recebe conexões** do site por TLS 1.2/1.3, **valida o login** (mesmas senhas
bcrypt do site) e **identifica o perfil** do usuário: participante, organizador ou moderador.
Todas as tentativas são registradas em log.

## Estrutura

| Arquivo | Função |
|---|---|
| `ServidorAutorizacao.java` | Abre o `SSLServerSocket` (porta 5000) e atende cada conexão em um pool de até 50 threads |
| `AtendimentoCliente.java` | Lê uma linha, valida, responde; trata timeout (10 s), entrada inválida, erro de conexão e banco fora do ar |
| `Autenticador.java` | Valida a senha com jBCrypt (`$2y$` do PHP vira `$2a$`), identifica o perfil, bloqueia a conta por 5 min após 5 erros e recusa conta suspensa |
| `Sessoes.java` | Gera um token aleatório de 256 bits (`SecureRandom`), válido por 30 min |
| `RegistroSeguranca.java` | Grava `logs/seguranca.log` (data, IP, usuário mascarado, evento, resultado; nunca a senha) |
| `BancoDados.java` | Conexão JDBC somente leitura com o MySQL do site (dados por variável de ambiente) |
| `Usuario.java` | Usuário autenticado: id, perfil e login |

## Protocolo (uma linha por conexão, campos separados por `;`)

```
LOGIN;perfil;login;senha   -> OK;token;perfil | NEGADO;CREDENCIAIS_INVALIDAS | NEGADO;BLOQUEADO | NEGADO;CONTA_SUSPENSA
LOGOUT;token               -> OK
(qualquer outra coisa)     -> ERRO;ENTRADA_INVALIDA
(banco fora do ar)         -> ERRO;SERVIDOR_INDISPONIVEL
```

- `perfil`: `participante`, `organizador` ou `moderador`. Qualquer outro valor é recusado.
- `login`: e-mail ou CPF/CNPJ (participante e organizador) ou o usuário do moderador.
- Participante e organizador são conferidos nas tabelas `participante` e `organizador`; o moderador,
  nas variáveis `VIEWRITIBA_MODERATOR_USER` e `VIEWRITIBA_MODERATOR_PASSWORD_HASH`, como no site.

## Como executar (nó servidor)

1. Compilar (Java 17+ e Maven):
   ```
   mvn compile dependency:copy-dependencies -DoutputDirectory=libs
   ```
2. Gerar o certificado (troque o IP pelo do nó servidor) e exportar a parte pública para o site:
   ```
   keytool -genkeypair -alias viewritiba -keyalg RSA -keysize 2048 -validity 365 \
     -dname "CN=servidor-viewritiba" -ext SAN=ip:192.168.56.20 \
     -keystore servidor.p12 -storetype PKCS12 -storepass SENHA_FORTE
   keytool -exportcert -rfc -alias viewritiba -keystore servidor.p12 -storepass SENHA_FORTE -file servidor.crt
   ```
3. Variáveis de ambiente (não colocar senhas no código):
   ```
   export VIEWRITIBA_DB_URL="jdbc:mysql://IP_DO_MYSQL:3306/viewritiba"
   export VIEWRITIBA_DB_USER="usuario"
   export VIEWRITIBA_DB_PASSWORD="senha"
   export VIEWRITIBA_MODERATOR_USER="moderador"
   export VIEWRITIBA_MODERATOR_PASSWORD_HASH='$2y$10$...'   # o mesmo hash usado no site
   export VIEWRITIBA_KEYSTORE="servidor.p12"
   export VIEWRITIBA_KEYSTORE_PASSWORD="SENHA_FORTE"
   ```
   No Windows (PowerShell), use `$env:NOME="valor"`.
4. Iniciar (o certificado vem das variáveis acima, e não de `-Djavax.net.ssl.keyStore`, que também
   afetaria a conexão com o MySQL e a quebraria):
   ```
   java -cp "target/classes:libs/*" viewritiba.ServidorAutorizacao 5000
   ```
   No Windows, troque `:` por `;` no `-cp`.

## Como testar (do nó cliente)

```
echo "LOGIN;moderador;moderador;SENHA" | openssl s_client -quiet -connect 192.168.56.20:5000 -CAfile servidor.crt
```

| Teste | Resultado esperado |
|---|---|
| Login correto (moderador, participante, organizador) | `OK;token;perfil` |
| Senha errada | `NEGADO;CREDENCIAIS_INVALIDAS` |
| 5 senhas erradas (por e-mail ou CPF) | `NEGADO;BLOQUEADO`, e a senha certa também fica bloqueada por 5 min |
| Conta suspensa | `NEGADO;CONTA_SUSPENSA` |
| Perfil inexistente / comando inválido | `ERRO;ENTRADA_INVALIDA` |
| Banco fora do ar | `ERRO;SERVIDOR_INDISPONIVEL` |
| Cliente sem TLS (ex.: `nc`) | Conexão encerrada, `ERRO_CONEXAO` no log |
| Cliente conecta e não envia nada | Desconectado em 10 s, `TIMEOUT` no log |
