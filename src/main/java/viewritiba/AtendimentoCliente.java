package viewritiba;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

// Atende uma conexão: lê um comando e devolve a resposta
public class AtendimentoCliente implements Runnable {

    private static final int TIMEOUT_MS = 10_000;
    private static final int TAMANHO_MAXIMO = 1024;

    private final Socket cliente;
    private final Autenticador autenticador;
    private final Sessoes sessoes;
    private final String ip;

    public AtendimentoCliente(Socket cliente, Autenticador autenticador, Sessoes sessoes) {
        this.cliente = cliente;
        this.autenticador = autenticador;
        this.sessoes = sessoes;
        this.ip = cliente.getInetAddress().getHostAddress();
    }

    @Override
    // Lê a linha enviada pelo cliente e responde
    public void run() {
        try (cliente;
             BufferedReader entrada = new BufferedReader(new InputStreamReader(cliente.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true, StandardCharsets.UTF_8)) {

            cliente.setSoTimeout(TIMEOUT_MS);
            String linha = entrada.readLine();
            saida.println(processar(linha));

        // Trata timeout, falha de conexão/TLS e erros inesperados
        } catch (SocketTimeoutException erro) {
            RegistroSeguranca.registrar(ip, "-", "TIMEOUT", "cliente nao enviou dados");
        } catch (IOException erro) {
            RegistroSeguranca.registrar(ip, "-", "ERRO_CONEXAO", erro.getClass().getSimpleName());
        } catch (RuntimeException erro) {
            RegistroSeguranca.registrar(ip, "-", "ERRO_INTERNO", erro.getClass().getSimpleName());
        }
    }

    // Valida a entrada e direciona para LOGIN ou LOGOUT
    String processar(String linha) {
        if (linha == null || linha.isBlank() || linha.length() > TAMANHO_MAXIMO) {
            RegistroSeguranca.registrar(ip, "-", "ENTRADA_INVALIDA", "linha vazia ou grande demais");
            return "ERRO;ENTRADA_INVALIDA";
        }
        String[] partes = linha.split(";", -1);
        try {
            return switch (partes[0]) {
                case "LOGIN" -> login(linha);
                case "LOGOUT" -> logout(partes);
                default -> throw new IllegalArgumentException("comando desconhecido");
            };
        } catch (IllegalArgumentException erro) {
            RegistroSeguranca.registrar(ip, "-", "ENTRADA_INVALIDA", partes[0]);
            return "ERRO;ENTRADA_INVALIDA";
        } catch (SQLException erro) {
            RegistroSeguranca.registrar(ip, "-", "ERRO_BANCO", erro.getClass().getSimpleName());
            return "ERRO;SERVIDOR_INDISPONIVEL";
        }
    }

    // LOGIN;perfil;login;senha -> valida o login e identifica o perfil
    private String login(String linha) throws SQLException {
        String[] p = linha.split(";", 4);
        if (p.length != 4 || p[2].isBlank() || p[3].isEmpty()) {
            throw new IllegalArgumentException("login incompleto");
        }
        String tipo = p[1], login = p[2], senha = p[3];
        String quem = tipo + ":" + RegistroSeguranca.mascarar(login);
        try {
            Usuario usuario = autenticador.autenticar(tipo, login, senha);
            String token = sessoes.criar(usuario);
            RegistroSeguranca.registrar(ip, quem + " #" + usuario.id(), "LOGIN", "PERMITIDO");
            return "OK;" + token + ";" + usuario.tipo();
        } catch (SecurityException negado) {
            RegistroSeguranca.registrar(ip, quem, "LOGIN", "NEGADO " + negado.getMessage());
            return "NEGADO;" + negado.getMessage();
        }
    }

    // LOGOUT;token -> encerra a sessão
    private String logout(String[] p) {
        if (p.length != 2) {
            throw new IllegalArgumentException("logout incompleto");
        }
        sessoes.encerrar(p[1]);
        RegistroSeguranca.registrar(ip, "-", "LOGOUT", "OK");
        return "OK";
    }
}
