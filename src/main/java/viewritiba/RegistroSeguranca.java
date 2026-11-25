package viewritiba;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

// Log de segurança em logs/seguranca.log
public final class RegistroSeguranca {

    private static final Path ARQUIVO = Path.of("logs", "seguranca.log");
    private static final DateTimeFormatter FORMATO = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    private RegistroSeguranca() { }

    // Remove quebras de linha e o separador para evitar log falso
    private static String limpar(String texto) {
        String semControle = texto.replaceAll("[\\p{Cntrl}|]", "_");
        return semControle.length() > 100 ? semControle.substring(0, 100) : semControle;
    }

    // Mascara e-mail/CPF no log (LGPD)
    public static String mascarar(String login) {
        int arroba = login.indexOf('@');
        String inicio = login.substring(0, Math.min(2, arroba > 0 ? arroba : login.length()));
        return inicio + "***" + (arroba > 0 ? login.substring(arroba) : "");
    }

    // Grava uma linha: data | IP | usuário | evento | resultado
    public static synchronized void registrar(String ip, String usuario, String evento, String detalhe) {
        String linha = String.join(" | ", LocalDateTime.now().format(FORMATO), ip,
                limpar(usuario), limpar(evento), limpar(detalhe));
        System.out.println(linha);
        try {
            Files.createDirectories(ARQUIVO.getParent());
            try (PrintWriter saida = new PrintWriter(new FileWriter(ARQUIVO.toFile(), true))) {
                saida.println(linha);
            }
        } catch (IOException erro) {
            System.err.println("Falha ao gravar o log de seguranca: " + erro.getMessage());
        }
    }
}
