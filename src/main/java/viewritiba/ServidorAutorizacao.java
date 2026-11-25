package viewritiba;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

// Servidor de autenticação: recebe conexões TLS do site
public class ServidorAutorizacao {

    private static final int MAX_CONEXOES_SIMULTANEAS = 50;

    // Carrega o certificado (keystore) e prepara o TLS
    private static SSLServerSocketFactory fabricaTls() throws Exception {
        String caminho = BancoDados.variavel("VIEWRITIBA_KEYSTORE", "servidor.p12");
        char[] senha = BancoDados.variavel("VIEWRITIBA_KEYSTORE_PASSWORD", "").toCharArray();

        KeyStore chaves = KeyStore.getInstance("PKCS12");
        try (InputStream arquivo = new FileInputStream(caminho)) {
            chaves.load(arquivo, senha);
        }
        KeyManagerFactory gerenciador = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        gerenciador.init(chaves, senha);

        SSLContext contexto = SSLContext.getInstance("TLS");
        contexto.init(gerenciador.getKeyManagers(), null, null);
        return contexto.getServerSocketFactory();
    }

    // Inicia o servidor na porta informada (padrão 5000)
    public static void main(String[] args) throws Exception {
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : 5000;

        SSLServerSocketFactory fabrica = fabricaTls();
        try (SSLServerSocket servidor = (SSLServerSocket) fabrica.createServerSocket(porta)) {
            // Aceita apenas TLS 1.2 e 1.3
            servidor.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});

            BancoDados banco = new BancoDados();
            Autenticador autenticador = new Autenticador(banco);
            Sessoes sessoes = new Sessoes();

            // Limita o número de conexões atendidas ao mesmo tempo
            ExecutorService atendentes = Executors.newFixedThreadPool(MAX_CONEXOES_SIMULTANEAS);

            // Remove sessões expiradas a cada minuto
            ScheduledExecutorService limpeza = Executors.newSingleThreadScheduledExecutor();
            limpeza.scheduleAtFixedRate(sessoes::limparExpiradas, 1, 1, TimeUnit.MINUTES);

            RegistroSeguranca.registrar("-", "-", "SERVIDOR_INICIADO", "porta " + porta);

            // Aguarda conexões e atende cada uma em uma thread
            while (true) {
                try {
                    Socket cliente = servidor.accept();
                    atendentes.execute(new AtendimentoCliente(cliente, autenticador, sessoes));
                } catch (IOException erro) {
                    RegistroSeguranca.registrar("-", "-", "ERRO_ACEITE", erro.getClass().getSimpleName());
                }
            }
        }
    }
}
