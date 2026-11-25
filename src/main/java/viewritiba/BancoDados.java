package viewritiba;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

// Conexão com o MySQL do site (dados por variável de ambiente)
public class BancoDados {

    private final String url = variavel("VIEWRITIBA_DB_URL", "jdbc:mysql://127.0.0.1:3306/viewritiba");
    private final String usuario = variavel("VIEWRITIBA_DB_USER", "root");
    private final String senha = variavel("VIEWRITIBA_DB_PASSWORD", "");

    // Abre uma conexão somente leitura
    public Connection conectar() throws SQLException {
        Connection conexao = DriverManager.getConnection(url, usuario, senha);
        conexao.setReadOnly(true);
        return conexao;
    }

    // Lê uma variável de ambiente ou usa o valor padrão
    static String variavel(String nome, String padrao) {
        String valor = System.getenv(nome);
        return (valor == null || valor.isBlank()) ? padrao : valor;
    }
}
