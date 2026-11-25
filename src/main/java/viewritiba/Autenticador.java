package viewritiba;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.mindrot.jbcrypt.BCrypt;

// Valida login e senha e identifica o perfil do usuário
public class Autenticador {

    // Bloqueio após 5 tentativas erradas, por 5 minutos
    private static final int MAX_FALHAS = 5;
    private static final long BLOQUEIO_MS = 5 * 60 * 1000;

    // Hash usado quando o login não existe (mesmo tempo de resposta)
    private static final String HASH_FICTICIO = BCrypt.hashpw("senha-ficticia", BCrypt.gensalt(10));

    private final BancoDados banco;
    private final Map<String, Integer> falhas = new ConcurrentHashMap<>();
    private final Map<String, Long> bloqueadoAte = new ConcurrentHashMap<>();

    public Autenticador(BancoDados banco) {
        this.banco = banco;
    }

    // Fluxo principal do login
    public Usuario autenticar(String tipo, String login, String senha) throws SQLException {
        if (!tipo.equals("participante") && !tipo.equals("organizador") && !tipo.equals("moderador")) {
            throw new IllegalArgumentException("tipo invalido");
        }
        String chave = chaveDaConta(tipo, login);

        // Conta bloqueada?
        Long ate = bloqueadoAte.get(chave);
        if (ate != null && ate > System.currentTimeMillis()) {
            throw new SecurityException("BLOQUEADO");
        }

        // Confere a senha de acordo com o perfil
        Usuario usuario = switch (tipo) {
            case "participante", "organizador" -> buscarNoBanco(tipo, login, senha);
            default -> verificarModerador(login, senha);
        };

        // Senha errada: conta a falha e bloqueia na 5ª
        if (usuario == null) {
            int total = falhas.merge(chave, 1, Integer::sum);
            if (total >= MAX_FALHAS) {
                bloqueadoAte.put(chave, System.currentTimeMillis() + BLOQUEIO_MS);
                falhas.remove(chave);
                throw new SecurityException("BLOQUEADO");
            }
            throw new SecurityException("CREDENCIAIS_INVALIDAS");
        }

        // Conta suspensa pela moderação
        if (!"moderador".equals(tipo) && estaBanido(usuario)) {
            throw new SecurityException("CONTA_SUSPENSA");
        }

        falhas.remove(chave);
        bloqueadoAte.remove(chave);
        return usuario;
    }

    // Identifica a conta para contar as falhas (e-mail e CPF contam juntos)
    private String chaveDaConta(String tipo, String login) throws SQLException {
        if (!"moderador".equals(tipo)) {
            String sql = "SELECT id FROM " + tipo + " WHERE email = ? OR documento = ? LIMIT 1";
            try (Connection c = banco.conectar(); PreparedStatement st = c.prepareStatement(sql)) {
                st.setString(1, login);
                st.setString(2, login);
                try (ResultSet rs = st.executeQuery()) {
                    if (rs.next()) {
                        return tipo + "|id:" + rs.getInt("id");
                    }
                }
            }
        }
        return tipo + "|login:" + login.toLowerCase();
    }

    // Busca participante/organizador por e-mail ou CPF e confere a senha
    private Usuario buscarNoBanco(String tipo, String login, String senha) throws SQLException {
        String sql = "SELECT id, senha FROM " + tipo + " WHERE email = ? OR documento = ? LIMIT 1";
        try (Connection c = banco.conectar(); PreparedStatement st = c.prepareStatement(sql)) {
            st.setString(1, login);
            st.setString(2, login);
            try (ResultSet rs = st.executeQuery()) {
                if (!rs.next()) {
                    senhaConfere(senha, HASH_FICTICIO);
                    return null;
                }
                if (senhaConfere(senha, rs.getString("senha"))) {
                    return new Usuario(rs.getInt("id"), tipo, login);
                }
            }
        }
        return null;
    }

    // Confere o moderador pelas variáveis de ambiente
    private Usuario verificarModerador(String login, String senha) {
        String usuarioConfig = BancoDados.variavel("VIEWRITIBA_MODERATOR_USER", "");
        String hashConfig = BancoDados.variavel("VIEWRITIBA_MODERATOR_PASSWORD_HASH", "");
        boolean senhaOk = senhaConfere(senha, hashConfig.isEmpty() ? HASH_FICTICIO : hashConfig);
        if (!usuarioConfig.isEmpty() && !hashConfig.isEmpty() && usuarioConfig.equals(login) && senhaOk) {
            return new Usuario(0, "moderador", login);
        }
        return null;
    }

    // Verifica se a conta está na tabela de banimentos
    private boolean estaBanido(Usuario usuario) throws SQLException {
        String sql = "SELECT 1 FROM conta_banimento WHERE tipo_conta = ? AND id_conta = ? LIMIT 1";
        try (Connection c = banco.conectar(); PreparedStatement st = c.prepareStatement(sql)) {
            st.setString(1, usuario.tipo());
            st.setInt(2, usuario.id());
            try (ResultSet rs = st.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Compara a senha com o hash bcrypt
    static boolean senhaConfere(String senha, String hash) {
        if (hash == null || hash.isEmpty()) {
            return false;
        }
        try {
            return BCrypt.checkpw(senha, hash.replaceFirst("^\\$2y\\$", "\\$2a\\$"));
        } catch (IllegalArgumentException hashInvalido) {
            return false;
        }
    }
}
