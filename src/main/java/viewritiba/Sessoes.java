package viewritiba;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// Sessões criadas após o login (token de 256 bits)
public class Sessoes {

    private static final long VALIDADE_MS = 30 * 60 * 1000;

    private record Sessao(Usuario usuario, long expiraEm) { }

    private final SecureRandom aleatorio = new SecureRandom();
    private final Map<String, Sessao> sessoes = new ConcurrentHashMap<>();

    // Gera um token aleatório para o usuário
    public String criar(Usuario usuario) {
        byte[] bytes = new byte[32];
        aleatorio.nextBytes(bytes);
        String token = HexFormat.of().formatHex(bytes);
        sessoes.put(token, new Sessao(usuario, System.currentTimeMillis() + VALIDADE_MS));
        return token;
    }

    // Valida o token e renova o prazo de 30 minutos
    public Usuario validar(String token) {
        Sessao sessao = sessoes.get(token);
        if (sessao == null) {
            return null;
        }
        long agora = System.currentTimeMillis();
        if (sessao.expiraEm() < agora) {
            sessoes.remove(token);
            return null;
        }
        sessoes.put(token, new Sessao(sessao.usuario(), agora + VALIDADE_MS));
        return sessao.usuario();
    }

    // Encerra a sessão (logout)
    public void encerrar(String token) {
        sessoes.remove(token);
    }

    // Apaga sessões vencidas
    public void limparExpiradas() {
        long agora = System.currentTimeMillis();
        sessoes.values().removeIf(sessao -> sessao.expiraEm() < agora);
    }
}
