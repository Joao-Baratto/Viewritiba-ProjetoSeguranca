
package viewritiba;

public final class ControleAcesso {

    private ControleAcesso() {
    }

    public static boolean podeExcluirCategoria(Usuario usuario) {

        if (usuario == null) {
            return false;
        }

        return "moderador".equalsIgnoreCase(usuario.tipo());
    }
}
