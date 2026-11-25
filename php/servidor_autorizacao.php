<?php

// Endereço do servidor Java e certificado confiável
const SERVIDOR_AUTH = 'tls://192.168.56.20:5000';
const CERTIFICADO_AUTH = __DIR__ . '/servidor.crt';

// Envia uma linha ao servidor Java por TLS e devolve a resposta
function servidor_autorizacao(string $linha): array
{
    // Impede quebra de linha no comando
    if (preg_match('/[\r\n]/', $linha)) {
        return ['ERRO', 'ENTRADA_INVALIDA'];
    }

    // Só aceita o certificado do servidor Java
    $endereco = getenv('VIEWRITIBA_AUTH_ADDR') ?: SERVIDOR_AUTH;
    $contexto = stream_context_create(['ssl' => [
        'cafile' => CERTIFICADO_AUTH,
        'verify_peer' => true,
        'verify_peer_name' => true,
        'peer_name' => getenv('VIEWRITIBA_AUTH_NOME') ?: '192.168.56.20',
    ]]);

    // Servidor fora do ar: nega (falha segura)
    $conexao = @stream_socket_client($endereco, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $contexto);
    if ($conexao === false) {
        error_log("Servidor de autorização indisponível: $errstr");
        return ['ERRO', 'SERVIDOR_INDISPONIVEL'];
    }

    // Envia o comando e lê a resposta
    stream_set_timeout($conexao, 5);
    fwrite($conexao, $linha . "\n");
    $resposta = trim((string) fgets($conexao));
    fclose($conexao);

    return $resposta === '' ? ['ERRO', 'SEM_RESPOSTA'] : explode(';', $resposta);
}

// Pergunta se uma ação é permitida (comando ACAO)
function acao_permitida(string $acao, int $recurso): bool
{
    $token = $_SESSION['token_auth'] ?? '';
    if ($token === '') {
        return false;
    }
    $resposta = servidor_autorizacao("ACAO;$token;$acao;$recurso");
    return $resposta[0] === 'PERMITIDO';
}
