#include "Bloco.h"
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

Bloco::Bloco(int indice, const std::vector<std::string>& transacoes,
             const std::string& hashAnterior, time_t timestamp)
    : indice(indice), transacoes(transacoes), hashAnterior(hashAnterior), timestamp(timestamp) {
    hashBloco = calcularHashBloco("");  // Passando string vazia para calcularHashBloco
}

std::string Bloco::minerarBloco() {
    std::string alvo(dificuldade, '0');  // Criar uma string com "dificuldade" zeros
    std::string tentativa = hashBloco;   // Começar com o hash inicial
    int nonce = 0;                       // O valor que vai ser alterado para encontrar o hash

    // Tentar encontrar um hash que comece com a quantidade de zeros definida pela dificuldade
    while (tentativa.substr(0, dificuldade) != alvo) {
        nonce++;
        // Criar o hash concatenando o hash do bloco com o nonce
        std::stringstream ss;
        ss << hashBloco << nonce;
        tentativa = calcularHashBloco(ss.str());  // Passamos a string concatenada
    }

    // Retorna o hash final após minerar
    return tentativa;
}

std::string Bloco::calcularHashBloco(const std::string& str) const {
    std::stringstream ss;
    ss << indice << timestamp << hashAnterior << str;  // Adiciona as informações do bloco + string extra
    for (const auto& tx : transacoes) {
        ss << tx;  // Adiciona as transações (como string) ao cálculo do hash
    }

    // Usando EVP para calcular o hash com SHA-256
    unsigned char hashResult[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, ss.str().c_str(), ss.str().length());
    EVP_DigestFinal_ex(mdctx, hashResult, &len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream hashHex;
    for (unsigned int i = 0; i < len; ++i) {
        hashHex << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hashResult[i]);
    }
    return hashHex.str();  // Retorna o hash em formato hexadecimal
}

void Bloco::exibirInformacoes() const {
    std::cout << "Bloco " << indice << " [" << timestamp << "]" << std::endl;
    std::cout << "Hash Anterior: " << hashAnterior << std::endl;
    std::cout << "Hash Atual: " << hashBloco << std::endl;
    for (const auto& tx : transacoes) {
        std::cout << "Transação: " << tx << std::endl;  // Exibe as transações
    }
}

void Bloco::ajustarDificuldade() {
    const int intervaloBlocos = 2016;  // Ajuste a cada 2016 blocos
    const double tempoAlvo = 20160;    // 10 dias (em minutos)

    if (totalBlocosMinerados % intervaloBlocos == 0 && totalBlocosMinerados > 0) {
        time_t tempoAtual = time(0);
        double tempoDecorrido = difftime(tempoAtual, tempoUltimoBloco) / 60;  // Tempo em minutos

        // Ajusta a dificuldade com base no tempo decorrido
        if (tempoDecorrido < tempoAlvo) {
            dificuldade++;  // Aumenta a dificuldade
        } else if (tempoDecorrido > tempoAlvo) {
            dificuldade--;  // Diminui a dificuldade
        }

        tempoUltimoBloco = tempoAtual;
        std::cout << "Dificuldade ajustada para: " << dificuldade << std::endl;
    }
}

int Bloco::getDificuldade() {
    return dificuldade;
}

// Inicializando variáveis estáticas
int Bloco::totalBlocosMinerados = 0;
time_t Bloco::tempoUltimoBloco = 0;
int Bloco::dificuldade = 3;  // Dificuldade inicial
