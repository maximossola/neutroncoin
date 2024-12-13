#include "Transacao.h"
#include <openssl/sha.h>
#include <openssl/err.h>

// Construtor da classe Transacao
Transacao::Transacao(const std::string& remetente, const std::string& destinatario,
                     double valor)
    : remetente(remetente), destinatario(destinatario), valor(valor) {}

// Método para assinar a transação
bool Transacao::assinarTransacao(EVP_PKEY* chavePrivada) {
    // Obter o hash da transação
    std::vector<unsigned char> hash = calcularHashTransacao();

    // Assinar o hash com a chave privada
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, chavePrivada);
    EVP_DigestSignUpdate(mdctx, hash.data(), hash.size());
    size_t assinaturaLen;
    EVP_DigestSignFinal(mdctx, NULL, &assinaturaLen);

    // Alocar espaço para a assinatura
    assinatura.resize(assinaturaLen);

    EVP_DigestSignFinal(mdctx, (unsigned char*)assinatura.data(), &assinaturaLen);
    EVP_MD_CTX_free(mdctx);

    return true;
}

// Método para verificar a assinatura da transação
bool Transacao::verificarAssinatura(EVP_PKEY* chavePublica) const {
    // Gerar hash da transação
    std::vector<unsigned char> hash = calcularHashTransacao();

    // Verificar a assinatura com a chave pública
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, chavePublica);
    EVP_DigestVerifyUpdate(mdctx, hash.data(), hash.size());

    // Converter a assinatura para o formato DER
    const unsigned char* sigptr = assinatura.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &sigptr, assinatura.size());
    if (!sig) {
        std::cerr << "Erro ao converter assinatura para DER." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Converter a assinatura para o formato DER
    unsigned char* der = NULL;
    int derLen = i2d_ECDSA_SIG(sig, &der);
    if (derLen <= 0) {
        std::cerr << "Erro ao converter assinatura para DER." << std::endl;
        EVP_MD_CTX_free(mdctx);
        ECDSA_SIG_free(sig);
        return false;
    }

    // Verificar a assinatura usando o formato DER
    int result = EVP_DigestVerifyFinal(mdctx, der, derLen);

    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);  // Liberar a memória alocada para a assinatura DER
    ECDSA_SIG_free(sig);  // Liberar a assinatura ECDSA_SIG

    if (result != 1) {
        std::cerr << "Erro na verificação da assinatura: "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    return true;
}

// Getters para acessar os atributos da transação
std::string Transacao::getRemetente() const { return remetente; }
std::string Transacao::getDestinatario() const { return destinatario; }
double Transacao::getValor() const { return valor; }

// Converter o vetor de assinatura para string hexadecimal
std::string Transacao::getAssinatura() const {
    std::stringstream ss;
    for (unsigned char c : assinatura) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(c);
    }
    return ss.str();
}

// Método para exibir informações da transação
void Transacao::exibirInformacoes() const {
    std::cout << "Remetente: " << remetente << std::endl;
    std::cout << "Destinatário: " << destinatario << std::endl;
    std::cout << "Valor: " << valor << std::endl;
}

// Método para calcular o hash da transação
std::vector<unsigned char> Transacao::calcularHashTransacao() const {
    std::stringstream ss;
    ss << remetente << destinatario << valor;

    // Gerar hash SHA-256 usando EVP_Digest
    unsigned char hashResult[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, (unsigned char*)ss.str().c_str(), ss.str().length());
    EVP_DigestFinal_ex(mdctx, hashResult, NULL);
    EVP_MD_CTX_free(mdctx);

    return std::vector<unsigned char>(hashResult, hashResult + SHA256_DIGEST_LENGTH);
}
