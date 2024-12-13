#ifndef BLOCO_H
#define BLOCO_H

#include <string>
#include <vector>
#include <ctime>
#include <openssl/evp.h>
#include <iostream>

class Bloco {
public:
    // Construtor
    Bloco(int indice, const std::vector<std::string>& transacoes,
          const std::string& hashAnterior, time_t timestamp);

    // Método para minerar o bloco
    std::string minerarBloco();

    // Método para calcular o hash do bloco
    std::string calcularHashBloco(const std::string& str) const;

    // Getter para o hash do bloco
    std::string getHashBloco() const;

    // Getter para o hash do bloco anterior
    std::string getHashAnterior() const;

    // Método para exibir as informações do bloco
    void exibirInformacoes() const;

    // Método para ajustar a dificuldade
    static void ajustarDificuldade();

    // Getter para a dificuldade
    static int getDificuldade();

    // Variáveis estáticas para controle global
    static int totalBlocosMinerados;  // Contador de blocos minerados
    static time_t tempoUltimoBloco;   // Tempo do último bloco minerado
    static int dificuldade;           // Dificuldade global (para todos os blocos)

private:
    int indice;
    std::vector<std::string> transacoes;
    std::string hashAnterior;
    std::string hashBloco;
    time_t timestamp;
};

#endif  // BLOCO_H
