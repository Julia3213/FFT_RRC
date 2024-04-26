#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>

int main() {
    // Создание сокета
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error: Unable to create socket" << std::endl;
        return 1;
    }

    // Подключение к серверу
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345); // Порт сервера
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // IP сервера

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error: Connection failed" << std::endl;
        return 1;
    }

    // Формирование и отправка сообщения RRCConnectionRequest серверу
    RRCConnectionRequest_t rrcrequest;
    memset(&rrcrequest, 0, sizeof(rrcrequest));

    // Заполняем поля структуры
    InitialUE_Identity_t initialUE_Identity;
    initialUE_Identity.present = InitialUE_Identity_PR_randomValue; 
    initialUE_Identity.choice.randomValue.size = 5; 
    initialUE_Identity.choice.randomValue.buf = (uint8_t *)"12345"; 

    EstablishmentCause_t establishmentCause = EstablishmentCause_initialAccess;

    ProtocolErrorIndicator_t protocolErrorIndicator;
    protocolErrorIndicator = ProtocolErrorIndicator_normal;

    rrcrequest.initialUE_Identity = initialUE_Identity;
    rrcrequest.establishmentCause = establishmentCause;
    rrcrequest.protocolErrorIndicator = protocolErrorIndicator;

    size_t bufSize = 1024; 
    uint8_t *buf = (uint8_t *)malloc(bufSize);
    if (!buf) {
        std::cerr << "Error: Memory allocation failed" << std::endl;
        return 1;
    }

    // Кодируем структуру RRCConnectionRequest в формат DER
    asn_enc_rval_t encRetVal = der_encode_to_buffer(&asn_DEF_RRCConnectionRequest, &rrcrequest, buf, bufSize);
    if (encRetVal.encoded == -1) {
        std::cerr << "Error: Encoding failed" << std::endl;
        free(buf);
        return 1;
    }

    // Выводим закодированное сообщение в формате DER
    std::cout << "Encoded message (DER format):" << std::endl;
    for (size_t i = 0; i < encRetVal.encoded; ++i) {
        printf("%02X ", buf[i]);
    }
    std::cout << std::endl;

    // Освобождаем выделенную память
    free(buf);

    ssize_t sentLen = send(clientSocket, encRetVal, sizeof(encRetVal), 0);
    if (sentLen < 0) {
        std::cerr << "Error: Send failed" << std::endl;
        return 1;
    }

    uint8_t receivedMessage[4096]; // Предполагаемый буфер для принятого сообщения

    // Принимаем сообщение от сервера
    ssize_t recvLen = recv(clientSocket, receivedMessage, sizeof(receivedMessage), 0);
    if (recvLen < 0) {
        std::cerr << "Error: Receive failed" << std::endl;
        return 1;
    }

    // Создаем структуру для декодированного сообщения RRCConnectionSetupComplete
    RRCConnectionSetupComplete_t rrcComplete;
    memset(&rrcComplete, 0, sizeof(rrcComplete)); // Обнуляем структуру

    // Декодируем принятое сообщение в формате DER
    asn_dec_rval_t decRetVal = der_decode(0, &asn_DEF_RRCConnectionSetupComplete, (void **)&rrcComplete, receivedMessage, recvLen);
    if (decRetVal.code != RC_OK) {
        std::cerr << "Error decoding RRCConnectionSetupComplete: " << decRetVal.code << std::endl;
        return 1;
    }

    // Выводим информацию на экран (пример)
    std::cout << "Decoded RRCConnectionSetupComplete:" << std::endl;
    std::cout << "Transaction Identifier: " << rrcComplete.rrc_TransactionIdentifier << std::endl;

    // Закрытие сокета
    close(clientSocket);

    return 0;
}
