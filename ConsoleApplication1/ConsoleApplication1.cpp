#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <string.h>

#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave1_u.h"

#define ENCLAVE_FILE _T("Enclave1.signed.dll")

#define BUF_LEN 100 

//const char table[6][41] = {
//    "7eb5ecd8ce73ae063e7ae783c54eac15748667a7",
//    "1c25628f790fd2258821bfe33d6284e8cacf445e",
//    "f4bace63c61af4dc9e1e3c1b6a4271f3bf2c7b25",
//    "ff018ffa70d2deccc38483d5cacc41d7321088f6",
//    "318e469cfb3582c4f6d280ff09654201bd218e85"
//};
//
//void getElementByIndex(char* buf, size_t len, size_t idx) {
//    if (idx < 5) {
//        const char* data_ptr = data_ptr = table[idx];
//        memcpy(buf, data_ptr, strlen(data_ptr)); // Функция memcpy копирует num байтов первого блока памяти, на который ссылается указатель srcptr, во второй блок памяти, на который ссылается указатель destptr.
//    }
//    else {
//        memset(buf, 0, strlen(table[0])); // Функция memset заполняет num байтов блока памяти, через указатель memptr. Код заполняемого символа передаётся в функцию через параметр val.
//    }
//    return;
//}

int main()
{
    char buffer[BUF_LEN] = { 0 }; //создаем пустую переменную, в которую запишем секрет из анклава

    sgx_enclave_id_t eid; // id анклава, в проекте может быть несколько анклавов, каждый со своим id
    sgx_status_t ret = SGX_SUCCESS; //необходимо для отлавливания ошибок на этапе доступа к анклаву	 
    sgx_launch_token_t token = { 0 }; //инициализация токена запуска для анклава
    int updated = 0; // токен запуска не был изменен

    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL); //функция создания анклава
    if (ret != SGX_SUCCESS) {
        printf("App: error %#x, failed to create enclave. \n", ret);
        return -1;
    }

    while (true)
    {
        printf("Input index to retrieve, or -1 to exit: \t");
        int idx = 0;
        scanf_s("%d", &idx); //сканирует импут
        if (idx < 0) {
            return 0;
        }
        getElementByIndex(eid, buffer, BUF_LEN, idx);
        printf("%s\n=======================\n\n", buffer);
        // std::cout << buffer<<"\n";
    }
    if (SGX_SUCCESS != sgx_destroy_enclave(eid))
        return -1;
    return 0;
}