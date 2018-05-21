/**
Example certifcate code
gcc -o certcheck certcheck.c -lssl -lcrypto
*/
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>//
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
// #include <resolv.h>
#include <netdb.h>

#include "list.h"
#define MAX_LINE_CHAR 200
#define MAX_CERT_CHAR 50
#define PORTNO 3000
#define MIN_KEY_BYTES 256

/*for handling errors*/
void error(const char *msg) {
    perror(msg);
    exit(1);
}

List* loadCVS(const char* path){
    List* certs_list = new_list();

    FILE *input;
    input = fopen(path,"r");
    if(input == NULL) {
        error("Error opening input file");
    }

    char* line = malloc(MAX_LINE_CHAR * sizeof(char));

    while (feof(input) == 0){
        if( fgets (line, MAX_LINE_CHAR, input)!=NULL ) {
            char *token;
            char *name = malloc(MAX_CERT_CHAR * sizeof(char));
            char *url= malloc((MAX_LINE_CHAR - MAX_CERT_CHAR) * sizeof(char));
            /* get the first argument */
            token = strtok(line, ",");
            strcpy(name,token);


            token = strtok(NULL, "\n");
            strcpy(url,token);
            // printf("name: %s url: %s\n", name, url);
            //insert input into list
            list_add_end(certs_list, name, url);
        }

    }
    free(line);
    fclose(input);
    return certs_list;
}

//check domain name if starts with *
bool wild_card_check(char* url, char* name){
    if (name[0] == '*') {
        name++;
        printf("wildcard %s\n", name);
        printf("url %s\n", url);
        //got rid of the first * char, now see if the domain name contains it
        if (strstr(url, name)) {
            // printf("%s\n", strstr(name, url));
            return true;
        }
    }
    return false;
}

// check validity of domain name (including Subject Alternative Name extension) and wildcards
bool domain_name_valid(char* url, char* commonName){
     //check if domain name is common name
    if (!strncmp(commonName, url, strlen(url))) {
        return true;
        //if it is a
    }else if (wild_card_check(url, commonName)) {
        return true;
    }else{
        //check Subject Alternative Names
    }


    return false;
}
//check public key size
bool keysize_check(X509 *cert){

     EVP_PKEY * pubkey;
     pubkey = X509_get_pubkey (cert);
     RSA * rsa = EVP_PKEY_get1_RSA(pubkey);
     //Now rsa contains RSA public key.
     bool key_valid = false;
     printf("key size %d\n",RSA_size(rsa));

     if (rsa) {
         if (RSA_size(rsa)>= MIN_KEY_BYTES) {
            key_valid = true;
        }else{
            key_valid = false;
            return false;
        }
     }
     EVP_PKEY_free (pubkey);
     return key_valid;

}
// check if the current time is between before and after date
bool date_check(const ASN1_TIME *not_before, const ASN1_TIME *not_after){
    // ASN1_TIME current :
    int before, pday, psec;
    before = ASN1_TIME_diff( &pday,&psec, not_before , NULL);
    if (before == 0) {
        error("invalid time format");
    }
    if ((pday < 0) || (psec < 0)){
        return false;
    }
    else{
        int after;
        after = ASN1_TIME_diff( &pday,&psec, NULL , not_after);
        if (after == 0) {
            error("invalid time format");
        }
        if ((pday < 0) || (psec < 0)){
            return false;
        }
    }
    return true;
}

// this function is based on the certexample.c provided
bool cert_check(char* certpath, char* url){

    //initialisation
    X509 *cert = NULL;
    //create BIO object to read certificate
    BIO *certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, certpath))){
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))){
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    //cert contains the x509 certificate and can be used to analyse the certificate

    //check before & after dates
    const ASN1_TIME *not_before = X509_get_notBefore(cert);
    const ASN1_TIME *not_after = X509_get_notAfter(cert);
    bool date_valid = date_check(not_before, not_after);
    printf("date valid : %d\n", date_valid);
    if (!date_valid) {
        X509_free(cert);
        BIO_free_all(certificate_bio);
        return false;
    }

    //domain name validation
    //get subject name
    X509_NAME *cert_name = X509_get_subject_name(cert);
    // X509_NAME_ENTRY *domain = X509_NAME_get_entry(  cert_name,  0);
    char* commomName = malloc(256 *sizeof(char));
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, commomName, 256);
    bool name_valid = domain_name_valid(url, commomName);
    printf("subject name exact match? %d\n", name_valid);

    const char * subjectname = X509_NAME_oneline(cert_name, 0, 0);
    printf("common name:%s\n", subjectname);

    X509_NAME *cert_issuer = X509_get_issuer_name(cert);
    char issuer_cn[256] = "Issuer CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
    printf("Issuer CommonName:%s\n", issuer_cn);

    //check public key size
    bool key_valid = keysize_check(cert);
    if (!key_valid) {
        return false;
    }

    //List of extensions available at
    //https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
    //Need to check extension exists and is not null
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;


    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    printf("Extension:%s\n", buff);

    BUF_MEM *bptr = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0)){
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    //error
    printf("%zu\n", bptr->length);
    // char *buf = malloc((bptr->length + 2) * sizeof(char));
    // memcpy(buf, bptr->data, bptr->length);
    // buf[bptr->length] = '\0';

    //Can print or parse value
    // printf("always malloc fail %s\n", bptr->data);

    //*********************
    // End of Example code
    //*********************
    X509_free(cert);
    BIO_free_all(certificate_bio);
    BIO_free_all(bio);

    //free(buf);
    return true;
}

int  main(int argc, char const *argv[]) {

    if (argc < 2) {
        error("no file path provided");
    }
    //a lsit to store certificate file input
    List* certs_list = loadCVS(argv[1]);

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    //check each cert
    Node *node = certs_list->head;
    int i = 0;
    while (node) {
        printf("\n\nchecking no.%d\n", i);
        node ->valid = cert_check(node -> name, node -> url);

        node = node->next;
        i++;
    }

    free_word_list(certs_list);
    exit(0);
}
