/**Qianqian Zheng 813288
Assignment 2
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

        //got rid of the first * char, now see if the domain name contains it
        if (strstr(url, name)) {
            return true;
        }
    }
    return false;
}

// check validity of domain name (including Subject Alternative Name extension) and wildcards
bool domain_name_valid(char* url, char* name){

    //check if domain name is common name
    if (strstr(url, name)) {
        return true;
        //if it is a
    }else if (wild_card_check(url, name)) {
        return true;
    }
    return false;
}

bool subject_alt_name_check (X509 *cert) {
    STACK_OF(GENERAL_NAME) * san = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    int num_of_sans;
    if (san) {
        num_of_sans = sk_GENERAL_NAME_num(san);
    } else {
        num_of_sans = 0;
        return false;
    }
    bool match = false;
    for (int i=0; i < num_of_sans; i++) {

        GENERAL_NAME *name =  sk_GENERAL_NAME_pop(san);
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (name) {
            ASN1_STRING_print_ex(ext_bio, name->d.dNSName,ASN1_STRFLGS_SHOW_TYPE);

            BUF_MEM *bptr;
            BIO_get_mem_ptr(ext_bio, &bptr);
            BIO_set_close(ext_bio, BIO_NOCLOSE);

            // remove newlines
            int lastchar = bptr->length;
            if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
                bptr->data[lastchar-1] = (char) 0;
            }
            if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
                bptr->data[lastchar] = (char) 0;
            }
            free(bptr);
        }

        BIO_free(ext_bio);

    }
    return match;
}

bool key_usage_check(X509* cert){
    bool valid = true; //initiate return value
    bool ext_key_usage_found = false;
    bool basic_constraint_found = false;
    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
        return false;
    }

    for (int i=0; i < num_of_exts; i++) {

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        // IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
            M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
        }

        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
            bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
            bptr->data[lastchar] = (char) 0;
        }

        BIO_free(ext_bio);
        unsigned nid = OBJ_obj2nid(obj);
        char* extname = malloc(MAX_CERT_CHAR);
        if (nid == NID_undef) {
            // no lookup found for the provided OID so nid came back as undefined.
            char ext_name[MAX_CERT_CHAR];
            OBJ_obj2txt(ext_name, MAX_CERT_CHAR, (const ASN1_OBJECT *) obj, 1);
            strcpy(extname, ext_name);
        } else {
            // the OID translated to a NID which implies that the OID has a known sn/ln
            const char *c_ext_name = OBJ_nid2ln(nid);
            strcpy(extname, c_ext_name);
        }
        if (strstr(extname, "Basic Constraints")) {
            if (strstr(bptr->data, "CA:TRUE")) {
                valid = false;
                break;
            }
            basic_constraint_found = true;

        }
        if (strstr(extname, "Extended Key Usage"  )) {
            if (!strstr(bptr->data, "TLS Web Server Authentication")) {
                valid = false;
            }
            ext_key_usage_found = true;
        }
        free(extname);
        free(bptr);
    }
    return valid && ext_key_usage_found && basic_constraint_found;
}
//check public key size
bool keysize_check(X509 *cert){

    EVP_PKEY * pubkey;
    pubkey = X509_get_pubkey (cert);
    RSA * rsa = EVP_PKEY_get1_RSA(pubkey);
    //Now rsa contains RSA public key.
    bool key_valid = false;
    if (rsa) {
        if (RSA_size(rsa)>= MIN_KEY_BYTES) {
            key_valid = true;
        }else{
            key_valid = false;
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
    if (!date_valid) {
        X509_free(cert);
        BIO_free_all(certificate_bio);
        return false;
    }

    //domain name validation
    //get subject name
    X509_NAME *cert_name = X509_get_subject_name(cert);
    char* commomName = malloc(256 *sizeof(char));
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, commomName, 256);
    bool name_valid = domain_name_valid(url, commomName);

    // if domain name doesnt match common name, check SANs
    if (!name_valid) {
        name_valid = subject_alt_name_check(cert);
    }
    if (!name_valid) {
        X509_free(cert);
        BIO_free_all(certificate_bio);
        return false;
    }

    //check public key size
    bool key_valid = keysize_check(cert);
    if (!key_valid) {
        X509_free(cert);
        BIO_free_all(certificate_bio);
        return false;
    }

    //List of extensions
    //Need to check extension exists and is not null
    if (!key_usage_check(cert)) {
        X509_free(cert);
        BIO_free_all(certificate_bio);
        return false;
    }
    //*********************
    // End of Example code
    //*********************
    X509_free(cert);
    BIO_free_all(certificate_bio);


    //if there is nothing invalid
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

    FILE *fp;
    fp = fopen("output.csv", "w");

    while (node) {
        node ->valid = cert_check(node -> name, node -> url); //check certificate
        //write result into csv file
        fprintf(fp, "%s,%s,%d\n", node -> name, node -> url, node ->valid);

        node = node->next;
        i++;
    }
    fclose(fp);
    free_word_list(certs_list);
    exit(0);
}
