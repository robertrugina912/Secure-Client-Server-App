#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "db.h"
#include "worker.h"
#include "api.h"


sqlite3 *get_db_instance(void) {
    char *err_msg = 0;

    sqlite3 *db;
    int res = sqlite3_open("chat.db",&db);
    if(res != SQLITE_OK) {
        printf("Error connecting to db!\n");
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return NULL;
    }
    return db;
}


char* generate_salt(char *salt) {

    const char *letters = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    srand(time(0));

    int i;
    int val;
    for(i = 0; i < 32; i++) {
        val = (rand() % 62);
        salt[i] = letters[val];
    }
    return 0;
}

char* hash_password(char *password, char *salt) {


    SHA_CTX ctx;
    unsigned char hash[SHA_DIGEST_LENGTH];


    size_t total_len = strlen(password) + strlen(salt);
    char *salted_password = (char*) malloc((total_len+1) * sizeof(char));
    strcpy(salted_password,salt);
    strcpy(salted_password + strlen(salt),password);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, salted_password, strlen(salted_password));
    SHA1_Final(hash, &ctx);

    free(salted_password);
    
    size_t hash_len = sizeof(hash);
    char *hex_hash = malloc(hash_len * 2 * sizeof(hash));

    char hex[2];
    char *hex_format = "%.2x";
    int offset = 0;
    int i = 0;

    for(i = 0; i < hash_len-1; i++) {
        sprintf(hex,hex_format,hash[i]);
        strcpy(hex_hash + offset,hex);
        offset += strlen(hex);
    }
    
    
    return hex_hash;
}



int set_user_online(char *username) {
    sqlite3 *db = get_db_instance();


    char *err_msg = 0;
    char *format = "UPDATE Users SET online = 1 WHERE username = '%s';";

    char *sql_update_user_state = (char *) malloc( (strlen(format) +strlen(username)) * sizeof(char) );
    sprintf(sql_update_user_state, format, username);


    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_exec(db,sql_update_user_state, 0, 0, &err_msg);

    if (res != SQLITE_OK) {
        printf("ERROR LOGGING IN USER %s: %s\n",username,err_msg);
    }

    sqlite3_close(db);
    sqlite3_free(err_msg);
    free(sql_update_user_state);
    return res;
}

int set_user_offline(char *username) {

    sqlite3 *db = get_db_instance();

    char *format = "UPDATE Users SET online = 0 WHERE username = '%s';";

    char *sql_update_user_state = (char *) malloc( (strlen(format) +strlen(username)) * sizeof(char) );
    sprintf(sql_update_user_state, format, username);

    char *err_msg = 0;

    
    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_exec(db,sql_update_user_state, 0, 0, &err_msg);
    if (res != SQLITE_OK) {
        printf("ERROR LOGGING OUT USER %s: %s\n",username,err_msg);
    }

    sqlite3_close(db);
    sqlite3_free(err_msg);
    free(sql_update_user_state);
    return res;
}


int sql_injection_prone(char *str) {
    int i;
    for(i = 0; i < strlen(str); i++) {
        if (
            str[i] == 34 ||
            str[i] == 37 ||
            str[i] == 39 ||
            str[i] == 59
        )
        return 1;
    }
    return 0;
}


int user_exists(char *username) {
    assert(username);


    if(sql_injection_prone(username)) 
        return 0;

    int res = 0;
    int exists = 1;

    sqlite3 *db = get_db_instance();
    if (!db) return 1;


    struct sqlite3_stmt *select;
    char *format = "SELECT * FROM Users WHERE username = '%s';";
    char *sql_user_exists = (char *) malloc( (strlen(format)+strlen(username)) * sizeof(char) );
    sprintf(sql_user_exists, format, username);

    sqlite3_busy_timeout(db,2000);
    res = sqlite3_prepare_v2(db,sql_user_exists, -1, &select, NULL);
    if(res == SQLITE_OK) {
        if(sqlite3_step(select) == SQLITE_ROW) {
            exists = 1;
        } else {
            exists = 0;
        }
    } 
    sqlite3_finalize(select);
    sqlite3_close_v2(db);
    free(sql_user_exists);
    return exists;
}

int create_user(char *username, char *password) {

    assert(username);
    assert(password);

    char *err_msg;


    if(strlen(username) < 2 || strlen(username) > 255) 
        return -2;
    
    if(strlen(password) < 3 || strlen(password) > 127) 
        return -3;

    if(sql_injection_prone(username) || sql_injection_prone(password)) 
        return -4;

    if (user_exists(username))
        return -1;
    

    sqlite3 *db = get_db_instance();
    if (!db) return 1;

    char salt[32];
    
    generate_salt(salt);
    char *hash = hash_password(password,salt);

    char *format = "INSERT INTO Users(username,password,salt,online) VALUES ('%s','%s','%s',%d);";
    char *sql_create_user = (char *) malloc( 
        (
            strlen(format) +
            strlen(username) +
            strlen(hash) +
            strlen(salt) + 1
        ) * sizeof(char) );
    sprintf(sql_create_user, format, username, (char*)hash, salt, 1);

    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_exec(db,sql_create_user, 0, 0, &err_msg);
    if(res != SQLITE_OK) {
        printf("%s\n",err_msg);
    }

    sqlite3_close(db);
    free(sql_create_user);
    free(hash);

    return res;
}



static int salt_callback(void *salt, int count, char **data,char **columns) {
    strcpy(salt,data[3]);
    return 0;
}
static int password_callback(void *pwd, int count, char **data, char **columns) {
    strcpy(pwd,data[2]);
    return 0;
}

void get_user_password(char *username, char *password) {
    assert(username);

    sqlite3 *db = get_db_instance();
    if (!db) return;

    char *format = "SELECT * FROM Users WHERE username = '%s';";
    char *sql_get_user = (char *) malloc(
        (strlen(format) + strlen(username)) * sizeof(char)
    );

    sprintf(sql_get_user, format, username);

    sqlite3_busy_timeout(db,2000);
    sqlite3_exec(db,sql_get_user, password_callback, password, NULL);

    sqlite3_close(db);
    free(sql_get_user);
}

void get_user_salt(char *username, char *salt) {
    assert(username);

    sqlite3 *db = get_db_instance();
    if (!db) return;

    char *format = "SELECT * FROM Users WHERE username = '%s';";
    char *sql_get_user = (char *) malloc(
        (strlen(format) + strlen(username)) * sizeof(char)
    );

    sprintf(sql_get_user, format, username);
    sqlite3_busy_timeout(db,2000);
    sqlite3_exec(db,sql_get_user, salt_callback, salt, NULL);

    sqlite3_close(db);
    free(sql_get_user);
}




int login_user(char *username, char *password) {
    assert(username);
    assert(password);

    if(sql_injection_prone(username) || sql_injection_prone(password)) 
        return -2;

    char *db_password = (char*)malloc(256*sizeof(char));
    char *db_salt = (char*)malloc(32*sizeof(char));

    get_user_password(username,db_password);
    get_user_salt(username,db_salt);

    char *hash = hash_password(password,db_salt);

    if(db_password == NULL) return -1;

    if(strcmp(hash,db_password) == 0) {
        set_user_online(username);
        free(hash);
        free(db_password);
        free(db_salt);
        return 0;
    }

    free(hash);
    free(db_password);
    free(db_salt);

    return -1;
}

char* all_users() {


    sqlite3 *db = get_db_instance();

    size_t username_len = 0;
    char *buf = NULL;
    int buf_offset = 0;
    size_t buf_size = 0;


    char *sql_online_users = "SELECT username FROM Users WHERE online = 1;";
    struct sqlite3_stmt *select;

    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_prepare_v2(db,sql_online_users, -1, &select, NULL);
    if (res == SQLITE_OK) {
        while (1) {
            if(sqlite3_step(select) == SQLITE_ROW) {
                username_len = strlen((char *)sqlite3_column_text(select,0));
                buf_size = buf_size + username_len + 2;
                buf = realloc(buf,buf_size);

                strcpy(buf + buf_offset,(char *)sqlite3_column_text(select,0));
                buf_offset += username_len;

                strcat(buf,"\n");
                buf_offset ++;
            } else break;
        }
    }


    sqlite3_finalize(select);
    sqlite3_close_v2(db);

    if(buf == NULL) return "ERROR\n";
    return buf;
}






int create_message(struct api_state *api, const struct api_msg *msg) {
    assert(msg);
    time_t now;
    time(&now);

    char now_buf[11];
    sprintf(now_buf,"%ld",now);



    sqlite3 *db = get_db_instance();
    if (!db) return 1;


    char *format = "INSERT INTO Chat(timestamp,type,recipient,sender,message) VALUES (%s,'%s','%s','%s','%s');";

    char *msg_type;
    char *msg_recipient;
    char *msg_content;
    if(msg->command == CMD_PRV_MSG) {

        msg_type = "PRV";

        msg_recipient = (char*) malloc((strlen(msg->payload) + 1) * sizeof(char));
        strcpy(msg_recipient,msg->payload);

        msg_content = (char*) malloc((strlen(msg->payload + msg->arg_1_size) + 1) * sizeof(char));
        strcpy(msg_content,(msg->payload + msg->arg_1_size));
    }
    else {
        
        msg_type = "PUB";

        msg_recipient = (char*) malloc(2 * sizeof(char));
        strcpy(msg_recipient,"_");

        msg_content = (char*) malloc((strlen(msg->payload) + 1) * sizeof(char));
        strcpy(msg_content,msg->payload);
    }

    if(sql_injection_prone(msg_recipient) || sql_injection_prone(msg_content)) {
        free(msg_content);
        free(msg_recipient);
        sqlite3_close(db);
        return -1;
    }



    char *sql_create_chat = (char *) malloc( 
        (
            strlen(format) +
            strlen(now_buf) +
            strlen(msg_type) +
            strlen(msg_recipient) +
            strlen(api->user) +
            strlen(msg_content)
        ) * sizeof(char) );

    sprintf(
        sql_create_chat, 
        format,
        now_buf,
        msg_type,
        msg_recipient,
        api->user,
        msg_content
    );


    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_exec(db,sql_create_chat, 0, 0, NULL);


    free(msg_content);
    free(msg_recipient);
    free(sql_create_chat);
    sqlite3_close(db);


    return res;
}




int get_msg_count(void) {

    sqlite3 *db = get_db_instance();
    if (!db) return 1;


    int res = 0;
    int count = 0;

    struct sqlite3_stmt *select;

    char *sql_all_msg = "SELECT * FROM Chat;";

    sqlite3_busy_timeout(db,2000);
    res = sqlite3_prepare_v2(db,sql_all_msg, -1, &select, NULL);

    if(res == SQLITE_OK) {
        while(sqlite3_step(select) == SQLITE_ROW) {
            count++;
        }
    } 
    sqlite3_finalize(select);
    sqlite3_close_v2(db);
    return count;
}





int get_msg(struct api_state *api, struct api_msg *msg, int index) {

    if(index < 0) return -1;
    int id = index + 1;
    int ret = -1;


    sqlite3 *db = get_db_instance();
    struct sqlite3_stmt *select;

    char *format = "SELECT * FROM Chat WHERE id = %d;";
    char *sql_get_msg = (char*) malloc(
        (
            (int)((ceil(log10(id))+1)) +
            strlen(format)
        )
        * sizeof(char)
    );

    sprintf(sql_get_msg,format,id);

    sqlite3_busy_timeout(db,2000);
    int res = sqlite3_prepare_v2(db,sql_get_msg, -1, &select, NULL);
    if (res == SQLITE_OK) {
        if (sqlite3_step(select) == SQLITE_ROW) {

            int timestamp = sqlite3_column_int(select,1);
            char* msg_type = (char*)sqlite3_column_text(select,2);
            char* msg_recipient = (char*)sqlite3_column_text(select,3);
            char* msg_sender = (char*)sqlite3_column_text(select,4);
            char* msg_content = (char*)sqlite3_column_text(select,5);
            


            if (strcmp(msg_type,"PUB") == 0) msg->command = CMD_PUB_MSG;
            else msg->command = CMD_PRV_MSG;            

            if (
                strcmp(msg_type,"PUB") == 0 ||
                strcmp(msg_recipient,api->user) == 0 ||
                strcmp(msg_sender,api->user) == 0
            ) {
                char *args = (char *) malloc ( 
                    (
                        (int)((ceil(log10(timestamp)))) +
                        strlen(msg_type) +
                        strlen(msg_recipient) +
                        strlen(msg_sender) +
                        5
                    ) * sizeof(char)
                );

                char *args_format = "%d:%s:%s:%s";
                sprintf(args,args_format,timestamp,msg_type,msg_recipient,msg_sender);

                msg->arg_1_size = (strlen(args)+1)*sizeof(char);
                msg->arg_2_size = (strlen(msg_content)+1)*sizeof(char);
                msg->total_size = sizeof(struct api_msg) + msg->arg_1_size + msg->arg_2_size;

                memcpy(
                    msg->payload,
                    args,
                    msg->arg_1_size
                );
                memcpy(
                    msg->payload + msg->arg_1_size,
                    msg_content,
                    msg->arg_2_size
                );
                ret = 0;
            }


        }
    }

    sqlite3_finalize(select);
    free(sql_get_msg);
    sqlite3_close_v2(db);


    return ret;
}






// function that ensures all tables exist on server start
int db_init( void ) {

    char *err_msg = 0;


    // CREATE DATABASE
    sqlite3 *db = get_db_instance();
    if (!db) return 1;
    int res;

    char *sql_init_users = "CREATE TABLE Users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, salt TEXT, online TINYINT);";
    char *sql_init_chat = "CREATE TABLE Chat (id INTEGER PRIMARY KEY, timestamp INTEGER, type TEXT, recipient TEXT, sender TEXT, message TEXT );";

    res = sqlite3_exec(db, sql_init_chat, 0, 0, &err_msg);
    if (res != SQLITE_OK) {
        printf("%s\n",err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    res = sqlite3_exec(db, sql_init_users, 0, 0, &err_msg);
    if (res != SQLITE_OK) {
        printf("%s\n",err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }


    sqlite3_close(db);
    return 0;
}
